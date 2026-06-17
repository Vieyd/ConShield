using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using ConShield.Data;
using ConShield.EventPipeline;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;
using RabbitMQ.Client.Exceptions;
using RabbitMQ.Client.Events;

namespace ConShield.Tests;

[Collection("PostgreSql")]
public class RabbitMqEventPipelineTests
{
    private const string PostgresVariable = "CONSHIELD_TEST_POSTGRES_CONNECTION";

    [Fact]
    public void RabbitMqProperties_ArePersistentAndBounded()
    {
        var envelope = Envelope();

        var properties = RabbitMqSecurityEventOutboxSink.CreateProperties(envelope);

        Assert.Equal("application/json", properties.ContentType);
        Assert.Equal("utf-8", properties.ContentEncoding);
        Assert.Equal(DeliveryModes.Persistent, properties.DeliveryMode);
        Assert.True(properties.Persistent);
        Assert.Equal(envelope.MessageId.ToString("D"), properties.MessageId);
        Assert.Equal("security.event.created", properties.Type);
        Assert.Equal("conshield", properties.AppId);
        Assert.NotNull(properties.Headers);
        Assert.Equal(1, properties.Headers["schema-version"]);
    }

    [Fact]
    public void RabbitMqEnvelopeValidation_RejectsMessageIdMismatch()
    {
        var envelope = Envelope();
        var properties = RabbitMqSecurityEventOutboxSink.CreateProperties(envelope);
        properties.MessageId = Guid.NewGuid().ToString("D");

        var result = SecurityEventEnvelopeValidator.ValidateRabbitProperties(
            properties,
            "security.event.created",
            RabbitOptions(),
            envelope);

        Assert.NotNull(result);
        Assert.Equal(OutboxSinkResultType.PermanentFailure, result!.Type);
        Assert.Equal("message_id_mismatch", result.ErrorCode);
    }

    [Fact]
    public void RabbitMqOptions_RequireCredentialsOnlyWhenEnabled()
    {
        var jsonlValidator = new RabbitMqOptionsValidator(Options.Create(new SecurityEventOutboxOptions { Transport = SecurityEventOutboxTransport.Jsonl }));
        var rabbitValidator = new RabbitMqOptionsValidator(Options.Create(new SecurityEventOutboxOptions { Transport = SecurityEventOutboxTransport.RabbitMq }));
        var disabledRabbit = RabbitOptions(userName: string.Empty, password: string.Empty);
        disabledRabbit.Enabled = false;

        Assert.False(jsonlValidator.Validate(null, disabledRabbit).Failed);
        Assert.True(rabbitValidator.Validate(null, RabbitOptions(userName: "", password: "")).Failed);
    }

    [Fact]
    public async Task RabbitMqSink_RejectsOversizedBodyWithoutBroker()
    {
        var sink = new RabbitMqSecurityEventOutboxSink(
            new ThrowingConnectionProvider(),
            new RabbitMqTopology(Options.Create(RabbitOptions())),
            Options.Create(RabbitOptions()),
            NullLogger<RabbitMqSecurityEventOutboxSink>.Instance);

        var result = await sink.DeliverAsync(Envelope(description: new string('x', 70000)), CancellationToken.None);

        Assert.Equal(OutboxSinkResultType.PermanentFailure, result.Type);
        Assert.Equal("body_too_large", result.ErrorCode);
    }

    [Fact]
    public void RabbitMqPublishFailureClassifier_MapsMandatoryReturnToMandatoryReturn()
    {
        var result = RabbitMqSecurityEventOutboxSink.ClassifyPublishFailure(
            new PublishReturnException(1, "exchange", "security.event.unbound", "message-id", 312, "NO_ROUTE"));

        Assert.Equal(OutboxSinkResultType.TransientFailure, result.Type);
        Assert.Equal("mandatory_return", result.ErrorCode);
    }

    [Fact]
    public void RabbitMqPublishFailureClassifier_MapsPublisherNackToPublisherNack()
    {
        var result = RabbitMqSecurityEventOutboxSink.ClassifyPublishFailure(new PublishException(1, false));

        Assert.Equal(OutboxSinkResultType.TransientFailure, result.Type);
        Assert.Equal("publisher_nack", result.ErrorCode);
    }

    [Fact]
    public void RabbitMqPublishFailureClassifier_MapsBrokerUnavailableToTransient()
    {
        var result = RabbitMqSecurityEventOutboxSink.ClassifyPublishFailure(
            new BrokerUnreachableException(new IOException("network unavailable")));

        Assert.Equal(OutboxSinkResultType.TransientFailure, result.Type);
        Assert.Equal("rabbitmq_unavailable", result.ErrorCode);
    }

    [Fact]
    public void RabbitMqPublishFailureClassifier_MapsCancellationToPublishTimeout()
    {
        var result = RabbitMqSecurityEventOutboxSink.ClassifyPublishFailure(new OperationCanceledException());

        Assert.Equal(OutboxSinkResultType.TransientFailure, result.Type);
        Assert.Equal("publish_timeout", result.ErrorCode);
    }

    [PostgreSqlFact]
    public async Task Inbox_InsertDuplicateAndConcurrentDuplicate_CreateOneRow()
    {
        await using var db = await CreateMigratedDbContextAsync();
        var envelope = Envelope();
        var body = JsonSerializer.SerializeToUtf8Bytes(envelope, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var properties = RabbitMqSecurityEventOutboxSink.CreateProperties(envelope);
        var processor = Processor(db);

        var first = await processor.ProcessAsync(body, properties, "security.event.created", false, CancellationToken.None);
        var duplicate = await processor.ProcessAsync(body, properties, "security.event.created", true, CancellationToken.None);

        Assert.Equal(InboxProcessOutcome.Processed, first.Outcome);
        Assert.Equal(InboxProcessOutcome.Duplicate, duplicate.Outcome);
        Assert.Equal(1, await db.SecurityEventInboxReceipts.CountAsync());
        var row = await db.SecurityEventInboxReceipts.SingleAsync();
        Assert.Equal(envelope.MessageId, row.MessageId);
        Assert.Equal(envelope.SecurityEvent.Id, row.SecurityEventId);
        Assert.Equal(SecurityEventEnvelopeValidator.Sha256Hex(body), row.PayloadSha256);
        Assert.True(row.Redelivered);
        Assert.Equal(DateTimeKind.Utc, row.ReceivedAtUtc.Kind);
    }

    [RabbitMqFact]
    public async Task RabbitMq_PublishConfirmAndMandatoryRouting_Work()
    {
        var options = RabbitOptionsFromEnvironment(Guid.NewGuid().ToString("N"));
        await using var provider = ConnectionProvider(options);
        var topology = new RabbitMqTopology(Options.Create(options));
        var sink = new RabbitMqSecurityEventOutboxSink(provider, topology, Options.Create(options), NullLogger<RabbitMqSecurityEventOutboxSink>.Instance);

        var success = await sink.DeliverAsync(Envelope(), CancellationToken.None);

        Assert.Equal(OutboxSinkResultType.Succeeded, success.Type);
        var connection = await provider.GetConnectionAsync("conshield-test", CancellationToken.None);
        await using var channel = await connection.CreateChannelAsync(cancellationToken: CancellationToken.None);
        Assert.Equal(1u, await channel.MessageCountAsync(options.QueueName, CancellationToken.None));

        var unroutableOptions = RabbitOptionsFromEnvironment(Guid.NewGuid().ToString("N"));
        unroutableOptions.ExchangeName = options.ExchangeName;
        unroutableOptions.DeadLetterExchangeName = options.DeadLetterExchangeName;
        unroutableOptions.RoutingKey = "security.event.unbound";
        var unroutable = new RabbitMqSecurityEventOutboxSink(provider, topology, Options.Create(unroutableOptions), NullLogger<RabbitMqSecurityEventOutboxSink>.Instance);
        var failure = await unroutable.DeliverAsync(Envelope(), CancellationToken.None);
        Assert.Equal(OutboxSinkResultType.TransientFailure, failure.Type);
        Assert.Equal("mandatory_return", failure.ErrorCode);
        Assert.Equal(1u, await channel.MessageCountAsync(options.QueueName, CancellationToken.None));

        var afterReturn = await sink.DeliverAsync(Envelope(), CancellationToken.None);
        Assert.Equal(OutboxSinkResultType.Succeeded, afterReturn.Type);
        Assert.Equal(2u, await channel.MessageCountAsync(options.QueueName, CancellationToken.None));
    }

    [RabbitMqFact]
    public async Task RabbitMq_ConsumerAckDuplicateAndDlq_Work()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var options = RabbitOptionsFromEnvironment(suffix);
        await using var provider = ConnectionProvider(options);
        var connection = await provider.GetConnectionAsync("conshield-test", CancellationToken.None);
        await using var channel = await connection.CreateChannelAsync(cancellationToken: CancellationToken.None);
        await new RabbitMqTopology(Options.Create(options)).DeclareAsync(channel, CancellationToken.None);

        await using var db = await CreateMigratedDbContextAsync();
        var envelope = Envelope();
        var body = JsonSerializer.SerializeToUtf8Bytes(envelope, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var props = RabbitMqSecurityEventOutboxSink.CreateProperties(envelope);
        await channel.BasicPublishAsync(options.ExchangeName, options.RoutingKey, true, props, body, CancellationToken.None);
        await channel.BasicPublishAsync(options.ExchangeName, options.RoutingKey, true, props, body, CancellationToken.None);
        await channel.BasicPublishAsync(options.ExchangeName, options.RoutingKey, true, props, Encoding.UTF8.GetBytes("{"), CancellationToken.None);

        for (var i = 0; i < 3; i++)
            await ConsumeOneAsync(channel, db, options);

        Assert.Equal(1, await db.SecurityEventInboxReceipts.CountAsync(x => x.MessageId == envelope.MessageId));
        Assert.True(await WaitForCountAsync(channel, options.DeadLetterQueueName, expectedAtLeast: 1));
    }

    private static async Task ConsumeOneAsync(IChannel channel, ApplicationDbContext db, RabbitMqOptions options)
    {
        var message = await channel.BasicGetAsync(options.QueueName, autoAck: false, CancellationToken.None);
        Assert.NotNull(message);
        var processor = Processor(db, options);
        var body = message!.Body.ToArray();
        try
        {
            var result = await processor.ProcessAsync(body, message.BasicProperties, message.RoutingKey, message.Redelivered, CancellationToken.None);
            if (result.Outcome is InboxProcessOutcome.Processed or InboxProcessOutcome.Duplicate)
                await channel.BasicAckAsync(message.DeliveryTag, false, CancellationToken.None);
            else
                await channel.BasicNackAsync(message.DeliveryTag, false, false, CancellationToken.None);
        }
        catch
        {
            await channel.BasicNackAsync(message.DeliveryTag, false, true, CancellationToken.None);
            throw;
        }
    }

    private static async Task<bool> WaitForCountAsync(IChannel channel, string queueName, uint expectedAtLeast)
    {
        for (var i = 0; i < 20; i++)
        {
            if (await channel.MessageCountAsync(queueName, CancellationToken.None) >= expectedAtLeast)
                return true;
            await Task.Delay(250);
        }

        return false;
    }

    private static SecurityEventInboxProcessor Processor(ApplicationDbContext db, RabbitMqOptions? options = null) =>
        new(db, new FakeClock(DateTime.UtcNow), Options.Create(options ?? RabbitOptions()));

    private static async Task<ApplicationDbContext> CreateMigratedDbContextAsync()
    {
        var db = new ApplicationDbContext(DbOptions());
        await db.Database.EnsureDeletedAsync();
        await db.Database.MigrateAsync();
        return db;
    }

    private static DbContextOptions<ApplicationDbContext> DbOptions()
    {
        var connectionString = Environment.GetEnvironmentVariable(PostgresVariable)
            ?? throw new InvalidOperationException($"{PostgresVariable} is required.");
        return new DbContextOptionsBuilder<ApplicationDbContext>().UseNpgsql(connectionString).Options;
    }

    private static RabbitMqConnectionProvider ConnectionProvider(RabbitMqOptions options) =>
        new(Options.Create(options), NullLogger<RabbitMqConnectionProvider>.Instance);

    private static RabbitMqOptions RabbitOptions(
        string suffix = "unit",
        string userName = "conshield",
        string password = "local-test-password") => new()
    {
        Enabled = true,
        HostName = "localhost",
        Port = 5672,
        VirtualHost = "/conshield",
        UserName = userName,
        Password = password,
        ExchangeName = $"conshield.security.events.v1.{suffix}",
        RoutingKey = "security.event.created",
        QueueName = $"conshield.security-events.consumer.v1.{suffix}",
        DeadLetterExchangeName = $"conshield.security.events.dlx.v1.{suffix}",
        DeadLetterRoutingKey = "security.event.dead",
        DeadLetterQueueName = $"conshield.security-events.dead.v1.{suffix}",
        PrefetchCount = 20,
        ConnectionTimeoutSeconds = 10,
        PublishTimeoutSeconds = 10,
        ConsumerShutdownTimeoutSeconds = 10
    };

    private static RabbitMqOptions RabbitOptionsFromEnvironment(string suffix)
    {
        var options = RabbitOptions(
            suffix,
            Environment.GetEnvironmentVariable("CONSHIELD_TEST_RABBITMQ_USERNAME") ?? string.Empty,
            Environment.GetEnvironmentVariable("CONSHIELD_TEST_RABBITMQ_PASSWORD") ?? string.Empty);
        options.HostName = Environment.GetEnvironmentVariable("CONSHIELD_TEST_RABBITMQ_HOST") ?? "localhost";
        options.Port = int.Parse(Environment.GetEnvironmentVariable("CONSHIELD_TEST_RABBITMQ_PORT") ?? "5672");
        options.VirtualHost = Environment.GetEnvironmentVariable("CONSHIELD_TEST_RABBITMQ_VHOST") ?? "/conshield";
        return options;
    }

    private static SecurityEventEnvelope Envelope(string description = "RabbitMQ test event.") => new(
        1,
        Guid.NewGuid(),
        "security.event.created",
        DateTime.UtcNow,
        new SecurityEventEnvelopeData(
            42,
            DateTime.UtcNow,
            "ExternalEvent",
            "Info",
            "rabbit-test",
            "127.0.0.1",
            Guid.NewGuid(),
            "conshield.tests",
            "rabbit.test",
            "test-host",
            description,
            JsonDocument.Parse("""{"test":true}""").RootElement.Clone()));

    private sealed class FakeClock : IOutboxClock
    {
        public FakeClock(DateTime utcNow) => UtcNow = DateTime.SpecifyKind(utcNow, DateTimeKind.Utc);
        public DateTime UtcNow { get; set; }
    }

    private sealed class ThrowingConnectionProvider : IRabbitMqConnectionProvider
    {
        public Task<IConnection> GetConnectionAsync(string connectionName, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Should not connect for permanent validation failures.");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

public sealed class RabbitMqFactAttribute : FactAttribute
{
    public RabbitMqFactAttribute()
    {
        var required = new[]
        {
            "CONSHIELD_TEST_RABBITMQ_HOST",
            "CONSHIELD_TEST_RABBITMQ_PORT",
            "CONSHIELD_TEST_RABBITMQ_VHOST",
            "CONSHIELD_TEST_RABBITMQ_USERNAME",
            "CONSHIELD_TEST_RABBITMQ_PASSWORD",
            "CONSHIELD_TEST_POSTGRES_CONNECTION"
        };

        if (required.Any(name => string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(name))))
            Skip = "Set PostgreSQL and RabbitMQ test environment variables to run RabbitMQ integration tests.";
    }
}
