using System.Diagnostics;
using System.Text;
using System.Text.Json;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.EventPipeline;
using ConShield.MongoProjection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;
using RabbitMQ.Client;

namespace ConShield.Tests;

[Collection("PostgreSql")]
public class MongoProjectionTests
{
    private const string PostgresVariable = "CONSHIELD_TEST_POSTGRES_CONNECTION";
    private const string MongoConnectionVariable = "CONSHIELD_TEST_MONGODB_CONNECTION";
    private const string MongoDatabaseVariable = "CONSHIELD_TEST_MONGODB_DATABASE";

    [Fact]
    public void MongoProjectionOptions_ValidateBounds()
    {
        var validator = new MongoProjectionOptionsValidator();

        Assert.False(validator.Validate(null, Options(enabled: false, connectionString: "")).Failed);
        Assert.True(validator.Validate(null, Options(enabled: true, connectionString: "")).Failed);
        Assert.True(validator.Validate(null, Options(databaseName: "bad/name")).Failed);
        Assert.True(validator.Validate(null, Options(collectionName: "bad name")).Failed);
        Assert.True(validator.Validate(null, Options(retentionDays: 0)).Failed);
        Assert.True(validator.Validate(null, Options(connectTimeoutSeconds: 0)).Failed);
        Assert.True(validator.Validate(null, Options(maxDocumentBytes: 1024)).Failed);
    }

    [Fact]
    public void MongoSecurityEventDocument_MapsEnvelopeToImmutableDocument()
    {
        var envelope = Envelope();
        var body = Body(envelope);
        var hash = SecurityEventEnvelopeValidator.Sha256Hex(body);
        var now = DateTime.SpecifyKind(DateTime.UtcNow, DateTimeKind.Utc);

        var mapped = MongoSecurityEventDocument.FromEnvelope(envelope, hash, now, retentionDays: 30);
        var document = mapped.ToBsonDocument();

        Assert.Equal(envelope.MessageId.ToString("D").ToLowerInvariant(), mapped.Id);
        Assert.Equal(mapped.Id, mapped.MessageId);
        Assert.Equal(hash, mapped.PayloadSha256);
        Assert.Equal(DateTimeKind.Utc, mapped.ProjectedAtUtc.Kind);
        Assert.Equal(now.AddDays(30), mapped.ExpiresAtUtc);
        Assert.True(document["securityEvent"]["additionalData"]["test"].AsBoolean);
        Assert.False(document.Contains("headers"));
    }

    [Fact]
    public void MongoSecurityEventDocument_RejectsMalformedAdditionalDataShape()
    {
        var envelope = Envelope(additionalData: JsonDocument.Parse("""[1,2]""").RootElement.Clone());

        Assert.Throws<InvalidOperationException>(() =>
            MongoSecurityEventDocument.FromEnvelope(envelope, "00", DateTime.UtcNow, 30));
    }

    [Fact]
    public void MongoProjectionClassifier_MapsFailures()
    {
        Assert.Equal(MongoProjectionOutcome.TransientFailure,
            MongoSecurityEventProjection.ClassifyFailure(new TimeoutException()).Outcome);
        Assert.Equal(MongoProjectionOutcome.PermanentFailure,
            MongoSecurityEventProjection.ClassifyFailure(new InvalidOperationException()).Outcome);
    }

    [PostgreSqlFact]
    public async Task Inbox_MismatchedPayloadIdentity_IsPermanentFailure()
    {
        await using var db = await CreateMigratedDbContextAsync();
        var envelope = Envelope();
        var body = Body(envelope);
        var processor = InboxProcessor(db);
        var props = RabbitMqSecurityEventOutboxSink.CreateProperties(envelope);

        var first = await processor.ProcessAsync(body, props, "security.event.created", false, CancellationToken.None);
        var changed = envelope with { SecurityEvent = envelope.SecurityEvent with { Id = envelope.SecurityEvent.Id + 1 } };
        var changedBody = Body(changed);
        var changedProps = RabbitMqSecurityEventOutboxSink.CreateProperties(changed);
        changedProps.MessageId = envelope.MessageId.ToString("D");

        var duplicate = await processor.ProcessAsync(changedBody, changedProps, "security.event.created", true, CancellationToken.None);

        Assert.Equal(InboxProcessOutcome.Processed, first.Outcome);
        Assert.Equal(InboxProcessOutcome.PermanentFailure, duplicate.Outcome);
        Assert.Equal("inbox_payload_mismatch", duplicate.Failure?.ErrorCode);
        Assert.Equal(1, await db.SecurityEventInboxReceipts.CountAsync());
    }

    [MongoDbFact]
    public async Task MongoProjection_InsertDuplicateMismatchAndIndexes_Work()
    {
        var options = MongoOptions();
        var client = new MongoClient(options.ConnectionString);
        var database = client.GetDatabase(options.DatabaseName);
        await database.DropCollectionAsync(options.CollectionName);
        var initializer = new MongoProjectionIndexInitializer(client, Microsoft.Extensions.Options.Options.Create(options));
        await initializer.InitializeAsync(CancellationToken.None);

        var projection = new MongoSecurityEventProjection(client, Microsoft.Extensions.Options.Options.Create(options));
        var envelope = Envelope();
        var body = Body(envelope);
        var hash = SecurityEventEnvelopeValidator.Sha256Hex(body);

        var inserted = await projection.ProjectMongoAsync(envelope, hash, DateTime.UtcNow, CancellationToken.None);
        var duplicate = await projection.ProjectMongoAsync(envelope, hash, DateTime.UtcNow, CancellationToken.None);
        var mismatch = await projection.ProjectMongoAsync(envelope, "ff" + hash[2..], DateTime.UtcNow, CancellationToken.None);

        var collection = database.GetCollection<BsonDocument>(options.CollectionName);
        var indexes = await (await collection.Indexes.ListAsync()).ToListAsync();
        var document = await collection.Find(Builders<BsonDocument>.Filter.Eq("_id", envelope.MessageId.ToString("D").ToLowerInvariant())).SingleAsync();

        Assert.Equal(MongoProjectionOutcome.Inserted, inserted.Outcome);
        Assert.Equal(MongoProjectionOutcome.AlreadyProjected, duplicate.Outcome);
        Assert.Equal("mongo_duplicate_payload_mismatch", mismatch.ErrorCode);
        Assert.Equal(1, await collection.CountDocumentsAsync(FilterDefinition<BsonDocument>.Empty));
        Assert.Contains(indexes, x => x["name"] == "ttl_expires_at_utc" && x["expireAfterSeconds"] == 0);
        Assert.True(document["securityEvent"]["additionalData"].IsBsonDocument);
        Assert.False(document.Contains("headers"));
    }

    [RabbitMqMongoFact]
    public async Task RabbitMqMongoPostgres_DuplicateAndPayloadMismatch_Work()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var rabbitOptions = RabbitOptionsFromEnvironment(suffix);
        await using var provider = new RabbitMqConnectionProvider(
            Microsoft.Extensions.Options.Options.Create(rabbitOptions),
            NullLogger<RabbitMqConnectionProvider>.Instance);
        var connection = await provider.GetConnectionAsync("conshield-mongo-test", CancellationToken.None);
        await using var channel = await connection.CreateChannelAsync(cancellationToken: CancellationToken.None);
        await using var publishChannel = await connection.CreateChannelAsync(
            new CreateChannelOptions(
                publisherConfirmationsEnabled: true,
                publisherConfirmationTrackingEnabled: true,
                outstandingPublisherConfirmationsRateLimiter: null,
                consumerDispatchConcurrency: null),
            CancellationToken.None);
        await new RabbitMqTopology(Microsoft.Extensions.Options.Options.Create(rabbitOptions)).DeclareAsync(channel, CancellationToken.None);

        var mongoOptions = MongoOptions(collectionName: $"security_event_raw_v1_{suffix}");
        var mongoClient = new MongoClient(mongoOptions.ConnectionString);
        await mongoClient.GetDatabase(mongoOptions.DatabaseName).DropCollectionAsync(mongoOptions.CollectionName);
        await new MongoProjectionIndexInitializer(mongoClient, Microsoft.Extensions.Options.Options.Create(mongoOptions)).InitializeAsync(CancellationToken.None);

        await using var db = await CreateMigratedDbContextAsync();
        var processor = DeliveryProcessor(db, rabbitOptions, mongoClient, mongoOptions);
        var envelope = Envelope();
        var body = Body(envelope);
        var props = RabbitMqSecurityEventOutboxSink.CreateProperties(envelope);
        await PublishConfirmedAsync(publishChannel, rabbitOptions, props, body);
        await PublishConfirmedAsync(publishChannel, rabbitOptions, props, body);

        var changed = envelope with { SecurityEvent = envelope.SecurityEvent with { Description = "Changed payload." } };
        var changedBody = Body(changed);
        var changedProps = RabbitMqSecurityEventOutboxSink.CreateProperties(changed);
        changedProps.MessageId = envelope.MessageId.ToString("D");
        await PublishConfirmedAsync(publishChannel, rabbitOptions, changedProps, changedBody);
        await WaitForQueueCountAtLeastAsync(channel, rabbitOptions.QueueName, 3, CancellationToken.None);

        var first = await ConsumeOneAsync(channel, processor, rabbitOptions, receiveNumber: 1);
        var duplicate = await ConsumeOneAsync(channel, processor, rabbitOptions, receiveNumber: 2);
        var mismatch = await ConsumeOneAsync(channel, processor, rabbitOptions, receiveNumber: 3);

        var collection = mongoClient.GetDatabase(mongoOptions.DatabaseName).GetCollection<BsonDocument>(mongoOptions.CollectionName);
        Assert.Equal(InboxProcessOutcome.Processed, first.Outcome);
        Assert.Equal(InboxProcessOutcome.Duplicate, duplicate.Outcome);
        Assert.Equal(InboxProcessOutcome.PermanentFailure, mismatch.Outcome);
        Assert.Equal(1, await db.SecurityEventInboxReceipts.CountAsync());
        Assert.Equal(1, await collection.CountDocumentsAsync(FilterDefinition<BsonDocument>.Empty));
        await WaitForQueueCountAtLeastAsync(channel, rabbitOptions.DeadLetterQueueName, 1, CancellationToken.None);
    }

    private static async Task<InboxProcessResult> ConsumeOneAsync(
        IChannel channel,
        SecurityEventDeliveryProcessor processor,
        RabbitMqOptions options,
        int receiveNumber)
    {
        var message = await GetMessageEventuallyAsync(channel, options.QueueName, receiveNumber, CancellationToken.None);
        var result = await processor.ProcessAsync(
            message.Body.ToArray(),
            message.BasicProperties,
            message.RoutingKey,
            message.Redelivered,
            CancellationToken.None);

        if (result.Outcome is InboxProcessOutcome.Processed or InboxProcessOutcome.Duplicate)
            await channel.BasicAckAsync(message.DeliveryTag, false, CancellationToken.None);
        else
            await channel.BasicNackAsync(message.DeliveryTag, false, result.Outcome == InboxProcessOutcome.TransientFailure, CancellationToken.None);

        return result;
    }

    private static async Task PublishConfirmedAsync(
        IChannel channel,
        RabbitMqOptions options,
        BasicProperties properties,
        ReadOnlyMemory<byte> body)
    {
        await channel.BasicPublishAsync(
            options.ExchangeName,
            options.RoutingKey,
            mandatory: true,
            basicProperties: properties,
            body: body,
            cancellationToken: CancellationToken.None);
    }

    private static async Task<BasicGetResult> GetMessageEventuallyAsync(
        IChannel channel,
        string queueName,
        int receiveNumber,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        while (stopwatch.Elapsed < TimeSpan.FromSeconds(5))
        {
            var message = await channel.BasicGetAsync(queueName, autoAck: false, cancellationToken);
            if (message is not null)
                return message;
            await Task.Delay(75, cancellationToken);
        }

        var count = await channel.MessageCountAsync(queueName, cancellationToken);
        throw new Xunit.Sdk.XunitException(
            $"Timed out waiting for RabbitMQ Mongo test message #{receiveNumber} from '{queueName}'. MessageCount={count}, ElapsedMs={stopwatch.ElapsedMilliseconds}.");
    }

    private static async Task WaitForQueueCountAtLeastAsync(
        IChannel channel,
        string queueName,
        uint expectedAtLeast,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        while (stopwatch.Elapsed < TimeSpan.FromSeconds(5))
        {
            var count = await channel.MessageCountAsync(queueName, cancellationToken);
            if (count >= expectedAtLeast)
                return;
            await Task.Delay(75, cancellationToken);
        }

        var finalCount = await channel.MessageCountAsync(queueName, cancellationToken);
        throw new Xunit.Sdk.XunitException(
            $"Timed out waiting for queue '{queueName}' to contain at least {expectedAtLeast} messages. MessageCount={finalCount}, ElapsedMs={stopwatch.ElapsedMilliseconds}.");
    }

    private static SecurityEventDeliveryProcessor DeliveryProcessor(
        ApplicationDbContext db,
        RabbitMqOptions rabbitOptions,
        IMongoClient mongoClient,
        MongoProjectionOptions mongoOptions)
    {
        var clock = new FakeClock(DateTime.UtcNow);
        return new SecurityEventDeliveryProcessor(
            InboxProcessor(db, rabbitOptions, clock),
            new MongoSecurityEventProjection(mongoClient, Microsoft.Extensions.Options.Options.Create(mongoOptions)),
            clock,
            Microsoft.Extensions.Options.Options.Create(rabbitOptions));
    }

    private static SecurityEventInboxProcessor InboxProcessor(ApplicationDbContext db, RabbitMqOptions? options = null, IOutboxClock? clock = null) =>
        new(db, clock ?? new FakeClock(DateTime.UtcNow), Microsoft.Extensions.Options.Options.Create(options ?? RabbitOptions()));

    private static byte[] Body(SecurityEventEnvelope envelope) =>
        JsonSerializer.SerializeToUtf8Bytes(envelope, new JsonSerializerOptions(JsonSerializerDefaults.Web));

    private static SecurityEventEnvelope Envelope(JsonElement? additionalData = null) => new(
        1,
        Guid.NewGuid(),
        SecurityEventEnvelope.SecurityEventCreatedMessageType,
        DateTime.UtcNow,
        new SecurityEventEnvelopeData(
            42,
            DateTime.UtcNow,
            "ExternalEvent",
            "Info",
            "mongo-test",
            "127.0.0.1",
            Guid.NewGuid(),
            "conshield.tests",
            "mongo.test",
            "test-host",
            "Mongo projection test event.",
            additionalData ?? JsonDocument.Parse("""{"test":true}""").RootElement.Clone()));

    private static MongoProjectionOptions Options(
        bool enabled = true,
        string connectionString = "mongodb://example.invalid",
        string databaseName = "conshield_events",
        string collectionName = "security_event_raw_v1",
        int retentionDays = 30,
        int connectTimeoutSeconds = 10,
        int maxDocumentBytes = 262144) => new()
    {
        Enabled = enabled,
        ConnectionString = connectionString,
        DatabaseName = databaseName,
        CollectionName = collectionName,
        RetentionDays = retentionDays,
        ConnectTimeoutSeconds = connectTimeoutSeconds,
        OperationTimeoutSeconds = 10,
        MaxDocumentBytes = maxDocumentBytes
    };

    private static MongoProjectionOptions MongoOptions(string? collectionName = null)
    {
        var connection = Environment.GetEnvironmentVariable(MongoConnectionVariable)
            ?? throw new InvalidOperationException($"{MongoConnectionVariable} is required.");
        var database = Environment.GetEnvironmentVariable(MongoDatabaseVariable) ?? "conshield_events";
        return Options(connectionString: connection, databaseName: database, collectionName: collectionName ?? $"security_event_raw_v1_{Guid.NewGuid():N}");
    }

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

    private static RabbitMqOptions RabbitOptions(string suffix = "mongo-unit") => new()
    {
        Enabled = true,
        HostName = "localhost",
        Port = 5672,
        VirtualHost = "/conshield",
        UserName = "conshield",
        Password = "local-test-password",
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
        var options = RabbitOptions(suffix);
        options.HostName = Environment.GetEnvironmentVariable("CONSHIELD_TEST_RABBITMQ_HOST") ?? "localhost";
        options.Port = int.Parse(Environment.GetEnvironmentVariable("CONSHIELD_TEST_RABBITMQ_PORT") ?? "5672");
        options.VirtualHost = Environment.GetEnvironmentVariable("CONSHIELD_TEST_RABBITMQ_VHOST") ?? "/conshield";
        options.UserName = Environment.GetEnvironmentVariable("CONSHIELD_TEST_RABBITMQ_USERNAME") ?? string.Empty;
        options.Password = Environment.GetEnvironmentVariable("CONSHIELD_TEST_RABBITMQ_PASSWORD") ?? string.Empty;
        return options;
    }

    private sealed class FakeClock : IOutboxClock
    {
        public FakeClock(DateTime utcNow) => UtcNow = DateTime.SpecifyKind(utcNow, DateTimeKind.Utc);
        public DateTime UtcNow { get; set; }
    }
}

public sealed class MongoDbFactAttribute : FactAttribute
{
    public MongoDbFactAttribute()
    {
        var required = new[] { "CONSHIELD_TEST_MONGODB_CONNECTION", "CONSHIELD_TEST_MONGODB_DATABASE" };
        if (required.Any(name => string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(name))))
            Skip = "Set MongoDB test environment variables to run MongoDB integration tests.";
    }
}

public sealed class RabbitMqMongoFactAttribute : FactAttribute
{
    public RabbitMqMongoFactAttribute()
    {
        var required = new[]
        {
            "CONSHIELD_TEST_RABBITMQ_HOST",
            "CONSHIELD_TEST_RABBITMQ_PORT",
            "CONSHIELD_TEST_RABBITMQ_VHOST",
            "CONSHIELD_TEST_RABBITMQ_USERNAME",
            "CONSHIELD_TEST_RABBITMQ_PASSWORD",
            "CONSHIELD_TEST_POSTGRES_CONNECTION",
            "CONSHIELD_TEST_MONGODB_CONNECTION",
            "CONSHIELD_TEST_MONGODB_DATABASE"
        };

        if (required.Any(name => string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(name))))
            Skip = "Set PostgreSQL, RabbitMQ, and MongoDB test environment variables to run pipeline integration tests.";
    }
}
