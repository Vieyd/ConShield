using System.Collections.Concurrent;
using System.Text.Json;
using ConShield.Application;
using ConShield.Application.Models;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.EventPipeline;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ConShield.Tests;

[Collection("PostgreSql")]
public class SecurityEventOutboxTests
{
    private const string ConnectionVariable = "CONSHIELD_TEST_POSTGRES_CONNECTION";

    [PostgreSqlFact]
    public async Task SecurityEventWriter_CreatesEventAndOutboxAtomically()
    {
        await using var db = await CreateMigratedDbContextAsync();
        var writer = new SecurityEventWriter(db);

        await writer.WriteAsync(Request(additionalData: new { action = "login", ok = true }));

        var entry = await db.SecurityEvents.SingleAsync();
        var outbox = await db.SecurityEventOutboxMessages.SingleAsync();
        using var payload = JsonDocument.Parse(outbox.PayloadJson);

        Assert.Equal(entry.Id, outbox.SecurityEventId);
        Assert.Equal("security.event.created", outbox.MessageType);
        Assert.Equal(SecurityEventOutboxStatus.Pending, outbox.Status);
        Assert.Equal(entry.Id, payload.RootElement.GetProperty("securityEvent").GetProperty("id").GetInt64());
        Assert.Equal(outbox.MessageId, payload.RootElement.GetProperty("messageId").GetGuid());
        Assert.Equal(JsonValueKind.Object, payload.RootElement.GetProperty("securityEvent").GetProperty("additionalData").ValueKind);
    }

    [PostgreSqlFact]
    public async Task SecurityEventWriter_OversizedEnvelopeRollsBackEvent()
    {
        await using var db = await CreateMigratedDbContextAsync();
        var writer = new SecurityEventWriter(db);

        await Assert.ThrowsAsync<InvalidOperationException>(() => writer.WriteAsync(
            Request(additionalData: new { value = new string('x', 70000) })));

        Assert.Equal(0, await db.SecurityEvents.CountAsync());
        Assert.Equal(0, await db.SecurityEventOutboxMessages.CountAsync());
    }

    [PostgreSqlFact]
    public async Task SecurityEventWriter_ExistingTransactionCommitsBothRows()
    {
        await using var db = await CreateMigratedDbContextAsync();
        await using var transaction = await db.Database.BeginTransactionAsync();
        var writer = new SecurityEventWriter(db);

        await writer.WriteAsync(Request());
        await transaction.CommitAsync();

        Assert.Equal(1, await db.SecurityEvents.CountAsync());
        Assert.Equal(1, await db.SecurityEventOutboxMessages.CountAsync());
    }

    [PostgreSqlFact]
    public async Task SecurityEventWriter_CancellationBeforeCommitLeavesNoRows()
    {
        await using var db = await CreateMigratedDbContextAsync();
        var writer = new SecurityEventWriter(db);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => writer.WriteAsync(Request(), cts.Token));

        Assert.Equal(0, await db.SecurityEvents.CountAsync());
        Assert.Equal(0, await db.SecurityEventOutboxMessages.CountAsync());
    }

    [PostgreSqlFact]
    public async Task ExternalEventDuplicate_DoesNotCreateSecondOutboxMessage()
    {
        await using var db = await CreateMigratedDbContextAsync();
        var writer = new SecurityEventWriter(db);
        var service = new ExternalSecurityEventIngestionService(db, writer);
        var externalEventId = Guid.NewGuid();
        var request = new ExternalSecurityEventIngestRequest
        {
            ExternalEventId = externalEventId,
            OccurredAtUtc = DateTime.UtcNow,
            SourceSystem = "collector-tests",
            EventType = "CollectorTestEvent",
            Severity = "Info",
            SourceHost = "test-host",
            Description = "Duplicate outbox test.",
            AdditionalData = JsonDocument.Parse("""{"test":true}""").RootElement
        };

        var first = await service.IngestAsync(request, "127.0.0.1");
        var second = await service.IngestAsync(request, "127.0.0.1");

        Assert.True(first.Created);
        Assert.False(second.Created);
        Assert.Equal(1, await db.SecurityEvents.CountAsync());
        Assert.Equal(1, await db.SecurityEventOutboxMessages.CountAsync());
    }

    [PostgreSqlFact]
    public async Task Dispatcher_DeliversPendingMessage()
    {
        await using var db = await CreateMigratedDbContextAsync();
        await new SecurityEventWriter(db).WriteAsync(Request());
        var sink = new FakeSink(OutboxSinkResult.Succeeded());
        var dispatcher = Dispatcher(db, sink);

        var result = await dispatcher.DispatchOnceAsync();

        Assert.Equal(1, result.Delivered);
        var row = await db.SecurityEventOutboxMessages.SingleAsync();
        Assert.Equal(SecurityEventOutboxStatus.Delivered, row.Status);
        Assert.NotNull(row.DeliveredAtUtc);
        Assert.Single(sink.DeliveredMessageIds);
    }

    [PostgreSqlFact]
    public async Task Dispatcher_TransientFailureSchedulesRetryThenSucceeds()
    {
        await using var db = await CreateMigratedDbContextAsync();
        await new SecurityEventWriter(db).WriteAsync(Request());
        var clock = new FakeClock(DateTime.UtcNow);
        var sink = new FakeSink(
            OutboxSinkResult.TransientFailure("io_error", "temporary"),
            OutboxSinkResult.Succeeded());
        var dispatcher = Dispatcher(db, sink, clock);

        await dispatcher.DispatchOnceAsync();
        var pending = await db.SecurityEventOutboxMessages.SingleAsync();
        Assert.Equal(SecurityEventOutboxStatus.Pending, pending.Status);
        Assert.Equal(1, pending.AttemptCount);
        Assert.True(pending.AvailableAtUtc > clock.UtcNow);

        clock.UtcNow = pending.AvailableAtUtc.AddMilliseconds(1);
        await dispatcher.DispatchOnceAsync();

        var delivered = await db.SecurityEventOutboxMessages.SingleAsync();
        Assert.Equal(SecurityEventOutboxStatus.Delivered, delivered.Status);
    }

    [PostgreSqlFact]
    public async Task Dispatcher_PermanentFailureDeadLetters()
    {
        await using var db = await CreateMigratedDbContextAsync();
        await new SecurityEventWriter(db).WriteAsync(Request());
        var dispatcher = Dispatcher(db, new FakeSink(OutboxSinkResult.PermanentFailure("bad_payload", "permanent")));

        await dispatcher.DispatchOnceAsync();

        var row = await db.SecurityEventOutboxMessages.SingleAsync();
        Assert.Equal(SecurityEventOutboxStatus.DeadLetter, row.Status);
        Assert.Equal("bad_payload", row.LastErrorCode);
    }

    [PostgreSqlFact]
    public async Task Dispatcher_MaxAttemptsDeadLetters()
    {
        await using var db = await CreateMigratedDbContextAsync();
        await new SecurityEventWriter(db).WriteAsync(Request());
        var row = await db.SecurityEventOutboxMessages.SingleAsync();
        row.AttemptCount = 4;
        await db.SaveChangesAsync();
        var dispatcher = Dispatcher(db, new FakeSink(OutboxSinkResult.TransientFailure("io_error", "temporary")));

        await dispatcher.DispatchOnceAsync();

        row = await db.SecurityEventOutboxMessages.SingleAsync();
        Assert.Equal(SecurityEventOutboxStatus.DeadLetter, row.Status);
        Assert.Equal(5, row.AttemptCount);
    }

    [PostgreSqlFact]
    public async Task Dispatcher_DoesNotClaimDeliveredOrDeadLetterRows()
    {
        await using var db = await CreateMigratedDbContextAsync();
        await new SecurityEventWriter(db).WriteAsync(Request());
        await new SecurityEventWriter(db).WriteAsync(Request(description: "second"));
        var rows = await db.SecurityEventOutboxMessages.OrderBy(x => x.Id).ToListAsync();
        rows[0].Status = SecurityEventOutboxStatus.Delivered;
        rows[1].Status = SecurityEventOutboxStatus.DeadLetter;
        await db.SaveChangesAsync();
        var sink = new FakeSink(OutboxSinkResult.Succeeded());

        var result = await Dispatcher(db, sink).DispatchOnceAsync();

        Assert.Equal(0, result.Claimed);
        Assert.Empty(sink.DeliveredMessageIds);
    }

    [PostgreSqlFact]
    public async Task Dispatcher_ReclaimsOnlyStaleProcessingLocks()
    {
        await using var db = await CreateMigratedDbContextAsync();
        await new SecurityEventWriter(db).WriteAsync(Request());
        await new SecurityEventWriter(db).WriteAsync(Request(description: "second"));
        var now = DateTime.UtcNow;
        var rows = await db.SecurityEventOutboxMessages.OrderBy(x => x.Id).ToListAsync();
        rows[0].Status = SecurityEventOutboxStatus.Processing;
        rows[0].LockToken = Guid.NewGuid();
        rows[0].LockedUntilUtc = now.AddSeconds(-1);
        rows[1].Status = SecurityEventOutboxStatus.Processing;
        rows[1].LockToken = Guid.NewGuid();
        rows[1].LockedUntilUtc = now.AddMinutes(1);
        await db.SaveChangesAsync();
        var sink = new FakeSink(OutboxSinkResult.Succeeded());

        var result = await Dispatcher(db, sink, new FakeClock(now)).DispatchOnceAsync();

        Assert.Equal(1, result.Claimed);
        Assert.Single(sink.DeliveredMessageIds);
    }

    [PostgreSqlFact]
    public async Task Dispatcher_LockTokenMismatchCannotMarkDelivered()
    {
        await using var db = await CreateMigratedDbContextAsync();
        await new SecurityEventWriter(db).WriteAsync(Request());
        var options = DbOptions();
        var sink = new FakeSink(OutboxSinkResult.Succeeded())
        {
            OnDeliver = async messageId =>
            {
                await using var other = new ApplicationDbContext(options);
                var row = await other.SecurityEventOutboxMessages.SingleAsync(x => x.MessageId == messageId);
                row.LockToken = Guid.NewGuid();
                await other.SaveChangesAsync();
            }
        };

        await Dispatcher(db, sink).DispatchOnceAsync();

        var result = await db.SecurityEventOutboxMessages.SingleAsync();
        Assert.Equal(SecurityEventOutboxStatus.Processing, result.Status);
        Assert.Null(result.DeliveredAtUtc);
    }

    [PostgreSqlFact]
    public async Task Dispatcher_BadPayloadDoesNotBlockNextMessage()
    {
        await using var db = await CreateMigratedDbContextAsync();
        await new SecurityEventWriter(db).WriteAsync(Request());
        await new SecurityEventWriter(db).WriteAsync(Request(description: "second"));
        var bad = await db.SecurityEventOutboxMessages.OrderBy(x => x.Id).FirstAsync();
        bad.PayloadJson = "{";
        await db.SaveChangesAsync();

        await Dispatcher(db, new FakeSink(OutboxSinkResult.Succeeded())).DispatchOnceAsync();

        Assert.Equal(1, await db.SecurityEventOutboxMessages.CountAsync(x => x.Status == SecurityEventOutboxStatus.DeadLetter));
        Assert.Equal(1, await db.SecurityEventOutboxMessages.CountAsync(x => x.Status == SecurityEventOutboxStatus.Delivered));
    }

    [PostgreSqlFact]
    public async Task Dispatcher_ConcurrentInstancesDeliverEachMessageOnce()
    {
        await using var setup = await CreateMigratedDbContextAsync();
        for (var i = 0; i < 10; i++)
            await new SecurityEventWriter(setup).WriteAsync(Request(description: $"event {i}"));

        var sink = new FakeSink(OutboxSinkResult.Succeeded());
        var options = DbOptions();
        await using var db1 = new ApplicationDbContext(options);
        await using var db2 = new ApplicationDbContext(options);

        await Task.WhenAll(
            Dispatcher(db1, sink).DispatchOnceAsync(),
            Dispatcher(db2, sink).DispatchOnceAsync());

        Assert.Equal(10, sink.DeliveredMessageIds.Count);
        Assert.Equal(10, sink.DeliveredMessageIds.Distinct().Count());
        Assert.Equal(10, await setup.SecurityEventOutboxMessages.CountAsync(x => x.Status == SecurityEventOutboxStatus.Delivered));
    }

    [Fact]
    public async Task JsonlSink_WritesSingleLineWithMessageIdAndObjectAdditionalData()
    {
        var root = TempRoot();
        var sink = new JsonlSecurityEventOutboxSink(root, Options.Create(OutboxOptions()));
        var envelope = Envelope();

        var result = await sink.DeliverAsync(envelope, CancellationToken.None);

        Assert.Equal(OutboxSinkResultType.Succeeded, result.Type);
        var line = Assert.Single(await File.ReadAllLinesAsync(Path.Combine(root, "logs", "security-events.jsonl")));
        using var json = JsonDocument.Parse(line);
        Assert.Equal(envelope.MessageId, json.RootElement.GetProperty("messageId").GetGuid());
        Assert.Equal(JsonValueKind.Object, json.RootElement.GetProperty("securityEvent").GetProperty("additionalData").ValueKind);
    }

    [Fact]
    public async Task JsonlSink_ConcurrentWritesDoNotMixLines()
    {
        var root = TempRoot();
        var sink = new JsonlSecurityEventOutboxSink(root, Options.Create(OutboxOptions()));
        var envelopes = Enumerable.Range(0, 20).Select(_ => Envelope()).ToArray();

        await Task.WhenAll(envelopes.Select(x => sink.DeliverAsync(x, CancellationToken.None)));

        var lines = await File.ReadAllLinesAsync(Path.Combine(root, "logs", "security-events.jsonl"));
        Assert.Equal(20, lines.Length);
        Assert.All(lines, line => JsonDocument.Parse(line).Dispose());
    }

    [Theory]
    [InlineData("..\\outside.jsonl")]
    [InlineData("logs/../outside.jsonl")]
    public async Task JsonlSink_RejectsTraversalPath(string path)
    {
        var sink = new JsonlSecurityEventOutboxSink(TempRoot(), Options.Create(OutboxOptions(path)));

        var result = await sink.DeliverAsync(Envelope(), CancellationToken.None);

        Assert.Equal(OutboxSinkResultType.PermanentFailure, result.Type);
        Assert.Equal("invalid_path", result.ErrorCode);
    }

    [Fact]
    public async Task JsonlSink_RejectsAbsolutePath()
    {
        var sink = new JsonlSecurityEventOutboxSink(TempRoot(), Options.Create(OutboxOptions(Path.GetTempFileName())));

        var result = await sink.DeliverAsync(Envelope(), CancellationToken.None);

        Assert.Equal(OutboxSinkResultType.PermanentFailure, result.Type);
    }

    [Fact]
    public async Task JsonlSink_CancellationIsTransient()
    {
        var sink = new JsonlSecurityEventOutboxSink(TempRoot(), Options.Create(OutboxOptions()));
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var result = await sink.DeliverAsync(Envelope(), cts.Token);

        Assert.Equal(OutboxSinkResultType.TransientFailure, result.Type);
        Assert.DoesNotContain("secret-local-key", result.SafeErrorSummary ?? string.Empty);
    }

    [Fact]
    public async Task JsonlSink_LineSizeIsBounded()
    {
        var sink = new JsonlSecurityEventOutboxSink(TempRoot(), Options.Create(OutboxOptions()));

        var result = await sink.DeliverAsync(Envelope(description: new string('x', 70000)), CancellationToken.None);

        Assert.Equal(OutboxSinkResultType.PermanentFailure, result.Type);
        Assert.Equal("line_too_large", result.ErrorCode);
    }

    [Fact]
    public void Dispatcher_BackoffIsBounded()
    {
        using var db = new ApplicationDbContext(new DbContextOptionsBuilder<ApplicationDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        var dispatcher = Dispatcher(db, new FakeSink(OutboxSinkResult.Succeeded()));

        Assert.Equal(1, dispatcher.CalculateBackoffSeconds(1));
        Assert.Equal(2, dispatcher.CalculateBackoffSeconds(2));
        Assert.Equal(60, dispatcher.CalculateBackoffSeconds(30));
    }

    private static SecurityEventWriteRequest Request(string description = "Outbox test event.", object? additionalData = null) => new()
    {
        OccurredAtUtc = DateTime.UtcNow,
        EventType = SecurityEventType.LoginSuccess,
        Severity = EventSeverity.Info,
        UserName = "adminib",
        SourceIp = "127.0.0.1",
        Description = description,
        AdditionalData = additionalData ?? new { test = true }
    };

    private static SecurityEventEnvelope Envelope(string description = "Outbox test event.")
    {
        using var additionalData = JsonDocument.Parse("""{"test":true}""");
        return new SecurityEventEnvelope(
            1,
            Guid.NewGuid(),
            "security.event.created",
            DateTime.UtcNow,
            new SecurityEventEnvelopeData(
                1,
                DateTime.UtcNow,
                "LoginSuccess",
                "Info",
                "adminib",
                "127.0.0.1",
                null,
                null,
                null,
                "test-host",
                description,
                additionalData.RootElement.Clone()));
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
        var connectionString = Environment.GetEnvironmentVariable(ConnectionVariable)
            ?? throw new InvalidOperationException($"{ConnectionVariable} is required.");
        return new DbContextOptionsBuilder<ApplicationDbContext>().UseNpgsql(connectionString).Options;
    }

    private static SecurityEventOutboxDispatcher Dispatcher(
        ApplicationDbContext db,
        ISecurityEventOutboxSink sink,
        IOutboxClock? clock = null)
    {
        return new SecurityEventOutboxDispatcher(
            db,
            sink,
            clock ?? new FakeClock(DateTime.UtcNow),
            Options.Create(OutboxOptions()),
            NullLogger<SecurityEventOutboxDispatcher>.Instance);
    }

    private static SecurityEventOutboxOptions OutboxOptions(string path = "logs/security-events.jsonl") => new()
    {
        Enabled = true,
        PollIntervalMilliseconds = 1000,
        BatchSize = 20,
        LockSeconds = 30,
        MaxAttempts = 5,
        BaseRetrySeconds = 1,
        MaxRetrySeconds = 60,
        JsonlRelativePath = path
    };

    private static string TempRoot()
    {
        var path = Path.Combine(Path.GetTempPath(), $"conshield-outbox-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }

    private sealed class FakeClock : IOutboxClock
    {
        public FakeClock(DateTime utcNow)
        {
            UtcNow = DateTime.SpecifyKind(utcNow, DateTimeKind.Utc);
        }

        public DateTime UtcNow { get; set; }
    }

    private sealed class FakeSink : ISecurityEventOutboxSink
    {
        private readonly Queue<OutboxSinkResult> _results;

        public FakeSink(params OutboxSinkResult[] results)
        {
            _results = new Queue<OutboxSinkResult>(results);
        }

        public ConcurrentBag<Guid> DeliveredMessageIds { get; } = new();
        public Func<Guid, Task>? OnDeliver { get; init; }

        public async Task<OutboxSinkResult> DeliverAsync(SecurityEventEnvelope envelope, CancellationToken cancellationToken)
        {
            DeliveredMessageIds.Add(envelope.MessageId);
            if (OnDeliver is not null)
                await OnDeliver(envelope.MessageId);

            lock (_results)
            {
                return _results.Count > 1 ? _results.Dequeue() : _results.Peek();
            }
        }
    }
}
