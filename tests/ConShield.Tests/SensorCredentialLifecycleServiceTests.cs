using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ConShield.Application;
using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Tests;

[Collection("PostgreSql")]
public sealed class SensorCredentialLifecycleServiceTests
{
    private const string OriginalCredential = "original-sensor-credential-with-high-entropy-placeholder";
    private const string ConnectionVariable = "CONSHIELD_TEST_POSTGRES_CONNECTION";

    [Fact]
    public async Task RotateCredential_CreatesNewCredentialAndStoresOnlyVerifier()
    {
        await using var db = CreateDbContext();
        var sensorId = await SeedSensorAsync(db);
        var service = CreateService(db);

        var result = await service.RotateCredentialAsync(sensorId, "adminib", "scheduled rotation");

        var credentials = await db.SensorCredentials.OrderBy(x => x.CreatedAtUtc).ToListAsync();
        var newCredential = Assert.Single(credentials, x => x.CredentialId == result.CredentialId);
        var expectedVerifier = SHA256.HashData(Encoding.UTF8.GetBytes(result.Credential));

        Assert.Equal(sensorId, result.SensorId);
        Assert.Equal(SecuritySourceSystems.FalcoRuntimeCollector, result.SourceSystem);
        Assert.Matches("^[A-Za-z0-9_-]{43}$", result.Credential);
        Assert.Equal(32, newCredential.VerifierSha256.Length);
        Assert.True(CryptographicOperations.FixedTimeEquals(expectedVerifier, newCredential.VerifierSha256));
        Assert.DoesNotContain(
            typeof(SensorCredential).GetProperties(),
            property => property.PropertyType == typeof(string));
        Assert.DoesNotContain(
            typeof(ConShield.Application.Models.SensorCredentialRotationResult).GetProperties(),
            property => property.Name.Contains("Verifier", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RotateCredential_MarksPreviousActiveCredentialRotated()
    {
        await using var db = CreateDbContext();
        var sensorId = await SeedSensorAsync(db);
        var service = CreateService(db);

        var result = await service.RotateCredentialAsync(sensorId, "adminib", reason: null);

        var credentials = await db.SensorCredentials.OrderBy(x => x.CreatedAtUtc).ToListAsync();
        Assert.Equal(2, credentials.Count);
        Assert.NotNull(credentials.Single(x => x.CredentialId != result.CredentialId).RotatedAtUtc);
        var active = credentials.Single(x => x.CredentialId == result.CredentialId);
        Assert.Null(active.RotatedAtUtc);
        Assert.Null(active.RevokedAtUtc);
        Assert.True((await db.Sensors.SingleAsync()).UpdatedAtUtc >= result.RotatedAtUtc);
    }

    [Fact]
    public async Task RotateCredential_RevokedSensorFails()
    {
        await using var db = CreateDbContext();
        var sensorId = await SeedSensorAsync(db, sensorRevokedAtUtc: DateTime.UtcNow);
        var service = CreateService(db);

        await Assert.ThrowsAsync<SensorCredentialLifecycleException>(() =>
            service.RotateCredentialAsync(sensorId, "adminib", reason: null));

        Assert.Equal(1, await db.SensorCredentials.CountAsync());
    }

    [Fact]
    public async Task RotateCredential_UnknownSensorFails()
    {
        await using var db = CreateDbContext();
        var service = CreateService(db);

        await Assert.ThrowsAsync<SensorCredentialLifecycleException>(() =>
            service.RotateCredentialAsync(Guid.NewGuid(), "adminib", reason: null));

        Assert.Empty(await db.SensorCredentials.ToListAsync());
    }

    [Fact]
    public async Task RevokeCredential_MarksCredentialRevoked()
    {
        await using var db = CreateDbContext();
        var sensorId = await SeedSensorAsync(db);
        var credentialId = await db.SensorCredentials.Select(x => x.CredentialId).SingleAsync();
        var service = CreateService(db);
        var before = DateTime.UtcNow;

        var result = await service.RevokeCredentialAsync(sensorId, credentialId, "adminib", "compromised");

        var credential = await db.SensorCredentials.SingleAsync();
        Assert.Equal(sensorId, result.SensorId);
        Assert.Equal(credentialId, result.CredentialId);
        Assert.False(result.WasAlreadyRevoked);
        Assert.NotNull(credential.RevokedAtUtc);
        Assert.True(credential.RevokedAtUtc >= before);
        Assert.True((await db.Sensors.SingleAsync()).UpdatedAtUtc >= result.RevokedAtUtc);
    }

    [Fact]
    public async Task RevokeCredential_DoesNotDeleteCredential()
    {
        await using var db = CreateDbContext();
        var sensorId = await SeedSensorAsync(db);
        var credentialId = await db.SensorCredentials.Select(x => x.CredentialId).SingleAsync();
        var service = CreateService(db);

        await service.RevokeCredentialAsync(sensorId, credentialId, "adminib", reason: null);
        var second = await service.RevokeCredentialAsync(sensorId, credentialId, "adminib", reason: null);

        Assert.True(second.WasAlreadyRevoked);
        Assert.Equal(1, await db.SensorCredentials.CountAsync());
        Assert.NotNull((await db.SensorCredentials.SingleAsync()).RevokedAtUtc);
    }

    [Fact]
    public async Task RevokeCredential_UnknownSensorFails()
    {
        await using var db = CreateDbContext();
        var service = CreateService(db);

        await Assert.ThrowsAsync<SensorCredentialLifecycleException>(() =>
            service.RevokeCredentialAsync(Guid.NewGuid(), Guid.NewGuid(), "adminib", reason: null));
    }

    [Fact]
    public async Task RevokeCredential_UnknownCredentialFails()
    {
        await using var db = CreateDbContext();
        var sensorId = await SeedSensorAsync(db);
        var service = CreateService(db);

        await Assert.ThrowsAsync<SensorCredentialLifecycleException>(() =>
            service.RevokeCredentialAsync(sensorId, Guid.NewGuid(), "adminib", reason: null));

        Assert.Null((await db.SensorCredentials.SingleAsync()).RevokedAtUtc);
    }

    [Fact]
    public async Task RevokeSensor_MarksSensorRevoked()
    {
        await using var db = CreateDbContext();
        var sensorId = await SeedSensorAsync(db);
        var service = CreateService(db);
        var before = DateTime.UtcNow;

        var result = await service.RevokeSensorAsync(sensorId, "adminib", "retired");

        var sensor = await db.Sensors.SingleAsync();
        Assert.Equal(sensorId, result.SensorId);
        Assert.False(result.WasAlreadyRevoked);
        Assert.NotNull(sensor.RevokedAtUtc);
        Assert.True(sensor.RevokedAtUtc >= before);
        Assert.True(sensor.UpdatedAtUtc >= result.RevokedAtUtc);
    }

    [Fact]
    public async Task RevokeSensor_MarksAllCredentialsRevoked()
    {
        await using var db = CreateDbContext();
        var sensorId = await SeedSensorAsync(db, credentialCount: 2);
        var service = CreateService(db);

        var result = await service.RevokeSensorAsync(sensorId, "adminib", reason: null);
        var second = await service.RevokeSensorAsync(sensorId, "adminib", reason: null);

        Assert.Equal(2, result.RevokedCredentialCount);
        Assert.True(second.WasAlreadyRevoked);
        Assert.Equal(0, second.RevokedCredentialCount);
        Assert.Equal(2, await db.SensorCredentials.CountAsync());
        Assert.All(await db.SensorCredentials.ToArrayAsync(), credential => Assert.NotNull(credential.RevokedAtUtc));
    }

    [Fact]
    public async Task RevokeSensor_UnknownSensorFails()
    {
        await using var db = CreateDbContext();
        var service = CreateService(db);

        await Assert.ThrowsAsync<SensorCredentialLifecycleException>(() =>
            service.RevokeSensorAsync(Guid.NewGuid(), "adminib", reason: null));
    }

    [Fact]
    public void RevocationResultModels_DoNotExposeVerifierOrPlaintextCredential()
    {
        Assert.DoesNotContain(
            typeof(ConShield.Application.Models.SensorCredentialRevocationResult).GetProperties(),
            property => property.Name.Contains("Verifier", StringComparison.OrdinalIgnoreCase)
                || property.Name.Equals("Credential", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(
            typeof(ConShield.Application.Models.SensorRevocationResult).GetProperties(),
            property => property.Name.Contains("Verifier", StringComparison.OrdinalIgnoreCase)
                || property.Name.Equals("Credential", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RotateCredential_WritesSecretSafeAuditEvent()
    {
        await using var db = CreateDbContext();
        var writer = new RecordingSecurityEventWriter();
        var sensorId = await SeedSensorAsync(db);
        var service = new SensorCredentialLifecycleService(db, writer);

        var result = await service.RotateCredentialAsync(sensorId, " adminib ", "scheduled rotation with operator note");

        var request = Assert.Single(writer.Requests);
        AssertLifecycleAuditBase(
            request,
            SensorLifecycleEventTypes.SensorCredentialRotated,
            "adminib",
            "rotateCredential",
            reasonProvided: true);

        var json = SerializeAdditionalData(request);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        Assert.Equal(sensorId, root.GetProperty("sensorId").GetGuid());
        Assert.Equal(result.CredentialId, root.GetProperty("credentialId").GetGuid());
        Assert.Equal("fedora-runtime-01", root.GetProperty("displayName").GetString());
        Assert.Equal(SecuritySourceSystems.FalcoRuntimeCollector, root.GetProperty("sourceSystem").GetString());
        Assert.Equal(SecuritySourceSystems.SensorLifecycle, root.GetProperty("lifecycleSourceSystem").GetString());
        AssertSecretSafe(request, json, result.Credential, "Verifier", "operator note");
    }

    [Fact]
    public async Task RevokeCredential_WritesSecretSafeAuditEvent()
    {
        await using var db = CreateDbContext();
        var writer = new RecordingSecurityEventWriter();
        var sensorId = await SeedSensorAsync(db);
        var credentialId = await db.SensorCredentials.Select(x => x.CredentialId).SingleAsync();
        var service = new SensorCredentialLifecycleService(db, writer);

        await service.RevokeCredentialAsync(sensorId, credentialId, "adminib", "compromised local token");

        var request = Assert.Single(writer.Requests);
        AssertLifecycleAuditBase(
            request,
            SensorLifecycleEventTypes.SensorCredentialRevoked,
            "adminib",
            "revokeCredential",
            reasonProvided: true);

        var json = SerializeAdditionalData(request);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        Assert.Equal(sensorId, root.GetProperty("sensorId").GetGuid());
        Assert.Equal(credentialId, root.GetProperty("credentialId").GetGuid());
        AssertSecretSafe(request, json, OriginalCredential, "Verifier", "compromised local token");
    }

    [Fact]
    public async Task RevokeSensor_WritesSecretSafeAuditEvent()
    {
        await using var db = CreateDbContext();
        var writer = new RecordingSecurityEventWriter();
        var sensorId = await SeedSensorAsync(db, credentialCount: 2);
        var service = new SensorCredentialLifecycleService(db, writer);

        await service.RevokeSensorAsync(sensorId, "adminib", "retired host");

        var request = Assert.Single(writer.Requests);
        AssertLifecycleAuditBase(
            request,
            SensorLifecycleEventTypes.SensorRevoked,
            "adminib",
            "revokeSensor",
            reasonProvided: true);

        var json = SerializeAdditionalData(request);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        Assert.Equal(sensorId, root.GetProperty("sensorId").GetGuid());
        Assert.Equal(2, root.GetProperty("revokedCredentialCount").GetInt32());
        Assert.False(root.TryGetProperty("credentialId", out _));
        AssertSecretSafe(request, json, OriginalCredential, "Verifier", "retired host");
    }

    [Fact]
    public async Task RevokeCredential_IdempotentPathDoesNotWriteDuplicateAuditEvent()
    {
        await using var db = CreateDbContext();
        var writer = new RecordingSecurityEventWriter();
        var sensorId = await SeedSensorAsync(db);
        var credentialId = await db.SensorCredentials.Select(x => x.CredentialId).SingleAsync();
        var service = new SensorCredentialLifecycleService(db, writer);

        await service.RevokeCredentialAsync(sensorId, credentialId, "adminib", reason: null);
        await service.RevokeCredentialAsync(sensorId, credentialId, "adminib", reason: null);

        Assert.Single(writer.Requests);
    }

    [Fact]
    public async Task RevokeSensor_IdempotentPathDoesNotWriteDuplicateAuditEvent()
    {
        await using var db = CreateDbContext();
        var writer = new RecordingSecurityEventWriter();
        var sensorId = await SeedSensorAsync(db, credentialCount: 2);
        var service = new SensorCredentialLifecycleService(db, writer);

        await service.RevokeSensorAsync(sensorId, "adminib", reason: null);
        await service.RevokeSensorAsync(sensorId, "adminib", reason: null);

        Assert.Single(writer.Requests);
    }

    [PostgreSqlFact]
    public async Task RotateCredential_WritesAuditEventAndOutboxMessage()
    {
        await using var db = await CreateMigratedDbContextAsync();
        var sensorId = await SeedSensorAsync(db);
        var service = new SensorCredentialLifecycleService(db, new SecurityEventWriter(db));

        var result = await service.RotateCredentialAsync(sensorId, "adminib", "scheduled rotation");

        var entry = await db.SecurityEvents.SingleAsync(x => x.SourceSystem == SecuritySourceSystems.SensorLifecycle);
        var outbox = await db.SecurityEventOutboxMessages.SingleAsync(x => x.SecurityEventId == entry.Id);

        Assert.Equal(SecurityEventType.ExternalEvent, entry.EventType);
        Assert.Equal(SensorLifecycleEventTypes.SensorCredentialRotated, entry.ExternalEventType);
        Assert.Equal(EventSeverity.Info, entry.Severity);
        Assert.Equal("adminib", entry.UserName);
        Assert.DoesNotContain(result.Credential, entry.AdditionalDataJson ?? string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain("Verifier", entry.AdditionalDataJson ?? string.Empty, StringComparison.Ordinal);
        Assert.Equal(SecurityEventWriter.SecurityEventCreatedMessageType, outbox.MessageType);
        Assert.Contains(SensorLifecycleEventTypes.SensorCredentialRotated, outbox.PayloadJson, StringComparison.Ordinal);
        Assert.DoesNotContain(result.Credential, outbox.PayloadJson, StringComparison.Ordinal);
    }

    private static async Task<Guid> SeedSensorAsync(
        ApplicationDbContext db,
        DateTime? sensorRevokedAtUtc = null,
        int credentialCount = 1)
    {
        var now = DateTime.UtcNow;
        var sensorId = Guid.NewGuid();
        var credentials = Enumerable.Range(0, credentialCount)
            .Select(index => new SensorCredential
            {
                CredentialId = Guid.NewGuid(),
                CreatedAtUtc = now.AddMinutes(-10 - index),
                VerifierSha256 = SHA256.HashData(Encoding.UTF8.GetBytes($"{OriginalCredential}-{index}"))
            })
            .ToList();

        db.Sensors.Add(new Sensor
        {
            SensorId = sensorId,
            DisplayName = "fedora-runtime-01",
            SourceSystem = SecuritySourceSystems.FalcoRuntimeCollector,
            RevokedAtUtc = sensorRevokedAtUtc,
            CreatedAtUtc = now.AddMinutes(-10),
            UpdatedAtUtc = now.AddMinutes(-10),
            Credentials = credentials
        });
        await db.SaveChangesAsync();
        return sensorId;
    }

    private static ApplicationDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase($"sensor-credential-lifecycle-{Guid.NewGuid():N}")
            .Options;
        return new ApplicationDbContext(options);
    }

    private static async Task<ApplicationDbContext> CreateMigratedDbContextAsync()
    {
        var db = new ApplicationDbContext(PostgresDbOptions());
        await db.Database.EnsureDeletedAsync();
        await db.Database.MigrateAsync();
        return db;
    }

    private static DbContextOptions<ApplicationDbContext> PostgresDbOptions()
    {
        var connectionString = Environment.GetEnvironmentVariable(ConnectionVariable)
            ?? throw new InvalidOperationException($"{ConnectionVariable} is required.");
        return new DbContextOptionsBuilder<ApplicationDbContext>().UseNpgsql(connectionString).Options;
    }

    private static SensorCredentialLifecycleService CreateService(ApplicationDbContext db) =>
        new(db, new RecordingSecurityEventWriter());

    private static void AssertLifecycleAuditBase(
        SecurityEventWriteRequest request,
        string externalEventType,
        string requestedBy,
        string action,
        bool reasonProvided)
    {
        Assert.Equal(SecurityEventType.ExternalEvent, request.EventType);
        Assert.Equal(EventSeverity.Info, request.Severity);
        Assert.Equal(SecuritySourceSystems.SensorLifecycle, request.SourceSystem);
        Assert.Equal(externalEventType, request.ExternalEventType);
        Assert.Equal(requestedBy, request.UserName);
        Assert.NotNull(request.OccurredAtUtc);
        Assert.NotNull(request.AdditionalData);

        var json = SerializeAdditionalData(request);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        Assert.Equal(requestedBy, root.GetProperty("requestedBy").GetString());
        Assert.Equal(action, root.GetProperty("action").GetString());
        Assert.Equal(reasonProvided, root.GetProperty("reasonProvided").GetBoolean());
    }

    private static void AssertSecretSafe(SecurityEventWriteRequest request, string additionalDataJson, params string[] forbiddenValues)
    {
        foreach (var forbidden in forbiddenValues.Where(x => !string.IsNullOrWhiteSpace(x)))
        {
            Assert.DoesNotContain(forbidden, request.Description, StringComparison.Ordinal);
            Assert.DoesNotContain(forbidden, additionalDataJson, StringComparison.Ordinal);
        }
    }

    private static string SerializeAdditionalData(SecurityEventWriteRequest request) =>
        JsonSerializer.Serialize(request.AdditionalData, new JsonSerializerOptions(JsonSerializerDefaults.Web));

    private sealed class RecordingSecurityEventWriter : ISecurityEventWriter
    {
        public List<SecurityEventWriteRequest> Requests { get; } = [];

        public Task WriteAsync(SecurityEventWriteRequest request, CancellationToken cancellationToken = default)
        {
            Requests.Add(request);
            return Task.CompletedTask;
        }
    }
}
