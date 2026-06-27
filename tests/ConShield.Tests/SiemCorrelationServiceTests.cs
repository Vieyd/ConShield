using ConShield.Application;
using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Tests;

public class SiemCorrelationServiceTests
{
    [Fact]
    public async Task BF001_TwoLoginFailures_DoesNotCreateAlert()
    {
        await using var db = CreateDbContext();
        AddLoginFailures(db, "operator", 2);
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var result = await service.RunAsync();

        Assert.Equal(0, result.CreatedAlerts);
        Assert.Equal(0, result.CreatedIncidents);
        Assert.Empty(db.SiemAlerts);
        Assert.Empty(db.Incidents);
    }

    [Fact]
    public async Task BF001_ThreeLoginFailures_CreatesOneAlertAndOneIncident()
    {
        await using var db = CreateDbContext();
        AddLoginFailures(db, "operator", 3);
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var result = await service.RunAsync();

        Assert.Equal(1, result.CreatedAlerts);
        Assert.Equal(1, result.CreatedIncidents);

        var alert = await db.SiemAlerts.SingleAsync();
        Assert.Equal("BF-001", alert.RuleCode);
        Assert.Equal(AlertStatuses.New, alert.Status);

        var incident = await db.Incidents.SingleAsync();
        Assert.Equal(alert.IncidentId, incident.Id);
        Assert.Equal(EventSeverity.High, incident.Severity);
    }

    [Fact]
    public async Task BF001_RepeatedRun_DoesNotCreateDuplicateActiveAlert()
    {
        await using var db = CreateDbContext();
        AddLoginFailures(db, "operator", 3);
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var firstRun = await service.RunAsync();
        var secondRun = await service.RunAsync();

        Assert.Equal(1, firstRun.CreatedAlerts);
        Assert.Equal(1, firstRun.CreatedIncidents);
        Assert.Equal(0, secondRun.CreatedAlerts);
        Assert.Equal(0, secondRun.CreatedIncidents);
        Assert.Equal(1, await db.SiemAlerts.CountAsync(x => x.RuleCode == "BF-001"));
        Assert.Equal(1, await db.Incidents.CountAsync());
    }

    [Fact]
    public async Task UE001_FiveUserExceptionChanges_CreatesAlert()
    {
        await using var db = CreateDbContext();
        AddUserExceptionChanges(db, "adminib", 5);
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var result = await service.RunAsync();

        Assert.Equal(1, result.CreatedAlerts);
        Assert.Equal(1, result.CreatedIncidents);

        var alert = await db.SiemAlerts.SingleAsync();
        Assert.Equal("UE-001", alert.RuleCode);
        Assert.Equal(EventSeverity.Critical, alert.Severity);
    }

    [Fact]
    public async Task CR001_CriticalEventsFromSameSourceIp_CreatesAlert()
    {
        await using var db = CreateDbContext();
        AddCriticalEvents(db, "172.16.5.44", 2);
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var result = await service.RunAsync();

        Assert.Equal(1, result.CreatedAlerts);
        Assert.Equal(1, result.CreatedIncidents);

        var alert = await db.SiemAlerts.SingleAsync();
        Assert.Equal("CR-001", alert.RuleCode);
        Assert.Equal("CR-001:172.16.5.44", alert.TriggerKey);
    }

    [Fact]
    public async Task CR001_DoesNotCorrelateSiemGeneratedEvents()
    {
        await using var db = CreateDbContext();
        db.SecurityEvents.AddRange(
            new SecurityEventEntry
            {
                OccurredAtUtc = DateTime.UtcNow.AddSeconds(-10),
                EventType = SecurityEventType.CorrelationAlert,
                Severity = EventSeverity.Critical,
                UserName = "siem-engine",
                SourceIp = null,
                Description = "Generated SIEM alert audit event."
            },
            new SecurityEventEntry
            {
                OccurredAtUtc = DateTime.UtcNow.AddSeconds(-9),
                EventType = SecurityEventType.IncidentCreated,
                Severity = EventSeverity.Critical,
                UserName = "siem-engine",
                SourceIp = null,
                Description = "Generated incident audit event."
            });
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var result = await service.RunAsync();

        Assert.Equal(0, result.CreatedAlerts);
        Assert.Equal(0, result.CreatedIncidents);
        Assert.DoesNotContain(await db.SiemAlerts.ToListAsync(), x => x.RuleCode == "CR-001");
    }

    [Fact]
    public async Task CR001_DoesNotCorrelateCriticalEventsWithoutSourceIp()
    {
        await using var db = CreateDbContext();
        db.SecurityEvents.AddRange(
            new SecurityEventEntry
            {
                OccurredAtUtc = DateTime.UtcNow.AddSeconds(-10),
                EventType = SecurityEventType.AccessDenied,
                Severity = EventSeverity.Critical,
                SourceIp = null,
                Description = "Critical source event without SourceIp."
            },
            new SecurityEventEntry
            {
                OccurredAtUtc = DateTime.UtcNow.AddSeconds(-9),
                EventType = SecurityEventType.AccessDenied,
                Severity = EventSeverity.Critical,
                SourceIp = "   ",
                Description = "Critical source event with blank SourceIp."
            });
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var result = await service.RunAsync();

        Assert.Equal(0, result.CreatedAlerts);
        Assert.Equal(0, result.CreatedIncidents);
        Assert.DoesNotContain(await db.SiemAlerts.ToListAsync(), x => x.RuleCode == "CR-001");
    }

    [Fact]
    public async Task IMG001_CriticalImageScan_CreatesAlertAndIncident()
    {
        await using var db = CreateDbContext();
        AddImageScanEvent(db, criticalCount: 2, highCount: 3, totalCount: 10, imageDigest: "repo/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var result = await service.RunAsync();

        Assert.Equal(1, result.CreatedAlerts);
        Assert.Equal(1, result.CreatedIncidents);

        var alert = await db.SiemAlerts.SingleAsync();
        Assert.Equal("IMG-001", alert.RuleCode);
        Assert.Equal("IMG-001:repo/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", alert.TriggerKey);
        Assert.Contains("critical=2", alert.Description);

        var incident = await db.Incidents.SingleAsync();
        Assert.Equal(alert.IncidentId, incident.Id);
        Assert.Equal(EventSeverity.Critical, incident.Severity);
        Assert.NotNull(incident.SourceEventId);
        Assert.Contains(incident.SourceEventId.Value.ToString(), alert.SourceEventIdsJson);
    }

    [Fact]
    public async Task IMG001_ZeroCritical_DoesNotCreateAlert()
    {
        await using var db = CreateDbContext();
        AddImageScanEvent(db, criticalCount: 0, highCount: 5, totalCount: 5);
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var result = await service.RunAsync();

        Assert.Equal(0, result.CreatedAlerts);
        Assert.Empty(db.SiemAlerts);
    }

    [Fact]
    public async Task IMG001_OtherExternalType_DoesNotCreateAlert()
    {
        await using var db = CreateDbContext();
        AddImageScanEvent(db, criticalCount: 1, highCount: 0, totalCount: 1, externalEventType: "other.event");
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var result = await service.RunAsync();

        Assert.Equal(0, result.CreatedAlerts);
        Assert.Empty(db.SiemAlerts);
    }

    [Fact]
    public async Task IMG001_MalformedAdditionalData_DoesNotBreakCorrelation()
    {
        await using var db = CreateDbContext();
        db.SecurityEvents.Add(new SecurityEventEntry
        {
            OccurredAtUtc = DateTime.UtcNow,
            EventType = SecurityEventType.ExternalEvent,
            ExternalEventType = "container.image.scan.completed",
            Severity = EventSeverity.Critical,
            Description = "Malformed scan event",
            AdditionalDataJson = "{"
        });
        AddLoginFailures(db, "operator", 3);
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var result = await service.RunAsync();

        Assert.Equal(1, result.CreatedAlerts);
        Assert.Contains(await db.SiemAlerts.ToListAsync(), x => x.RuleCode == "BF-001");
    }

    [Fact]
    public async Task IMG001_RepeatedRun_DoesNotCreateDuplicateActiveAlert()
    {
        await using var db = CreateDbContext();
        AddImageScanEvent(db, criticalCount: 1, highCount: 0, totalCount: 1);
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var first = await service.RunAsync();
        var second = await service.RunAsync();

        Assert.Equal(1, first.CreatedAlerts);
        Assert.Equal(0, second.CreatedAlerts);
        Assert.Equal(1, await db.SiemAlerts.CountAsync(x => x.RuleCode == "IMG-001"));
    }

    [Fact]
    public async Task IMG001_UsesImageReferenceFallback()
    {
        await using var db = CreateDbContext();
        AddImageScanEvent(db, criticalCount: 1, highCount: 0, totalCount: 1, imageDigest: null, imageReference: "Repo/App:Latest");
        await db.SaveChangesAsync();

        var service = CreateService(db);

        await service.RunAsync();

        var alert = await db.SiemAlerts.SingleAsync();
        Assert.Equal("IMG-001:repo/app:latest", alert.TriggerKey);
    }

    [Fact]
    public async Task POL001_BlockPolicyEvent_CreatesAlertAndIncident()
    {
        await using var db = CreateDbContext();
        AddPolicyEvent(db, "Block", imageDigest: "repo/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var result = await service.RunAsync();

        Assert.Equal(1, result.CreatedAlerts);
        Assert.Equal(1, result.CreatedIncidents);

        var alert = await db.SiemAlerts.SingleAsync();
        Assert.Equal("POL-001", alert.RuleCode);
        Assert.Equal("POL-001:container-baseline:1.0.0:repo/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", alert.TriggerKey);
        Assert.Contains("blocked image", alert.Description);
        Assert.Equal(EventSeverity.Critical, alert.Severity);

        var incident = await db.Incidents.SingleAsync();
        Assert.Equal(alert.IncidentId, incident.Id);
    }

    [Theory]
    [InlineData("Allow")]
    [InlineData("Warn")]
    [InlineData("Unknown")]
    public async Task POL001_NonBlockDecision_DoesNotCreateAlert(string decision)
    {
        await using var db = CreateDbContext();
        AddPolicyEvent(db, decision);
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var result = await service.RunAsync();

        Assert.Equal(0, result.CreatedAlerts);
        Assert.Empty(db.SiemAlerts);
    }

    [Fact]
    public async Task POL001_MalformedAdditionalData_DoesNotBreakCorrelation()
    {
        await using var db = CreateDbContext();
        db.SecurityEvents.Add(new SecurityEventEntry
        {
            OccurredAtUtc = DateTime.UtcNow,
            EventType = SecurityEventType.ExternalEvent,
            ExternalEventType = "container.image.policy.evaluated",
            Severity = EventSeverity.High,
            Description = "Malformed policy event",
            AdditionalDataJson = "{"
        });
        AddLoginFailures(db, "operator", 3);
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var result = await service.RunAsync();

        Assert.Equal(1, result.CreatedAlerts);
        Assert.Contains(await db.SiemAlerts.ToListAsync(), x => x.RuleCode == "BF-001");
    }

    [Fact]
    public async Task POL001_RepeatedRun_DoesNotCreateDuplicateActiveAlert()
    {
        await using var db = CreateDbContext();
        AddPolicyEvent(db, "Block");
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var first = await service.RunAsync();
        var second = await service.RunAsync();

        Assert.Equal(1, first.CreatedAlerts);
        Assert.Equal(0, second.CreatedAlerts);
        Assert.Equal(1, await db.SiemAlerts.CountAsync(x => x.RuleCode == "POL-001"));
    }

    [Fact]
    public async Task POL001_UsesImageReferenceFallback()
    {
        await using var db = CreateDbContext();
        AddPolicyEvent(db, "Block", imageDigest: null, imageReference: "Repo/App:Latest");
        await db.SaveChangesAsync();

        var service = CreateService(db);

        await service.RunAsync();

        var alert = await db.SiemAlerts.SingleAsync();
        Assert.Equal("POL-001:container-baseline:1.0.0:repo/app:latest", alert.TriggerKey);
    }

    [Fact]
    public async Task POL001_DoesNotTriggerCR001SelfCorrelation()
    {
        await using var db = CreateDbContext();
        AddPolicyEvent(db, "Block");
        await db.SaveChangesAsync();

        var service = CreateService(db);

        var first = await service.RunAsync();
        var second = await service.RunAsync();

        Assert.Equal(1, first.CreatedAlerts);
        Assert.Equal(0, second.CreatedAlerts);
        Assert.Equal(0, await db.SiemAlerts.CountAsync(x => x.RuleCode == "CR-001"));
        Assert.Equal(1, await db.SiemAlerts.CountAsync(x => x.RuleCode == "POL-001"));
    }

    [Fact]
    public async Task RTE001_MappedRuntimeEvent_CreatesAlertAndIncident()
    {
        await using var db = CreateDbContext();
        AddRuntimeEvent(db, "container.runtime.shell_spawned", "shell-in-container", "runtime-container-1");
        await db.SaveChangesAsync();

        var result = await CreateService(db).RunAsync();

        Assert.Equal(1, result.CreatedAlerts);
        Assert.Equal(1, result.CreatedIncidents);
        var alert = await db.SiemAlerts.SingleAsync();
        Assert.Equal("RTE-001", alert.RuleCode);
        Assert.Contains("shell-in-container", alert.TriggerKey);
        Assert.Contains("runtime-container-1", alert.TriggerKey);
        Assert.DoesNotContain("raw output", alert.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RTE001_LocalFalcoLinuxSensorEvent_CreatesAlertAndIncident()
    {
        await using var db = CreateDbContext();
        AddRuntimeEvent(
            db,
            "container.runtime.shell_spawned",
            "shell-in-container",
            "runtime-container-local",
            sourceSystem: SecuritySourceSystems.FalcoLinuxSensor);
        await db.SaveChangesAsync();

        var result = await CreateService(db).RunAsync();

        Assert.Equal(1, result.CreatedAlerts);
        Assert.Equal(1, result.CreatedIncidents);
        Assert.Equal("RTE-001", (await db.SiemAlerts.SingleAsync()).RuleCode);
    }

    [Fact]
    public async Task RTE001_RepeatedRun_DoesNotDuplicateActiveAlert()
    {
        await using var db = CreateDbContext();
        AddRuntimeEvent(db, "container.runtime.shell_spawned", "shell-in-container", "runtime-container-1");
        await db.SaveChangesAsync();

        var service = CreateService(db);
        var first = await service.RunAsync();
        var second = await service.RunAsync();

        Assert.Equal(1, first.CreatedAlerts);
        Assert.Equal(0, second.CreatedAlerts);
        Assert.Equal(1, await db.SiemAlerts.CountAsync(x => x.RuleCode == "RTE-001"));
    }

    [Fact]
    public async Task RTE001_UnmappedEvent_DoesNotCreateAlert()
    {
        await using var db = CreateDbContext();
        AddRuntimeEvent(db, "container.runtime.unmapped", "unmapped", "runtime-container-1", correlate: false);
        await db.SaveChangesAsync();

        var result = await CreateService(db).RunAsync();

        Assert.Equal(0, result.CreatedAlerts);
        Assert.Empty(db.SiemAlerts);
    }

    [Fact]
    public async Task RTE001_SeparateContainerCreatesSeparateAlert()
    {
        await using var db = CreateDbContext();
        AddRuntimeEvent(db, "container.runtime.shell_spawned", "shell-in-container", "runtime-container-1");
        AddRuntimeEvent(db, "container.runtime.shell_spawned", "shell-in-container", "runtime-container-2");
        await db.SaveChangesAsync();

        var result = await CreateService(db).RunAsync();

        Assert.Equal(2, result.CreatedAlerts);
        Assert.Equal(2, await db.SiemAlerts.CountAsync(x => x.RuleCode == "RTE-001"));
    }

    [Fact]
    public async Task RTE001_EtcWriteRuntimeEvent_CreatesAlertAndIncident()
    {
        await using var db = CreateDbContext();
        AddRuntimeEvent(db, "container.runtime.etc_write", "etc-write", "runtime-container-etc");
        await db.SaveChangesAsync();

        var result = await CreateService(db).RunAsync();

        Assert.Equal(1, result.CreatedAlerts);
        Assert.Equal(1, result.CreatedIncidents);
        Assert.Equal("RTE-001", (await db.SiemAlerts.SingleAsync()).RuleCode);
    }

    [Fact]
    public async Task RTE001_CriticalCandidatePreservesCriticalAlertAndIncidentSeverity()
    {
        await using var db = CreateDbContext();
        AddRuntimeEvent(db, "container.runtime.shell_spawned", "shell-in-container", "runtime-container-1", severity: EventSeverity.High);
        AddRuntimeEvent(db, "container.runtime.shell_spawned", "shell-in-container", "runtime-container-1", severity: EventSeverity.Critical);
        await db.SaveChangesAsync();

        var result = await CreateService(db).RunAsync();

        Assert.Equal(1, result.CreatedAlerts);
        Assert.Equal(EventSeverity.Critical, (await db.SiemAlerts.SingleAsync()).Severity);
        Assert.Equal(EventSeverity.Critical, (await db.Incidents.SingleAsync()).Severity);
    }

    [Fact]
    public async Task RTE001_MalformedAdditionalData_DoesNotBreakCorrelation()
    {
        await using var db = CreateDbContext();
        db.SecurityEvents.Add(new SecurityEventEntry
        {
            OccurredAtUtc = DateTime.UtcNow,
            EventType = SecurityEventType.ExternalEvent,
            ExternalEventType = "container.runtime.shell_spawned",
            Severity = EventSeverity.High,
            SourceSystem = "conshield.falco-runtime-collector",
            Description = "Malformed runtime event",
            AdditionalDataJson = "{"
        });
        AddLoginFailures(db, "operator", 3);
        await db.SaveChangesAsync();

        var result = await CreateService(db).RunAsync();

        Assert.Equal(1, result.CreatedAlerts);
        Assert.Contains(await db.SiemAlerts.ToListAsync(), x => x.RuleCode == "BF-001");
    }

    [Fact]
    public async Task SensorRevokedLifecycleEvent_CreatesAlert()
    {
        await using var db = CreateDbContext();
        var sensorId = Guid.NewGuid();
        AddSensorRevokedLifecycleEvent(db, sensorId, "fedora-runtime-01", "adminib", revokedCredentialCount: 2);
        await db.SaveChangesAsync();

        var result = await CreateService(db).RunAsync();

        Assert.Equal(1, result.CreatedAlerts);
        Assert.Equal(1, result.CreatedIncidents);
        var alert = await db.SiemAlerts.SingleAsync();
        Assert.Equal("LIFE-001", alert.RuleCode);
        Assert.Equal(EventSeverity.Warning, alert.Severity);
        Assert.Equal($"LIFE-001:{sensorId:D}", alert.TriggerKey);
        Assert.Contains("Sensor identity was revoked", alert.Description, StringComparison.Ordinal);
        Assert.Contains(sensorId.ToString("D"), alert.Description, StringComparison.Ordinal);
        Assert.Contains("fedora-runtime-01", alert.Description, StringComparison.Ordinal);
        Assert.Contains("revokedCredentialCount=2", alert.Description, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SensorRevokedLifecycleEvent_AlertPayloadIsSecretSafe()
    {
        await using var db = CreateDbContext();
        var plaintextCredential = "plaintext-credential-that-must-not-render";
        AddSensorRevokedLifecycleEvent(
            db,
            Guid.NewGuid(),
            "fedora-runtime-01",
            "adminib",
            revokedCredentialCount: 1,
            additionalSecretLikeFields: new Dictionary<string, object?>
            {
                ["credential"] = plaintextCredential,
                ["VerifierSha256"] = "verifier-that-must-not-render",
                ["apiKey"] = "api-key-that-must-not-render",
                ["connectionString"] = "Host=localhost;Password=must-not-render"
            });
        await db.SaveChangesAsync();

        await CreateService(db).RunAsync();

        var alert = await db.SiemAlerts.SingleAsync();
        var incident = await db.Incidents.SingleAsync();
        var rendered = string.Join('|', alert.Description, alert.TriggerKey, alert.SourceEventIdsJson, incident.Notes);
        Assert.DoesNotContain(plaintextCredential, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain("VerifierSha256", rendered, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("api-key-that-must-not-render", rendered, StringComparison.Ordinal);
        Assert.DoesNotContain("Password=", rendered, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connectionString", rendered, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SensorRevokedLifecycleEvent_DoesNotDuplicateAlert()
    {
        await using var db = CreateDbContext();
        AddSensorRevokedLifecycleEvent(db, Guid.NewGuid(), "fedora-runtime-01", "adminib", revokedCredentialCount: 1);
        await db.SaveChangesAsync();
        var service = CreateService(db);

        var first = await service.RunAsync();
        var second = await service.RunAsync();

        Assert.Equal(1, first.CreatedAlerts);
        Assert.Equal(0, second.CreatedAlerts);
        Assert.Equal(1, await db.SiemAlerts.CountAsync(x => x.RuleCode == "LIFE-001"));
        Assert.Equal(1, await db.Incidents.CountAsync(x => x.Name.Contains("LIFE-001", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task RepeatedCredentialLifecycleEvents_CreateAlert()
    {
        await using var db = CreateDbContext();
        var sensorId = Guid.NewGuid();
        AddCredentialLifecycleEvent(db, sensorId, SensorLifecycleEventTypes.SensorCredentialRotated, minutesAgo: 1);
        AddCredentialLifecycleEvent(db, sensorId, SensorLifecycleEventTypes.SensorCredentialRevoked, minutesAgo: 2);
        AddCredentialLifecycleEvent(db, sensorId, SensorLifecycleEventTypes.SensorCredentialRotated, minutesAgo: 3);
        await db.SaveChangesAsync();

        var result = await CreateService(db).RunAsync();

        Assert.Equal(1, result.CreatedAlerts);
        var alert = await db.SiemAlerts.SingleAsync();
        Assert.Equal("LIFE-002", alert.RuleCode);
        Assert.Equal(EventSeverity.Warning, alert.Severity);
        Assert.Equal($"LIFE-002:{sensorId:D}", alert.TriggerKey);
        Assert.Contains("changed 3 times in 15 minutes", alert.Description, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RepeatedCredentialLifecycleEvents_GroupBySensor()
    {
        await using var db = CreateDbContext();
        var sensorA = Guid.NewGuid();
        var sensorB = Guid.NewGuid();
        AddCredentialLifecycleEvent(db, sensorA, SensorLifecycleEventTypes.SensorCredentialRotated, minutesAgo: 1);
        AddCredentialLifecycleEvent(db, sensorA, SensorLifecycleEventTypes.SensorCredentialRevoked, minutesAgo: 2);
        AddCredentialLifecycleEvent(db, sensorA, SensorLifecycleEventTypes.SensorCredentialRotated, minutesAgo: 3);
        AddCredentialLifecycleEvent(db, sensorB, SensorLifecycleEventTypes.SensorCredentialRotated, minutesAgo: 1);
        AddCredentialLifecycleEvent(db, sensorB, SensorLifecycleEventTypes.SensorCredentialRevoked, minutesAgo: 2);
        await db.SaveChangesAsync();

        await CreateService(db).RunAsync();

        var alert = await db.SiemAlerts.SingleAsync();
        Assert.Equal("LIFE-002", alert.RuleCode);
        Assert.Equal($"LIFE-002:{sensorA:D}", alert.TriggerKey);
    }

    [Fact]
    public async Task RepeatedCredentialLifecycleEvents_BelowThreshold_NoAlert()
    {
        await using var db = CreateDbContext();
        var sensorId = Guid.NewGuid();
        AddCredentialLifecycleEvent(db, sensorId, SensorLifecycleEventTypes.SensorCredentialRotated, minutesAgo: 1);
        AddCredentialLifecycleEvent(db, sensorId, SensorLifecycleEventTypes.SensorCredentialRevoked, minutesAgo: 2);
        await db.SaveChangesAsync();

        var result = await CreateService(db).RunAsync();

        Assert.Equal(0, result.CreatedAlerts);
        Assert.Empty(db.SiemAlerts);
    }

    [Fact]
    public async Task RepeatedCredentialLifecycleEvents_AlertPayloadIsSecretSafe()
    {
        await using var db = CreateDbContext();
        var sensorId = Guid.NewGuid();
        var plaintextCredential = "plaintext-credential-that-must-not-render";
        AddCredentialLifecycleEvent(db, sensorId, SensorLifecycleEventTypes.SensorCredentialRotated, minutesAgo: 1, additionalSecretLikeFields: new Dictionary<string, object?>
        {
            ["credential"] = plaintextCredential,
            ["VerifierSha256"] = "verifier-that-must-not-render"
        });
        AddCredentialLifecycleEvent(db, sensorId, SensorLifecycleEventTypes.SensorCredentialRevoked, minutesAgo: 2, additionalSecretLikeFields: new Dictionary<string, object?>
        {
            ["apiKey"] = "api-key-that-must-not-render"
        });
        AddCredentialLifecycleEvent(db, sensorId, SensorLifecycleEventTypes.SensorCredentialRotated, minutesAgo: 3, additionalSecretLikeFields: new Dictionary<string, object?>
        {
            ["connectionString"] = "Host=localhost;Password=must-not-render"
        });
        await db.SaveChangesAsync();

        await CreateService(db).RunAsync();

        var alert = await db.SiemAlerts.SingleAsync();
        var incident = await db.Incidents.SingleAsync();
        var rendered = string.Join('|', alert.Description, alert.TriggerKey, alert.SourceEventIdsJson, incident.Notes);
        Assert.DoesNotContain(plaintextCredential, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain("VerifierSha256", rendered, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("api-key-that-must-not-render", rendered, StringComparison.Ordinal);
        Assert.DoesNotContain("Password=", rendered, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connectionString", rendered, StringComparison.OrdinalIgnoreCase);
    }

    private static ApplicationDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        return new ApplicationDbContext(options);
    }

    private static SiemCorrelationService CreateService(ApplicationDbContext dbContext)
    {
        return new SiemCorrelationService(dbContext, new SpySecurityEventWriter());
    }

    private static void AddLoginFailures(ApplicationDbContext dbContext, string userName, int count)
    {
        for (var i = 0; i < count; i++)
        {
            dbContext.SecurityEvents.Add(new SecurityEventEntry
            {
                OccurredAtUtc = DateTime.UtcNow.AddSeconds(-10 - i),
                EventType = SecurityEventType.LoginFailure,
                Severity = EventSeverity.Warning,
                UserName = userName,
                SourceIp = "10.10.10.21",
                Description = "Неуспешная попытка входа в систему."
            });
        }
    }

    private static void AddUserExceptionChanges(ApplicationDbContext dbContext, string userName, int count)
    {
        for (var i = 0; i < count; i++)
        {
            dbContext.SecurityEvents.Add(new SecurityEventEntry
            {
                OccurredAtUtc = DateTime.UtcNow.AddSeconds(-5 - i),
                EventType = SecurityEventType.UserExceptionUpdated,
                Severity = EventSeverity.Info,
                UserName = userName,
                SourceIp = "127.0.0.1",
                Description = $"Изменена запись UserException #{i + 1}."
            });
        }
    }

    private static void AddCriticalEvents(ApplicationDbContext dbContext, string sourceIp, int count)
    {
        for (var i = 0; i < count; i++)
        {
            dbContext.SecurityEvents.Add(new SecurityEventEntry
            {
                OccurredAtUtc = DateTime.UtcNow.AddSeconds(-15 - i),
                EventType = SecurityEventType.AccessDenied,
                Severity = EventSeverity.Critical,
                UserName = "runtime-agent",
                SourceIp = sourceIp,
                Description = "Критическое событие контроля выполнения контейнера."
            });
        }
    }

    private static void AddImageScanEvent(
        ApplicationDbContext dbContext,
        int criticalCount,
        int highCount,
        int totalCount,
        string? imageDigest = "repo/app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        string imageReference = "repo/app:latest",
        string externalEventType = "container.image.scan.completed")
    {
        dbContext.SecurityEvents.Add(new SecurityEventEntry
        {
            OccurredAtUtc = DateTime.UtcNow.AddSeconds(-10),
            EventType = SecurityEventType.ExternalEvent,
            ExternalEventType = externalEventType,
            Severity = criticalCount > 0 ? EventSeverity.Critical : EventSeverity.High,
            SourceSystem = "conshield.image-scanner",
            Description = "Trivy image scan completed.",
            AdditionalDataJson = System.Text.Json.JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                scanner = "trivy",
                imageReference,
                imageDigest,
                criticalCount,
                highCount,
                totalCount,
                reportSha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            })
        });
    }

    private static void AddPolicyEvent(
        ApplicationDbContext dbContext,
        string decision,
        string? imageDigest = "repo/app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        string imageReference = "repo/app:latest")
    {
        dbContext.SecurityEvents.Add(new SecurityEventEntry
        {
            OccurredAtUtc = DateTime.UtcNow.AddSeconds(-10),
            EventType = SecurityEventType.ExternalEvent,
            ExternalEventType = "container.image.policy.evaluated",
            Severity = decision.Equals("Block", StringComparison.OrdinalIgnoreCase) ? EventSeverity.High : EventSeverity.Warning,
            SourceSystem = "conshield.container-guard",
            Description = "Container policy evaluated.",
            AdditionalDataJson = System.Text.Json.JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                decision,
                policyId = "container-baseline",
                policyVersion = "1.0.0",
                policySha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                imageReference,
                imageDigest,
                reportSha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                criticalCount = 1,
                highCount = 0,
                totalCount = 1,
                reasonCodes = new[] { "CRITICAL_THRESHOLD_REACHED" }
            })
        });
    }

    private static void AddRuntimeEvent(
        ApplicationDbContext dbContext,
        string externalEventType,
        string mappingKey,
        string containerId,
        bool correlate = true,
        EventSeverity severity = EventSeverity.High,
        string sourceSystem = SecuritySourceSystems.FalcoRuntimeCollector)
    {
        dbContext.SecurityEvents.Add(new SecurityEventEntry
        {
            OccurredAtUtc = DateTime.UtcNow.AddSeconds(-10),
            EventType = SecurityEventType.ExternalEvent,
            ExternalEventType = externalEventType,
            Severity = severity,
            SourceSystem = sourceSystem,
            SourceHost = "runtime-node",
            Description = "Falco-compatible runtime event.",
            AdditionalDataJson = System.Text.Json.JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                provider = "falco-compatible",
                mappingId = "falco-container-runtime-baseline",
                mappingVersion = "1.0.0",
                mappingSha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                mappingKey,
                correlate,
                falcoRule = "Terminal shell in container",
                falcoPriority = "Critical",
                falcoSource = "syscall",
                falcoTags = new[] { "container" },
                eventFingerprintSha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                containerId,
                containerName = "runtime-demo",
                imageReference = "alpine:3.20",
                imageDigest = (string?)null,
                processName = "sh",
                eventType = "execve",
                rawOutputSha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                commandLineSha256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            })
        });
    }

    private static void AddSensorRevokedLifecycleEvent(
        ApplicationDbContext dbContext,
        Guid sensorId,
        string displayName,
        string requestedBy,
        int revokedCredentialCount,
        Dictionary<string, object?>? additionalSecretLikeFields = null)
    {
        var payload = LifecyclePayload(
            sensorId,
            displayName,
            requestedBy,
            action: "revokeSensor",
            credentialId: null,
            revokedCredentialCount,
            additionalSecretLikeFields);

        dbContext.SecurityEvents.Add(new SecurityEventEntry
        {
            OccurredAtUtc = DateTime.UtcNow.AddSeconds(-10),
            EventType = SecurityEventType.ExternalEvent,
            ExternalEventType = SensorLifecycleEventTypes.SensorRevoked,
            Severity = EventSeverity.Info,
            SourceSystem = SecuritySourceSystems.SensorLifecycle,
            Description = "Sensor revoked.",
            AdditionalDataJson = System.Text.Json.JsonSerializer.Serialize(payload)
        });
    }

    private static void AddCredentialLifecycleEvent(
        ApplicationDbContext dbContext,
        Guid sensorId,
        string externalEventType,
        int minutesAgo,
        Dictionary<string, object?>? additionalSecretLikeFields = null)
    {
        var payload = LifecyclePayload(
            sensorId,
            "fedora-runtime-01",
            "adminib",
            externalEventType == SensorLifecycleEventTypes.SensorCredentialRotated ? "rotateCredential" : "revokeCredential",
            Guid.NewGuid(),
            revokedCredentialCount: null,
            additionalSecretLikeFields);

        dbContext.SecurityEvents.Add(new SecurityEventEntry
        {
            OccurredAtUtc = DateTime.UtcNow.AddMinutes(-minutesAgo),
            EventType = SecurityEventType.ExternalEvent,
            ExternalEventType = externalEventType,
            Severity = EventSeverity.Info,
            SourceSystem = SecuritySourceSystems.SensorLifecycle,
            Description = "Credential lifecycle event.",
            AdditionalDataJson = System.Text.Json.JsonSerializer.Serialize(payload)
        });
    }

    private static Dictionary<string, object?> LifecyclePayload(
        Guid sensorId,
        string displayName,
        string requestedBy,
        string action,
        Guid? credentialId,
        int? revokedCredentialCount,
        Dictionary<string, object?>? additionalSecretLikeFields)
    {
        var payload = new Dictionary<string, object?>
        {
            ["sensorId"] = sensorId,
            ["displayName"] = displayName,
            ["sourceSystem"] = SecuritySourceSystems.FalcoRuntimeCollector,
            ["lifecycleSourceSystem"] = SecuritySourceSystems.SensorLifecycle,
            ["requestedBy"] = requestedBy,
            ["action"] = action,
            ["reasonProvided"] = true
        };

        if (credentialId is not null)
            payload["credentialId"] = credentialId.Value;
        if (revokedCredentialCount is not null)
            payload["revokedCredentialCount"] = revokedCredentialCount.Value;
        if (additionalSecretLikeFields is not null)
        {
            foreach (var pair in additionalSecretLikeFields)
                payload[pair.Key] = pair.Value;
        }

        return payload;
    }

    private sealed class SpySecurityEventWriter : ISecurityEventWriter
    {
        public List<SecurityEventWriteRequest> Requests { get; } = new();

        public Task WriteAsync(SecurityEventWriteRequest request, CancellationToken cancellationToken = default)
        {
            Requests.Add(request);
            return Task.CompletedTask;
        }
    }
}
