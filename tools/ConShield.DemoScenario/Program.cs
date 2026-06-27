using System.Text.Json;
using ConShield.Application;
using ConShield.Application.Models;
using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using Microsoft.EntityFrameworkCore;

namespace ConShield.DemoScenario;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var parseResult = DemoScenarioOptions.TryParse(args, out var options, out var error);
        if (!parseResult || options is null)
        {
            Console.Error.WriteLine(error);
            PrintUsage(Console.Error);
            return 2;
        }

        var runner = new DemoScenarioRunner();
        if (options.DryRun && !options.ResetDemoData)
        {
            await runner.RunDryPlanOnlyAsync(options, Console.Out);
            return 0;
        }

        var connectionString = Environment.GetEnvironmentVariable("CONSHIELD_DEMO_CONNECTION_STRING");
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            Console.Error.WriteLine("CONSHIELD_DEMO_CONNECTION_STRING is required for database writes or reset counts. Its value is never printed.");
            return 2;
        }

        var dbOptions = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseNpgsql(connectionString)
            .Options;

        await using var dbContext = new ApplicationDbContext(dbOptions);
        var result = await runner.RunAsync(dbContext, options, Console.Out);
        return result.ExitCode;
    }

    private static void PrintUsage(TextWriter writer)
    {
        writer.WriteLine("Usage:");
        writer.WriteLine("  dotnet run --project tools/ConShield.DemoScenario -- --scenario healthy --dry-run");
        writer.WriteLine("  dotnet run --project tools/ConShield.DemoScenario -- --scenario defense-demo --yes");
        writer.WriteLine("  dotnet run --project tools/ConShield.DemoScenario -- --scenario full-demo --yes");
        writer.WriteLine("  dotnet run --project tools/ConShield.DemoScenario -- --reset-demo-data --dry-run");
        writer.WriteLine("  dotnet run --project tools/ConShield.DemoScenario -- --reset-demo-data --yes");
    }
}

public sealed record DemoScenarioOptions(
    string Scenario,
    bool DryRun,
    bool ResetDemoData,
    bool Yes)
{
    public static readonly string[] SupportedScenarios =
    [
        "healthy",
        "defense-demo",
        "full-demo",
        "lifecycle-alerts",
        "runtime-incident",
        "outbox-backlog"
    ];

    public static bool TryParse(string[] args, out DemoScenarioOptions? options, out string error)
    {
        options = null;
        error = string.Empty;
        var scenario = "healthy";
        var dryRun = false;
        var reset = false;
        var yes = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--scenario":
                    if (i + 1 >= args.Length)
                    {
                        error = "--scenario requires a value.";
                        return false;
                    }

                    scenario = args[++i].Trim();
                    break;
                case "--dry-run":
                    dryRun = true;
                    break;
                case "--reset-demo-data":
                    reset = true;
                    break;
                case "--yes":
                case "-y":
                    yes = true;
                    break;
                default:
                    error = $"Unknown option: {args[i]}";
                    return false;
            }
        }

        if (!SupportedScenarios.Contains(scenario, StringComparer.OrdinalIgnoreCase))
        {
            error = $"Unsupported scenario '{scenario}'. Supported scenarios: {string.Join(", ", SupportedScenarios)}.";
            return false;
        }

        if (reset && !string.Equals(scenario, "healthy", StringComparison.OrdinalIgnoreCase))
        {
            error = "--reset-demo-data cannot be combined with --scenario.";
            return false;
        }

        options = new DemoScenarioOptions(scenario.ToLowerInvariant(), dryRun, reset, yes);
        return true;
    }
}

public sealed class DemoScenarioRunner
{
    public async Task<DemoScenarioRunResult> RunAsync(
        ApplicationDbContext dbContext,
        DemoScenarioOptions options,
        TextWriter output,
        CancellationToken cancellationToken = default)
    {
        if (options.ResetDemoData)
            return await ResetDemoDataAsync(dbContext, options, output, cancellationToken);

        var plan = DemoScenarioPlan.For(options.Scenario);
        await WritePlanAsync(plan, options, output);
        if (options.DryRun)
            return DemoScenarioRunResult.Success();

        await SeedScenarioAsync(dbContext, options.Scenario, cancellationToken);
        var correlationResult = await RunSafeCorrelationAsync(dbContext, options.Scenario, cancellationToken);
        var summary = await DemoScenarioSummary.CreateAsync(dbContext, options.Scenario, cancellationToken);
        await output.WriteLineAsync($"Seeded demo scenario '{options.Scenario}'.");
        await output.WriteLineAsync($"SIEM correlation: alerts_created={correlationResult.CreatedAlerts} incidents_created={correlationResult.CreatedIncidents} rules={string.Join(",", correlationResult.TriggeredRules.Distinct().Order())}");
        await WriteSummaryAsync(summary, output);
        await WriteNextStepsAsync(output);
        return DemoScenarioRunResult.Success();
    }

    public async Task RunDryPlanOnlyAsync(DemoScenarioOptions options, TextWriter output)
    {
        var plan = DemoScenarioPlan.For(options.Scenario);
        await WritePlanAsync(plan, options, output);
        await WriteNextStepsAsync(output);
    }

    private static async Task WritePlanAsync(DemoScenarioPlan plan, DemoScenarioOptions options, TextWriter output)
    {
        await output.WriteLineAsync($"ConShield demo scenario: {plan.Scenario}");
        await output.WriteLineAsync($"dry_run={options.DryRun.ToString().ToLowerInvariant()} reset_demo_data={options.ResetDemoData.ToString().ToLowerInvariant()}");
        await output.WriteLineAsync($"intended_sensors={plan.Sensors}");
        await output.WriteLineAsync($"intended_security_events={plan.SecurityEvents}");
        await output.WriteLineAsync($"intended_inbox_receipts={plan.InboxReceipts}");
        await output.WriteLineAsync($"intended_outbox_messages={plan.OutboxMessages}");
        await output.WriteLineAsync($"expected_correlation_rules={string.Join(",", plan.ExpectedCorrelationRules)}");
        await output.WriteLineAsync("All generated records are synthetic and marked with DemoScenario=true metadata or demo-* names.");
    }

    private static async Task WriteSummaryAsync(DemoScenarioSummary summary, TextWriter output)
    {
        await output.WriteLineAsync("Demo evidence summary:");
        await output.WriteLineAsync($"  actual_sensors={summary.Sensors}");
        await output.WriteLineAsync($"  actual_security_events={summary.SecurityEvents}");
        await output.WriteLineAsync($"  actual_inbox_receipts={summary.InboxReceipts}");
        await output.WriteLineAsync($"  actual_outbox_messages={summary.OutboxMessages}");
        await output.WriteLineAsync($"  actual_outbox_pending={summary.OutboxPending}");
        await output.WriteLineAsync($"  actual_outbox_processing={summary.OutboxProcessing}");
        await output.WriteLineAsync($"  actual_outbox_deadletter={summary.OutboxDeadLetter}");
        await output.WriteLineAsync($"  actual_siem_alerts={summary.SiemAlerts}");
        await output.WriteLineAsync($"  actual_incidents={summary.Incidents}");
        await output.WriteLineAsync($"  actual_rules={string.Join(",", summary.Rules)}");
    }

    private static async Task WriteNextStepsAsync(TextWriter output)
    {
        await output.WriteLineAsync("Next safe demo routes:");
        await output.WriteLineAsync("  /Operations/Health");
        await output.WriteLineAsync("  /Sensors");
        await output.WriteLineAsync("  /SecurityEvents");
        await output.WriteLineAsync("  /SiemAlerts");
        await output.WriteLineAsync("  /Incidents");
        await output.WriteLineAsync("  /Reports/SecuritySummary");
    }

    private static async Task SeedScenarioAsync(
        ApplicationDbContext dbContext,
        string scenario,
        CancellationToken cancellationToken)
    {
        switch (scenario)
        {
            case "healthy":
                await SeedHealthyAsync(dbContext, cancellationToken);
                break;
            case "defense-demo":
                await SeedHealthyAsync(dbContext, cancellationToken, scenarioName: "defense-demo");
                await SeedImageScanAsync(dbContext, cancellationToken, scenarioName: "defense-demo");
                await SeedPolicyGateAsync(dbContext, cancellationToken, scenarioName: "defense-demo");
                await SeedRuntimeIncidentAsync(dbContext, cancellationToken, scenarioName: "defense-demo");
                await SeedLifecycleAlertsAsync(dbContext, cancellationToken, scenarioName: "defense-demo");
                break;
            case "lifecycle-alerts":
                await SeedLifecycleAlertsAsync(dbContext, cancellationToken);
                break;
            case "runtime-incident":
                await SeedRuntimeIncidentAsync(dbContext, cancellationToken);
                break;
            case "outbox-backlog":
                await SeedOutboxBacklogAsync(dbContext, cancellationToken);
                break;
            case "full-demo":
                await SeedHealthyAsync(dbContext, cancellationToken, scenarioName: "full-demo");
                await SeedImageScanAsync(dbContext, cancellationToken, scenarioName: "full-demo");
                await SeedPolicyGateAsync(dbContext, cancellationToken, scenarioName: "full-demo");
                await SeedLifecycleAlertsAsync(dbContext, cancellationToken, scenarioName: "full-demo");
                await SeedRuntimeIncidentAsync(dbContext, cancellationToken, scenarioName: "full-demo");
                await SeedOutboxBacklogAsync(dbContext, cancellationToken, scenarioName: "full-demo");
                break;
            default:
                throw new InvalidOperationException($"Unsupported scenario: {scenario}");
        }
    }

    private static async Task SeedImageScanAsync(ApplicationDbContext dbContext, CancellationToken cancellationToken, string scenarioName = "defense-demo")
    {
        await EnsureSecurityEventAsync(
            dbContext,
            DemoIds.EventImageScanCritical,
            DateTime.UtcNow.AddMinutes(-5),
            EventSeverity.Critical,
            "conshield.image-scanner",
            "container.image.scan.completed",
            "demo-build-agent-01",
            "[DemoScenario] Synthetic Trivy-compatible image scan result with critical findings.",
            scenarioName,
            new Dictionary<string, object?>
            {
                ["schemaVersion"] = 1,
                ["scanner"] = "trivy",
                ["imageReference"] = "repo/conshield-demo:latest",
                ["imageDigest"] = $"repo/conshield-demo@sha256:{DemoIds.ShaB}",
                ["criticalCount"] = 1,
                ["highCount"] = 2,
                ["totalCount"] = 3,
                ["reportSha256"] = DemoIds.ShaA
            },
            cancellationToken);
    }

    private static async Task SeedPolicyGateAsync(ApplicationDbContext dbContext, CancellationToken cancellationToken, string scenarioName = "defense-demo")
    {
        await EnsureSecurityEventAsync(
            dbContext,
            DemoIds.EventPolicyBlocked,
            DateTime.UtcNow.AddMinutes(-4),
            EventSeverity.High,
            "conshield.container-guard",
            "container.image.policy.evaluated",
            "demo-build-agent-01",
            "[DemoScenario] Synthetic container policy gate block decision.",
            scenarioName,
            new Dictionary<string, object?>
            {
                ["schemaVersion"] = 1,
                ["decision"] = "Block",
                ["policyId"] = "container-baseline",
                ["policyVersion"] = "1.0.0",
                ["policySha256"] = DemoIds.ShaA,
                ["imageReference"] = "repo/conshield-demo:latest",
                ["imageDigest"] = $"repo/conshield-demo@sha256:{DemoIds.ShaB}",
                ["reportSha256"] = DemoIds.ShaC,
                ["criticalCount"] = 1,
                ["highCount"] = 2,
                ["totalCount"] = 3,
                ["reasonCodes"] = new[] { "CRITICAL_THRESHOLD_REACHED" }
            },
            cancellationToken);
    }

    private static async Task SeedHealthyAsync(ApplicationDbContext dbContext, CancellationToken cancellationToken, string scenarioName = "healthy")
    {
        var now = DateTime.UtcNow;
        await EnsureDemoSensorAsync(dbContext, DemoIds.HealthySensorA, "demo-fedora-runtime-01", now.AddSeconds(-25), cancellationToken);
        await EnsureDemoSensorAsync(dbContext, DemoIds.HealthySensorB, "demo-build-agent-01", now.AddMinutes(-2), cancellationToken);

        var healthEvent = await EnsureSecurityEventAsync(
            dbContext,
            DemoIds.EventHealthyInfo,
            now.AddSeconds(-30),
            EventSeverity.Info,
            "conshield.demo.health",
            "demo.health.sensor.heartbeat",
            "demo-fedora-runtime-01",
            "[DemoScenario] Healthy enrolled sensor heartbeat sample.",
            scenarioName,
            new Dictionary<string, object?>
            {
                ["status"] = "Fresh",
                ["sensorId"] = DemoIds.HealthySensorA,
                ["displayName"] = "demo-fedora-runtime-01"
            },
            cancellationToken);

        await EnsureSecurityEventAsync(
            dbContext,
            DemoIds.EventHealthyWarning,
            now.AddMinutes(-1),
            EventSeverity.Warning,
            "conshield.demo.policy",
            "demo.policy.warning",
            "demo-build-agent-01",
            "[DemoScenario] Low-risk demo policy warning.",
            scenarioName,
            new Dictionary<string, object?>
            {
                ["policyId"] = "demo-baseline",
                ["decision"] = "Warn"
            },
            cancellationToken);

        await EnsureInboxReceiptAsync(dbContext, healthEvent.Id, DemoIds.MessageHealthyInbox, "conshield.demo.health", cancellationToken);
        await EnsureOutboxMessageAsync(dbContext, healthEvent.Id, DemoIds.MessageHealthyOutbox, SecurityEventOutboxStatus.Delivered, scenarioName, cancellationToken);
    }

    private static async Task SeedLifecycleAlertsAsync(ApplicationDbContext dbContext, CancellationToken cancellationToken, string scenarioName = "lifecycle-alerts")
    {
        var now = DateTime.UtcNow;
        await EnsureDemoSensorAsync(dbContext, DemoIds.LifecycleSensor, "demo-lifecycle-sensor-01", now.AddMinutes(-4), cancellationToken);

        await EnsureSecurityEventAsync(
            dbContext,
            DemoIds.EventLifecycleRevoked,
            now.AddMinutes(-4),
            EventSeverity.Info,
            SecuritySourceSystems.SensorLifecycle,
            SensorLifecycleEventTypes.SensorRevoked,
            "demo-lifecycle-sensor-01",
            "[DemoScenario] Demo sensor identity revoked lifecycle audit event.",
            scenarioName,
            LifecyclePayload(
                DemoIds.LifecycleSensor,
                "demo-lifecycle-sensor-01",
                "demo-adminib",
                "revokeSensor",
                credentialId: null,
                revokedCredentialCount: 2),
            cancellationToken);

        await EnsureSecurityEventAsync(
            dbContext,
            DemoIds.EventLifecycleCredentialRotated1,
            now.AddMinutes(-3),
            EventSeverity.Info,
            SecuritySourceSystems.SensorLifecycle,
            SensorLifecycleEventTypes.SensorCredentialRotated,
            "demo-lifecycle-sensor-01",
            "[DemoScenario] Demo sensor credential rotated lifecycle audit event.",
            scenarioName,
            LifecyclePayload(DemoIds.LifecycleSensor, "demo-lifecycle-sensor-01", "demo-adminib", "rotateCredential", DemoIds.LifecycleCredentialA, null),
            cancellationToken);

        await EnsureSecurityEventAsync(
            dbContext,
            DemoIds.EventLifecycleCredentialRevoked,
            now.AddMinutes(-2),
            EventSeverity.Info,
            SecuritySourceSystems.SensorLifecycle,
            SensorLifecycleEventTypes.SensorCredentialRevoked,
            "demo-lifecycle-sensor-01",
            "[DemoScenario] Demo sensor credential revoked lifecycle audit event.",
            scenarioName,
            LifecyclePayload(DemoIds.LifecycleSensor, "demo-lifecycle-sensor-01", "demo-adminib", "revokeCredential", DemoIds.LifecycleCredentialA, null),
            cancellationToken);

        await EnsureSecurityEventAsync(
            dbContext,
            DemoIds.EventLifecycleCredentialRotated2,
            now.AddMinutes(-1),
            EventSeverity.Info,
            SecuritySourceSystems.SensorLifecycle,
            SensorLifecycleEventTypes.SensorCredentialRotated,
            "demo-lifecycle-sensor-01",
            "[DemoScenario] Demo sensor credential rotated lifecycle audit event.",
            scenarioName,
            LifecyclePayload(DemoIds.LifecycleSensor, "demo-lifecycle-sensor-01", "demo-adminib", "rotateCredential", DemoIds.LifecycleCredentialB, null),
            cancellationToken);
    }

    private static async Task SeedRuntimeIncidentAsync(ApplicationDbContext dbContext, CancellationToken cancellationToken, string scenarioName = "runtime-incident")
    {
        await EnsureDemoSensorAsync(dbContext, DemoIds.RuntimeSensor, "demo-runtime-incident-01", DateTime.UtcNow.AddSeconds(-40), cancellationToken);
        await EnsureSecurityEventAsync(
            dbContext,
            DemoIds.EventRuntimeIncident,
            DateTime.UtcNow.AddSeconds(-20),
            EventSeverity.High,
            SecuritySourceSystems.FalcoRuntimeCollector,
            "container.runtime.shell_spawned",
            "demo-runtime-incident-01",
            "[DemoScenario] Synthetic Falco-compatible runtime shell event; no real Fedora state touched.",
            scenarioName,
            new Dictionary<string, object?>
            {
                ["schemaVersion"] = 1,
                ["provider"] = "falco-compatible",
                ["mappingId"] = "falco-container-runtime-baseline",
                ["mappingVersion"] = "1.0.0",
                ["mappingSha256"] = DemoIds.ShaA,
                ["mappingKey"] = "shell-in-container",
                ["correlate"] = true,
                ["falcoRule"] = "Terminal shell in container",
                ["falcoPriority"] = "Warning",
                ["falcoSource"] = "syscall",
                ["falcoTags"] = new[] { "container", "demo" },
                ["eventFingerprintSha256"] = DemoIds.ShaB,
                ["containerId"] = "demo-runtime-container-01",
                ["containerName"] = "conshield-demo-runtime",
                ["imageReference"] = "alpine:3.20",
                ["processName"] = "sh",
                ["eventType"] = "execve",
                ["rawOutputSha256"] = DemoIds.ShaC,
                ["commandLineSha256"] = DemoIds.ShaD
            },
            cancellationToken);
    }

    private static async Task SeedOutboxBacklogAsync(ApplicationDbContext dbContext, CancellationToken cancellationToken, string scenarioName = "outbox-backlog")
    {
        var pending = await EnsureSecurityEventAsync(
            dbContext,
            DemoIds.EventOutboxPending,
            DateTime.UtcNow.AddMinutes(-8),
            EventSeverity.Warning,
            "conshield.demo.outbox",
            "demo.outbox.pending",
            "demo-outbox-node-01",
            "[DemoScenario] Demo outbox pending backlog row.",
            scenarioName,
            new Dictionary<string, object?> { ["backlogStatus"] = "Pending" },
            cancellationToken);

        var processing = await EnsureSecurityEventAsync(
            dbContext,
            DemoIds.EventOutboxProcessing,
            DateTime.UtcNow.AddMinutes(-7),
            EventSeverity.Warning,
            "conshield.demo.outbox",
            "demo.outbox.processing",
            "demo-outbox-node-01",
            "[DemoScenario] Demo outbox processing backlog row.",
            scenarioName,
            new Dictionary<string, object?> { ["backlogStatus"] = "Processing" },
            cancellationToken);

        var deadLetter = await EnsureSecurityEventAsync(
            dbContext,
            DemoIds.EventOutboxDeadLetter,
            DateTime.UtcNow.AddMinutes(-6),
            EventSeverity.High,
            "conshield.demo.outbox",
            "demo.outbox.deadletter",
            "demo-outbox-node-01",
            "[DemoScenario] Demo outbox dead-letter backlog row.",
            scenarioName,
            new Dictionary<string, object?> { ["backlogStatus"] = "DeadLetter" },
            cancellationToken);

        await EnsureOutboxMessageAsync(dbContext, pending.Id, DemoIds.MessageOutboxPending, SecurityEventOutboxStatus.Pending, scenarioName, cancellationToken);
        await EnsureOutboxMessageAsync(dbContext, processing.Id, DemoIds.MessageOutboxProcessing, SecurityEventOutboxStatus.Processing, scenarioName, cancellationToken);
        await EnsureOutboxMessageAsync(dbContext, deadLetter.Id, DemoIds.MessageOutboxDeadLetter, SecurityEventOutboxStatus.DeadLetter, scenarioName, cancellationToken);
    }

    private static async Task<CorrelationRunResult> RunSafeCorrelationAsync(
        ApplicationDbContext dbContext,
        string scenario,
        CancellationToken cancellationToken)
    {
        if (scenario is not ("lifecycle-alerts" or "runtime-incident" or "defense-demo" or "full-demo"))
            return new CorrelationRunResult();

        var service = new SiemCorrelationService(dbContext, new NoOpSecurityEventWriter());
        return await service.RunAsync(cancellationToken);
    }

    private static async Task<Sensor> EnsureDemoSensorAsync(
        ApplicationDbContext dbContext,
        Guid sensorId,
        string displayName,
        DateTime lastSeenAtUtc,
        CancellationToken cancellationToken)
    {
        var sensor = await dbContext.Sensors.SingleOrDefaultAsync(x => x.SensorId == sensorId, cancellationToken);
        if (sensor is null)
        {
            sensor = new Sensor
            {
                SensorId = sensorId,
                DisplayName = displayName,
                SourceSystem = "conshield.demo.sensor",
                LastSeenAtUtc = lastSeenAtUtc,
                CreatedAtUtc = DateTime.UtcNow,
                UpdatedAtUtc = DateTime.UtcNow
            };
            dbContext.Sensors.Add(sensor);
        }
        else
        {
            sensor.DisplayName = displayName;
            sensor.SourceSystem = "conshield.demo.sensor";
            sensor.LastSeenAtUtc = lastSeenAtUtc;
            sensor.UpdatedAtUtc = DateTime.UtcNow;
        }

        await dbContext.SaveChangesAsync(cancellationToken);
        return sensor;
    }

    private static async Task<SecurityEventEntry> EnsureSecurityEventAsync(
        ApplicationDbContext dbContext,
        Guid externalEventId,
        DateTime occurredAtUtc,
        EventSeverity severity,
        string sourceSystem,
        string externalEventType,
        string sourceHost,
        string description,
        string scenarioName,
        Dictionary<string, object?> metadata,
        CancellationToken cancellationToken)
    {
        var entry = await dbContext.SecurityEvents.SingleOrDefaultAsync(x => x.ExternalEventId == externalEventId, cancellationToken);
        metadata["DemoScenario"] = true;
        metadata["ScenarioName"] = scenarioName;
        metadata["ExternalEventId"] = externalEventId;

        if (entry is null)
        {
            entry = new SecurityEventEntry
            {
                ExternalEventId = externalEventId,
                EventType = SecurityEventType.ExternalEvent
            };
            dbContext.SecurityEvents.Add(entry);
        }

        entry.OccurredAtUtc = occurredAtUtc;
        entry.Severity = severity;
        entry.SourceSystem = sourceSystem;
        entry.ExternalEventType = externalEventType;
        entry.SourceHost = sourceHost;
        entry.UserName = "conshield-demo-runner";
        entry.Description = description;
        entry.AdditionalDataJson = JsonSerializer.Serialize(metadata);

        await dbContext.SaveChangesAsync(cancellationToken);
        return entry;
    }

    private static async Task EnsureOutboxMessageAsync(
        ApplicationDbContext dbContext,
        long securityEventId,
        Guid messageId,
        SecurityEventOutboxStatus status,
        string scenarioName,
        CancellationToken cancellationToken)
    {
        var message = await dbContext.SecurityEventOutboxMessages.SingleOrDefaultAsync(x => x.MessageId == messageId, cancellationToken);
        var now = DateTime.UtcNow;
        if (message is null)
        {
            message = new SecurityEventOutboxMessage
            {
                MessageId = messageId,
                CreatedAtUtc = now
            };
            dbContext.SecurityEventOutboxMessages.Add(message);
        }

        message.SecurityEventId = securityEventId;
        message.MessageType = "conshield.demo.security-event";
        message.SchemaVersion = 1;
        message.PayloadJson = JsonSerializer.Serialize(new
        {
            DemoScenario = true,
            ScenarioName = scenarioName,
            SecurityEventId = securityEventId,
            Status = status.ToString()
        });
        message.Status = status;
        message.AvailableAtUtc = now.AddMinutes(-5);
        message.AttemptCount = status switch
        {
            SecurityEventOutboxStatus.Processing => 1,
            SecurityEventOutboxStatus.DeadLetter => 3,
            _ => 0
        };
        message.LastAttemptAtUtc = status == SecurityEventOutboxStatus.Pending ? null : now.AddMinutes(-1);
        message.LockedUntilUtc = status == SecurityEventOutboxStatus.Processing ? now.AddMinutes(10) : null;
        message.LockToken = status == SecurityEventOutboxStatus.Processing ? DemoIds.MessageOutboxProcessingLock : null;
        message.DeliveredAtUtc = status == SecurityEventOutboxStatus.Delivered ? now.AddSeconds(-5) : null;
        message.LastErrorCode = status == SecurityEventOutboxStatus.DeadLetter ? "DEMO_DEADLETTER" : null;
        message.LastErrorSummary = status == SecurityEventOutboxStatus.DeadLetter ? "Synthetic demo dead-letter row; no broker publish attempted." : null;

        await dbContext.SaveChangesAsync(cancellationToken);
    }

    private static async Task EnsureInboxReceiptAsync(
        ApplicationDbContext dbContext,
        long securityEventId,
        Guid messageId,
        string routingKey,
        CancellationToken cancellationToken)
    {
        var receipt = await dbContext.SecurityEventInboxReceipts.SingleOrDefaultAsync(x => x.MessageId == messageId, cancellationToken);
        if (receipt is null)
        {
            receipt = new SecurityEventInboxReceipt
            {
                MessageId = messageId,
                ReceivedAtUtc = DateTime.UtcNow.AddSeconds(-20)
            };
            dbContext.SecurityEventInboxReceipts.Add(receipt);
        }

        receipt.SecurityEventId = securityEventId;
        receipt.MessageType = "conshield.demo.security-event";
        receipt.SchemaVersion = 1;
        receipt.PayloadSha256 = DemoIds.ShaA;
        receipt.RoutingKey = routingKey;
        receipt.ProcessedAtUtc = DateTime.UtcNow.AddSeconds(-10);
        receipt.Redelivered = false;
        receipt.DeliveryCount = 1;
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    private static Dictionary<string, object?> LifecyclePayload(
        Guid sensorId,
        string displayName,
        string requestedBy,
        string action,
        Guid? credentialId,
        int? revokedCredentialCount)
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

        return payload;
    }

    private static async Task<DemoScenarioRunResult> ResetDemoDataAsync(
        ApplicationDbContext dbContext,
        DemoScenarioOptions options,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var demoEventIds = await dbContext.SecurityEvents
            .Where(x => (x.SourceSystem != null && x.SourceSystem.StartsWith("conshield.demo"))
                || x.Description.StartsWith("[DemoScenario]")
                || (x.AdditionalDataJson != null && x.AdditionalDataJson.Contains("\"DemoScenario\":true")))
            .Select(x => x.Id)
            .ToListAsync(cancellationToken);

        var demoEventIdSet = demoEventIds.ToHashSet();
        var alerts = (await dbContext.SiemAlerts.ToListAsync(cancellationToken))
            .Where(x => AlertReferencesAnyDemoEvent(x, demoEventIdSet))
            .ToList();
        var alertIncidentIds = alerts
            .Select(x => x.IncidentId)
            .Where(x => x.HasValue)
            .Select(x => x!.Value)
            .ToHashSet();

        var outbox = await dbContext.SecurityEventOutboxMessages
            .Where(x => demoEventIds.Contains(x.SecurityEventId)
                || x.MessageType.StartsWith("conshield.demo")
                || x.PayloadJson.Contains("\"DemoScenario\":true"))
            .ToListAsync(cancellationToken);
        var inbox = await dbContext.SecurityEventInboxReceipts
            .Where(x => demoEventIds.Contains(x.SecurityEventId)
                || x.MessageType.StartsWith("conshield.demo")
                || x.RoutingKey.StartsWith("conshield.demo"))
            .ToListAsync(cancellationToken);
        var incidents = await dbContext.Incidents
            .Where(x => (x.SourceEventId.HasValue && demoEventIds.Contains(x.SourceEventId.Value))
                || alertIncidentIds.Contains(x.Id)
                || x.Name.StartsWith("[DemoScenario]")
                || (x.Notes != null && x.Notes.Contains("demo-")))
            .ToListAsync(cancellationToken);
        var events = await dbContext.SecurityEvents
            .Where(x => demoEventIds.Contains(x.Id))
            .ToListAsync(cancellationToken);
        var sensors = await dbContext.Sensors
            .Where(x => x.DisplayName.StartsWith("demo-") || x.SourceSystem.StartsWith("conshield.demo"))
            .ToListAsync(cancellationToken);

        await output.WriteLineAsync("Demo reset candidate counts:");
        await output.WriteLineAsync($"  sensors={sensors.Count}");
        await output.WriteLineAsync($"  security_events={events.Count}");
        await output.WriteLineAsync($"  inbox_receipts={inbox.Count}");
        await output.WriteLineAsync($"  outbox_messages={outbox.Count}");
        await output.WriteLineAsync($"  siem_alerts={alerts.Count}");
        await output.WriteLineAsync($"  incidents={incidents.Count}");

        if (options.DryRun)
        {
            await output.WriteLineAsync("Dry-run reset completed; no rows were deleted.");
            return DemoScenarioRunResult.Success();
        }

        if (!options.Yes)
        {
            await output.WriteLineAsync("Reset requires --yes because it deletes marked demo data.");
            return new DemoScenarioRunResult(2);
        }

        dbContext.SecurityEventOutboxMessages.RemoveRange(outbox);
        dbContext.SecurityEventInboxReceipts.RemoveRange(inbox);
        dbContext.SiemAlerts.RemoveRange(alerts);
        dbContext.Incidents.RemoveRange(incidents);
        dbContext.SecurityEvents.RemoveRange(events);
        dbContext.Sensors.RemoveRange(sensors);
        await dbContext.SaveChangesAsync(cancellationToken);

        await output.WriteLineAsync("Marked demo data removed.");
        return DemoScenarioRunResult.Success();
    }

    private static bool AlertReferencesAnyDemoEvent(SiemAlertRecord alert, HashSet<long> demoEventIds)
    {
        if (string.IsNullOrWhiteSpace(alert.SourceEventIdsJson))
            return false;

        try
        {
            var ids = JsonSerializer.Deserialize<List<long>>(alert.SourceEventIdsJson) ?? [];
            return ids.Any(demoEventIds.Contains);
        }
        catch (JsonException)
        {
            return false;
        }
    }
}

public sealed record DemoScenarioPlan(
    string Scenario,
    int Sensors,
    int SecurityEvents,
    int InboxReceipts,
    int OutboxMessages,
    string[] ExpectedCorrelationRules)
{
    public static DemoScenarioPlan For(string scenario) => scenario switch
    {
        "healthy" => new DemoScenarioPlan("healthy", 2, 2, 1, 1, []),
        "defense-demo" => new DemoScenarioPlan("defense-demo", 4, 9, 1, 1, ["IMG-001", "POL-001", "LIFE-001", "LIFE-002", "RTE-001"]),
        "lifecycle-alerts" => new DemoScenarioPlan("lifecycle-alerts", 1, 4, 0, 0, ["LIFE-001", "LIFE-002"]),
        "runtime-incident" => new DemoScenarioPlan("runtime-incident", 1, 1, 0, 0, ["RTE-001"]),
        "outbox-backlog" => new DemoScenarioPlan("outbox-backlog", 0, 3, 0, 3, []),
        "full-demo" => new DemoScenarioPlan("full-demo", 4, 12, 1, 4, ["IMG-001", "POL-001", "LIFE-001", "LIFE-002", "RTE-001"]),
        _ => throw new InvalidOperationException($"Unsupported scenario: {scenario}")
    };
}

public sealed record DemoScenarioSummary(
    int Sensors,
    int SecurityEvents,
    int InboxReceipts,
    int OutboxMessages,
    int OutboxPending,
    int OutboxProcessing,
    int OutboxDeadLetter,
    int SiemAlerts,
    int Incidents,
    string[] Rules)
{
    public static async Task<DemoScenarioSummary> CreateAsync(
        ApplicationDbContext dbContext,
        string scenario,
        CancellationToken cancellationToken)
    {
        var demoEventIds = await dbContext.SecurityEvents
            .Where(x => (x.SourceSystem != null && x.SourceSystem.StartsWith("conshield.demo"))
                || x.Description.StartsWith("[DemoScenario]")
                || (x.AdditionalDataJson != null && x.AdditionalDataJson.Contains("\"DemoScenario\":true")))
            .Where(x => scenario == "all"
                || (x.AdditionalDataJson != null && x.AdditionalDataJson.Contains($"\"ScenarioName\":\"{scenario}\"")))
            .Select(x => x.Id)
            .ToListAsync(cancellationToken);
        var demoEventIdSet = demoEventIds.ToHashSet();
        var alerts = (await dbContext.SiemAlerts.ToListAsync(cancellationToken))
            .Where(x => AlertReferencesAnyDemoEvent(x, demoEventIdSet))
            .ToList();
        var alertIncidentIds = alerts
            .Select(x => x.IncidentId)
            .Where(x => x.HasValue)
            .Select(x => x!.Value)
            .ToHashSet();

        var outbox = await dbContext.SecurityEventOutboxMessages
            .Where(x => scenario == "all"
                ? demoEventIds.Contains(x.SecurityEventId)
                    || x.MessageType.StartsWith("conshield.demo")
                    || x.PayloadJson.Contains("\"DemoScenario\":true")
                : x.PayloadJson.Contains($"\"ScenarioName\":\"{scenario}\""))
            .ToListAsync(cancellationToken);
        var inbox = await dbContext.SecurityEventInboxReceipts
            .Where(x => demoEventIds.Contains(x.SecurityEventId)
                || x.MessageType.StartsWith("conshield.demo")
                || x.RoutingKey.StartsWith("conshield.demo"))
            .ToListAsync(cancellationToken);
        var incidents = await dbContext.Incidents
            .Where(x => (x.SourceEventId.HasValue && demoEventIds.Contains(x.SourceEventId.Value))
                || alertIncidentIds.Contains(x.Id)
                || x.Name.StartsWith("[DemoScenario]")
                || (x.Notes != null && x.Notes.Contains("demo-")))
            .ToListAsync(cancellationToken);

        return new DemoScenarioSummary(
            Sensors: await dbContext.Sensors.CountAsync(x => x.DisplayName.StartsWith("demo-") || x.SourceSystem.StartsWith("conshield.demo"), cancellationToken),
            SecurityEvents: demoEventIds.Count,
            InboxReceipts: inbox.Count,
            OutboxMessages: outbox.Count,
            OutboxPending: outbox.Count(x => x.Status == SecurityEventOutboxStatus.Pending),
            OutboxProcessing: outbox.Count(x => x.Status == SecurityEventOutboxStatus.Processing),
            OutboxDeadLetter: outbox.Count(x => x.Status == SecurityEventOutboxStatus.DeadLetter),
            SiemAlerts: alerts.Count,
            Incidents: incidents.Count,
            Rules: alerts.Select(x => x.RuleCode).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray());
    }

    private static bool AlertReferencesAnyDemoEvent(SiemAlertRecord alert, HashSet<long> demoEventIds)
    {
        if (string.IsNullOrWhiteSpace(alert.SourceEventIdsJson))
            return false;

        try
        {
            var ids = JsonSerializer.Deserialize<List<long>>(alert.SourceEventIdsJson) ?? [];
            return ids.Any(demoEventIds.Contains);
        }
        catch (JsonException)
        {
            return false;
        }
    }
}

public sealed record DemoScenarioRunResult(int ExitCode)
{
    public static DemoScenarioRunResult Success() => new(0);
}

public static class DemoIds
{
    public static readonly Guid HealthySensorA = Guid.Parse("11111111-1111-1111-1111-000000000001");
    public static readonly Guid HealthySensorB = Guid.Parse("11111111-1111-1111-1111-000000000002");
    public static readonly Guid LifecycleSensor = Guid.Parse("11111111-1111-1111-1111-000000000003");
    public static readonly Guid RuntimeSensor = Guid.Parse("11111111-1111-1111-1111-000000000004");
    public static readonly Guid LifecycleCredentialA = Guid.Parse("22222222-2222-2222-2222-000000000001");
    public static readonly Guid LifecycleCredentialB = Guid.Parse("22222222-2222-2222-2222-000000000002");

    public static readonly Guid EventHealthyInfo = Guid.Parse("33333333-3333-3333-3333-000000000001");
    public static readonly Guid EventHealthyWarning = Guid.Parse("33333333-3333-3333-3333-000000000002");
    public static readonly Guid EventImageScanCritical = Guid.Parse("33333333-3333-3333-3333-000000000003");
    public static readonly Guid EventPolicyBlocked = Guid.Parse("33333333-3333-3333-3333-000000000004");
    public static readonly Guid EventLifecycleRevoked = Guid.Parse("33333333-3333-3333-3333-000000000005");
    public static readonly Guid EventLifecycleCredentialRotated1 = Guid.Parse("33333333-3333-3333-3333-000000000006");
    public static readonly Guid EventLifecycleCredentialRevoked = Guid.Parse("33333333-3333-3333-3333-000000000007");
    public static readonly Guid EventLifecycleCredentialRotated2 = Guid.Parse("33333333-3333-3333-3333-000000000008");
    public static readonly Guid EventRuntimeIncident = Guid.Parse("33333333-3333-3333-3333-000000000009");
    public static readonly Guid EventOutboxPending = Guid.Parse("33333333-3333-3333-3333-000000000010");
    public static readonly Guid EventOutboxProcessing = Guid.Parse("33333333-3333-3333-3333-000000000011");
    public static readonly Guid EventOutboxDeadLetter = Guid.Parse("33333333-3333-3333-3333-000000000012");

    public static readonly Guid MessageHealthyInbox = Guid.Parse("44444444-4444-4444-4444-000000000001");
    public static readonly Guid MessageHealthyOutbox = Guid.Parse("44444444-4444-4444-4444-000000000002");
    public static readonly Guid MessageOutboxPending = Guid.Parse("44444444-4444-4444-4444-000000000003");
    public static readonly Guid MessageOutboxProcessing = Guid.Parse("44444444-4444-4444-4444-000000000004");
    public static readonly Guid MessageOutboxDeadLetter = Guid.Parse("44444444-4444-4444-4444-000000000005");
    public static readonly Guid MessageOutboxProcessingLock = Guid.Parse("44444444-4444-4444-4444-000000000006");

    public const string ShaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    public const string ShaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    public const string ShaC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    public const string ShaD = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
}

internal sealed class NoOpSecurityEventWriter : ISecurityEventWriter
{
    public Task WriteAsync(SecurityEventWriteRequest request, CancellationToken cancellationToken = default) => Task.CompletedTask;
}
