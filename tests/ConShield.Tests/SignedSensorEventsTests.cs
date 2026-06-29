using System.Diagnostics;
using System.Text.Json;
using ConShield.Application;
using ConShield.Application.Models;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.RuntimeDetection;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Tests;

public sealed class SignedSensorEventsTests
{
    [Fact]
    public void DemoSignatureVerification_IsDeterministicAndSafe()
    {
        var envelope = DemoEnvelope(SignedSensorEventVerifier.ComputeCanonicalPayloadHash("demo-payload"));
        var first = SignedSensorEventVerifier.CreateSignature(envelope, SignedSensorEventVerifier.DemoSigningMaterial);
        var second = SignedSensorEventVerifier.CreateSignature(envelope, SignedSensorEventVerifier.DemoSigningMaterial);
        var result = SignedSensorEventVerifier.Verify(envelope with { Signature = first }, SignedSensorEventVerifier.DemoSigningMaterial, envelope.EventTimestampUtc);

        Assert.Equal(first, second);
        Assert.Equal(RuntimeSignatureStatuses.Valid, result.Status);
        Assert.Equal(RuntimeSignatureStatuses.Valid, result.Metadata.SignatureStatus);
        Assert.Equal(SignedSensorEventVerifier.DemoSignatureKeyId, result.Metadata.SignatureKeyId);
        Assert.DoesNotContain(SignedSensorEventVerifier.DemoSigningMaterial, result.Metadata.SignatureVerificationReason ?? string.Empty, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null, RuntimeSignatureStatuses.Missing)]
    [InlineData("bad-signature", RuntimeSignatureStatuses.Invalid)]
    public void SignatureVerification_ClassifiesMissingAndInvalid(string? signature, string expectedStatus)
    {
        var envelope = DemoEnvelope(SignedSensorEventVerifier.ComputeCanonicalPayloadHash("demo-payload")) with { Signature = signature };
        var result = SignedSensorEventVerifier.Verify(envelope, SignedSensorEventVerifier.DemoSigningMaterial, envelope.EventTimestampUtc);

        Assert.Equal(expectedStatus, result.Status);
    }

    [Fact]
    public void SignatureVerification_ClassifiesStaleAndReplay()
    {
        var staleEnvelope = DemoEnvelope(
            SignedSensorEventVerifier.ComputeCanonicalPayloadHash("demo-payload"),
            DateTime.UtcNow.AddHours(-2));
        var staleSignature = SignedSensorEventVerifier.CreateSignature(staleEnvelope, SignedSensorEventVerifier.DemoSigningMaterial);

        var stale = SignedSensorEventVerifier.Verify(staleEnvelope with { Signature = staleSignature }, SignedSensorEventVerifier.DemoSigningMaterial);
        var replay = SignedSensorEventVerifier.Verify(staleEnvelope with { Signature = staleSignature }, SignedSensorEventVerifier.DemoSigningMaterial, replayDetected: true);

        Assert.Equal(RuntimeSignatureStatuses.Stale, stale.Status);
        Assert.Equal(RuntimeSignatureStatuses.ReplayDetected, replay.Status);
    }

    [Theory]
    [InlineData(RuntimeSignatureStatuses.Valid, "RTE-001", 1, 1)]
    [InlineData(RuntimeSignatureStatuses.Missing, "SIGN-001", 1, 0)]
    [InlineData(RuntimeSignatureStatuses.Invalid, "SIGN-002", 1, 1)]
    [InlineData(RuntimeSignatureStatuses.Stale, "SIGN-003", 1, 1)]
    [InlineData(RuntimeSignatureStatuses.ReplayDetected, "SIGN-003", 1, 1)]
    public async Task SignatureStatus_CreatesExpectedCorrelation(
        string signatureStatus,
        string expectedRule,
        int expectedAlerts,
        int expectedIncidents)
    {
        await using var db = CreateDbContext();
        AddRuntimeEvent(db, signatureStatus);
        await db.SaveChangesAsync();

        var result = await CreateService(db).RunAsync();

        Assert.Equal(expectedAlerts, result.CreatedAlerts);
        Assert.Equal(expectedIncidents, result.CreatedIncidents);
        Assert.Contains(await db.SiemAlerts.ToListAsync(), x => x.RuleCode == expectedRule);
        Assert.DoesNotContain(await db.SiemAlerts.ToListAsync(), x => x.Description.Contains("AdditionalDataJson", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RuntimeSensorHealth_IncludesSignatureFields()
    {
        await using var db = CreateDbContext();
        AddRuntimeEvent(db, RuntimeSignatureStatuses.Invalid);
        await db.SaveChangesAsync();
        var eventId = await db.SecurityEvents.Select(x => x.Id).SingleAsync();
        db.SiemAlerts.Add(new SiemAlertRecord
        {
            CreatedAtUtc = DateTime.UtcNow,
            RuleCode = "SIGN-002",
            RuleName = "Invalid runtime sensor signature",
            TriggerKey = "SIGN-002:demo-falco-linux-01",
            Severity = EventSeverity.Critical,
            Status = "New",
            SourceEventIdsJson = JsonSerializer.Serialize(new[] { eventId })
        });
        await db.SaveChangesAsync();

        var health = await new RuntimeSensorHealthService(db, DefaultRegistry()).GetAsync();
        var row = health.Sources.Single(x => x.SourceSystem == "conshield.falco-linux-sensor");

        Assert.Equal(RuntimeSignatureStatuses.Invalid, row.SignatureStatus);
        Assert.Equal(SignedSensorEventVerifier.DemoSignatureKeyId, row.SignatureKeyId);
        Assert.Equal(1, row.RelatedSignatureAlertCount);
        Assert.Contains("signature mismatch", row.LastSignatureFailure, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("-DemoSignature", "Signature: Valid", "Expected rules: RTE-001")]
    [InlineData("-SimulateMissingSignature", "Signature: Missing", "Expected rules: SIGN-001")]
    [InlineData("-SimulateInvalidSignature", "Signature: Invalid", "Expected rules: SIGN-002")]
    [InlineData("-SimulateStaleSignature", "Signature: Stale", "Expected rules: SIGN-003")]
    [InlineData("-SimulateReplaySignature", "Signature: ReplayDetected", "Expected rules: SIGN-003")]
    public void ReplayScript_SignedModesAreDeterministicAndSafe(
        string mode,
        string expectedSignature,
        string expectedRules)
    {
        var result = RunPwsh("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ".\\scripts\\Replay-ConShieldFalcoRuntimeEvent.ps1", mode, "-NoSubmit");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains(expectedSignature, result.Output, StringComparison.Ordinal);
        Assert.Contains(expectedRules, result.Output, StringComparison.Ordinal);
        Assert.Contains("Result: PASS", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output);
    }

    [Fact]
    public void EvidenceReadinessDemoAndDocsContainSignedSensorHooks()
    {
        var combined = string.Join(
            Environment.NewLine,
            ReadRepoFile("scripts", "Export-ConShieldDefenseEvidence.ps1"),
            ReadRepoFile("scripts", "Test-ConShieldDemoReadiness.ps1"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"),
            ReadRepoFile("src", "ConShield.Web", "Views", "RuntimeSensors", "Index.cshtml"));

        Assert.Contains("Signed Sensor Event Evidence", combined, StringComparison.Ordinal);
        Assert.Contains("DemoSignature", combined, StringComparison.Ordinal);
        Assert.Contains("SimulateMissingSignature", combined, StringComparison.Ordinal);
        Assert.Contains("SIGN-001", combined, StringComparison.Ordinal);
        Assert.Contains("SIGN-002", combined, StringComparison.Ordinal);
        Assert.Contains("SIGN-003", combined, StringComparison.Ordinal);
        Assert.DoesNotContain("-----BEGIN PRIVATE KEY-----", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("-----BEGIN CERTIFICATE-----", combined, StringComparison.OrdinalIgnoreCase);
    }

    private static SignedSensorEventEnvelope DemoEnvelope(string payloadHash, DateTime? timestampUtc = null) =>
        new(
            "demo-falco-linux-01",
            "conshield.falco-linux-sensor",
            "container.runtime.shell_spawned",
            timestampUtc ?? DateTime.UtcNow,
            "demo-nonce-0001",
            SignedSensorEventVerifier.DemoSignatureAlgorithm,
            SignedSensorEventVerifier.DemoSignatureKeyId,
            null,
            payloadHash);

    private static void AddRuntimeEvent(ApplicationDbContext dbContext, string signatureStatus)
    {
        dbContext.SecurityEvents.Add(new SecurityEventEntry
        {
            OccurredAtUtc = DateTime.UtcNow.AddSeconds(-10),
            EventType = SecurityEventType.ExternalEvent,
            ExternalEventType = "container.runtime.shell_spawned",
            Severity = signatureStatus == RuntimeSignatureStatuses.Valid ? EventSeverity.High : EventSeverity.Critical,
            SourceSystem = "conshield.falco-linux-sensor",
            SourceHost = "runtime-node",
            Description = "Falco-compatible runtime event.",
            AdditionalDataJson = JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                provider = "falco-compatible",
                mappingId = "falco-container-runtime-baseline",
                mappingVersion = "1.0.0",
                mappingSha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                mappingKey = "shell-in-container",
                correlate = true,
                falcoRule = "Terminal shell in container",
                eventFingerprintSha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                containerId = "signed-runtime-container",
                processName = "sh",
                signature = new
                {
                    sensorId = "demo-falco-linux-01",
                    eventTimestampUtc = DateTime.UtcNow,
                    nonce = "demo-nonce-0001",
                    signatureAlgorithm = SignedSensorEventVerifier.DemoSignatureAlgorithm,
                    signatureKeyId = SignedSensorEventVerifier.DemoSignatureKeyId,
                    canonicalPayloadHash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    signatureStatus,
                    signatureVerificationReason = signatureStatus == RuntimeSignatureStatuses.Valid ? "signature verified" : "signature mismatch"
                }
            })
        });
    }

    private static SiemCorrelationService CreateService(ApplicationDbContext dbContext) =>
        new(dbContext, new SpySecurityEventWriter(), new StaticRuleProvider(SiemRulesConfigurationLoader.BuiltInDefaults("test-defaults", usedFallback: true)), DefaultRegistry());

    private static SensorTrustRegistry DefaultRegistry() =>
        SensorTrustRegistryLoader.LoadFromFile(
            Path.Combine(GetRepositoryRoot(), "config", "sensor-registry.default.json"),
            GetRepositoryRoot());

    private static ApplicationDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new ApplicationDbContext(options);
    }

    private static CommandResult RunPwsh(params string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "pwsh",
            WorkingDirectory = GetRepositoryRoot(),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("pwsh was not started.");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit(60_000);
        return new CommandResult(process.ExitCode, output + error);
    }

    private static void AssertSafeOutput(string output)
    {
        foreach (var marker in new[]
        {
            "AdditionalDataJson",
            "PayloadJson",
            "CONSHIELD_",
            "connection string",
            "password",
            "token",
            "-----BEGIN",
            "PRIVATE KEY",
            "Docker logs"
        })
        {
            Assert.DoesNotContain(marker, output, StringComparison.OrdinalIgnoreCase);
        }
    }

    private static string ReadRepoFile(params string[] relativePath)
    {
        var fullPath = Path.Combine(GetRepositoryRoot(), Path.Combine(relativePath));
        return File.ReadAllText(fullPath);
    }

    private static string GetRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "ConShield.sln")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root not found.");
    }

    private sealed class StaticRuleProvider : ISiemRuleProvider
    {
        private readonly SiemRuleSet _ruleSet;
        public StaticRuleProvider(SiemRuleSet ruleSet) => _ruleSet = ruleSet;
        public SiemRuleSet GetRules() => _ruleSet;
    }

    private sealed class SpySecurityEventWriter : ISecurityEventWriter
    {
        public Task WriteAsync(SecurityEventWriteRequest request, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed record CommandResult(int ExitCode, string Output);
}
