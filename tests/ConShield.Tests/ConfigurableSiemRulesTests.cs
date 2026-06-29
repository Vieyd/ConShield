using System.Diagnostics;
using ConShield.Application;
using ConShield.Application.Models;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Tests;

public sealed class ConfigurableSiemRulesTests
{
    [Fact]
    public void DefaultConfig_ExistsAndValidatesRequiredRules()
    {
        var path = Path.Combine(GetRepositoryRoot(), "config", "siem-rules.default.json");

        var load = SiemRulesConfigurationLoader.TryLoadFile(path);

        Assert.NotNull(load.Configuration);
        Assert.True(load.Validation.IsValid, string.Join(Environment.NewLine, load.Validation.Errors));
        Assert.Equal(1, load.Configuration!.Version);
        Assert.Equal(5, load.Configuration.Rules.Count);
        Assert.Equal(
            new[] { "IMG-001", "LIFE-001", "LIFE-002", "POL-001", "RTE-001" },
            load.Configuration.Rules.Select(x => x.Id).Order(StringComparer.Ordinal).ToArray());
        Assert.Equal(load.Configuration.Rules.Count, load.Configuration.Rules.Select(x => x.Id).Distinct(StringComparer.Ordinal).Count());
        Assert.All(load.Configuration.Rules, rule =>
        {
            Assert.True(rule.IsEnabled);
            Assert.NotEmpty(rule.EffectiveSourceSystems);
            Assert.NotEmpty(rule.EffectiveEventTypes);
            Assert.True(rule.Threshold > 0);
            Assert.True(rule.TimeWindowMinutes > 0);
        });
    }

    [Fact]
    public void InvalidConfig_FailsValidationWithSafeMessage()
    {
        var config = new SiemRulesConfiguration
        {
            Version = 1,
            Rules =
            [
                new ConfigurableSiemRule
                {
                    Id = "IMG-001",
                    Name = "Invalid wildcard rule",
                    Enabled = true,
                    SourceSystems = ["*"],
                    EventTypes = ["container.image.scan.completed"],
                    MinimumSeverity = "Critical",
                    Threshold = 0,
                    TimeWindowMinutes = 60,
                    GroupingKey = "image",
                    AlertSeverity = "Critical",
                    Incident = new ConfigurableSiemIncidentRule { Create = true, Severity = "Critical" }
                },
                CreateDefaultRule("IMG-001")
            ]
        };

        var result = SiemRulesConfigurationLoader.Validate(config);

        Assert.False(result.IsValid);
        var rendered = string.Join('|', result.Errors);
        Assert.Contains("threshold must be positive", rendered, StringComparison.Ordinal);
        Assert.Contains("wildcard source/event matching is not allowed", rendered, StringComparison.Ordinal);
        Assert.Contains("id must be unique", rendered, StringComparison.Ordinal);
        Assert.DoesNotContain("password", rendered, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("token", rendered, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("AdditionalDataJson", rendered, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DisabledConfiguredRule_DoesNotCreateAlertOrIncident()
    {
        await using var db = CreateDbContext();
        AddImageScanEvent(db, criticalCount: 2, highCount: 0, totalCount: 2);
        await db.SaveChangesAsync();

        var result = await CreateService(
            db,
            CreateRuleSet(CreateDefaultRule("IMG-001", enabled: false))).RunAsync();

        Assert.Equal(0, result.CreatedAlerts);
        Assert.Equal(0, result.CreatedIncidents);
        Assert.Empty(db.SiemAlerts);
        Assert.Empty(db.Incidents);
    }

    [Fact]
    public async Task ConfiguredSeverityAndThreshold_AreDeterministic()
    {
        await using var belowThreshold = CreateDbContext();
        AddImageScanEvent(belowThreshold, criticalCount: 2, highCount: 10, totalCount: 12);
        await belowThreshold.SaveChangesAsync();

        var rule = CreateDefaultRule("IMG-001", threshold: 3);
        var first = await CreateService(belowThreshold, CreateRuleSet(rule)).RunAsync();

        Assert.Equal(0, first.CreatedAlerts);
        Assert.Empty(belowThreshold.SiemAlerts);

        await using var atThreshold = CreateDbContext();
        AddImageScanEvent(atThreshold, criticalCount: 3, highCount: 10, totalCount: 13);
        await atThreshold.SaveChangesAsync();

        var second = await CreateService(atThreshold, CreateRuleSet(rule)).RunAsync();

        Assert.Equal(1, second.CreatedAlerts);
        Assert.Equal(EventSeverity.Critical, (await atThreshold.SiemAlerts.SingleAsync()).Severity);
    }

    [Fact]
    public async Task RepeatedCorrelation_WithConfiguredRule_DoesNotDuplicateActiveAlertOrIncident()
    {
        await using var db = CreateDbContext();
        AddImageScanEvent(db, criticalCount: 1, highCount: 0, totalCount: 1);
        await db.SaveChangesAsync();

        var service = CreateService(db, CreateRuleSet(CreateDefaultRule("IMG-001")));

        var first = await service.RunAsync();
        var second = await service.RunAsync();

        Assert.Equal(1, first.CreatedAlerts);
        Assert.Equal(1, first.CreatedIncidents);
        Assert.Equal(0, second.CreatedAlerts);
        Assert.Equal(0, second.CreatedIncidents);
        Assert.Equal(1, await db.SiemAlerts.CountAsync(x => x.RuleCode == "IMG-001"));
        Assert.Equal(1, await db.Incidents.CountAsync());
    }

    [Fact]
    public void ValidationScript_DefaultConfigPassesAndDoesNotPrintUnsafeMarkers()
    {
        var result = RunPwsh(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            ".\\scripts\\Test-ConShieldSiemRules.ps1");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("ConShield SIEM rules validation", result.Output, StringComparison.Ordinal);
        Assert.Contains("Config: config/siem-rules.default.json", result.Output, StringComparison.Ordinal);
        Assert.Contains("Rules: 5", result.Output, StringComparison.Ordinal);
        Assert.Contains("Enabled: 5", result.Output, StringComparison.Ordinal);
        Assert.Contains("Disabled: 0", result.Output, StringComparison.Ordinal);
        foreach (var id in new[] { "IMG-001", "POL-001", "RTE-001", "LIFE-001", "LIFE-002" })
            Assert.Contains($"{id}: OK", result.Output, StringComparison.Ordinal);
        Assert.Contains("Result: PASS", result.Output, StringComparison.Ordinal);
        AssertSafeOutput(result.Output);
    }

    [Fact]
    public void ValidationScript_InvalidConfigFailsWithSafeHint()
    {
        var tempPath = Path.Combine(Path.GetTempPath(), $"conshield-invalid-siem-rules-{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(tempPath, """
            {
              "version": 1,
              "rules": [
                {
                  "id": "IMG-001",
                  "name": "Invalid rule",
                  "enabled": true,
                  "sourceSystems": [ "*" ],
                  "eventTypes": [ "container.image.scan.completed" ],
                  "minimumSeverity": "Critical",
                  "threshold": 0,
                  "timeWindowMinutes": 60,
                  "groupingKey": "image",
                  "alertSeverity": "Critical",
                  "incident": { "create": true, "severity": "Critical" }
                }
              ]
            }
            """);

            var result = RunPwsh(
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                ".\\scripts\\Test-ConShieldSiemRules.ps1",
                "-ConfigPath",
                tempPath);

            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains("Failed rule: IMG-001", result.Output, StringComparison.Ordinal);
            Assert.Contains("Result: FAIL", result.Output, StringComparison.Ordinal);
            AssertSafeOutput(result.Output);
        }
        finally
        {
            File.Delete(tempPath);
        }
    }

    private static SiemCorrelationService CreateService(ApplicationDbContext dbContext, SiemRuleSet ruleSet) =>
        new(dbContext, new SpySecurityEventWriter(), new StaticRuleProvider(ruleSet));

    private static SiemRuleSet CreateRuleSet(params ConfigurableSiemRule[] rules) =>
        new("test-config", rules, usedFallback: false);

    private static ConfigurableSiemRule CreateDefaultRule(
        string id,
        bool enabled = true,
        int threshold = 1) =>
        id switch
        {
            "IMG-001" => new ConfigurableSiemRule
            {
                Id = "IMG-001",
                Name = "Critical image scan finding",
                Enabled = enabled,
                SourceSystems = ["conshield.image-scanner"],
                EventTypes = ["container.image.scan.completed"],
                MinimumSeverity = "Critical",
                Threshold = threshold,
                TimeWindowMinutes = 1440,
                GroupingKey = "image",
                AlertSeverity = "Critical",
                Incident = new ConfigurableSiemIncidentRule { Create = true, Severity = "Critical" }
            },
            _ => throw new ArgumentOutOfRangeException(nameof(id), id, "Unsupported test rule.")
        };

    private static ApplicationDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        return new ApplicationDbContext(options);
    }

    private static void AddImageScanEvent(
        ApplicationDbContext dbContext,
        int criticalCount,
        int highCount,
        int totalCount)
    {
        dbContext.SecurityEvents.Add(new SecurityEventEntry
        {
            OccurredAtUtc = DateTime.UtcNow.AddSeconds(-10),
            EventType = SecurityEventType.ExternalEvent,
            ExternalEventType = "container.image.scan.completed",
            Severity = criticalCount > 0 ? EventSeverity.Critical : EventSeverity.High,
            SourceSystem = "conshield.image-scanner",
            Description = "Trivy image scan completed.",
            AdditionalDataJson = System.Text.Json.JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                scanner = "trivy",
                imageReference = "repo/app:latest",
                imageDigest = "repo/app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                criticalCount,
                highCount,
                totalCount,
                reportSha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            })
        });
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
            "api_key",
            "api key",
            "connection string",
            "password",
            "token",
            "Docker logs",
            "\"Results\"",
            "\"Vulnerabilities\""
        })
        {
            Assert.DoesNotContain(marker, output, StringComparison.OrdinalIgnoreCase);
        }
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

        public StaticRuleProvider(SiemRuleSet ruleSet)
        {
            _ruleSet = ruleSet;
        }

        public SiemRuleSet GetRules() => _ruleSet;
    }

    private sealed class SpySecurityEventWriter : ISecurityEventWriter
    {
        public Task WriteAsync(SecurityEventWriteRequest request, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed record CommandResult(int ExitCode, string Output);
}
