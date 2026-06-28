namespace ConShield.Tests;

public sealed class LocalDemoResetScriptTests
{
    [Fact]
    public void LocalDemoResetScript_ExistsWithDryRunAndConfirmationSafety()
    {
        var script = ReadRepoFile("scripts", "Reset-ConShieldLocalDemoData.ps1");

        Assert.Contains("[CmdletBinding(SupportsShouldProcess = $true)]", script, StringComparison.Ordinal);
        Assert.Contains("[switch]$ConfirmReset", script, StringComparison.Ordinal);
        Assert.Contains("$applyReset = $ConfirmReset.IsPresent -and -not $WhatIfPreference", script, StringComparison.Ordinal);
        Assert.Contains("dry-run only; pass -ConfirmReset for actual reset", script, StringComparison.Ordinal);
        Assert.Contains("Result: {0}", script, StringComparison.Ordinal);
    }

    [Fact]
    public void LocalDemoResetScript_HasLocalEnvironmentAndNoVolumeDeletionGuards()
    {
        var script = ReadRepoFile("scripts", "Reset-ConShieldLocalDemoData.ps1");

        Assert.Contains("[switch]$AllowNonLocal", script, StringComparison.Ordinal);
        Assert.Contains("Test-LocalDatabaseLink", script, StringComparison.Ordinal);
        Assert.Contains("Refusing reset without -AllowNonLocal", script, StringComparison.Ordinal);
        Assert.Contains("Docker volumes are not removed.", script, StringComparison.Ordinal);
        Assert.DoesNotContain("docker volume rm", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("docker compose down -v", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("drop database", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LocalDemoResetScript_TargetsOperationalDataAndKeepsConfig()
    {
        var script = ReadRepoFile("scripts", "Reset-ConShieldLocalDemoData.ps1");

        Assert.Contains("\"SecurityEvents\"", script, StringComparison.Ordinal);
        Assert.Contains("\"SiemAlerts\"", script, StringComparison.Ordinal);
        Assert.Contains("\"Incidents\"", script, StringComparison.Ordinal);
        Assert.Contains("\"SecurityEventOutbox\"", script, StringComparison.Ordinal);
        Assert.Contains("\"SecurityEventInboxReceipts\"", script, StringComparison.Ordinal);
        Assert.Contains("\"DeadLetterQuarantineMessages\"", script, StringComparison.Ordinal);
        Assert.Contains("security_event_raw_v1", script, StringComparison.Ordinal);
        Assert.Contains("conshield-mongo", script, StringComparison.Ordinal);
        Assert.DoesNotContain("DemoUsers__", script, StringComparison.Ordinal);
        Assert.DoesNotContain("SensorCredentials", script, StringComparison.Ordinal);
        Assert.DoesNotContain("UserExceptions", script, StringComparison.Ordinal);
        Assert.DoesNotContain("__EFMigrationsHistory", script, StringComparison.Ordinal);
    }

    [Fact]
    public void LocalDemoResetScript_CleansOnlyArtifactsLocalWhenRequested()
    {
        var script = ReadRepoFile("scripts", "Reset-ConShieldLocalDemoData.ps1");

        Assert.Contains("[switch]$CleanLocalArtifacts", script, StringComparison.Ordinal);
        Assert.Contains("artifacts\\local", script, StringComparison.Ordinal);
        Assert.Contains("refusing to clean outside artifacts/local", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Remove-Item -LiteralPath $repoRoot", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LocalDemoResetScript_DoesNotPrintSecretSourcesOrRawPayloads()
    {
        var script = ReadRepoFile("scripts", "Reset-ConShieldLocalDemoData.ps1");

        Assert.Contains("No secrets are printed.", script, StringComparison.Ordinal);
        Assert.Contains("raw `AdditionalDataJson`", ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"), StringComparison.Ordinal);
        Assert.DoesNotContain("Get-Content Env:", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Host $env:", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $env:", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PayloadJson:", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("AdditionalDataJson:", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("appsettings.Development.json", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LocalDemoResetDocs_MentionPreviewConfirmAndSafety()
    {
        var combinedDocs = string.Join(
            Environment.NewLine,
            ReadRepoFile("README.md"),
            ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"));

        Assert.Contains("scripts\\Reset-ConShieldLocalDemoData.ps1", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("-WhatIf", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("-ConfirmReset", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("does not remove Docker volumes", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("Сброс локальных demo-данных", combinedDocs, StringComparison.Ordinal);
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
}
