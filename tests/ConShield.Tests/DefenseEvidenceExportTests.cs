namespace ConShield.Tests;

public sealed class DefenseEvidenceExportTests
{
    [Fact]
    public void DefenseEvidenceExporter_ExistsAndWritesOnlyIgnoredMarkdownEvidence()
    {
        var script = ReadRepoFile("scripts", "Export-ConShieldDefenseEvidence.ps1");

        Assert.Contains("[string]$OutputMarkdownPath = \".\\artifacts\\local\\defense-evidence.md\"", script, StringComparison.Ordinal);
        Assert.Contains("Set-Content -LiteralPath $resolvedOutputPath", script, StringComparison.Ordinal);
        Assert.Contains("Sensitive configuration values, raw event bodies, and local logs are intentionally excluded.", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Get-Content Env:", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ConvertTo-Json", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DefenseEvidenceExporter_HasRequiredReportSections()
    {
        var script = ReadRepoFile("scripts", "Export-ConShieldDefenseEvidence.ps1");

        Assert.Contains("# ConShield Defense Evidence Pack v1", script, StringComparison.Ordinal);
        Assert.Contains("## Health and availability", script, StringComparison.Ordinal);
        Assert.Contains("## Scenario summary", script, StringComparison.Ordinal);
        Assert.Contains("## SIEM alerts", script, StringComparison.Ordinal);
        Assert.Contains("## Incidents", script, StringComparison.Ordinal);
        Assert.Contains("## Security events", script, StringComparison.Ordinal);
        Assert.Contains("## Outbox and inbox summary", script, StringComparison.Ordinal);
        Assert.Contains("## Demo navigation checklist", script, StringComparison.Ordinal);
        Assert.Contains("## Operator checklist", script, StringComparison.Ordinal);
    }

    [Fact]
    public void DefenseEvidenceExporter_DoesNotQueryRawPayloadColumns()
    {
        var script = ReadRepoFile("scripts", "Export-ConShieldDefenseEvidence.ps1");

        Assert.DoesNotContain("AdditionalDataJson", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PayloadJson", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SourceEventIdsJson", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PayloadSha256", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("LastErrorSummary", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DefenseEvidenceExporter_DocsMentionSafeEvidencePackCommand()
    {
        var readme = ReadRepoFile("README.md");

        Assert.Contains("scripts\\Export-ConShieldDefenseEvidence.ps1", readme, StringComparison.Ordinal);
        Assert.Contains("artifacts\\local\\defense-evidence.md", readme, StringComparison.Ordinal);
        Assert.Contains("safe aggregate and metadata fields", readme, StringComparison.Ordinal);
        Assert.Contains("generated Markdown under `artifacts/local/`", readme, StringComparison.Ordinal);
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
