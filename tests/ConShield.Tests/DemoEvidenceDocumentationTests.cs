namespace ConShield.Tests;

public sealed class DemoEvidenceDocumentationTests
{
    [Fact]
    public void DemoEvidencePack_ExistsAndCoversCoreScreens()
    {
        var pack = ReadRepoFile("docs", "DEMO_EVIDENCE_PACK.md");

        Assert.Contains("/Operations/Health", pack, StringComparison.Ordinal);
        Assert.Contains("/Reports/SecuritySummary", pack, StringComparison.Ordinal);
        Assert.Contains("/SecurityEvents", pack, StringComparison.Ordinal);
        Assert.Contains("/Sensors", pack, StringComparison.Ordinal);
        Assert.Contains("LIFE-001", pack, StringComparison.Ordinal);
        Assert.Contains("LIFE-002", pack, StringComparison.Ordinal);
    }

    [Fact]
    public void DemoEvidencePack_ContainsSecretSafetyWarnings()
    {
        var pack = ReadRepoFile("docs", "DEMO_EVIDENCE_PACK.md");

        Assert.Contains("VerifierSha256", pack, StringComparison.Ordinal);
        Assert.Contains("appsettings.Development.json", pack, StringComparison.Ordinal);
        Assert.Contains("API keys", pack, StringComparison.Ordinal);
        Assert.Contains("Generated sensor credentials", pack, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DiplomaFeatureMap_ExistsAndCoversCoreModules()
    {
        var map = ReadRepoFile("docs", "DIPLOMA_FEATURE_MAP.md");

        Assert.Contains("Image scanning", map, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("policy gate", map, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runtime collector", map, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ingestion", map, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("outbox", map, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("SIEM", map, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("report/export", map, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("future work", map, StringComparison.OrdinalIgnoreCase);
    }

    private static string ReadRepoFile(params string[] relativePath)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(new[] { directory.FullName }.Concat(relativePath).ToArray());
            if (File.Exists(candidate))
                return File.ReadAllText(candidate);

            directory = directory.Parent;
        }

        throw new FileNotFoundException($"Could not find repository file: {Path.Combine(relativePath)}");
    }
}
