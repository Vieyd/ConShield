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

    [Fact]
    public void FinalHandoffSnapshot_ExistsAndCoversCurrentState()
    {
        var snapshot = ReadRepoFile("docs", "CONSHIELD_FINAL_HANDOFF_SNAPSHOT.md");

        Assert.Contains("ConShield Final Handoff Snapshot", snapshot, StringComparison.Ordinal);
        Assert.Contains("/Reports/SecuritySummary", snapshot, StringComparison.Ordinal);
        Assert.Contains("/Operations/Health", snapshot, StringComparison.Ordinal);
        Assert.Contains("Security Summary", snapshot, StringComparison.Ordinal);
        Assert.Contains("lifecycle SIEM", snapshot, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("RabbitMQ", snapshot, StringComparison.Ordinal);
        Assert.Contains("VerifierSha256", snapshot, StringComparison.Ordinal);
    }

    [Fact]
    public void DiplomaTextDraftRu_ExistsAndCoversCoreSections()
    {
        var draft = ReadRepoFile("docs", "DIPLOMA_TEXT_SECTIONS_DRAFT_RU.md");

        Assert.Contains("Черновик разделов ВКР", draft, StringComparison.Ordinal);
        Assert.Contains("Объект и предмет", draft, StringComparison.Ordinal);
        Assert.Contains("Цель работы", draft, StringComparison.Ordinal);
        Assert.Contains("Задачи работы", draft, StringComparison.Ordinal);
        Assert.Contains("Архитектура решения", draft, StringComparison.Ordinal);
        Assert.Contains("Сценарий демонстрации", draft, StringComparison.Ordinal);
        Assert.Contains("Направления дальнейшего развития", draft, StringComparison.Ordinal);
    }

    [Fact]
    public void DiplomaTextDraftRu_DoesNotClaimProductionReadiness()
    {
        var draft = ReadRepoFile("docs", "DIPLOMA_TEXT_SECTIONS_DRAFT_RU.md");

        Assert.Contains("прототип", draft, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("полностью предотвращает все атаки", draft, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("гарантирует безопасность", draft, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("production-ready", draft, StringComparison.OrdinalIgnoreCase);
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
