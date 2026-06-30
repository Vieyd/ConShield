using System.Text.RegularExpressions;

namespace ConShield.Tests;

public sealed class ProductPositioningDocsTests
{
    private static readonly string PrivateKeyMarker = "-----BEGIN " + "PRIVATE KEY-----";
    private static readonly string CertificateMarker = "-----BEGIN " + "CERTIFICATE-----";

    [Fact]
    public void PositioningCompetitiveNarrativeAndRoadmapDocsExist()
    {
        foreach (var relativePath in PositioningDocPaths())
        {
            Assert.True(
                File.Exists(Path.Combine(RepoRoot(), relativePath.Replace('/', Path.DirectorySeparatorChar))),
                $"Missing positioning doc: {relativePath}");
        }
    }

    [Fact]
    public void ProductPositioningStatesScopeDifferentiatorsAndLimitations()
    {
        var doc = ReadRepoFile("docs", "PRODUCT_POSITIONING.md");

        foreach (var expected in new[]
        {
            "# ConShield Product Positioning",
            "local-first DevSecOps/SIEM control plane",
            "not scanner-only",
            "not an enterprise CNAPP replacement",
            "policy-as-code",
            "SIEM-as-code",
            "sensor trust",
            "signed sensor event",
            "evidence-first",
            "scan -> policy gate -> runtime/lifecycle -> sensor trust/signatures -> SIEM -> incidents -> evidence",
            "Limitations",
            "Roadmap"
        })
        {
            Assert.Contains(expected, doc, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void CompetitiveAnalysisContainsExpectedMatrixAndCategories()
    {
        var doc = ReadRepoFile("docs", "COMPETITIVE_ANALYSIS.md");

        foreach (var expected in new[]
        {
            "# Competitive Analysis",
            "| Capability | ConShield | Trivy | Falco | Kyverno | Wazuh | Commercial CNAPP category |",
            "Image scan input",
            "Policy-as-code gate",
            "CI/CD exit code gate",
            "Runtime/Falco event ingestion",
            "Sensor trust registry",
            "Signed sensor event verification",
            "SIEM correlation rules",
            "Incident creation",
            "Evidence export",
            "Kubernetes admission control",
            "Enterprise multi-cluster management",
            "Compliance/certification"
        })
        {
            Assert.Contains(expected, doc, StringComparison.OrdinalIgnoreCase);
        }

        foreach (var category in new[] { "Trivy", "Falco", "Kyverno", "Wazuh", "Commercial CNAPP", "ConShield" })
            Assert.Contains(category, doc, StringComparison.OrdinalIgnoreCase);

        Assert.Contains("not differentiated by outperforming specialized tools", doc, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("does not claim to replace", doc, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DiplomaNarrativeAnswersExpectedDefenseQuestions()
    {
        var doc = ReadRepoFile("docs", "DIPLOMA_DEFENSE_NARRATIVE.md");

        foreach (var expected in new[]
        {
            "## What to say if asked “why not just Trivy?”",
            "## What to say if asked “why not just Falco?”",
            "## What to say if asked “why not Kubernetes?”",
            "## What to say if asked “is it production-ready?”",
            "Отличие ConShield заключается",
            "сквозной цепочке принятия решения",
            "scan -> policy gate -> runtime/lifecycle -> sensor trust/signatures -> SIEM -> incidents -> evidence"
        })
        {
            Assert.Contains(expected, doc, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ReadmeReleaseChecklistRunbookAndDemoLinkPositioningDocs()
    {
        var combined = string.Join(
            Environment.NewLine,
            ReadRepoFile("README.md"),
            ReadRepoFile("docs", "RELEASE_AND_DEMO_PACKAGING.md"),
            ReadRepoFile("docs", "CONSHIELD_FULL_VALIDATION_CHECKLIST.md"),
            ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"),
            ReadRepoFile("scripts", "New-ConShieldDemoReleasePack.ps1"));

        foreach (var relativePath in PositioningDocPaths())
        {
            var windowsPath = relativePath.Replace('/', '\\');
            Assert.True(
                combined.Contains(relativePath, StringComparison.OrdinalIgnoreCase) ||
                combined.Contains(windowsPath, StringComparison.OrdinalIgnoreCase),
                $"Missing docs link/reference: {relativePath}");
        }

        Assert.Contains("Read product positioning docs", combined, StringComparison.Ordinal);
        Assert.Contains("ProductPositioningDocsTests", combined, StringComparison.Ordinal);
    }

    [Fact]
    public void PositioningDocsAvoidOverclaimsSecretsAndRawPayloads()
    {
        var text = string.Join(Environment.NewLine, PositioningDocPaths().Select(ReadRepoFileByRelativePath));

        foreach (var forbidden in new[]
        {
            "best in the world",
            "guarantees protection",
            "zero false positives",
            "replaces all CNAPP",
            "fully production-ready enterprise platform",
            "is a certified compliance product",
            "replaces Aqua",
            "replaces Wiz",
            "replaces Snyk",
            "ultra secure",
            "raw AdditionalDataJson",
            "raw payload JSON",
            "raw Trivy JSON",
            "Docker logs",
            "API key:",
            "connection string:",
            "password:",
            "token:",
            PrivateKeyMarker,
            CertificateMarker
        })
        {
            Assert.DoesNotContain(forbidden, text, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void ReadmeKeepsEnglishThenRussianStructureAndLinksResolve()
    {
        var readme = ReadRepoFile("README.md");
        var englishIndex = readme.IndexOf("## English", StringComparison.Ordinal);
        var russianAnchorIndex = readme.IndexOf("<a id=\"русский\"></a>", StringComparison.Ordinal);
        var russianIndex = readme.IndexOf("## Русский", StringComparison.Ordinal);

        Assert.True(englishIndex >= 0, "README English section is missing.");
        Assert.True(russianAnchorIndex > englishIndex, "Russian anchor must follow English section.");
        Assert.True(russianIndex > russianAnchorIndex, "Russian section must follow its anchor.");
        Assert.DoesNotMatch("[А-Яа-яЁё]", readme[englishIndex..russianAnchorIndex]);
        Assert.Matches("[А-Яа-яЁё]", readme[russianIndex..]);

        foreach (Match match in Regex.Matches(readme, @"\[[^\]]+\]\((?<target>[^)#]+)(#[^)]+)?\)"))
        {
            var target = match.Groups["target"].Value;
            if (target.StartsWith("http", StringComparison.OrdinalIgnoreCase) ||
                target.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var fullPath = Path.Combine(RepoRoot(), target.Replace('/', Path.DirectorySeparatorChar));
            Assert.True(File.Exists(fullPath), $"README link target does not exist: {target}");
        }
    }

    private static IReadOnlyList<string> PositioningDocPaths() =>
    [
        "docs/PRODUCT_POSITIONING.md",
        "docs/COMPETITIVE_ANALYSIS.md",
        "docs/DIPLOMA_DEFENSE_NARRATIVE.md",
        "docs/ROADMAP_TO_PRODUCTION.md"
    ];

    private static string ReadRepoFileByRelativePath(string relativePath) =>
        File.ReadAllText(Path.Combine(RepoRoot(), relativePath.Replace('/', Path.DirectorySeparatorChar)));

    private static string ReadRepoFile(params string[] parts) =>
        File.ReadAllText(Path.Combine(new[] { RepoRoot() }.Concat(parts).ToArray()));

    private static string RepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "ConShield.sln")))
            directory = directory.Parent;

        return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root was not found.");
    }
}
