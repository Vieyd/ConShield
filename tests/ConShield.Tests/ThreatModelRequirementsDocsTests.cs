using System.Text.RegularExpressions;

namespace ConShield.Tests;

public sealed class ThreatModelRequirementsDocsTests
{
    private static readonly string PrivateKeyMarker = "-----BEGIN " + "PRIVATE KEY-----";
    private static readonly string CertificateMarker = "-----BEGIN " + "CERTIFICATE-----";

    private static readonly string[] RequirementIds =
    [
        "REQ-IMG-001",
        "REQ-POL-001",
        "REQ-CICD-001",
        "REQ-RUN-001",
        "REQ-LIFE-001",
        "REQ-RTE-001",
        "REQ-SENS-001",
        "REQ-SENS-002",
        "REQ-SIGN-001",
        "REQ-SIEM-001",
        "REQ-INC-001",
        "REQ-EVID-001",
        "REQ-VAL-001",
        "REQ-PACK-001",
        "REQ-DOC-001"
    ];

    [Fact]
    public void ThreatModelRequirementsAndTraceabilityDocsExist()
    {
        foreach (var relativePath in TraceabilityDocPaths())
        {
            Assert.True(
                File.Exists(Path.Combine(RepoRoot(), relativePath.Replace('/', Path.DirectorySeparatorChar))),
                $"Missing traceability doc: {relativePath}");
        }
    }

    [Fact]
    public void ThreatModelContainsAssetsTrustBoundariesThreatsAndLimitations()
    {
        var doc = ReadRepoFile("docs", "THREAT_MODEL.md");

        foreach (var expected in new[]
        {
            "# ConShield Threat Model",
            "Protected assets",
            "Trust boundaries",
            "CLI/user input",
            "external ingestion API",
            "runtime/lifecycle sensors",
            "release packaging boundary",
            "vulnerable image promoted to deployment",
            "unknown sensor submits runtime event",
            "revoked or disabled sensor submits event",
            "unsafe generated evidence/report output",
            "Out-of-scope threats",
            "full mTLS/PKI",
            "cloud CNAPP replacement"
        })
        {
            Assert.Contains(expected, doc, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void AttackerScenariosIncludeAs001ThroughAs010AndExpectedRules()
    {
        var doc = ReadRepoFile("docs", "ATTACKER_SCENARIOS.md");

        for (var i = 1; i <= 10; i++)
            Assert.Contains($"AS-{i:000}", doc, StringComparison.Ordinal);

        foreach (var expected in new[]
        {
            "IMG-001",
            "POL-001",
            "RTE-001",
            "LIFE-001",
            "LIFE-002",
            "SENSOR-001",
            "SENSOR-002",
            "SIGN-001",
            "SIGN-002",
            "SIGN-003",
            "Evidence produced",
            "Residual risk"
        })
        {
            Assert.Contains(expected, doc, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void SecurityRequirementsContainStableReqIdsAndStatuses()
    {
        var doc = ReadRepoFile("docs", "SECURITY_REQUIREMENTS.md");

        foreach (var requirementId in RequirementIds)
            Assert.Contains(requirementId, doc, StringComparison.Ordinal);

        foreach (var expected in new[]
        {
            "Rationale",
            "Implemented by",
            "Verification",
            "Related scenarios",
            "Status: Implemented",
            "Status values are limited to `Implemented`, `Partially implemented`, or `Planned`"
        })
        {
            Assert.Contains(expected, doc, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void TraceabilityMatrixReferencesEveryRequirementAndMajorFeatureArea()
    {
        var matrix = ReadRepoFile("docs", "REQUIREMENTS_TRACEABILITY_MATRIX.md");

        foreach (var requirementId in RequirementIds)
            Assert.Contains(requirementId, matrix, StringComparison.Ordinal);

        foreach (var expected in new[]
        {
            "Requirement ID",
            "Threat/scenario IDs",
            "Implemented by",
            "Config/rule IDs",
            "CLI/script command",
            "Tests",
            "Evidence/demo output",
            "image scan",
            "protected run",
            "CI/CD gate",
            "Docker lifecycle collector",
            "runtime/Falco replay",
            "sensor trust",
            "signed sensor events",
            "SIEM rules",
            "incidents/operator workflow",
            "evidence export",
            "full validation",
            "release packaging",
            "product positioning limitations"
        })
        {
            Assert.Contains(expected, matrix, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void ReadmeReleaseRunbookChecklistDemoAndPositioningDocsLinkTraceabilityDocs()
    {
        var combined = string.Join(
            Environment.NewLine,
            ReadRepoFile("README.md"),
            ReadRepoFile("docs", "PRODUCT_POSITIONING.md"),
            ReadRepoFile("docs", "DIPLOMA_DEFENSE_NARRATIVE.md"),
            ReadRepoFile("docs", "RELEASE_AND_DEMO_PACKAGING.md"),
            ReadRepoFile("docs", "CONSHIELD_FULL_VALIDATION_CHECKLIST.md"),
            ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"),
            ReadRepoFile("scripts", "New-ConShieldDemoReleasePack.ps1"));

        foreach (var relativePath in TraceabilityDocPaths())
        {
            var windowsPath = relativePath.Replace('/', '\\');
            Assert.True(
                combined.Contains(relativePath, StringComparison.OrdinalIgnoreCase) ||
                combined.Contains(windowsPath, StringComparison.OrdinalIgnoreCase),
                $"Missing traceability doc link/reference: {relativePath}");
        }

        Assert.Contains("Read threat model docs", combined, StringComparison.Ordinal);
        Assert.Contains("ThreatModelRequirementsDocsTests", combined, StringComparison.Ordinal);
    }

    [Fact]
    public void TraceabilityDocsAvoidOverclaimsSecretsAndRawArtifacts()
    {
        var text = string.Join(Environment.NewLine, TraceabilityDocPaths().Select(ReadRepoFileByRelativePath));

        foreach (var forbidden in new[]
        {
            "guarantees protection",
            "complete security",
            "zero false positives",
            "fully production-ready",
            "enterprise-grade replacement",
            "ConShield is a formal compliance-attestation product",
            "ConShield is a cloud CNAPP replacement",
            "raw payload JSON",
            "raw AdditionalDataJson",
            "Docker logs",
            "API key:",
            "password:",
            "token:",
            "connection string:",
            "env value:",
            PrivateKeyMarker,
            CertificateMarker
        })
        {
            Assert.DoesNotContain(forbidden, text, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void ReadmeKeepsBilingualStructureAndLinksResolveAfterTraceabilityLinks()
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

    private static IReadOnlyList<string> TraceabilityDocPaths() =>
    [
        "docs/THREAT_MODEL.md",
        "docs/ATTACKER_SCENARIOS.md",
        "docs/SECURITY_REQUIREMENTS.md",
        "docs/REQUIREMENTS_TRACEABILITY_MATRIX.md",
        "docs/RESIDUAL_RISKS.md"
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
