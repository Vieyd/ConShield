using System.Text.RegularExpressions;

namespace ConShield.Tests;

public sealed class ArchitectureDocsTests
{
    private static readonly string PrivateKeyMarker = "-----BEGIN " + "PRIVATE KEY-----";
    private static readonly string CertificateMarker = "-----BEGIN " + "CERTIFICATE-----";

    [Fact]
    public void ArchitectureDataFlowDeploymentAndSequenceDocsExist()
    {
        foreach (var relativePath in ArchitectureDocPaths())
        {
            Assert.True(
                File.Exists(Path.Combine(RepoRoot(), relativePath.Replace('/', Path.DirectorySeparatorChar))),
                $"Missing architecture doc: {relativePath}");
        }
    }

    [Fact]
    public void ArchitectureDocsReferenceKeyComponents()
    {
        var docs = CombinedArchitectureDocs();

        foreach (var expected in new[]
        {
            "ConShield.Web",
            "ConShield.Cli",
            "external event ingestion API",
            "EventConsumer",
            "RabbitMQ",
            "PostgreSQL",
            "MongoDB",
            "image scanner path",
            "Protected runner path",
            "CI/CD gate",
            "Docker lifecycle collector",
            "Falco/runtime replay path",
            "Sensor trust registry",
            "Sensor trust enforcement",
            "Signed sensor event verifier",
            "SIEM correlation service",
            "Incident/operator workflow",
            "Evidence export",
            "Full validation"
        })
        {
            Assert.Contains(expected, docs, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void ArchitectureDiagramsContainRequiredMermaidDiagramsAndTrustBoundaries()
    {
        var doc = ReadRepoFile("docs", "ARCHITECTURE_DIAGRAMS.md");

        Assert.True(Regex.Matches(doc, "```mermaid", RegexOptions.IgnoreCase).Count >= 5);

        foreach (var expected in new[]
        {
            "System context diagram",
            "Component diagram",
            "Trust boundary diagram",
            "End-to-end event pipeline diagram",
            "Configuration-as-code diagram",
            "local operator boundary",
            "CLI/scripts boundary",
            "external event ingestion boundary",
            "message broker boundary",
            "database boundary",
            "runtime sensor boundary",
            "Docker host boundary",
            "Web UI boundary",
            "Release packaging boundary",
            "Purpose",
            "Scope",
            "How to read it",
            "Related implementation",
            "Related requirements"
        })
        {
            Assert.Contains(expected, doc, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void DataFlowModelContainsDfdLevelsEntitiesProcessesAndStores()
    {
        var doc = ReadRepoFile("docs", "DATA_FLOW_MODEL.md");

        foreach (var expected in new[]
        {
            "DFD Level 0 — Context",
            "DFD Level 1 — Main processing",
            "DFD Level 2 — Security event processing",
            "DFD Level 2 — Evidence export",
            "Developer / CI system",
            "Operator",
            "Docker host",
            "Runtime sensor",
            "Trivy scan source",
            "P1 Validate configuration",
            "P2 Scan/evaluate image",
            "P3 Enforce CI/CD or protected-run decision",
            "P4 Ingest normalized event",
            "P5 Correlate SIEM alert/incident",
            "P6 Validate sensor trust/signature",
            "P7 Export evidence",
            "P8 Present Web/CLI views",
            "D1 PostgreSQL operational data",
            "D2 MongoDB projection",
            "D3 RabbitMQ message queue",
            "D4 Config files",
            "D5 Local artifacts",
            "Traceability to requirements"
        })
        {
            Assert.Contains(expected, doc, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void DeploymentViewContainsLocalEndpointsWithoutSecretValues()
    {
        var doc = ReadRepoFile("docs", "DEPLOYMENT_VIEW.md");

        foreach (var expected in new[]
        {
            "Web/API mode",
            "Message pipeline mode",
            "CLI-only offline mode",
            "Optional live integrations",
            "Release pack layout",
            "http://127.0.0.1:5080",
            "http://localhost:15672",
            "127.0.0.1:5432",
            "127.0.0.1:27017"
        })
        {
            Assert.Contains(expected, doc, StringComparison.OrdinalIgnoreCase);
        }

        foreach (var forbidden in new[] { "password=", "api_key=", "token=", "connection string:" })
            Assert.DoesNotContain(forbidden, doc, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SequenceFlowsContainExpectedMermaidSequences()
    {
        var doc = ReadRepoFile("docs", "SEQUENCE_FLOWS.md");

        Assert.True(Regex.Matches(doc, "sequenceDiagram", RegexOptions.IgnoreCase).Count >= 6);

        foreach (var expected in new[]
        {
            "CI/CD gate sequence",
            "Protected run sequence",
            "Docker lifecycle replay sequence",
            "Runtime sensor signed event sequence",
            "Sensor trust enforcement sequence",
            "Evidence export sequence",
            "Full validation sequence"
        })
        {
            Assert.Contains(expected, doc, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void ReadmeReleaseRunbookThreatAndTraceabilityDocsLinkArchitectureDocs()
    {
        var combined = string.Join(
            Environment.NewLine,
            ReadRepoFile("README.md"),
            ReadRepoFile("docs", "DIPLOMA_DEFENSE_NARRATIVE.md"),
            ReadRepoFile("docs", "THREAT_MODEL.md"),
            ReadRepoFile("docs", "REQUIREMENTS_TRACEABILITY_MATRIX.md"),
            ReadRepoFile("docs", "RELEASE_AND_DEMO_PACKAGING.md"),
            ReadRepoFile("docs", "CONSHIELD_FULL_VALIDATION_CHECKLIST.md"),
            ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"),
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"),
            ReadRepoFile("scripts", "New-ConShieldDemoReleasePack.ps1"));

        foreach (var relativePath in ArchitectureDocPaths())
        {
            var windowsPath = relativePath.Replace('/', '\\');
            Assert.True(
                combined.Contains(relativePath, StringComparison.OrdinalIgnoreCase) ||
                combined.Contains(windowsPath, StringComparison.OrdinalIgnoreCase),
                $"Missing architecture doc link/reference: {relativePath}");
        }

        Assert.Contains("Read architecture docs", combined, StringComparison.Ordinal);
        Assert.Contains("ArchitectureDocsTests", combined, StringComparison.Ordinal);
    }

    [Fact]
    public void ArchitectureDocsLinkToThreatModelAndTraceability()
    {
        var docs = CombinedArchitectureDocs();

        foreach (var expected in new[]
        {
            "THREAT_MODEL.md",
            "SECURITY_REQUIREMENTS.md",
            "REQUIREMENTS_TRACEABILITY_MATRIX.md",
            "REQ-IMG-001",
            "REQ-SIEM-001",
            "REQ-EVID-001"
        })
        {
            Assert.Contains(expected, docs, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void ArchitectureDocsAvoidOverclaimsSecretsAndGeneratedBinaryDiagrams()
    {
        var docs = CombinedArchitectureDocs();

        foreach (var forbidden in new[]
        {
            "guarantees protection",
            "zero false positives",
            "fully production-ready enterprise platform",
            "replaces all CNAPP",
            "ConShield is a cloud CNAPP replacement",
            "API key:",
            "password:",
            "token:",
            "connection string:",
            "env value:",
            "Docker logs",
            PrivateKeyMarker,
            CertificateMarker
        })
        {
            Assert.DoesNotContain(forbidden, docs, StringComparison.OrdinalIgnoreCase);
        }

        foreach (var binaryExtension in new[] { ".png", ".jpg", ".jpeg", ".svg", ".drawio" })
            Assert.DoesNotContain(binaryExtension, docs, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ReadmeKeepsBilingualStructureAndArchitectureLinksResolve()
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

    private static IReadOnlyList<string> ArchitectureDocPaths() =>
    [
        "docs/ARCHITECTURE.md",
        "docs/ARCHITECTURE_DIAGRAMS.md",
        "docs/DATA_FLOW_MODEL.md",
        "docs/DEPLOYMENT_VIEW.md",
        "docs/SEQUENCE_FLOWS.md"
    ];

    private static string CombinedArchitectureDocs() =>
        string.Join(Environment.NewLine, ArchitectureDocPaths().Select(ReadRepoFileByRelativePath));

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
