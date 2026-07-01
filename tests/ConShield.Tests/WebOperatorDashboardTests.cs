namespace ConShield.Tests;

public sealed class WebOperatorDashboardTests
{
    private static readonly string PrivateKeyMarker = "-----BEGIN " + "PRIVATE KEY-----";
    private static readonly string CertificateMarker = "-----BEGIN " + "CERTIFICATE-----";

    [Fact]
    public void DashboardRouteControllerViewAndNavExist()
    {
        var controller = ReadRepoFile("src", "ConShield.Web", "Controllers", "DashboardController.cs");
        var view = ReadRepoFile("src", "ConShield.Web", "Views", "Dashboard", "Index.cshtml");
        var viewModel = ReadRepoFile("src", "ConShield.Web", "ViewModels", "OperatorDashboardViewModel.cs");
        var layout = ReadRepoFile("src", "ConShield.Web", "Views", "Shared", "_Layout.cshtml");

        Assert.Contains("public sealed class DashboardController", controller, StringComparison.Ordinal);
        Assert.Contains("[Authorize]", controller, StringComparison.Ordinal);
        Assert.Contains("Task<IActionResult> Index", controller, StringComparison.Ordinal);
        Assert.Contains("ConShield Operator Dashboard", view, StringComparison.Ordinal);
        Assert.Contains("OperatorDashboardViewModel", viewModel, StringComparison.Ordinal);
        Assert.Contains("asp-controller=\"Dashboard\"", layout, StringComparison.Ordinal);
    }

    [Fact]
    public void DashboardContainsRequiredStatusCards()
    {
        var combined = DashboardSource();

        foreach (var label in new[]
        {
            "Security Events",
            "SIEM Alerts",
            "Open Incidents",
            "Critical/High Findings",
            "Trusted Sensors",
            "Unknown/Revoked Sensors",
            "Signed Event Failures",
            "Lifecycle Events",
            "Evidence Status",
            "Configuration Status"
        })
        {
            Assert.Contains(label, combined, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void DashboardContainsWorkflowTilesSafeCommandsAndDocs()
    {
        var combined = DashboardSource();

        foreach (var category in new[]
        {
            "Pre-deployment controls",
            "Runtime and lifecycle",
            "Operations and evidence"
        })
        {
            Assert.Contains(category, combined, StringComparison.Ordinal);
        }

        foreach (var workflow in new[]
        {
            "Image Scan",
            "CI/CD Gate",
            "Protected Run",
            "Docker Lifecycle Collector",
            "Runtime/Falco Replay",
            "Sensor Trust",
            "Signed Sensor Events",
            "SIEM Rules",
            "Container Policy",
            "Evidence Export",
            "Full Validation",
            "Release Pack"
        })
        {
            Assert.Contains(workflow, combined, StringComparison.Ordinal);
        }

        foreach (var command in new[]
        {
            "ConShield.Cli -- scan image",
            "ConShield.Cli -- gate image",
            "ConShield.Cli -- run protected",
            "ConShield.Cli -- lifecycle replay",
            "ConShield.Cli -- sensor replay",
            "Test-ConShieldFullValidation.ps1",
            "New-ConShieldDemoReleasePack.ps1"
        })
        {
            Assert.Contains(command, combined, StringComparison.Ordinal);
        }

        foreach (var doc in new[]
        {
            "docs/ARCHITECTURE.md",
            "docs/DATA_FLOW_MODEL.md",
            "docs/THREAT_MODEL.md",
            "docs/REQUIREMENTS_TRACEABILITY_MATRIX.md",
            "docs/PRODUCT_POSITIONING.md",
            "docs/CONSHIELD_CLI.md"
        })
        {
            Assert.Contains(doc, combined, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void DashboardShowsLatestAlertsIncidentsAndSensorSummarySafely()
    {
        var view = ReadRepoFile("src", "ConShield.Web", "Views", "Dashboard", "Index.cshtml");
        var controller = ReadRepoFile("src", "ConShield.Web", "Controllers", "DashboardController.cs");

        foreach (var expected in new[]
        {
            "Latest sanitized SIEM alerts",
            "Latest sanitized incidents",
            "Sensor trust and signature summary",
            "Runtime sources",
            "Trusted / Unknown",
            "Revoked / Disabled",
            "Missing signatures",
            "Invalid / UnknownKey signatures",
            "Stale / Replay signatures",
            "SourceEventId",
            "asp-controller=\"SecurityEvents\"",
            "asp-controller=\"RuntimeSensors\""
        })
        {
            Assert.Contains(expected, view + controller, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void DashboardIsReadOnlyAndDoesNotExecuteServerSideCommands()
    {
        var controller = ReadRepoFile("src", "ConShield.Web", "Controllers", "DashboardController.cs");
        var view = ReadRepoFile("src", "ConShield.Web", "Views", "Dashboard", "Index.cshtml");
        var combined = controller + Environment.NewLine + view;

        foreach (var forbidden in new[]
        {
            "Process.Start",
            "System.Diagnostics.Process",
            "PowerShell.Create",
            "CliWrap",
            "UseShellExecute",
            "cmd.exe",
            "powershell.exe",
            "<form",
            "asp-action=\"Reset",
            "method=\"post\"",
            "onclick=",
            "fetch("
        })
        {
            Assert.DoesNotContain(forbidden, combined, StringComparison.OrdinalIgnoreCase);
        }

        Assert.Contains("This dashboard is read-only", view, StringComparison.Ordinal);
        Assert.Contains("the browser does not execute", view, StringComparison.Ordinal);
        Assert.Contains("Commands are shown as local copy/paste references", view, StringComparison.Ordinal);
    }

    [Fact]
    public void DashboardPrioritizesStatusGuidedDemoAndCollapsedCommandReferences()
    {
        var view = ReadRepoFile("src", "ConShield.Web", "Views", "Dashboard", "Index.cshtml");

        var postureIndex = view.IndexOf("Current demo posture", StringComparison.Ordinal);
        var alertsIndex = view.IndexOf("Latest sanitized SIEM alerts", StringComparison.Ordinal);
        var guidedIndex = view.IndexOf("Guided demo flow", StringComparison.Ordinal);
        var workflowIndex = view.IndexOf("Workflow references", StringComparison.Ordinal);
        var docsIndex = view.IndexOf("Documentation links", StringComparison.Ordinal);

        Assert.True(postureIndex >= 0, "Posture summary must be present.");
        Assert.True(alertsIndex > postureIndex, "Latest alerts should follow posture/status cards.");
        Assert.True(guidedIndex > alertsIndex, "Guided demo should follow status and recent activity.");
        Assert.True(workflowIndex > guidedIndex, "Workflow command references should be secondary to guided demo flow.");
        Assert.True(docsIndex > workflowIndex, "Documentation links should support the dashboard after workflow references.");

        Assert.Contains("Optional local command reference", view, StringComparison.Ordinal);
        Assert.Contains("Command reference", view, StringComparison.Ordinal);
        Assert.Contains("<details", view, StringComparison.Ordinal);
        Assert.Contains("<summary", view, StringComparison.Ordinal);

        foreach (var step in new[]
        {
            "Validate repository and configuration",
            "Generate or replay demo data",
            "Review dashboard posture",
            "Inspect SIEM alerts and incidents",
            "Review runtime sensors and signed events",
            "Export evidence",
            "Create release pack"
        })
        {
            Assert.Contains(step, view + DashboardSource(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public void DashboardDoesNotDisplayForbiddenRawPayloadOrSecretMarkers()
    {
        var combined = DashboardSource();

        foreach (var forbidden in new[]
        {
            "AdditionalDataJson",
            "raw Trivy JSON",
            "raw Docker event JSON",
            "raw runtime payload JSON",
            "Docker logs",
            "API key",
            "password",
            "connection string",
            "private key",
            "certificate block",
            "artifacts/local",
            "artifacts\\local",
            PrivateKeyMarker,
            CertificateMarker
        })
        {
            Assert.DoesNotContain(forbidden, combined, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void DocsMentionReadOnlyDashboardAndSafeRoute()
    {
        var combined = string.Join(
            Environment.NewLine,
            ReadRepoFile("README.md"),
            ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"),
            ReadRepoFile("docs", "CONSHIELD_FULL_VALIDATION_CHECKLIST.md"),
            ReadRepoFile("docs", "RELEASE_AND_DEMO_PACKAGING.md"),
            ReadRepoFile("docs", "DIPLOMA_DEFENSE_NARRATIVE.md"));

        Assert.Contains("http://127.0.0.1:5080/Dashboard", combined, StringComparison.Ordinal);
        Assert.Contains("read-only", combined, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("does not run", combined, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("WebOperatorDashboardTests", combined, StringComparison.Ordinal);
    }

    [Fact]
    public void ReadmeKeepsBilingualStructureAndDashboardLinksResolve()
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
    }

    private static string DashboardSource() =>
        string.Join(
            Environment.NewLine,
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DashboardController.cs"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Dashboard", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "ViewModels", "OperatorDashboardViewModel.cs"));

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
