namespace ConShield.Tests;

public sealed class DemoWalkthroughPageTests
{
    [Fact]
    public void DemoWalkthroughRouteAndPageExist()
    {
        var controller = ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs");
        var view = ReadRepoFile("src", "ConShield.Web", "Views", "Demo", "Index.cshtml");
        var viewModel = ReadRepoFile("src", "ConShield.Web", "ViewModels", "DemoWalkthroughViewModel.cs");

        Assert.Contains("public sealed class DemoController", controller, StringComparison.Ordinal);
        Assert.Contains("[Authorize]", controller, StringComparison.Ordinal);
        Assert.Contains("public async Task<IActionResult> Index", controller, StringComparison.Ordinal);
        Assert.Contains("Demo Walkthrough", view, StringComparison.Ordinal);
        Assert.Contains("DemoWalkthroughViewModel", viewModel, StringComparison.Ordinal);
    }

    [Fact]
    public void DemoWalkthroughPage_ShowsSafeCommandsAndDoesNotExecuteScripts()
    {
        var combined = string.Join(
            Environment.NewLine,
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Demo", "Index.cshtml"));

        foreach (var scriptName in new[]
        {
            "Start-ConShield.ps1",
            "Reset-ConShieldLocalDemoData.ps1",
            "Invoke-ConShieldImageScan.ps1",
            "Run-ConShieldDefenseScenario.ps1",
            "Replay-ConShieldFalcoRuntimeEvent.ps1",
            "Export-ConShieldDefenseEvidence.ps1",
            "Test-ConShieldDemoReadiness.ps1"
        })
        {
            Assert.Contains(scriptName, combined, StringComparison.Ordinal);
        }

        Assert.Contains("this page does not execute local scripts", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Start-Process", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Process.Start", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("System.Diagnostics.Process", combined, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DemoWalkthroughPage_LinksToExistingDemoPages()
    {
        var combined = string.Join(
            Environment.NewLine,
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Demo", "Index.cshtml"));

        Assert.Contains("/Reports/SecuritySummary", combined, StringComparison.Ordinal);
        Assert.Contains("/SecurityEvents", combined, StringComparison.Ordinal);
        Assert.Contains("/Siem", combined, StringComparison.Ordinal);
        Assert.Contains("/Incidents", combined, StringComparison.Ordinal);
        Assert.Contains("/RuntimeSensors", combined, StringComparison.Ordinal);
        Assert.Contains("sample-image-scan.json", combined, StringComparison.Ordinal);
        Assert.Contains("asp-controller=\"Reports\"", combined, StringComparison.Ordinal);
        Assert.Contains("asp-controller=\"SecurityEvents\"", combined, StringComparison.Ordinal);
        Assert.Contains("asp-controller=\"Siem\"", combined, StringComparison.Ordinal);
        Assert.Contains("asp-controller=\"Incidents\"", combined, StringComparison.Ordinal);
        Assert.Contains("asp-controller=\"RuntimeSensors\"", combined, StringComparison.Ordinal);
    }

    [Fact]
    public void DemoWalkthroughPage_RendersSafeCountsAndEmptyState()
    {
        var controller = ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs");
        var view = ReadRepoFile("src", "ConShield.Web", "Views", "Demo", "Index.cshtml");

        Assert.Contains("SecurityEvents.CountAsync", controller, StringComparison.Ordinal);
        Assert.Contains("SiemAlerts.CountAsync", controller, StringComparison.Ordinal);
        Assert.Contains("Incidents.CountAsync", controller, StringComparison.Ordinal);
        Assert.Contains("RuntimeSensorSourcesCount", view, StringComparison.Ordinal);
        Assert.Contains("No data yet", view, StringComparison.Ordinal);
    }

    [Fact]
    public void DemoWalkthroughPage_DoesNotExposeSecretsOrRawJsonLabels()
    {
        var combined = string.Join(
            Environment.NewLine,
            ReadRepoFile("src", "ConShield.Web", "Controllers", "DemoController.cs"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Demo", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "ViewModels", "DemoWalkthroughViewModel.cs"));

        Assert.DoesNotContain("AdditionalDataJson", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PayloadJson", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connection string", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("api key", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("GetEnvironmentVariable", combined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("appsettings.Development.json", combined, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DemoWalkthroughDocs_MentionActualRoute()
    {
        var docs = string.Join(
            Environment.NewLine,
            ReadRepoFile("README.md"),
            ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"));

        Assert.Contains("http://127.0.0.1:5080/Demo", docs, StringComparison.Ordinal);
        Assert.Contains("Demo walkthrough page", docs, StringComparison.Ordinal);
        Assert.Contains("Страница демонстрационного сценария", docs, StringComparison.Ordinal);
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
