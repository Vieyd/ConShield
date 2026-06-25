namespace ConShield.Tests;

public class WebUiLocalizationPolishTests
{
    [Fact]
    public void Views_DoNotRenderRazorControlFlowArtifacts()
    {
        var views = ReadAllViewText();

        Assert.DoesNotContain("} else {", views, StringComparison.Ordinal);
        Assert.DoesNotContain("not available", views, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Rotate credential", views, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Navigation_UsesLocalizedLabels()
    {
        var layout = ReadRepoFile("src", "ConShield.Web", "Views", "Shared", "_Layout.cshtml");

        Assert.Contains("Исключения доступа", layout, StringComparison.Ordinal);
        Assert.Contains("События", layout, StringComparison.Ordinal);
        Assert.Contains("Инциденты", layout, StringComparison.Ordinal);
        Assert.Contains("Оповещения SIEM", layout, StringComparison.Ordinal);
        Assert.Contains("Правила SIEM", layout, StringComparison.Ordinal);
        Assert.Contains("Сенсоры", layout, StringComparison.Ordinal);
        Assert.Contains("Состояние", layout, StringComparison.Ordinal);
        Assert.Contains("Отчёты", layout, StringComparison.Ordinal);
        Assert.Contains("Очередь", layout, StringComparison.Ordinal);
        Assert.Contains("IsActive", layout, StringComparison.Ordinal);
    }

    [Fact]
    public void UiTerminology_DoesNotUseOldAwkwardLabels()
    {
        var views = ReadAllViewText();

        Assert.DoesNotContain("Здоровье операций", views, StringComparison.Ordinal);
        Assert.DoesNotContain("Security summary", views, StringComparison.Ordinal);
        Assert.DoesNotContain("Security Event Outbox", views, StringComparison.Ordinal);
        Assert.DoesNotContain(">Outbox<", views, StringComparison.Ordinal);
        Assert.DoesNotContain("Generated UTC", views, StringComparison.Ordinal);
    }

    [Fact]
    public void UiTables_UseConsistentLightTheme()
    {
        var views = ReadAllViewText();

        Assert.DoesNotContain("table-dark", views, StringComparison.Ordinal);
        Assert.Contains("app-navbar", views, StringComparison.Ordinal);
    }

    [Fact]
    public void DiagnosticsDocumentation_RecommendsUtf8LocalConfig()
    {
        var docs = string.Join(
            Environment.NewLine,
            ReadRepoFile("README.md"),
            ReadRepoFile("docs", "DEMO_EVIDENCE_PACK.md"),
            ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"));

        Assert.Contains("UTF-8", docs, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("appsettings.Development.json", docs, StringComparison.Ordinal);
        Assert.Contains("environment variables may override", docs, StringComparison.OrdinalIgnoreCase);
    }

    private static string ReadAllViewText()
    {
        var viewsRoot = Path.Combine(GetRepositoryRoot(), "src", "ConShield.Web", "Views");
        var files = Directory.GetFiles(viewsRoot, "*.cshtml", SearchOption.AllDirectories)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .Select(File.ReadAllText);

        return string.Join(Environment.NewLine, files);
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
