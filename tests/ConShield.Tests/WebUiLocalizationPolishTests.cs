using ConShield.Application;
using ConShield.Web.Infrastructure;

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

    [Fact]
    public void UiLocalization_NoCommonEnglishLabelsOnCorePages()
    {
        var coreText = string.Join(
            Environment.NewLine,
            ReadRepoFile("src", "ConShield.Web", "Views", "Reports", "SecuritySummary.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Outbox", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Operations", "Health.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Siem", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Siem", "Rules.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Incidents", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Incidents", "Details.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "DeadLetters", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "DeadLetters", "Details.cshtml"));

        var forbidden = new[]
        {
            "Security summary",
            "Security Event Outbox",
            "Generated UTC",
            "Events in range",
            "Latest event",
            "Severity counts",
            "Operator checklist",
            "Markdown export preview",
            "Consumer inbox / projection receipts",
            "Latest received",
            "Latest processed",
            "<th>MessageType",
            "<th>SecurityEventId",
            "<th>Attempts",
            ">Connected<",
            ">Documents<",
            ">Collection<",
            "not available",
            ">New</option>",
            ">Acknowledged</option>",
            ">Closed</option>"
        };

        foreach (var value in forbidden)
            Assert.DoesNotContain(value, coreText, StringComparison.Ordinal);
    }

    [Fact]
    public void SiemRuleDisplayNames_AreLocalized()
    {
        Assert.Equal("Отзыв идентификатора сенсора", DisplayText.RuleName("LIFE-001"));
        Assert.Equal("Повторные изменения учетных данных сенсора", DisplayText.RuleName("LIFE-002"));
        Assert.Equal("Угроза во время выполнения контейнера", DisplayText.RuleName("RTE-001"));
        Assert.Equal("Критические уязвимости в контейнерном образе", DisplayText.RuleName("IMG-001"));
        Assert.Equal("Блокировка контейнерного образа политикой", DisplayText.RuleName("POL-001"));
        Assert.Equal("Неизвестный runtime-сенсор", DisplayText.RuleName("SENSOR-001"));
        Assert.Equal("Отозванный или отключенный runtime-сенсор", DisplayText.RuleName("SENSOR-002"));

        var rules = SiemRuleCatalog.Rules.ToDictionary(rule => rule.RuleCode);
        Assert.Equal("Отзыв идентификатора сенсора", rules["LIFE-001"].RuleName);
        Assert.Equal("Повторные изменения учетных данных сенсора", rules["LIFE-002"].RuleName);
        Assert.Equal("Угроза во время выполнения контейнера", rules["RTE-001"].RuleName);
        Assert.Equal("Неизвестный runtime-сенсор", rules["SENSOR-001"].RuleName);
        Assert.Equal("Отозванный или отключенный runtime-сенсор", rules["SENSOR-002"].RuleName);
    }

    [Fact]
    public void IncidentAndAlertViews_UseLocalizedRuleDisplayNames()
    {
        var siemIndex = ReadRepoFile("src", "ConShield.Web", "Views", "Siem", "Index.cshtml");
        var siemDetails = ReadRepoFile("src", "ConShield.Web", "Views", "Siem", "Details.cshtml");
        var incidentIndex = ReadRepoFile("src", "ConShield.Web", "Views", "Incidents", "Index.cshtml");
        var incidentDetails = ReadRepoFile("src", "ConShield.Web", "Views", "Incidents", "Details.cshtml");

        Assert.Contains("DisplayText.RuleName", siemIndex, StringComparison.Ordinal);
        Assert.Contains("DisplayText.AlertDescription", siemIndex, StringComparison.Ordinal);
        Assert.Contains("DisplayText.RuleName", siemDetails, StringComparison.Ordinal);
        Assert.Contains("DisplayText.AlertDescription", siemDetails, StringComparison.Ordinal);
        Assert.Contains("DisplayText.IncidentTitle", incidentIndex, StringComparison.Ordinal);
        Assert.Contains("DisplayText.IncidentTitle", incidentDetails, StringComparison.Ordinal);
        Assert.Contains("DisplayText.IncidentNotes", incidentDetails, StringComparison.Ordinal);
    }

    [Fact]
    public void ReportMarkdownExport_IsLocalizedAndSecretSafe()
    {
        var reportsController = ReadRepoFile("src", "ConShield.Web", "Controllers", "ReportsController.cs");

        Assert.Contains("# ConShield — сводка безопасности", reportsController, StringComparison.Ordinal);
        Assert.Contains("Чек-лист оператора", reportsController, StringComparison.Ordinal);
        Assert.Contains("Событий за период", reportsController, StringComparison.Ordinal);
        Assert.DoesNotContain("raw event JSON", reportsController, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("credentials", reportsController, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("passwords", reportsController, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("tokens", reportsController, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("API keys", reportsController, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connection strings", reportsController, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("env values", reportsController, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("cookies", reportsController, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void OutboxAndOperationsPages_UseLocalizedLabels()
    {
        var outbox = ReadRepoFile("src", "ConShield.Web", "Views", "Outbox", "Index.cshtml");
        var operations = ReadRepoFile("src", "ConShield.Web", "Views", "Operations", "Health.cshtml");

        Assert.Contains("Очередь отправки событий", outbox, StringComparison.Ordinal);
        Assert.Contains("ID сообщения", outbox, StringComparison.Ordinal);
        Assert.Contains("Тип сообщения", outbox, StringComparison.Ordinal);
        Assert.Contains("Попытки", outbox, StringComparison.Ordinal);
        Assert.Contains("Проекция MongoDB", outbox, StringComparison.Ordinal);
        Assert.Contains("Подтверждения обработки", operations, StringComparison.Ordinal);
        Assert.Contains("Последнее получение", operations, StringComparison.Ordinal);
        Assert.Contains("Последняя обработка", operations, StringComparison.Ordinal);
    }

    [Fact]
    public void UiDesign_UsesAppStyleClasses()
    {
        var coreText = string.Join(
            Environment.NewLine,
            ReadAllViewText(),
            ReadRepoFile("src", "ConShield.Web", "wwwroot", "css", "site.css"));

        Assert.Contains("--app-bg", coreText, StringComparison.Ordinal);
        Assert.Contains(".app-page-header", coreText, StringComparison.Ordinal);
        Assert.Contains(".app-card", coreText, StringComparison.Ordinal);
        Assert.Contains(".app-filter-panel", coreText, StringComparison.Ordinal);
        Assert.Contains(".app-table", coreText, StringComparison.Ordinal);
        Assert.Contains(".app-badge", coreText, StringComparison.Ordinal);
        Assert.Contains(".app-code", coreText, StringComparison.Ordinal);
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
