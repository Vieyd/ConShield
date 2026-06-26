using ConShield.Contracts.Enums;
using ConShield.Web.Infrastructure;

namespace ConShield.Tests;

public sealed class WebUiReadabilityStatusPolishTests
{
    [Fact]
    public void StatusBadges_DoNotUseTextOutlineOrUnreadablePatterns()
    {
        var css = ReadRepoFile("src", "ConShield.Web", "wwwroot", "css", "site.css");

        Assert.DoesNotContain("text-shadow", css, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("-webkit-text-stroke", css, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(".app-status", css, StringComparison.Ordinal);
        Assert.Contains(".app-status-dot", css, StringComparison.Ordinal);
        Assert.Contains(".app-status-warning", css, StringComparison.Ordinal);
        Assert.Contains(".app-status-critical", css, StringComparison.Ordinal);
        Assert.Contains(".app-status-ok", css, StringComparison.Ordinal);
    }

    [Fact]
    public void StatusBadges_HaveStablePillLayout()
    {
        var css = ReadRepoFile("src", "ConShield.Web", "wwwroot", "css", "site.css");

        Assert.Contains("display: inline-flex", css, StringComparison.Ordinal);
        Assert.Contains("align-items: center", css, StringComparison.Ordinal);
        Assert.Contains("border-radius: 999px", css, StringComparison.Ordinal);
        Assert.Contains("min-height: 28px", css, StringComparison.Ordinal);
        Assert.Contains("padding: .35rem .65rem", css, StringComparison.Ordinal);
        Assert.Contains("max-width: 100%", css, StringComparison.Ordinal);
    }

    [Fact]
    public void NoVisibleEnglishStatusLabelsRemain()
    {
        var views = ReadAllViewText();

        Assert.DoesNotContain("Needs attention", views, StringComparison.Ordinal);
        Assert.DoesNotContain(">unavailable<", views, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(">LoginSuccess<", views, StringComparison.Ordinal);
        Assert.DoesNotContain(">LoginFailure<", views, StringComparison.Ordinal);
        Assert.DoesNotContain(">Never seen<", views, StringComparison.Ordinal);
        Assert.Equal("Требует внимания", DisplayText.SecuritySummaryStatus("Needs attention"));
        Assert.Equal("Недоступно", DisplayText.Status("unavailable"));
    }

    [Fact]
    public void SecurityEvents_EventTypesUseLocalizedDisplayNames()
    {
        var view = ReadRepoFile("src", "ConShield.Web", "Views", "SecurityEvents", "Index.cshtml");

        Assert.Contains("DisplayText.EventType", view, StringComparison.Ordinal);
        Assert.Equal("Успешный вход", DisplayText.EventType(SecurityEventType.LoginSuccess));
        Assert.Equal("Неуспешный вход", DisplayText.EventType(SecurityEventType.LoginFailure));
        Assert.Equal("Отказ в доступе", DisplayText.EventType(SecurityEventType.AccessDenied));
        Assert.Equal("Повтор dead-letter не выполнен", DisplayText.EventType(SecurityEventType.DeadLetterReplayFailed));
    }

    [Fact]
    public void ThemeToggle_IsVisibleInAuthenticatedLayout()
    {
        var layout = ReadRepoFile("src", "ConShield.Web", "Views", "Shared", "_Layout.cshtml");
        var script = ReadRepoFile("src", "ConShield.Web", "wwwroot", "js", "site.js");

        Assert.Contains("app-theme-toggle", layout, StringComparison.Ordinal);
        Assert.Contains("data-theme-toggle", layout, StringComparison.Ordinal);
        Assert.Contains("Тема:", layout, StringComparison.Ordinal);
        Assert.Contains("conshield-theme", script, StringComparison.Ordinal);
        Assert.Contains("\"light\"", script, StringComparison.Ordinal);
        Assert.Contains("\"dark\"", script, StringComparison.Ordinal);
    }

    [Fact]
    public void CoreViews_UseAppActionGroupsAndTableCards()
    {
        var combined = string.Join(
            Environment.NewLine,
            ReadRepoFile("src", "ConShield.Web", "Views", "SecurityEvents", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Incidents", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Siem", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Siem", "Rules.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Sensors", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Outbox", "Index.cshtml"));

        Assert.Contains("app-table-card", combined, StringComparison.Ordinal);
        Assert.Contains("app-table-scroll", combined, StringComparison.Ordinal);
        Assert.Contains("app-action-group", combined, StringComparison.Ordinal);
        Assert.Contains("app-status-dot", combined, StringComparison.Ordinal);
        Assert.Contains("app-display-secondary", combined, StringComparison.Ordinal);
    }

    [Fact]
    public void TechnicalValues_AreMutedNotNeon()
    {
        var css = ReadRepoFile("src", "ConShield.Web", "wwwroot", "css", "site.css");

        Assert.Contains("--app-code-text", css, StringComparison.Ordinal);
        Assert.Contains(".app-technical", css, StringComparison.Ordinal);
        Assert.DoesNotContain("hotpink", css, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("magenta", css, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("#ff00", css, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("#f0f", css, StringComparison.OrdinalIgnoreCase);
    }

    private static string ReadAllViewText()
    {
        var viewsRoot = Path.Combine(GetRepositoryRoot(), "src", "ConShield.Web", "Views");
        return string.Join(
            Environment.NewLine,
            Directory.GetFiles(viewsRoot, "*.cshtml", SearchOption.AllDirectories)
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .Select(File.ReadAllText));
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
