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
        Assert.Contains("conshield.theme", script, StringComparison.Ordinal);
        Assert.Contains("\"light\"", script, StringComparison.Ordinal);
        Assert.Contains("\"dark\"", script, StringComparison.Ordinal);
    }

    [Fact]
    public void LoginView_ExposesThemeToggleBeforeAuthentication()
    {
        var login = ReadRepoFile("src", "ConShield.Web", "Views", "Account", "Login.cshtml");
        var layout = ReadRepoFile("src", "ConShield.Web", "Views", "Shared", "_Layout.cshtml");
        var script = ReadRepoFile("src", "ConShield.Web", "wwwroot", "js", "site.js");

        Assert.Contains("data-theme-toggle", login, StringComparison.Ordinal);
        Assert.Contains("Тема:", login, StringComparison.Ordinal);
        Assert.Contains("data-theme-label", login, StringComparison.Ordinal);
        Assert.Contains("const storageKey = \"conshield.theme\"", script, StringComparison.Ordinal);
        Assert.Contains("const cookieName = \"conshield.theme\"", script, StringComparison.Ordinal);
        Assert.Contains("new Set([\"light\", \"dark\"])", script, StringComparison.Ordinal);
        Assert.Contains("Context.Request.Cookies[\"conshield.theme\"]", layout, StringComparison.Ordinal);
    }

    [Fact]
    public void LoginView_ExposesPasswordVisibilityButtonWithoutLoggingPassword()
    {
        var login = ReadRepoFile("src", "ConShield.Web", "Views", "Account", "Login.cshtml");
        var script = ReadRepoFile("src", "ConShield.Web", "wwwroot", "js", "site.js");

        Assert.Contains("data-password-input", login, StringComparison.Ordinal);
        Assert.Contains("data-password-toggle", login, StringComparison.Ordinal);
        Assert.Contains("type=\"button\"", login, StringComparison.Ordinal);
        Assert.Contains("aria-pressed=\"false\"", login, StringComparison.Ordinal);
        Assert.Contains("Показать", login, StringComparison.Ordinal);
        Assert.Contains("input.type = shouldShowPassword ? \"text\" : \"password\"", script, StringComparison.Ordinal);
        Assert.Contains("Скрыть пароль", script, StringComparison.Ordinal);
        Assert.DoesNotContain("console.log", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(".value", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Theme_DoesNotFlashLightBeforeDarkPreference()
    {
        var layout = ReadRepoFile("src", "ConShield.Web", "Views", "Shared", "_Layout.cshtml");
        var script = ReadRepoFile("src", "ConShield.Web", "wwwroot", "js", "site.js");

        Assert.True(
            layout.IndexOf("document.documentElement.dataset.theme", StringComparison.Ordinal) <
            layout.IndexOf("~/css/site.css", StringComparison.Ordinal));
        Assert.Contains("Context.Request.Cookies[\"conshield.theme\"]", layout, StringComparison.Ordinal);
        Assert.Contains("data-theme=\"@initialTheme\"", layout, StringComparison.Ordinal);
        Assert.Contains("allowedThemes", layout, StringComparison.Ordinal);
        Assert.Contains("const storageKey = \"conshield.theme\"", script, StringComparison.Ordinal);
        Assert.Contains("document.cookie = `${cookieName}=${theme}; Path=/; Max-Age=31536000; SameSite=Lax`", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Severity_HighIsOrangeAndDistinctFromInfo()
    {
        var css = ReadRepoFile("src", "ConShield.Web", "wwwroot", "css", "site.css");

        Assert.Contains("--app-info-bg: #eef2f7", css, StringComparison.Ordinal);
        Assert.Contains("--app-info-text: #344054", css, StringComparison.Ordinal);
        Assert.Contains("--app-high-bg: #fff1e6", css, StringComparison.Ordinal);
        Assert.Contains("--app-high-text: #9a3412", css, StringComparison.Ordinal);
        Assert.DoesNotContain("--app-high-bg: #e8f1ff", css, StringComparison.Ordinal);
        Assert.DoesNotContain("--app-high-text: #16418a", css, StringComparison.Ordinal);
    }

    [Fact]
    public void SecurityEvents_ListDoesNotRenderRawAdditionalData()
    {
        var view = ReadRepoFile("src", "ConShield.Web", "Views", "SecurityEvents", "Index.cshtml");

        Assert.DoesNotContain("<th>Доп. данные</th>", view, StringComparison.Ordinal);
        Assert.DoesNotContain("@item.AdditionalDataJson", view, StringComparison.Ordinal);
        Assert.Contains("app-table-description", view, StringComparison.Ordinal);
    }

    [Fact]
    public void SecurityEvents_IdDoesNotWrap()
    {
        var view = ReadRepoFile("src", "ConShield.Web", "Views", "SecurityEvents", "Index.cshtml");

        Assert.Contains("id-code app-id-nowrap", view, StringComparison.Ordinal);
    }

    [Fact]
    public void WideTables_UseScrollAndStickyActions()
    {
        var combined = string.Join(
            Environment.NewLine,
            ReadRepoFile("src", "ConShield.Web", "Views", "SecurityEvents", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Siem", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Sensors", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "UserExceptions", "Index.cshtml"));
        var css = ReadRepoFile("src", "ConShield.Web", "wwwroot", "css", "site.css");

        Assert.Contains("app-table-scroll", combined, StringComparison.Ordinal);
        Assert.Contains("app-table-actions-col", combined, StringComparison.Ordinal);
        Assert.Contains("position: sticky", css, StringComparison.Ordinal);
        Assert.Contains("right: 0", css, StringComparison.Ordinal);
    }

    [Fact]
    public void StickyActionCells_DoNotUseAccentBackgroundBlocks()
    {
        var css = ReadRepoFile("src", "ConShield.Web", "wwwroot", "css", "site.css");
        var actionCellStart = css.IndexOf(".app-table-actions-col {", StringComparison.Ordinal);
        var actionCellEnd = css.IndexOf("}", actionCellStart, StringComparison.Ordinal);
        var actionCellBlock = css[actionCellStart..actionCellEnd];

        Assert.Contains("background: inherit", actionCellBlock, StringComparison.Ordinal);
        Assert.DoesNotContain("--app-accent", actionCellBlock, StringComparison.Ordinal);
        Assert.DoesNotContain("background: var(--app-surface)", actionCellBlock, StringComparison.Ordinal);
    }

    [Fact]
    public void WideTableScrollbars_AreDiscoverableInCss()
    {
        var css = ReadRepoFile("src", "ConShield.Web", "wwwroot", "css", "site.css");

        Assert.Contains(".app-table-scroll::-webkit-scrollbar", css, StringComparison.Ordinal);
        Assert.Contains(".app-table-scroll::-webkit-scrollbar-thumb", css, StringComparison.Ordinal);
        Assert.Contains("scrollbar-color: var(--app-accent)", css, StringComparison.Ordinal);
        Assert.Contains("Прокрутите таблицу по горизонтали", css, StringComparison.Ordinal);
    }

    [Fact]
    public void TechnicalValues_UseTruncatedMutedPattern()
    {
        var css = ReadRepoFile("src", "ConShield.Web", "wwwroot", "css", "site.css");
        var displayText = ReadRepoFile("src", "ConShield.Web", "Infrastructure", "DisplayText.cs");
        var combinedViews = string.Join(
            Environment.NewLine,
            ReadRepoFile("src", "ConShield.Web", "Views", "SecurityEvents", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Sensors", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Outbox", "Index.cshtml"));

        Assert.Contains(".app-technical-code--truncate", css, StringComparison.Ordinal);
        Assert.Contains(".app-id-nowrap", css, StringComparison.Ordinal);
        Assert.Contains("ShortTechnicalValue", displayText, StringComparison.Ordinal);
        Assert.Contains("title=\"@", combinedViews, StringComparison.Ordinal);
    }

    [Fact]
    public void Reports_MarkdownPreviewHasFramedSpacing()
    {
        var view = ReadRepoFile("src", "ConShield.Web", "Views", "Reports", "SecuritySummary.cshtml");
        var css = ReadRepoFile("src", "ConShield.Web", "wwwroot", "css", "site.css");

        Assert.Contains("app-markdown-preview", view, StringComparison.Ordinal);
        Assert.Contains(".app-markdown-preview", css, StringComparison.Ordinal);
    }

    [Fact]
    public void UserExceptions_UsesDesignSystemTable()
    {
        var view = ReadRepoFile("src", "ConShield.Web", "Views", "UserExceptions", "Index.cshtml");

        Assert.Contains("app-page-header", view, StringComparison.Ordinal);
        Assert.Contains("app-table-card", view, StringComparison.Ordinal);
        Assert.Contains("app-table-scroll", view, StringComparison.Ordinal);
        Assert.Contains("app-action-group", view, StringComparison.Ordinal);
        Assert.Contains("app-table-actions-col", view, StringComparison.Ordinal);
    }

    [Fact]
    public void OutboxShowsSecurityEventIdBeforeMessageId()
    {
        var view = ReadRepoFile("src", "ConShield.Web", "Views", "Outbox", "Index.cshtml");

        Assert.True(
            view.IndexOf("<th>ID события</th>", StringComparison.Ordinal) <
            view.IndexOf("<th>ID сообщения</th>", StringComparison.Ordinal));
        Assert.True(
            view.IndexOf("@item.SecurityEventId", StringComparison.Ordinal) <
            view.IndexOf("@item.MessageId", StringComparison.Ordinal));
    }

    [Fact]
    public void HeavyListPagesUseSharedPagination()
    {
        var combinedViews = string.Join(
            Environment.NewLine,
            ReadRepoFile("src", "ConShield.Web", "Views", "SecurityEvents", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Incidents", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "Siem", "Index.cshtml"),
            ReadRepoFile("src", "ConShield.Web", "Views", "UserExceptions", "Index.cshtml"));
        var partial = ReadRepoFile("src", "ConShield.Web", "Views", "Shared", "_Pagination.cshtml");

        Assert.Equal(4, CountOccurrences(combinedViews, "partial name=\"_Pagination\""));
        Assert.Contains("Context.Request.Query", partial, StringComparison.Ordinal);
        Assert.Contains("pageSize", partial, StringComparison.Ordinal);
        Assert.Contains("QueryHelpers.AddQueryString", partial, StringComparison.Ordinal);
    }

    [Fact]
    public void PagingViewModel_NormalizesInvalidInputs()
    {
        var (page, pageSize) = ConShield.Web.ViewModels.PagingViewModel.Normalize(-3, 500);

        Assert.Equal(1, page);
        Assert.Equal(ConShield.Web.ViewModels.PagingViewModel.MaxPageSize, pageSize);
        Assert.Equal(2, ConShield.Web.ViewModels.PagingViewModel.ClampPage(10, 25, 40));
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

    private static int CountOccurrences(string text, string value)
    {
        var count = 0;
        var startIndex = 0;

        while ((startIndex = text.IndexOf(value, startIndex, StringComparison.Ordinal)) >= 0)
        {
            count++;
            startIndex += value.Length;
        }

        return count;
    }

    private static string GetRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "ConShield.sln")))
            directory = directory.Parent;

        return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root not found.");
    }
}
