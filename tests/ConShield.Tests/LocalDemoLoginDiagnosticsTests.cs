using System.Text.Json;
using System.Text;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using ConShield.Web.Controllers;
using ConShield.Web.Options;
using ConShield.Web.ViewModels;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ConShield.Tests;

public class LocalDemoLoginDiagnosticsTests
{
    [Fact]
    public void DemoUserDiagnostics_ReturnsSafeSummaryInDevelopment()
    {
        var controller = CreateController(
            "Development",
            [
                new DemoUserOptions
                {
                    UserName = "adminib",
                    Password = "configured-password-that-must-not-render",
                    DisplayName = "Администратор ИБ",
                    Role = "AdminIB"
                }
            ]);

        var result = Assert.IsType<JsonResult>(controller.DemoUserDiagnostics());
        var model = Assert.IsType<DemoUserDiagnosticsViewModel>(result.Value);

        Assert.Equal("Development", model.Environment);
        Assert.Equal(1, model.ConfiguredDemoUserCount);
        var user = Assert.Single(model.Users);
        Assert.Equal("adminib", user.UserName);
        Assert.Equal("Администратор ИБ", user.DisplayName);
        Assert.Equal("AdminIB", user.Role);
        Assert.True(user.HasPassword);
        Assert.Empty(model.Warnings);
    }

    [Fact]
    public void DemoUserDiagnostics_NotAvailableOutsideDevelopment()
    {
        var controller = CreateController(
            "Production",
            [
                new DemoUserOptions
                {
                    UserName = "adminib",
                    Password = "configured-password-that-must-not-render",
                    DisplayName = "Администратор ИБ",
                    Role = "AdminIB"
                }
            ]);

        Assert.IsType<NotFoundResult>(controller.DemoUserDiagnostics());
    }

    [Fact]
    public void DemoUserDiagnostics_DoesNotExposeSecrets()
    {
        const string configuredPassword = "configured-password-that-must-not-render";
        var controller = CreateController(
            "Development",
            [
                new DemoUserOptions
                {
                    UserName = "adminib",
                    Password = configuredPassword,
                    DisplayName = "Администратор ИБ",
                    Role = "AdminIB"
                }
            ]);

        var result = Assert.IsType<JsonResult>(controller.DemoUserDiagnostics());
        var serialized = JsonSerializer.Serialize(result.Value);

        Assert.DoesNotContain(configuredPassword, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("Password=", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ConnectionString", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Cookie", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Token", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("VerifierSha256", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("HasPassword", serialized, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DemoUserPasswordVerify_ReturnsSafeMatchInDevelopment()
    {
        const string configuredPassword = "configured-password-that-must-not-render";
        var controller = CreateController(
            "Development",
            [
                new DemoUserOptions
                {
                    UserName = "adminib",
                    Password = configuredPassword,
                    DisplayName = "Администратор ИБ",
                    Role = "AdminIB"
                }
            ]);
        SetJsonRequest(controller, new { userName = "adminib", password = configuredPassword });

        var result = Assert.IsType<JsonResult>(await controller.VerifyDemoUserPassword());
        var model = Assert.IsType<DemoUserPasswordVerifyViewModel>(result.Value);
        var serialized = JsonSerializer.Serialize(result.Value);

        Assert.Equal("Development", model.Environment);
        Assert.Equal("adminib", model.UserName);
        Assert.True(model.UserFound);
        Assert.True(model.HasConfiguredPassword);
        Assert.True(model.PasswordMatches);
        Assert.Equal("AdminIB", model.Role);
        Assert.DoesNotContain(configuredPassword, serialized, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DemoUserPasswordVerify_ReturnsMismatchWithoutLeakingPassword()
    {
        const string configuredPassword = "configured-password-that-must-not-render";
        const string submittedPassword = "submitted-password-that-must-not-render";
        var controller = CreateController(
            "Development",
            [
                new DemoUserOptions
                {
                    UserName = "adminib",
                    Password = configuredPassword,
                    DisplayName = "Администратор ИБ",
                    Role = "AdminIB"
                }
            ]);
        SetJsonRequest(controller, new { userName = "adminib", password = submittedPassword });

        var result = Assert.IsType<JsonResult>(await controller.VerifyDemoUserPassword());
        var model = Assert.IsType<DemoUserPasswordVerifyViewModel>(result.Value);
        var serialized = JsonSerializer.Serialize(result.Value);

        Assert.True(model.UserFound);
        Assert.True(model.HasConfiguredPassword);
        Assert.False(model.PasswordMatches);
        Assert.DoesNotContain(configuredPassword, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain(submittedPassword, serialized, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DemoUserPasswordVerify_AcceptsFormPayload()
    {
        const string configuredPassword = "configured-password-that-must-not-render";
        var controller = CreateController(
            "Development",
            [
                new DemoUserOptions
                {
                    UserName = "adminib",
                    Password = configuredPassword,
                    DisplayName = "Администратор ИБ",
                    Role = "AdminIB"
                }
            ]);
        controller.Request.ContentType = "application/x-www-form-urlencoded";
        controller.Request.Form = new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            ["userName"] = "adminib",
            ["password"] = configuredPassword
        });

        var result = Assert.IsType<JsonResult>(await controller.VerifyDemoUserPassword());
        var model = Assert.IsType<DemoUserPasswordVerifyViewModel>(result.Value);

        Assert.True(model.UserFound);
        Assert.True(model.HasConfiguredPassword);
        Assert.True(model.PasswordMatches);
    }

    [Fact]
    public async Task DemoUserPasswordVerify_NotAvailableOutsideDevelopment()
    {
        var controller = CreateController(
            "Production",
            [
                new DemoUserOptions
                {
                    UserName = "adminib",
                    Password = "configured-password-that-must-not-render",
                    DisplayName = "Администратор ИБ",
                    Role = "AdminIB"
                }
            ]);
        SetJsonRequest(controller, new { userName = "adminib", password = "submitted-password-that-must-not-render" });

        Assert.IsType<NotFoundResult>(await controller.VerifyDemoUserPassword());
    }

    [Fact]
    public async Task DemoUserPasswordVerify_DoesNotExposeSecrets()
    {
        const string configuredPassword = "configured-password-that-must-not-render";
        const string submittedPassword = "submitted-password-that-must-not-render";
        var controller = CreateController(
            "Development",
            [
                new DemoUserOptions
                {
                    UserName = "adminib",
                    Password = configuredPassword,
                    DisplayName = "Администратор ИБ",
                    Role = "AdminIB"
                }
            ]);
        SetJsonRequest(controller, new { userName = "adminib", password = submittedPassword });

        var result = Assert.IsType<JsonResult>(await controller.VerifyDemoUserPassword());
        var serialized = JsonSerializer.Serialize(result.Value);

        Assert.DoesNotContain(configuredPassword, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain(submittedPassword, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("passwordLength", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("hash", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("cookie", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("token", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connection string", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("api key", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("VerifierSha256", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Password values are intentionally not returned or logged", serialized, StringComparison.Ordinal);
    }

    [Fact]
    public void LocalDemoLoginScript_UsesSafeLocationHeaderAccess()
    {
        var script = ReadRepoFile("scripts", "Test-LocalDemoLogin.ps1");

        Assert.Contains("function Get-SafeHeaderValue", script, StringComparison.Ordinal);
        Assert.Contains("Get-SafeHeaderValue -Headers $loginPost.Headers -Name 'Location'", script, StringComparison.Ordinal);
        Assert.Contains("Get-SafeHeaderValue -Headers $authenticatedProbe.Headers -Name 'Location'", script, StringComparison.Ordinal);
        Assert.DoesNotContain(".Headers.Location", script, StringComparison.Ordinal);
        Assert.DoesNotContain(".Location", script, StringComparison.Ordinal);
    }

    [Fact]
    public void LocalDemoLoginScript_DoesNotUseHeaderContains()
    {
        var script = ReadRepoFile("scripts", "Test-LocalDemoLogin.ps1");

        Assert.DoesNotContain(".Contains($Name)", script, StringComparison.Ordinal);
        Assert.DoesNotContain(".ContainsKey($Name)", script, StringComparison.Ordinal);
        Assert.DoesNotContain(".Headers.Location", script, StringComparison.Ordinal);
        Assert.DoesNotContain(".Location", script, StringComparison.Ordinal);
    }

    [Fact]
    public void LocalDemoLoginScript_HeaderHelperIteratesKeys()
    {
        var script = ReadRepoFile("scripts", "Test-LocalDemoLogin.ps1");

        Assert.Contains("$Headers.Keys", script, StringComparison.Ordinal);
        Assert.Contains("[string]::Equals", script, StringComparison.Ordinal);
        Assert.Contains("OrdinalIgnoreCase", script, StringComparison.Ordinal);
        Assert.Contains("return $null", script, StringComparison.Ordinal);
    }

    [Fact]
    public void LocalDemoLoginScript_ContinuesWhenLocationHeaderMissing()
    {
        var script = ReadRepoFile("scripts", "Test-LocalDemoLogin.ps1");

        Assert.Contains("if ($null -eq $Headers)", script, StringComparison.Ordinal);
        Assert.Contains("return $null", script, StringComparison.Ordinal);
        Assert.Contains("catch", script, StringComparison.Ordinal);
        Assert.Contains("$successByProbe = $probeStatus -eq 200", script, StringComparison.Ordinal);
        Assert.Contains("$failedByProbeRedirect", script, StringComparison.Ordinal);
    }

    [Fact]
    public void LocalDemoLoginScript_NoRedirectRequestsDoNotThrowOnRedirectStatus()
    {
        var script = ReadRepoFile("scripts", "Test-LocalDemoLogin.ps1");

        Assert.Contains("function Invoke-WebRequestNoRedirect", script, StringComparison.Ordinal);
        Assert.Contains("MaximumRedirection", script, StringComparison.Ordinal);
        Assert.Contains("ErrorAction", script, StringComparison.Ordinal);
        Assert.Contains("'SilentlyContinue'", script, StringComparison.Ordinal);
        Assert.Contains("Invoke-WebRequestNoRedirect", script, StringComparison.Ordinal);
    }

    [Fact]
    public void LocalDemoLoginScript_DoesNotPrintPasswordCookiesTokensOrBodies()
    {
        var script = ReadRepoFile("scripts", "Test-LocalDemoLogin.ps1");

        Assert.Contains("Read-Host -Prompt 'Password' -AsSecureString", script, StringComparison.Ordinal);
        Assert.Contains("cookies, antiforgery tokens", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Host $Password", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $Password", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Host $plainPassword", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $plainPassword", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Host $token", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $token", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Host $session", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $session", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Host $body", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $body", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Host $content", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $content", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Password=", script, StringComparison.Ordinal);
        Assert.DoesNotContain("ConnectionStrings", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TestLocalDemoUserPasswordScript_DoesNotPrintPasswordOrBody()
    {
        var script = ReadRepoFile("scripts", "Test-LocalDemoUserPassword.ps1");

        Assert.Contains("Read-Host -Prompt 'Password' -AsSecureString", script, StringComparison.Ordinal);
        Assert.Contains("password_match={0}", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Write-Host $Password", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $Password", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Host $plainPassword", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $plainPassword", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Host $body", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $body", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Host $verify", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $verify", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("cookie", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("antiforgery", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TestLocalDemoLoginScript_PrintsPasswordMatchButNotPassword()
    {
        var script = ReadRepoFile("scripts", "Test-LocalDemoLogin.ps1");

        Assert.Contains("password_match={0}", script, StringComparison.Ordinal);
        Assert.Contains("SkipPasswordVerify", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Write-Host $Password", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $Password", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Host $plainPassword", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $plainPassword", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Host $body", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $body", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Host $token", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $token", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Host $session", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Write-Output $session", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LocalDemoLoginScript_PrintsSafeStatusAndResult()
    {
        var script = ReadRepoFile("scripts", "Test-LocalDemoLogin.ps1");

        Assert.Contains("login_get_status={0}", script, StringComparison.Ordinal);
        Assert.Contains("login_post_status={0}", script, StringComparison.Ordinal);
        Assert.Contains("authenticated_probe_status={0}", script, StringComparison.Ordinal);
        Assert.Contains("login_result=success", script, StringComparison.Ordinal);
        Assert.Contains("login_result=failed", script, StringComparison.Ordinal);
        Assert.Contains("login_result=unknown", script, StringComparison.Ordinal);
    }

    [Fact]
    public void LocalLoginTroubleshootingDocs_ExplainDemoUsersConfig()
    {
        var combinedDocs = string.Join(
            Environment.NewLine,
            ReadRepoFile("README.md"),
            ReadRepoFile("docs", "DEMO_EVIDENCE_PACK.md"),
            ReadRepoFile("docs", "CONSHIELD_FINAL_HANDOFF_SNAPSHOT.md"),
            ReadRepoFile("docs", "OPERATIONS_AND_SIEM_RUNBOOK.md"));

        Assert.Contains("DemoUsers", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("/Account/DemoUserDiagnostics", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("/Account/DemoUserDiagnostics/VerifyPassword", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("password_match=False", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("password_match=True", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("scripts/Test-LocalDemoLogin.ps1", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("scripts/Test-LocalDemoUserPassword.ps1", combinedDocs, StringComparison.Ordinal);
        Assert.Contains("restart", combinedDocs, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("do not paste passwords", combinedDocs, StringComparison.OrdinalIgnoreCase);
    }

    private static AccountController CreateController(
        string environmentName,
        List<DemoUserOptions> users) =>
        new(
            Options.Create(users),
            new NoOpSecurityEventWriter(),
            new TestWebHostEnvironment { EnvironmentName = environmentName },
            NullLogger<AccountController>.Instance)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };

    private static void SetJsonRequest(AccountController controller, object body)
    {
        var json = JsonSerializer.Serialize(body);
        controller.Request.ContentType = "application/json";
        controller.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(json));
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

    private sealed class NoOpSecurityEventWriter : ISecurityEventWriter
    {
        public Task WriteAsync(SecurityEventWriteRequest request, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class TestWebHostEnvironment : IWebHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "ConShield.Tests";
        public string WebRootPath { get; set; } = string.Empty;
        public IFileProvider WebRootFileProvider { get; set; } = new NullFileProvider();
        public string ContentRootPath { get; set; } = string.Empty;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
