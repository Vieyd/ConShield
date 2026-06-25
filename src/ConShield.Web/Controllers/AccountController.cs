using System.Security.Claims;
using System.Text.Json;
using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using ConShield.Web.Options;
using ConShield.Web.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace ConShield.Web.Controllers;

public class AccountController : Controller
{
    private readonly List<DemoUserOptions> _users;
    private readonly ISecurityEventWriter _eventWriter;
    private readonly IWebHostEnvironment _environment;
    private readonly ILogger<AccountController> _logger;

    public AccountController(
        IOptions<List<DemoUserOptions>> usersOptions,
        ISecurityEventWriter eventWriter,
        IWebHostEnvironment environment,
        ILogger<AccountController> logger)
    {
        _users = usersOptions.Value;
        _eventWriter = eventWriter;
        _environment = environment;
        _logger = logger;
    }

    [HttpGet]
    public IActionResult Login(string? returnUrl = null)
    {
        ViewBag.ReturnUrl = returnUrl;
        return View(new LoginViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
    {
        ViewBag.ReturnUrl = returnUrl;

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = _users.FirstOrDefault(x =>
            string.Equals(x.UserName, model.UserName, StringComparison.OrdinalIgnoreCase) &&
            x.Password == model.Password);

        var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString();

        if (user is null)
        {
            _logger.LogWarning(
                "Demo login failed with reason {Reason} for user {UserName}.",
                LoginFailureReason(model.UserName),
                model.UserName);

            await _eventWriter.WriteAsync(new SecurityEventWriteRequest
            {
                EventType = SecurityEventType.LoginFailure,
                Severity = EventSeverity.Warning,
                UserName = model.UserName,
                SourceIp = sourceIp,
                Description = "Неуспешная попытка входа в систему."
            });

            ModelState.AddModelError(string.Empty, "Неверный логин или пароль");
            return View(model);
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, user.UserName),
            new(ClaimTypes.GivenName, user.DisplayName),
            new(ClaimTypes.Role, user.Role)
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties
            {
                IsPersistent = model.RememberMe
            });

        await _eventWriter.WriteAsync(new SecurityEventWriteRequest
        {
            EventType = SecurityEventType.LoginSuccess,
            Severity = EventSeverity.Info,
            UserName = user.UserName,
            SourceIp = sourceIp,
            Description = "Успешная авторизация пользователя."
        });

        if (!string.IsNullOrWhiteSpace(returnUrl) && Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }

        return RedirectToAction("Index", "Home");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString();

        await _eventWriter.WriteAsync(new SecurityEventWriteRequest
        {
            EventType = SecurityEventType.LoginSuccess,
            Severity = EventSeverity.Info,
            UserName = User.Identity?.Name,
            SourceIp = sourceIp,
            Description = "Выход пользователя из системы."
        });

        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction(nameof(Login));
    }

    public IActionResult AccessDenied()
    {
        return View();
    }

    [HttpGet]
    public IActionResult DemoUserDiagnostics()
    {
        if (!_environment.IsDevelopment())
            return NotFound();

        var warnings = new List<string>();
        if (_users.Count == 0)
            warnings.Add("no demo users configured");

        warnings.AddRange(_users
            .Where(x => string.IsNullOrWhiteSpace(x.Role))
            .Select(x => $"missing role for user {SafeUserName(x.UserName)}"));

        warnings.AddRange(_users
            .Where(x => string.IsNullOrWhiteSpace(x.Password))
            .Select(x => $"missing password for user {SafeUserName(x.UserName)}"));

        warnings.AddRange(_users
            .Where(x => !string.IsNullOrWhiteSpace(x.UserName))
            .GroupBy(x => x.UserName.Trim(), StringComparer.OrdinalIgnoreCase)
            .Where(x => x.Count() > 1)
            .Select(x => $"duplicate user name {SafeUserName(x.Key)}"));

        var result = new DemoUserDiagnosticsViewModel
        {
            Environment = _environment.EnvironmentName,
            ConfiguredDemoUserCount = _users.Count,
            Users = _users
                .Select(x => new DemoUserDiagnosticsUserViewModel
                {
                    UserName = SafeUserName(x.UserName),
                    DisplayName = x.DisplayName,
                    Role = x.Role,
                    HasPassword = !string.IsNullOrWhiteSpace(x.Password)
                })
                .ToList(),
            Warnings = warnings
        };

        return Json(result);
    }

    [HttpPost("/Account/DemoUserDiagnostics/VerifyPassword")]
    public async Task<IActionResult> VerifyDemoUserPassword()
    {
        if (!_environment.IsDevelopment())
            return NotFound();

        var request = await ReadDemoUserPasswordVerifyRequestAsync();
        var requestedUserName = SafeUserName(request.UserName);
        var configuredUser = _users.FirstOrDefault(x =>
            string.Equals(x.UserName, request.UserName, StringComparison.OrdinalIgnoreCase));
        var hasConfiguredPassword = !string.IsNullOrWhiteSpace(configuredUser?.Password);
        var passwordMatches = configuredUser is not null &&
            hasConfiguredPassword &&
            configuredUser.Password == request.Password;

        return Json(new DemoUserPasswordVerifyViewModel
        {
            Environment = _environment.EnvironmentName,
            UserName = requestedUserName,
            UserFound = configuredUser is not null,
            HasConfiguredPassword = hasConfiguredPassword,
            PasswordMatches = passwordMatches,
            Role = configuredUser?.Role
        });
    }

    private string LoginFailureReason(string userName)
    {
        if (_users.Count == 0)
            return "no_demo_users_configured";

        var configuredUser = _users.FirstOrDefault(x =>
            string.Equals(x.UserName, userName, StringComparison.OrdinalIgnoreCase));

        return configuredUser is null
            ? "username_not_found"
            : "password_mismatch";
    }

    private static string SafeUserName(string? userName) =>
        string.IsNullOrWhiteSpace(userName)
            ? "missing-user-name"
            : userName.Trim();

    private async Task<DemoUserPasswordVerifyRequestViewModel> ReadDemoUserPasswordVerifyRequestAsync()
    {
        if (Request.HasFormContentType)
        {
            var form = await Request.ReadFormAsync();
            return new DemoUserPasswordVerifyRequestViewModel
            {
                UserName = form["userName"].ToString(),
                Password = form["password"].ToString()
            };
        }

        if (Request.ContentType?.Contains("application/json", StringComparison.OrdinalIgnoreCase) == true)
        {
            var request = await JsonSerializer.DeserializeAsync<DemoUserPasswordVerifyRequestViewModel>(
                Request.Body,
                new JsonSerializerOptions(JsonSerializerDefaults.Web));

            return request ?? new DemoUserPasswordVerifyRequestViewModel();
        }

        return new DemoUserPasswordVerifyRequestViewModel();
    }
}
