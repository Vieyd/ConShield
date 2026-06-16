using System.Security.Claims;
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

    public AccountController(
        IOptions<List<DemoUserOptions>> usersOptions,
        ISecurityEventWriter eventWriter)
    {
        _users = usersOptions.Value;
        _eventWriter = eventWriter;
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
            x.UserName.Equals(model.UserName, StringComparison.OrdinalIgnoreCase) &&
            x.Password == model.Password);

        var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString();

        if (user is null)
        {
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
}
