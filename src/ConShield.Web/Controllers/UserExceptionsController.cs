using ConShield.Application;
using ConShield.Application.Models;
using ConShield.Web.ViewModels;
using ConShield.Web.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ConShield.Web.Controllers;

[Authorize]
public class UserExceptionsController : Controller
{
    private readonly IUserExceptionService _userExceptionService;

    public UserExceptionsController(IUserExceptionService userExceptionService)
    {
        _userExceptionService = userExceptionService;
    }

    public async Task<IActionResult> Index([FromQuery] int? page = null, [FromQuery] int? pageSize = null)
    {
        var (normalizedPage, normalizedPageSize) = PagingViewModel.Normalize(page, pageSize);
        var totalCount = await _userExceptionService.CountAsync(HttpContext.RequestAborted);
        normalizedPage = PagingViewModel.ClampPage(normalizedPage, normalizedPageSize, totalCount);

        var items = await _userExceptionService.GetPageAsync(
            (normalizedPage - 1) * normalizedPageSize,
            normalizedPageSize,
            HttpContext.RequestAborted);

        return View(new UserExceptionIndexViewModel
        {
            Items = items,
            Paging = new PagingViewModel
            {
                Page = normalizedPage,
                PageSize = normalizedPageSize,
                TotalCount = totalCount
            }
        });
    }

    public async Task<IActionResult> Details(int id)
    {
        var item = await _userExceptionService.GetByIdAsync(id);
        if (item is null)
        {
            return NotFound();
        }

        return View(item);
    }

    [Authorize(Roles = "AdminIB")]
    public IActionResult Create()
    {
        return View(new UserExceptionEditViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = "AdminIB")]
    public async Task<IActionResult> Create(UserExceptionEditViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        await _userExceptionService.CreateAsync(new UserExceptionCreateRequest
        {
            UserLogin = model.UserLogin,
            SourceSystem = model.SourceSystem,
            ExceptionType = model.ExceptionType,
            Description = model.Description,
            IsActive = model.IsActive,
            ExpiresAtUtc = model.ExpiresAtLocal.HasValue
                ? MoscowTimeExtensions.FromMoscowLocal(model.ExpiresAtLocal.Value)
                : null,
            CreatedBy = User.Identity?.Name ?? "unknown"
        });

        return RedirectToAction(nameof(Index));
    }

    [Authorize(Roles = "AdminIB")]
    public async Task<IActionResult> Edit(int id)
    {
        var entity = await _userExceptionService.GetByIdAsync(id);
        if (entity is null)
        {
            return NotFound();
        }

        return View(new UserExceptionEditViewModel
        {
            Id = entity.Id,
            UserLogin = entity.UserLogin,
            SourceSystem = entity.SourceSystem,
            ExceptionType = entity.ExceptionType,
            Description = entity.Description,
            IsActive = entity.IsActive,
            ExpiresAtUtc = entity.ExpiresAtUtc,
            ExpiresAtLocal = entity.ExpiresAtUtc?.ToMoscowLocal()
        });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = "AdminIB")]
    public async Task<IActionResult> Edit(UserExceptionEditViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var result = await _userExceptionService.UpdateAsync(new UserExceptionUpdateRequest
        {
            Id = model.Id,
            UserLogin = model.UserLogin,
            SourceSystem = model.SourceSystem,
            ExceptionType = model.ExceptionType,
            Description = model.Description,
            IsActive = model.IsActive,
            ExpiresAtUtc = model.ExpiresAtLocal.HasValue
                ? MoscowTimeExtensions.FromMoscowLocal(model.ExpiresAtLocal.Value)
                : null,
            ChangedBy = User.Identity?.Name ?? "unknown"
        });

        if (result is null)
        {
            return NotFound();
        }

        return RedirectToAction(nameof(Index));
    }

    [Authorize(Roles = "AdminIB")]
    public async Task<IActionResult> Delete(int id)
    {
        var entity = await _userExceptionService.GetByIdAsync(id);
        if (entity is null)
        {
            return NotFound();
        }

        return View(entity);
    }

    [HttpPost, ActionName("Delete")]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = "AdminIB")]
    public async Task<IActionResult> DeleteConfirmed(int id)
    {
        var deleted = await _userExceptionService.DeleteAsync(id, User.Identity?.Name);
        if (!deleted)
        {
            return NotFound();
        }

        return RedirectToAction(nameof(Index));
    }
}
