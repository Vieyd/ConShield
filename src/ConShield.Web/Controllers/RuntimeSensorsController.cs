using ConShield.Application;
using ConShield.Application.Models;
using ConShield.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ConShield.Web.Controllers;

[Authorize]
public sealed class RuntimeSensorsController : Controller
{
    private readonly IRuntimeSensorHealthService _runtimeSensorHealthService;

    public RuntimeSensorsController(IRuntimeSensorHealthService runtimeSensorHealthService)
    {
        _runtimeSensorHealthService = runtimeSensorHealthService;
    }

    public async Task<IActionResult> Index(CancellationToken cancellationToken)
    {
        var health = await _runtimeSensorHealthService.GetAsync(
            RuntimeSensorHealthOptions.Default(),
            cancellationToken);

        return View(new RuntimeSensorHealthViewModel
        {
            Summary = health.Summary,
            Sources = health.Sources,
            ActiveWindowLabel = "24h"
        });
    }
}
