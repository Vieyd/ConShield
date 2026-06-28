using ConShield.Application;
using ConShield.Application.Models;
using ConShield.Data;
using ConShield.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Web.Controllers;

[Authorize]
public sealed class DemoController : Controller
{
    private readonly ApplicationDbContext _dbContext;
    private readonly IRuntimeSensorHealthService _runtimeSensorHealthService;

    public DemoController(
        ApplicationDbContext dbContext,
        IRuntimeSensorHealthService runtimeSensorHealthService)
    {
        _dbContext = dbContext;
        _runtimeSensorHealthService = runtimeSensorHealthService;
    }

    public async Task<IActionResult> Index(CancellationToken cancellationToken)
    {
        var runtimeHealth = await _runtimeSensorHealthService.GetAsync(
            RuntimeSensorHealthOptions.Default(),
            cancellationToken);

        var model = new DemoWalkthroughViewModel
        {
            SecurityEventsCount = await _dbContext.SecurityEvents.CountAsync(cancellationToken),
            SiemAlertsCount = await _dbContext.SiemAlerts.CountAsync(cancellationToken),
            IncidentsCount = await _dbContext.Incidents.CountAsync(cancellationToken),
            RuntimeSensorSourcesCount = runtimeHealth.Summary.RuntimeSourcesCount,
            LatestRuntimeSensorLastSeenUtc = runtimeHealth.Summary.LatestRuntimeEventUtc,
            Steps = BuildSteps(),
            Commands = BuildCommands()
        };

        return View(model);
    }

    private static IReadOnlyList<DemoWalkthroughStepViewModel> BuildSteps() =>
    [
        new(1, "Start local stack", "Start Docker services, Web, EventConsumer, and RabbitMQ UI.", "PowerShell command", null, null, "Local stack is reachable."),
        new(2, "Reset local demo data", "Preview and confirm a clean local demo dataset.", "PowerShell command", null, null, "Operational demo data is reset safely."),
        new(3, "Run defense scenario", "Generate the baseline local defense story.", "PowerShell command", null, null, "Scenario prints Result: PASS."),
        new(4, "Replay Falco runtime fixture", "Add a Falco-compatible runtime event without real Fedora/Falco.", "PowerShell command", null, null, "Replay prints Result: PASS."),
        new(5, "Open Security Summary", "Review the executive security summary.", "/Reports/SecuritySummary", "Reports", "SecuritySummary", "Summary cards and status render."),
        new(6, "Open Security Events", "Review source events behind alerts and incidents.", "/SecurityEvents", "SecurityEvents", "Index", "Events list renders safely."),
        new(7, "Open SIEM", "Review correlated alerts and RTE-001.", "/Siem", "Siem", "Index", "SIEM alerts render safely."),
        new(8, "Open Incidents / Operator Workflow", "Follow alert-to-incident workflow and close with a conclusion.", "/Incidents", "Incidents", "Index", "Incidents and workflow links render."),
        new(9, "Open Runtime Sensor Health", "Review runtime/Falco source health derived from events.", "/RuntimeSensors", "RuntimeSensors", "Index", "Runtime sensor health renders."),
        new(10, "Export defense evidence", "Create the safe Markdown evidence pack in ignored local artifacts.", "PowerShell command", null, null, "Evidence export prints Result: PASS."),
        new(11, "Run demo readiness check", "Verify the full local demo path before defense.", "PowerShell command", null, null, "Readiness check prints Result: PASS.")
    ];

    private static IReadOnlyList<DemoWalkthroughCommandViewModel> BuildCommands() =>
    [
        new("Start local stack", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\Start-ConShield.ps1 -StartApps -OpenRabbit", "Docker services, Web, EventConsumer, and RabbitMQ UI are available."),
        new("Reset local demo data preview", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Reset-ConShieldLocalDemoData.ps1 -WhatIf", "Dry-run prints counts and Result: DRY-RUN."),
        new("Reset local demo data", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Reset-ConShieldLocalDemoData.ps1 -ConfirmReset", "Confirmed reset prints Result: PASS."),
        new("Run defense scenario", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Run-ConShieldDefenseScenario.ps1", "Scenario prints Result: PASS."),
        new("Replay Falco runtime fixture", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Replay-ConShieldFalcoRuntimeEvent.ps1", "Replay prints Result: PASS; real Fedora/Falco is not required."),
        new("Export defense evidence", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Export-ConShieldDefenseEvidence.ps1 `\n  -OutputMarkdownPath .\\artifacts\\local\\defense-evidence.md", "Evidence export prints Result: PASS and writes to ignored local artifacts."),
        new("Run demo readiness check", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Test-ConShieldDemoReadiness.ps1", "Readiness check prints step-level status and Result: PASS.")
    ];
}
