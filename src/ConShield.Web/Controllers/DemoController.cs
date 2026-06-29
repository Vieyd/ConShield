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
        new(3, "Validate SIEM rules config", "Validate the committed configurable SIEM rules without external services.", "PowerShell command", null, null, "SIEM rules validation prints Result: PASS."),
        new(4, "Validate container policy config", "Validate policy-as-code Allow/Warn/Block rules without external services.", "PowerShell command", null, null, "Container policy validation prints Result: PASS."),
        new(5, "Validate sensor registry config", "Validate runtime sensor trust registry without external services or real certificates.", "PowerShell command", null, null, "Sensor registry validation prints Result: PASS."),
        new(6, "Simulate sensor trust enforcement", "Validate Unknown and Revoked runtime sensor handling without submitting events.", "PowerShell command", null, null, "Unknown expects SENSOR-001; revoked expects SENSOR-002."),
        new(7, "Run image scan fixture", "Submit a deterministic Trivy fixture through the image scan CLI path.", "PowerShell command", null, null, "Image scan prints Result: PASS and expects IMG-001."),
        new(8, "Validate protected run fixture", "Show scan → policy → launch decision without Docker execution.", "PowerShell command", null, null, "Protected run prints Result: PASS and no container is started."),
        new(9, "Run defense scenario", "Generate the baseline local defense story.", "PowerShell command", null, null, "Scenario prints Result: PASS."),
        new(10, "Replay Falco runtime fixture", "Add a Falco-compatible runtime event without real Fedora/Falco.", "PowerShell command", null, null, "Replay prints Result: PASS."),
        new(11, "Open Security Summary", "Review the executive security summary.", "/Reports/SecuritySummary", "Reports", "SecuritySummary", "Summary cards and status render."),
        new(12, "Open Security Events", "Review source events behind alerts and incidents.", "/SecurityEvents", "SecurityEvents", "Index", "Events list renders safely."),
        new(13, "Open SIEM", "Review correlated alerts, including IMG-001/RTE-001/SENSOR-001/SENSOR-002 when available.", "/Siem", "Siem", "Index", "SIEM alerts render safely."),
        new(14, "Open Incidents / Operator Workflow", "Follow alert-to-incident workflow and close with a conclusion.", "/Incidents", "Incidents", "Index", "Incidents and workflow links render."),
        new(15, "Open Runtime Sensor Health", "Review runtime/Falco source health, trust, and enforcement derived from events and registry.", "/RuntimeSensors", "RuntimeSensors", "Index", "Runtime sensor health renders trust and enforcement status."),
        new(16, "Export defense evidence", "Create the safe Markdown evidence pack in ignored local artifacts.", "PowerShell command", null, null, "Evidence export prints Result: PASS."),
        new(17, "Run demo readiness check", "Verify the full local demo path before defense.", "PowerShell command", null, null, "Readiness check prints Result: PASS.")
    ];

    private static IReadOnlyList<DemoWalkthroughCommandViewModel> BuildCommands() =>
    [
        new("Start local stack", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\Start-ConShield.ps1 -StartApps -OpenRabbit", "Docker services, Web, EventConsumer, and RabbitMQ UI are available."),
        new("Reset local demo data preview", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Reset-ConShieldLocalDemoData.ps1 -WhatIf", "Dry-run prints counts and Result: DRY-RUN."),
        new("Reset local demo data", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Reset-ConShieldLocalDemoData.ps1 -ConfirmReset", "Confirmed reset prints Result: PASS."),
        new("Validate SIEM rules config", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Test-ConShieldSiemRules.ps1", "Offline validation checks config/siem-rules.default.json and prints Result: PASS."),
        new("Validate container policy config", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Test-ConShieldContainerPolicy.ps1", "Offline validation checks config/container-policy.default.json and prints Result: PASS."),
        new("Validate sensor registry config", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Test-ConShieldSensorRegistry.ps1", "Offline validation checks config/sensor-registry.default.json and prints Result: PASS."),
        new("Simulate unknown sensor enforcement", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Replay-ConShieldFalcoRuntimeEvent.ps1 `\n  -SimulateUnknownSensor `\n  -NoSubmit", "Deterministic replay prints Sensor trust: Unknown, Enforcement: AcceptUnknownWithAlert, and Expected rule: SENSOR-001."),
        new("Simulate revoked sensor enforcement", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Replay-ConShieldFalcoRuntimeEvent.ps1 `\n  -SimulateRevokedSensor `\n  -NoSubmit", "Deterministic replay prints Sensor trust: Revoked, Enforcement: FlagRevokedWithAlert, and Expected rule: SENSOR-002."),
        new("Run image scan fixture", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Invoke-ConShieldImageScan.ps1 `\n  -FromTrivyJson .\\tests\\TestData\\Trivy\\sample-image-scan.json", "Deterministic Trivy fixture submits an IMG security event; real Fedora/Falco and live Trivy DB are not required."),
        new("Validate protected run fixture", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Invoke-ConShieldProtectedRun.ps1 `\n  -Image demo/insecure-api:latest `\n  -ContainerName conshield-demo-insecure `\n  -FromTrivyJson .\\tests\\TestData\\Trivy\\sample-image-scan.json `\n  -NoRun", "Deterministic protected run submits IMG/POL/LIFE events without Docker execution."),
        new("Run defense scenario", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Run-ConShieldDefenseScenario.ps1", "Scenario prints Result: PASS."),
        new("Replay Falco runtime fixture", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Replay-ConShieldFalcoRuntimeEvent.ps1", "Replay prints Result: PASS; real Fedora/Falco is not required."),
        new("Export defense evidence", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Export-ConShieldDefenseEvidence.ps1 `\n  -OutputMarkdownPath .\\artifacts\\local\\defense-evidence.md", "Evidence export prints Result: PASS and writes to ignored local artifacts."),
        new("Run demo readiness check", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Test-ConShieldDemoReadiness.ps1", "Readiness check prints step-level status and Result: PASS.")
    ];
}
