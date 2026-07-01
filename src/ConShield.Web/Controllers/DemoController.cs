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
        new(7, "Simulate signed sensor events", "Validate valid, missing, invalid, and stale signed runtime sensor metadata without real signing keys.", "PowerShell command", null, null, "Valid expects RTE-001; missing/invalid/stale expect SIGN rules."),
        new(8, "Run image scan fixture", "Submit a deterministic Trivy fixture through the image scan CLI path.", "PowerShell command", null, null, "Image scan prints Result: PASS and expects IMG-001."),
        new(9, "Validate protected run fixture", "Show scan → policy → launch decision without Docker execution.", "PowerShell command", null, null, "Protected run prints Result: PASS and no container is started."),
        new(10, "Run CI/CD container gate fixture", "Evaluate image scan fixture through container policy-as-code with deterministic CI exit-code behavior.", "PowerShell command", null, null, "Gate prints PASS_WITH_FINDINGS with --fail-on never."),
        new(11, "Replay Docker lifecycle fixture", "Map deterministic Docker-compatible lifecycle events into sanitized ConShield LIFE events without live Docker.", "PowerShell command", null, null, "Lifecycle replay prints Result: PASS."),
        new(12, "Run defense scenario", "Generate the baseline local defense story.", "PowerShell command", null, null, "Scenario prints Result: PASS."),
        new(13, "Replay Falco runtime fixture", "Add a Falco-compatible runtime event without real Fedora/Falco.", "PowerShell command", null, null, "Replay prints Result: PASS."),
        new(14, "Open Security Summary", "Review the executive security summary.", "/Reports/SecuritySummary", "Reports", "SecuritySummary", "Summary cards and status render."),
        new(15, "Open Security Events", "Review source events behind alerts and incidents.", "/SecurityEvents", "SecurityEvents", "Index", "Events list renders safely."),
        new(16, "Open SIEM", "Review correlated alerts, including IMG-001/RTE-001/SENSOR-001/SENSOR-002/SIGN-001/SIGN-002/SIGN-003 when available.", "/Siem", "Siem", "Index", "SIEM alerts render safely."),
        new(17, "Open Incidents / Operator Workflow", "Follow alert-to-incident workflow and close with a conclusion.", "/Incidents", "Incidents", "Index", "Incidents and workflow links render."),
        new(18, "Open Runtime Sensor Health", "Review runtime/Falco source health, trust, enforcement, and signature status derived from events and registry.", "/RuntimeSensors", "RuntimeSensors", "Index", "Runtime sensor health renders trust, enforcement, and signature status."),
        new(19, "Export defense evidence", "Create the safe Markdown evidence pack in ignored local artifacts.", "PowerShell command", null, null, "Evidence export prints Result: PASS."),
        new(20, "Run demo readiness check", "Verify the full local demo path before defense.", "PowerShell command", null, null, "Readiness check prints Result: PASS."),
        new(21, "Create demo release pack", "Publish the CLI and collect safe docs/config/scripts into a local ignored release bundle.", "PowerShell command", null, null, "Release pack prints Result: PASS and writes under artifacts/local."),
        new(22, "Review product positioning docs", "Use the positioning, competitive analysis, and diploma narrative docs to explain why ConShield is an integrated local control plane, not a scanner-only wrapper.", "Documentation", null, null, "Docs explain scope, limitations, and roadmap conservatively."),
        new(23, "Review threat model and traceability", "Use the threat model, attacker scenarios, security requirements, and traceability matrix to explain what is in scope and how it is verified.", "Documentation", null, null, "Docs map threats to requirements, modules, SIEM rules, evidence, and tests."),
        new(24, "Review architecture and data-flow diagrams", "Use the architecture, Mermaid diagrams, data flow model, deployment view, and sequence flows to explain components and boundaries.", "Documentation", null, null, "Docs show system context, components, trust boundaries, DFD levels, deployment, and sequences.")
    ];

    private static IReadOnlyList<DemoWalkthroughCommandViewModel> BuildCommands() =>
    [
        new("Unified CLI help", "dotnet run --project .\\src\\ConShield.Cli -- --help", "Lists validate, demo, scan, run, sensor, and evidence commands."),
        new("Unified CLI validate", "dotnet run --project .\\src\\ConShield.Cli -- validate", "Runs SIEM rules, container policy, and sensor registry validation in deterministic mode."),
        new("Unified CLI guided demo seed", "dotnet run --project .\\src\\ConShield.Cli -- demo seed", "Creates or reuses deterministic IMG/POL/LIFE/RTE/SENSOR/SIGN demo data through the same safe seed script; the browser does not run it."),
        new("Unified CLI image scan fixture", "dotnet run --project .\\src\\ConShield.Cli -- scan image `\n  --from-trivy-json .\\tests\\TestData\\Trivy\\sample-image-scan.json `\n  --no-submit", "Deterministic image scan fixture validates IMG path without live Trivy DB or Web submit."),
        new("Optional live Trivy image scan", "dotnet run --project .\\src\\ConShield.Cli -- scan image `\n  --image alpine:3.19 `\n  --live-trivy `\n  --no-submit", "Optional live Trivy check. Requires local Trivy installation and image access, is not required for full validation, and Web UI does not execute Trivy."),
        new("Unified CLI CI/CD gate fixture", "dotnet run --project .\\src\\ConShield.Cli -- gate image `\n  --image demo/insecure-api:latest `\n  --from-trivy-json .\\tests\\TestData\\Trivy\\sample-image-scan.json `\n  --fail-on never `\n  --report .\\artifacts\\local\\cicd-gate-report.md `\n  --no-submit", "Evaluates image scan fixture against policy-as-code and writes a sanitized ignored Markdown report."),
        new("Optional live Trivy CI/CD gate", "dotnet run --project .\\src\\ConShield.Cli -- gate image `\n  --image alpine:3.19 `\n  --live-trivy `\n  --fail-on block `\n  --no-submit", "Optional live Trivy gate. Requires local Trivy installation and image access; browser only shows this copy/paste command."),
        new("Unified CLI protected run fixture", "dotnet run --project .\\src\\ConShield.Cli -- run protected `\n  --image demo/insecure-api:latest `\n  --container-name conshield-demo-insecure `\n  --from-trivy-json .\\tests\\TestData\\Trivy\\sample-image-scan.json `\n  --no-run `\n  --no-submit", "Validates scan → policy → launch decision without Docker execution or Web submit."),
        new("Unified CLI Docker lifecycle replay", "dotnet run --project .\\src\\ConShield.Cli -- lifecycle replay `\n  --from-docker-events-json .\\tests\\TestData\\DockerEvents\\container-lifecycle-events.json `\n  --no-submit", "Maps deterministic Docker-compatible lifecycle fixture events without live Docker or Web submit."),
        new("Optional live Docker lifecycle watch", "dotnet run --project .\\src\\ConShield.Cli -- lifecycle watch `\n  --duration-seconds 30 `\n  --no-submit", "Optional manual check when Docker Desktop is running; not required for CI or full validation and not executed by the browser."),
        new("Unified CLI signed sensor replay", "dotnet run --project .\\src\\ConShield.Cli -- sensor replay `\n  --demo-signature `\n  --no-submit", "Validates signed runtime sensor replay without Fedora/Falco or Web submit."),
        new("Unified CLI runtime sensor stream collector", "dotnet run --project .\\src\\ConShield.Cli -- sensor collect `\n  --from-json-lines .\\tests\\TestData\\Falco\\falco-runtime-stream.jsonl `\n  --demo-signature `\n  --no-submit", "Reads a deterministic Falco-compatible JSON-lines stream, skips malformed lines safely, applies trust/signature handling, and does not require real Fedora/Falco."),
        new("Unified CLI evidence export", "dotnet run --project .\\src\\ConShield.Cli -- evidence export `\n  --output .\\artifacts\\local\\defense-evidence-cli.md", "Exports safe evidence to ignored local artifacts when local services are available."),
        new("Unified CLI readiness", "dotnet run --project .\\src\\ConShield.Cli -- demo readiness", "Runs the existing readiness workflow through the unified CLI."),
        new("Create demo release pack", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\New-ConShieldDemoReleasePack.ps1", "Publishes ConShield.Cli and creates a safe local release folder plus zip under ignored artifacts/local."),
        new("Read product positioning docs", "docs\\PRODUCT_POSITIONING.md; docs\\COMPETITIVE_ANALYSIS.md; docs\\DIPLOMA_DEFENSE_NARRATIVE.md", "Use these docs for defense wording, comparison matrix, limitations, and roadmap."),
        new("Read threat model docs", "docs\\THREAT_MODEL.md; docs\\ATTACKER_SCENARIOS.md; docs\\SECURITY_REQUIREMENTS.md; docs\\REQUIREMENTS_TRACEABILITY_MATRIX.md", "Trace threats to scenarios, requirement IDs, modules, CLI/scripts, SIEM rules, evidence, and tests."),
        new("Read architecture docs", "docs\\ARCHITECTURE.md; docs\\ARCHITECTURE_DIAGRAMS.md; docs\\DATA_FLOW_MODEL.md; docs\\DEPLOYMENT_VIEW.md; docs\\SEQUENCE_FLOWS.md", "Use Mermaid diagrams and DFDs to explain system context, components, trust boundaries, deployment, and sequences."),
        new("Start local stack", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\Start-ConShield.ps1 -StartApps -OpenRabbit", "Docker services, Web, EventConsumer, and RabbitMQ UI are available."),
        new("Seed guided demo data", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Seed-ConShieldDemoData.ps1", "Creates or reuses deterministic demo data for dashboard, SIEM, incidents, runtime sensor health, and evidence export without browser-side execution."),
        new("Reset local demo data preview", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Reset-ConShieldLocalDemoData.ps1 -WhatIf", "Dry-run prints counts and Result: DRY-RUN."),
        new("Reset local demo data", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Reset-ConShieldLocalDemoData.ps1 -ConfirmReset", "Confirmed reset prints Result: PASS."),
        new("Validate SIEM rules config", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Test-ConShieldSiemRules.ps1", "Offline validation checks config/siem-rules.default.json and prints Result: PASS."),
        new("Validate container policy config", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Test-ConShieldContainerPolicy.ps1", "Offline validation checks config/container-policy.default.json and prints Result: PASS."),
        new("Validate sensor registry config", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Test-ConShieldSensorRegistry.ps1", "Offline validation checks config/sensor-registry.default.json and prints Result: PASS."),
        new("Simulate unknown sensor enforcement", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Replay-ConShieldFalcoRuntimeEvent.ps1 `\n  -SimulateUnknownSensor `\n  -NoSubmit", "Deterministic replay prints Sensor trust: Unknown, Enforcement: AcceptUnknownWithAlert, and Expected rule: SENSOR-001."),
        new("Simulate revoked sensor enforcement", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Replay-ConShieldFalcoRuntimeEvent.ps1 `\n  -SimulateRevokedSensor `\n  -NoSubmit", "Deterministic replay prints Sensor trust: Revoked, Enforcement: FlagRevokedWithAlert, and Expected rule: SENSOR-002."),
        new("Replay valid signed sensor event", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Replay-ConShieldFalcoRuntimeEvent.ps1 `\n  -DemoSignature `\n  -NoSubmit", "Deterministic replay prints Signature: Valid and Expected rules: RTE-001."),
        new("Replay missing sensor signature", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Replay-ConShieldFalcoRuntimeEvent.ps1 `\n  -SimulateMissingSignature `\n  -NoSubmit", "Deterministic replay prints Signature: Missing and Expected rules: SIGN-001."),
        new("Replay invalid sensor signature", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Replay-ConShieldFalcoRuntimeEvent.ps1 `\n  -SimulateInvalidSignature `\n  -NoSubmit", "Deterministic replay prints Signature: Invalid and Expected rules: SIGN-002."),
        new("Replay stale sensor signature", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Replay-ConShieldFalcoRuntimeEvent.ps1 `\n  -SimulateStaleSignature `\n  -NoSubmit", "Deterministic replay prints Signature: Stale and Expected rules: SIGN-003."),
        new("Run image scan fixture", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Invoke-ConShieldImageScan.ps1 `\n  -FromTrivyJson .\\tests\\TestData\\Trivy\\sample-image-scan.json", "Deterministic Trivy fixture submits an IMG security event; real Fedora/Falco and live Trivy DB are not required."),
        new("Optional live Trivy image scan", "dotnet run --project .\\src\\ConShield.Cli -- scan image `\n  --image alpine:3.19 `\n  --live-trivy `\n  --no-submit", "Manual live scanner smoke when Trivy is installed; full validation uses fixtures instead."),
        new("Validate protected run fixture", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Invoke-ConShieldProtectedRun.ps1 `\n  -Image demo/insecure-api:latest `\n  -ContainerName conshield-demo-insecure `\n  -FromTrivyJson .\\tests\\TestData\\Trivy\\sample-image-scan.json `\n  -NoRun", "Deterministic protected run submits IMG/POL/LIFE events without Docker execution."),
        new("Replay Docker lifecycle fixture", "dotnet run --project .\\src\\ConShield.Cli -- lifecycle replay `\n  --from-docker-events-json .\\tests\\TestData\\DockerEvents\\container-lifecycle-events.json `\n  --no-submit", "Deterministic Docker-compatible fixture maps to sanitized container.lifecycle events without live Docker."),
        new("Optional live Docker lifecycle watch", "dotnet run --project .\\src\\ConShield.Cli -- lifecycle watch `\n  --duration-seconds 30 `\n  --no-submit", "Manual bounded watch for local Docker Desktop container events; CI and full validation use replay instead."),
        new("Collect runtime sensor stream fixture", "dotnet run --project .\\src\\ConShield.Cli -- sensor collect `\n  --from-json-lines .\\tests\\TestData\\Falco\\falco-runtime-stream.jsonl `\n  --demo-signature `\n  --no-submit", "Deterministic stream collector validates RTE/SENSOR/SIGN handling without real Fedora/Falco or browser execution."),
        new("Run defense scenario", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Run-ConShieldDefenseScenario.ps1", "Scenario prints Result: PASS."),
        new("Replay Falco runtime fixture", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Replay-ConShieldFalcoRuntimeEvent.ps1", "Replay prints Result: PASS; real Fedora/Falco is not required."),
        new("Export defense evidence", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Export-ConShieldDefenseEvidence.ps1 `\n  -OutputMarkdownPath .\\artifacts\\local\\defense-evidence.md", "Evidence export prints Result: PASS and writes to ignored local artifacts."),
        new("Run demo readiness check", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Test-ConShieldDemoReadiness.ps1", "Readiness check prints step-level status and Result: PASS.")
    ];
}
