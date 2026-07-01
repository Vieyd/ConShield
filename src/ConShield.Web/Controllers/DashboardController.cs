using ConShield.Application;
using ConShield.Application.Models;
using ConShield.Contracts.Constants;
using ConShield.Contracts.Enums;
using ConShield.Data;
using ConShield.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Web.Controllers;

[Authorize]
public sealed class DashboardController : Controller
{
    private readonly ApplicationDbContext _dbContext;
    private readonly IRuntimeSensorHealthService _runtimeSensorHealthService;

    public DashboardController(
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

        var securityEventsCount = await _dbContext.SecurityEvents.CountAsync(cancellationToken);
        var siemAlertsCount = await _dbContext.SiemAlerts.CountAsync(cancellationToken);
        var openIncidentsCount = await _dbContext.Incidents
            .CountAsync(x => x.Status != IncidentStatuses.Closed, cancellationToken);
        var criticalHighFindingsCount = await _dbContext.SecurityEvents
            .CountAsync(
                x => (x.Severity == EventSeverity.Critical || x.Severity == EventSeverity.High)
                    && (x.SourceSystem == "conshield.image-scanner"
                        || x.ExternalEventType == "container.image.scan.completed"),
                cancellationToken);
        var lifecycleEventsCount = await _dbContext.SecurityEvents
            .CountAsync(
                x => x.SourceSystem == SecuritySourceSystems.SensorLifecycle
                    || (x.ExternalEventType != null
                        && (x.ExternalEventType.ToLower().Contains("lifecycle")
                            || x.ExternalEventType.ToLower().Contains("sensor.credential")
                            || x.ExternalEventType.ToLower().Contains("sensor.revoked"))),
                cancellationToken);

        var trustedSensors = runtimeHealth.Sources.Count(x => string.Equals(x.TrustStatus, SensorTrustStatuses.Trusted, StringComparison.OrdinalIgnoreCase));
        var unknownSensors = runtimeHealth.Sources.Count(x => string.Equals(x.TrustStatus, SensorTrustStatuses.Unknown, StringComparison.OrdinalIgnoreCase));
        var revokedOrDisabledSensors = runtimeHealth.Sources.Count(x =>
            string.Equals(x.TrustStatus, SensorTrustStatuses.Revoked, StringComparison.OrdinalIgnoreCase)
            || string.Equals(x.TrustStatus, SensorTrustStatuses.Disabled, StringComparison.OrdinalIgnoreCase));
        var validSignatures = runtimeHealth.Sources.Count(x => x.SignatureStatus is "Valid" or "NotRequired");
        var missingSignatures = runtimeHealth.Sources.Count(x => string.Equals(x.SignatureStatus, "Missing", StringComparison.OrdinalIgnoreCase));
        var invalidOrUnknownKeySignatures = runtimeHealth.Sources.Count(x =>
            string.Equals(x.SignatureStatus, "Invalid", StringComparison.OrdinalIgnoreCase)
            || string.Equals(x.SignatureStatus, "UnknownKey", StringComparison.OrdinalIgnoreCase));
        var staleOrReplaySignatures = runtimeHealth.Sources.Count(x =>
            string.Equals(x.SignatureStatus, "Stale", StringComparison.OrdinalIgnoreCase)
            || string.Equals(x.SignatureStatus, "ReplayDetected", StringComparison.OrdinalIgnoreCase));
        var signatureFailures = missingSignatures + invalidOrUnknownKeySignatures + staleOrReplaySignatures;

        var latestAlerts = await _dbContext.SiemAlerts
            .OrderByDescending(x => x.CreatedAtUtc)
            .ThenByDescending(x => x.Id)
            .Take(5)
            .Select(x => new OperatorDashboardAlertViewModel(
                x.Id,
                x.CreatedAtUtc,
                x.RuleCode,
                x.RuleName,
                x.Severity,
                x.Status,
                x.IncidentId))
            .ToListAsync(cancellationToken);

        var latestIncidents = await _dbContext.Incidents
            .OrderByDescending(x => x.CreatedAtUtc)
            .ThenByDescending(x => x.Id)
            .Take(5)
            .Select(x => new OperatorDashboardIncidentViewModel(
                x.Id,
                x.CreatedAtUtc,
                x.Name,
                x.Severity,
                x.Status,
                x.SourceEventId))
            .ToListAsync(cancellationToken);

        var posture = ResolvePosture(openIncidentsCount, criticalHighFindingsCount, unknownSensors, revokedOrDisabledSensors, signatureFailures, securityEventsCount);
        var configOk = FileExistsInRepo("config", "siem-rules.default.json")
            && FileExistsInRepo("config", "container-policy.default.json")
            && FileExistsInRepo("config", "sensor-registry.default.json");

        var model = new OperatorDashboardViewModel
        {
            PostureStatus = posture.Status,
            PostureSummary = posture.Summary,
            StatusCards =
            [
                new("Security Events", securityEventsCount.ToString(), securityEventsCount > 0 ? "OK" : "NoData", "Normalized security events stored in PostgreSQL.", "SecurityEvents", "Index"),
                new("SIEM Alerts", siemAlertsCount.ToString(), siemAlertsCount > 0 ? "Attention" : "NoData", "Correlated alerts generated from configured SIEM rules.", "Siem", "Index"),
                new("Open Incidents", openIncidentsCount.ToString(), openIncidentsCount > 0 ? "Attention" : "OK", "Incidents that are not closed.", "Incidents", "Index"),
                new("Critical/High Findings", criticalHighFindingsCount.ToString(), criticalHighFindingsCount > 0 ? "Attention" : "OK", "Critical/high image scan findings visible in local data.", "SecurityEvents", "Index", "image"),
                new("Trusted Sensors", trustedSensors.ToString(), trustedSensors > 0 ? "OK" : "NoData", "Runtime sources marked Trusted by the sensor registry.", "RuntimeSensors", "Index"),
                new("Unknown/Revoked Sensors", (unknownSensors + revokedOrDisabledSensors).ToString(), unknownSensors + revokedOrDisabledSensors > 0 ? "Attention" : "OK", "Runtime sources that need trust review.", "RuntimeSensors", "Index"),
                new("Signed Event Failures", signatureFailures.ToString(), signatureFailures > 0 ? "Attention" : "OK", "Missing, invalid, unknown-key, stale, or replay signature states.", "RuntimeSensors", "Index"),
                new("Lifecycle Events", lifecycleEventsCount.ToString(), lifecycleEventsCount > 0 ? "OK" : "NoData", "Docker/sensor lifecycle events represented as safe summaries.", "SecurityEvents", "Index", "lifecycle"),
                new("Evidence Status", securityEventsCount > 0 ? "Ready to export" : "Demo data missing", securityEventsCount > 0 ? "OK" : "NoData", "Evidence export is a local command, not a browser action."),
                new("Configuration Status", configOk ? "Default configs present" : "Not available in local demo data", configOk ? "OK" : "Unavailable", "SIEM rules, container policy, and sensor registry configs are validated by CLI.")
            ],
            LatestAlerts = latestAlerts,
            LatestIncidents = latestIncidents,
            SensorSummary = new OperatorDashboardSensorSummaryViewModel
            {
                TrustedSensors = trustedSensors,
                UnknownSensors = unknownSensors,
                RevokedOrDisabledSensors = revokedOrDisabledSensors,
                ValidSignatures = validSignatures,
                MissingSignatures = missingSignatures,
                InvalidOrUnknownKeySignatures = invalidOrUnknownKeySignatures,
                StaleOrReplaySignatures = staleOrReplaySignatures,
                SignatureFailures = signatureFailures,
                RuntimeSources = runtimeHealth.Summary.RuntimeSourcesCount,
                LatestRuntimeEventUtc = runtimeHealth.Summary.LatestRuntimeEventUtc
            },
            WorkflowTiles = BuildWorkflowTiles(),
            DocumentationLinks = BuildDocumentationLinks()
        };

        return View(model);
    }

    private static (string Status, string Summary) ResolvePosture(
        int openIncidents,
        int criticalHighFindings,
        int unknownSensors,
        int revokedOrDisabledSensors,
        int signatureFailures,
        int securityEvents)
    {
        if (securityEvents == 0)
            return ("Demo data missing", "Run the local defense scenario or replay fixtures before using the dashboard as live evidence.");

        if (openIncidents > 0 || criticalHighFindings > 0 || unknownSensors > 0 || revokedOrDisabledSensors > 0 || signatureFailures > 0)
            return ("Attention needed", "Review open incidents, critical/high findings, sensor trust warnings, and signed event failures.");

        return ("Healthy", "No open incidents or current dashboard warning counters are present in local demo data.");
    }

    private static IReadOnlyList<OperatorDashboardWorkflowTileViewModel> BuildWorkflowTiles() =>
    [
        new("Image Scan", "Map Trivy-compatible scan output into IMG security events.", "dotnet run --project .\\src\\ConShield.Cli -- scan image `\n  --from-trivy-json .\\tests\\TestData\\Trivy\\sample-image-scan.json `\n  --no-submit", "docs/CONTAINER_IMAGE_SCANNING.md", "SecurityEvents", "Index"),
        new("CI/CD Gate", "Evaluate scan findings against policy and return deterministic CI exit behavior.", "dotnet run --project .\\src\\ConShield.Cli -- gate image `\n  --from-trivy-json .\\tests\\TestData\\Trivy\\sample-image-scan.json `\n  --fail-on never `\n  --no-submit", "docs/CICD_CONTAINER_GATE.md"),
        new("Protected Run", "Show scan → policy → launch decision without browser-triggered execution.", "dotnet run --project .\\src\\ConShield.Cli -- run protected `\n  --from-trivy-json .\\tests\\TestData\\Trivy\\sample-image-scan.json `\n  --no-run `\n  --no-submit", "docs/CONTAINER_POLICY.md"),
        new("Docker Lifecycle Collector", "Replay Docker-compatible lifecycle fixture events into LIFE summaries.", "dotnet run --project .\\src\\ConShield.Cli -- lifecycle replay `\n  --from-docker-events-json .\\tests\\TestData\\DockerEvents\\container-lifecycle-events.json `\n  --no-submit", "docs/DOCKER_LIFECYCLE_COLLECTOR.md", "SecurityEvents", "Index"),
        new("Runtime/Falco Replay", "Replay a Falco-compatible runtime event without real Fedora/Falco.", "dotnet run --project .\\src\\ConShield.Cli -- sensor replay `\n  --demo-signature `\n  --no-submit", "docs/FALCO_RUNTIME_SENSOR.md", "RuntimeSensors", "Index"),
        new("Sensor Trust", "Validate sensor registry and simulate unknown/revoked enforcement.", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Test-ConShieldSensorRegistry.ps1", "docs/SENSOR_TRUST_REGISTRY.md", "RuntimeSensors", "Index"),
        new("Signed Sensor Events", "Validate signed runtime sensor event paths without real signing keys.", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Replay-ConShieldFalcoRuntimeEvent.ps1 `\n  -SimulateInvalidSignature `\n  -NoSubmit", "docs/SIGNED_SENSOR_EVENTS.md", "RuntimeSensors", "Index"),
        new("SIEM Rules", "Validate configurable correlation rules.", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Test-ConShieldSiemRules.ps1", "docs/SIEM_RULES.md", "Siem", "Rules"),
        new("Container Policy", "Validate container policy-as-code defaults.", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Test-ConShieldContainerPolicy.ps1", "docs/CONTAINER_POLICY.md"),
        new("Evidence Export", "Export safe Markdown evidence under ignored local artifacts.", "dotnet run --project .\\src\\ConShield.Cli -- evidence export `\n  --output .\\artifacts\\local\\defense-evidence-dashboard.md", "docs/DEMO_EVIDENCE_PACK.md", "Reports", "SecuritySummary"),
        new("Full Validation", "Run deterministic repository validation without live external dependencies.", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\Test-ConShieldFullValidation.ps1", "docs/CONSHIELD_FULL_VALIDATION_CHECKLIST.md"),
        new("Release Pack", "Create a safe local handoff bundle under ignored artifacts.", "pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\New-ConShieldDemoReleasePack.ps1", "docs/RELEASE_AND_DEMO_PACKAGING.md")
    ];

    private static IReadOnlyList<OperatorDashboardDocLinkViewModel> BuildDocumentationLinks() =>
    [
        new("Architecture", "docs/ARCHITECTURE.md"),
        new("Data flow model", "docs/DATA_FLOW_MODEL.md"),
        new("Threat model", "docs/THREAT_MODEL.md"),
        new("Security requirements", "docs/SECURITY_REQUIREMENTS.md"),
        new("Requirements traceability matrix", "docs/REQUIREMENTS_TRACEABILITY_MATRIX.md"),
        new("Product positioning", "docs/PRODUCT_POSITIONING.md"),
        new("Competitive analysis", "docs/COMPETITIVE_ANALYSIS.md"),
        new("Diploma defense narrative", "docs/DIPLOMA_DEFENSE_NARRATIVE.md"),
        new("Full validation checklist", "docs/CONSHIELD_FULL_VALIDATION_CHECKLIST.md"),
        new("Release/demo packaging", "docs/RELEASE_AND_DEMO_PACKAGING.md"),
        new("CLI docs", "docs/CONSHIELD_CLI.md")
    ];

    private static bool FileExistsInRepo(params string[] parts)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !System.IO.File.Exists(Path.Combine(directory.FullName, "ConShield.sln")))
            directory = directory.Parent;

        if (directory is null)
            return false;

        var repoRoot = directory.FullName;
        return System.IO.File.Exists(Path.Combine(new[] { repoRoot }.Concat(parts).ToArray()));
    }
}
