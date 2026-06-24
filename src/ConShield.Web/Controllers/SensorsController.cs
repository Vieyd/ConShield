using ConShield.Application;
using ConShield.Contracts.Constants;
using ConShield.Data;
using ConShield.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Web.Controllers;

[Authorize(Roles = AppRoles.AdminIB)]
public sealed class SensorsController : Controller
{
    private const int MaxSensors = 500;
    private const string RotationReason = "AdminIB UI credential rotation";
    private const string CredentialRevocationReason = "AdminIB UI credential revocation";
    private const string SensorRevocationReason = "AdminIB UI sensor revocation";
    private readonly ApplicationDbContext _dbContext;
    private readonly ISensorCredentialLifecycleService _credentialLifecycleService;

    public SensorsController(
        ApplicationDbContext dbContext,
        ISensorCredentialLifecycleService credentialLifecycleService)
    {
        _dbContext = dbContext;
        _credentialLifecycleService = credentialLifecycleService;
    }

    [HttpGet]
    public async Task<IActionResult> Index(CancellationToken cancellationToken)
    {
        var nowUtc = DateTime.UtcNow;
        var sensors = await _dbContext.Sensors
            .AsNoTracking()
            .OrderBy(sensor => sensor.RevokedAtUtc != null)
            .ThenByDescending(sensor => sensor.LastSeenAtUtc)
            .ThenBy(sensor => sensor.DisplayName)
            .Take(MaxSensors)
            .Select(sensor => new
            {
                sensor.SensorId,
                sensor.DisplayName,
                sensor.SourceSystem,
                sensor.LastSeenAtUtc,
                sensor.CreatedAtUtc,
                sensor.UpdatedAtUtc,
                sensor.RevokedAtUtc,
                HasCertificateFingerprint = sensor.CertificateFingerprintSha256 != null && sensor.CertificateFingerprintSha256 != string.Empty,
                CredentialCount = sensor.Credentials.Count,
                ActiveCredentialCount = sensor.Credentials.Count(credential =>
                    credential.RotatedAtUtc == null && credential.RevokedAtUtc == null),
                OldestCredentialCreatedAtUtc = sensor.Credentials
                    .Select(credential => (DateTime?)credential.CreatedAtUtc)
                    .Min(),
                NewestCredentialCreatedAtUtc = sensor.Credentials
                    .Select(credential => (DateTime?)credential.CreatedAtUtc)
                    .Max()
            })
            .ToListAsync(cancellationToken);

        var model = new SensorFleetIndexViewModel
        {
            GeneratedAtUtc = nowUtc,
            Sensors = sensors
                .Select(sensor => SensorFleetItemViewModel.Create(
                    sensor.SensorId,
                    sensor.DisplayName,
                    sensor.SourceSystem,
                    sensor.LastSeenAtUtc,
                    sensor.CreatedAtUtc,
                    sensor.UpdatedAtUtc,
                    sensor.RevokedAtUtc,
                    sensor.HasCertificateFingerprint,
                    sensor.CredentialCount,
                    sensor.ActiveCredentialCount,
                    sensor.OldestCredentialCreatedAtUtc,
                    sensor.NewestCredentialCreatedAtUtc,
                    nowUtc))
                .ToArray()
        };

        return View(model);
    }

    [HttpGet]
    public async Task<IActionResult> Details(Guid sensorId, CancellationToken cancellationToken)
    {
        var nowUtc = DateTime.UtcNow;
        var sensor = await _dbContext.Sensors
            .AsNoTracking()
            .Where(x => x.SensorId == sensorId)
            .Select(x => new
            {
                x.SensorId,
                x.DisplayName,
                x.SourceSystem,
                x.LastSeenAtUtc,
                x.CreatedAtUtc,
                x.UpdatedAtUtc,
                x.RevokedAtUtc,
                HasCertificateFingerprint = x.CertificateFingerprintSha256 != null && x.CertificateFingerprintSha256 != string.Empty,
                Credentials = x.Credentials
                    .OrderByDescending(credential => credential.CreatedAtUtc)
                    .Select(credential => new
                    {
                        credential.CredentialId,
                        credential.CreatedAtUtc,
                        credential.RotatedAtUtc,
                        credential.RevokedAtUtc
                    })
                    .ToArray()
            })
            .SingleOrDefaultAsync(cancellationToken);

        if (sensor is null)
            return NotFound();

        return View(SensorDetailsViewModel.Create(
            sensor.SensorId,
            sensor.DisplayName,
            sensor.SourceSystem,
            sensor.LastSeenAtUtc,
            sensor.CreatedAtUtc,
            sensor.UpdatedAtUtc,
            sensor.RevokedAtUtc,
            sensor.HasCertificateFingerprint,
            sensor.Credentials.Select(credential => SensorCredentialDetailsViewModel.Create(
                credential.CredentialId,
                credential.CreatedAtUtc,
                credential.RotatedAtUtc,
                credential.RevokedAtUtc)),
            nowUtc));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RotateCredential(Guid sensorId, CancellationToken cancellationToken)
    {
        try
        {
            var requestedBy = User.Identity?.Name ?? "unknown";
            var result = await _credentialLifecycleService.RotateCredentialAsync(
                sensorId,
                requestedBy,
                RotationReason,
                cancellationToken);

            return View("RotateCredentialResult", SensorCredentialRotationResultViewModel.From(result));
        }
        catch (SensorCredentialLifecycleException)
        {
            return View(
                "RotateCredentialFailed",
                new SensorCredentialRotationFailureViewModel
                {
                    SensorId = sensorId,
                    Message = "Credential rotation could not be completed. The sensor may be missing or revoked."
                });
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RevokeCredential(
        Guid sensorId,
        Guid credentialId,
        string? reason,
        CancellationToken cancellationToken)
    {
        try
        {
            var requestedBy = User.Identity?.Name ?? "unknown";
            var result = await _credentialLifecycleService.RevokeCredentialAsync(
                sensorId,
                credentialId,
                requestedBy,
                string.IsNullOrWhiteSpace(reason) ? CredentialRevocationReason : reason,
                cancellationToken);

            return View("RevocationResult", SensorRevocationUiResultViewModel.FromCredential(result));
        }
        catch (SensorCredentialLifecycleException)
        {
            return View(
                "RevocationFailed",
                new SensorRevocationFailureViewModel
                {
                    SensorId = sensorId,
                    CredentialId = credentialId,
                    Message = "Credential revocation could not be completed. The sensor or credential may be missing."
                });
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RevokeSensor(
        Guid sensorId,
        string? reason,
        CancellationToken cancellationToken)
    {
        try
        {
            var requestedBy = User.Identity?.Name ?? "unknown";
            var result = await _credentialLifecycleService.RevokeSensorAsync(
                sensorId,
                requestedBy,
                string.IsNullOrWhiteSpace(reason) ? SensorRevocationReason : reason,
                cancellationToken);

            return View("RevocationResult", SensorRevocationUiResultViewModel.FromSensor(result));
        }
        catch (SensorCredentialLifecycleException)
        {
            return View(
                "RevocationFailed",
                new SensorRevocationFailureViewModel
                {
                    SensorId = sensorId,
                    Message = "Sensor revocation could not be completed. The sensor may be missing."
                });
        }
    }
}
