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
    private readonly ApplicationDbContext _dbContext;

    public SensorsController(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
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
}
