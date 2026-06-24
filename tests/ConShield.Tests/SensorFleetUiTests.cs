using System.Reflection;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using ConShield.Application;
using ConShield.Contracts.Constants;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.Web.Controllers;
using ConShield.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace ConShield.Tests;

public sealed class SensorFleetUiTests
{
    [Fact]
    public void SensorsController_IsRestrictedToAdminIB()
    {
        var attribute = typeof(SensorsController).GetCustomAttribute<AuthorizeAttribute>();

        Assert.NotNull(attribute);
        Assert.Equal(AppRoles.AdminIB, attribute.Roles);
    }

    [Fact]
    public void RotateCredential_PostRequiresAntiForgery()
    {
        var method = typeof(SensorsController).GetMethod(
            nameof(SensorsController.RotateCredential),
            [typeof(Guid), typeof(CancellationToken)]);

        Assert.NotNull(method);
        Assert.NotNull(method.GetCustomAttribute<HttpPostAttribute>());
        Assert.NotNull(method.GetCustomAttribute<ValidateAntiForgeryTokenAttribute>());
        Assert.Null(method.GetCustomAttribute<AllowAnonymousAttribute>());
    }

    [Fact]
    public async Task Index_ProjectsSensorMetadataAndCredentialCountsWithoutVerifier()
    {
        await using var db = CreateDbContext();
        var nowUtc = DateTime.UtcNow;
        var sensorId = Guid.NewGuid();
        await SeedSensorAsync(db, sensorId, nowUtc);

        var result = await CreateController(db).Index(CancellationToken.None);
        var view = Assert.IsType<ViewResult>(result);
        var model = Assert.IsType<SensorFleetIndexViewModel>(view.Model);
        var sensor = Assert.Single(model.Sensors);

        Assert.Equal(sensorId, sensor.SensorId);
        Assert.Equal("fedora-runtime-01", sensor.DisplayName);
        Assert.Equal(SecuritySourceSystems.FalcoRuntimeCollector, sensor.SourceSystem);
        Assert.Equal("Online", sensor.Status);
        Assert.Equal(2, sensor.CredentialCount);
        Assert.Equal(1, sensor.ActiveCredentialCount);
        Assert.True(sensor.CanRotateCredential);
        Assert.True(sensor.HasCertificateFingerprint);
        Assert.DoesNotContain(
            typeof(SensorFleetItemViewModel).GetProperties(),
            property => property.Name.Contains("Verifier", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task AdminIB_CanSeeRotateButtonForActiveSensor()
    {
        await using var db = CreateDbContext();
        var nowUtc = DateTime.UtcNow;
        var sensorId = Guid.NewGuid();
        await SeedSensorAsync(db, sensorId, nowUtc);

        var result = await CreateController(db).Index(CancellationToken.None);
        var model = Assert.IsType<SensorFleetIndexViewModel>(Assert.IsType<ViewResult>(result).Model);
        var sensor = Assert.Single(model.Sensors);
        var viewText = ReadRepoFile("src", "ConShield.Web", "Views", "Sensors", "Index.cshtml");

        Assert.True(sensor.CanRotateCredential);
        Assert.Contains("Rotate credential", viewText, StringComparison.Ordinal);
        Assert.Contains("asp-action=\"RotateCredential\"", viewText, StringComparison.Ordinal);
        Assert.Contains("sensor.CanRotateCredential", viewText, StringComparison.Ordinal);
    }

    [Fact]
    public void Operator_CannotSeeOrPostRotateCredential()
    {
        var controllerAuthorize = typeof(SensorsController).GetCustomAttribute<AuthorizeAttribute>();
        var method = typeof(SensorsController).GetMethod(
            nameof(SensorsController.RotateCredential),
            [typeof(Guid), typeof(CancellationToken)]);

        Assert.NotNull(controllerAuthorize);
        Assert.Equal(AppRoles.AdminIB, controllerAuthorize.Roles);
        Assert.DoesNotContain(AppRoles.Operator, controllerAuthorize.Roles, StringComparison.Ordinal);
        Assert.NotNull(method);
        Assert.Null(method.GetCustomAttribute<AllowAnonymousAttribute>());
    }

    [Fact]
    public async Task Unauthenticated_PostRotateCredential_RedirectsToLogin()
    {
        await using var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Production");
                builder.ConfigureAppConfiguration((_, configuration) =>
                {
                    configuration.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["ConnectionStrings:DefaultConnection"] = "Host=localhost;Database=unused;Username=unused;Password=unused",
                        ["ExternalEventIngestion:Enabled"] = "false",
                        ["SecurityEventOutbox:Enabled"] = "false",
                        ["DeadLetterReplay:Enabled"] = "false",
                        ["MongoProjection:Enabled"] = "false",
                        ["RabbitMq:Enabled"] = "false"
                    });
                });
                builder.ConfigureServices(services => services.RemoveAll<IHostedService>());
            });
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var response = await client.PostAsync(
            "/Sensors/RotateCredential",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["sensorId"] = Guid.NewGuid().ToString("D")
            }));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("/Account/Login", response.Headers.Location?.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task RotateCredential_Post_ReturnsOneTimeCredentialResult()
    {
        await using var db = CreateDbContext();
        var nowUtc = DateTime.UtcNow;
        var sensorId = Guid.NewGuid();
        await SeedSensorAsync(db, sensorId, nowUtc);
        var controller = CreateAuthenticatedController(db);

        var result = await controller.RotateCredential(sensorId, CancellationToken.None);

        var view = Assert.IsType<ViewResult>(result);
        Assert.Equal("RotateCredentialResult", view.ViewName);
        var model = Assert.IsType<SensorCredentialRotationResultViewModel>(view.Model);
        Assert.Equal(sensorId, model.SensorId);
        Assert.Equal("fedora-runtime-01", model.DisplayName);
        Assert.Matches("^[A-Za-z0-9_-]{43}$", model.OneTimeCredential);
        Assert.DoesNotContain(
            typeof(SensorCredentialRotationResultViewModel).GetProperties(),
            property => property.Name.Contains("Verifier", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RotateCredential_Result_DoesNotContainVerifier()
    {
        var resultView = ReadRepoFile("src", "ConShield.Web", "Views", "Sensors", "RotateCredentialResult.cshtml");

        Assert.DoesNotContain("Verifier", resultView, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("TempData", resultView, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Session", resultView, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("cookie", resultView, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("type=\"hidden\"", resultView, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("CONSHIELD_SENSOR_ID", resultView, StringComparison.Ordinal);
        Assert.Contains("CONSHIELD_SENSOR_CREDENTIAL_ID", resultView, StringComparison.Ordinal);
        Assert.Contains("CONSHIELD_RUNTIME_COLLECTOR_API_KEY", resultView, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RotateCredential_RotatesOldCredentialAndCreatesNewCredential()
    {
        await using var db = CreateDbContext();
        var nowUtc = DateTime.UtcNow;
        var sensorId = Guid.NewGuid();
        await SeedSensorAsync(db, sensorId, nowUtc);
        var controller = CreateAuthenticatedController(db);

        var result = await controller.RotateCredential(sensorId, CancellationToken.None);
        var model = Assert.IsType<SensorCredentialRotationResultViewModel>(Assert.IsType<ViewResult>(result).Model);
        var credentials = await db.SensorCredentials.OrderBy(x => x.CreatedAtUtc).ToArrayAsync();

        Assert.Equal(3, credentials.Length);
        Assert.NotNull(credentials.Single(x => x.CredentialId != model.CredentialId && x.RevokedAtUtc is null).RotatedAtUtc);
        var active = credentials.Single(x => x.CredentialId == model.CredentialId);
        Assert.Null(active.RotatedAtUtc);
        Assert.Null(active.RevokedAtUtc);
        Assert.Equal(32, active.VerifierSha256.Length);
    }

    [Fact]
    public async Task RotateCredential_ForRevokedSensor_ShowsSafeFailure()
    {
        await using var db = CreateDbContext();
        var nowUtc = DateTime.UtcNow;
        var sensorId = Guid.NewGuid();
        await SeedSensorAsync(db, sensorId, nowUtc, sensorRevokedAtUtc: nowUtc);
        var controller = CreateAuthenticatedController(db);

        var result = await controller.RotateCredential(sensorId, CancellationToken.None);

        var view = Assert.IsType<ViewResult>(result);
        Assert.Equal("RotateCredentialFailed", view.ViewName);
        var model = Assert.IsType<SensorCredentialRotationFailureViewModel>(view.Model);
        Assert.Equal(sensorId, model.SensorId);
        Assert.Contains("could not be completed", model.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Verifier", model.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("CONSHIELD_RUNTIME_COLLECTOR_API_KEY", model.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RotateCredential_ButtonNotShownForRevokedSensor()
    {
        await using var db = CreateDbContext();
        var nowUtc = DateTime.UtcNow;
        var sensorId = Guid.NewGuid();
        await SeedSensorAsync(db, sensorId, nowUtc, sensorRevokedAtUtc: nowUtc);

        var result = await CreateController(db).Index(CancellationToken.None);
        var model = Assert.IsType<SensorFleetIndexViewModel>(Assert.IsType<ViewResult>(result).Model);
        var sensor = Assert.Single(model.Sensors);
        var viewText = ReadRepoFile("src", "ConShield.Web", "Views", "Sensors", "Index.cshtml");

        Assert.False(sensor.CanRotateCredential);
        Assert.Contains("sensor.CanRotateCredential", viewText, StringComparison.Ordinal);
        Assert.Contains("not available", viewText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SensorFleet_ShowsRevokedStatus()
    {
        await using var db = CreateDbContext();
        var nowUtc = DateTime.UtcNow;
        var sensorId = Guid.NewGuid();
        await SeedSensorAsync(db, sensorId, nowUtc);
        await new SensorCredentialLifecycleService(db).RevokeSensorAsync(sensorId, "adminib", "test revocation");

        var result = await CreateController(db).Index(CancellationToken.None);
        var model = Assert.IsType<SensorFleetIndexViewModel>(Assert.IsType<ViewResult>(result).Model);
        var sensor = Assert.Single(model.Sensors);
        var viewText = ReadRepoFile("src", "ConShield.Web", "Views", "Sensors", "Index.cshtml");

        Assert.Equal("Revoked", sensor.Status);
        Assert.False(sensor.CanRotateCredential);
        Assert.DoesNotContain("Revoke credential", viewText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Revoke sensor", viewText, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(null, false, "Never seen")]
    [InlineData(1, false, "Online")]
    [InlineData(4, false, "Warning")]
    [InlineData(6, false, "Offline")]
    [InlineData(1, true, "Revoked")]
    public void CalculateStatus_ReturnsExpectedFleetStatus(int? heartbeatAgeMinutes, bool revoked, string expected)
    {
        var nowUtc = new DateTime(2026, 6, 24, 12, 0, 0, DateTimeKind.Utc);
        var lastSeenAtUtc = heartbeatAgeMinutes is null
            ? (DateTime?)null
            : nowUtc.AddMinutes(-heartbeatAgeMinutes.Value);
        var revokedAtUtc = revoked ? nowUtc.AddMinutes(-1) : (DateTime?)null;

        var (status, _) = SensorFleetItemViewModel.CalculateStatus(lastSeenAtUtc, revokedAtUtc, nowUtc);

        Assert.Equal(expected, status);
    }

    private static SensorsController CreateController(ApplicationDbContext db) =>
        new(db, new SensorCredentialLifecycleService(db));

    private static SensorsController CreateAuthenticatedController(ApplicationDbContext db)
    {
        var controller = CreateController(db);
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(
                    [
                        new Claim(ClaimTypes.Name, "adminib@example.test"),
                        new Claim(ClaimTypes.Role, AppRoles.AdminIB)
                    ],
                    "test"))
            }
        };
        return controller;
    }

    private static async Task SeedSensorAsync(
        ApplicationDbContext db,
        Guid sensorId,
        DateTime nowUtc,
        DateTime? sensorRevokedAtUtc = null)
    {
        db.Sensors.Add(new Sensor
        {
            SensorId = sensorId,
            DisplayName = "fedora-runtime-01",
            SourceSystem = SecuritySourceSystems.FalcoRuntimeCollector,
            LastSeenAtUtc = nowUtc.AddSeconds(-30),
            CertificateFingerprintSha256 = new string('a', 64),
            RevokedAtUtc = sensorRevokedAtUtc,
            CreatedAtUtc = nowUtc.AddHours(-2),
            UpdatedAtUtc = nowUtc.AddSeconds(-30),
            Credentials =
            [
                new SensorCredential
                {
                    CredentialId = Guid.NewGuid(),
                    CreatedAtUtc = nowUtc.AddHours(-2),
                    VerifierSha256 = SHA256.HashData(Encoding.UTF8.GetBytes("active-test-secret"))
                },
                new SensorCredential
                {
                    CredentialId = Guid.NewGuid(),
                    CreatedAtUtc = nowUtc.AddHours(-3),
                    RevokedAtUtc = nowUtc.AddHours(-1),
                    VerifierSha256 = SHA256.HashData(Encoding.UTF8.GetBytes("revoked-test-secret"))
                }
            ]
        });

        await db.SaveChangesAsync();
    }

    private static string ReadRepoFile(params string[] relativePath)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(new[] { directory.FullName }.Concat(relativePath).ToArray());
            if (File.Exists(candidate))
                return File.ReadAllText(candidate);
            directory = directory.Parent;
        }

        throw new FileNotFoundException($"Could not find repository file: {Path.Combine(relativePath)}");
    }

    private static ApplicationDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase($"sensor-fleet-ui-{Guid.NewGuid():N}")
            .Options;
        return new ApplicationDbContext(options);
    }
}
