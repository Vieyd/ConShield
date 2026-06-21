using ConShield.Application;
using ConShield.Application.Models;
using ConShield.Data;
using ConShield.SensorProvisioning;
using Microsoft.EntityFrameworkCore;

const string ConnectionVariable = "CONSHIELD_SENSOR_PROVISIONING_CONNECTION";

var options = ProvisioningCommandOptions.Parse(args);
if (!options.IsValid)
{
    Console.Error.WriteLine(options.Error);
    Console.Error.WriteLine("Usage: ConShield.SensorProvisioning provision --display-name <name> [--heartbeat-interval-seconds <15-3600>]");
    return 2;
}

var connectionString = Environment.GetEnvironmentVariable(ConnectionVariable);
if (string.IsNullOrWhiteSpace(connectionString))
{
    Console.Error.WriteLine($"{ConnectionVariable} is required.");
    return 3;
}

try
{
    var dbOptions = new DbContextOptionsBuilder<ApplicationDbContext>()
        .UseNpgsql(connectionString)
        .Options;
    await using var dbContext = new ApplicationDbContext(dbOptions);
    if ((await dbContext.Database.GetPendingMigrationsAsync()).Any())
    {
        Console.Error.WriteLine("Database migrations are pending. Apply them before provisioning a sensor.");
        return 4;
    }

    var service = new SensorProvisioningService(dbContext);
    var result = await service.ProvisionAsync(new SensorProvisioningRequest(
        options.DisplayName!,
        options.HeartbeatIntervalSeconds));

    Console.Error.WriteLine("Provisioning succeeded. The credential below is shown once; transfer it directly to the protected Fedora environment file.");
    Console.WriteLine(ProvisioningEnvironmentOutput.Format(result));
    return 0;
}
catch (SensorProvisioningException exception)
{
    Console.Error.WriteLine(exception.Message);
    return 5;
}
catch (Exception)
{
    Console.Error.WriteLine("Sensor provisioning failed. No credential details were written.");
    return 6;
}
