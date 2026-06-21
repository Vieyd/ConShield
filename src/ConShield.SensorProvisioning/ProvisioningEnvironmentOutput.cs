using ConShield.Application.Models;

namespace ConShield.SensorProvisioning;

public static class ProvisioningEnvironmentOutput
{
    public static string Format(SensorProvisioningResult result) => string.Join(
        Environment.NewLine,
        $"CONSHIELD_SENSOR_ID={result.SensorId:D}",
        $"CONSHIELD_SENSOR_CREDENTIAL_ID={result.CredentialId:D}",
        $"CONSHIELD_RUNTIME_COLLECTOR_API_KEY={result.Credential}",
        $"CONSHIELD_HEARTBEAT_INTERVAL_SECONDS={result.HeartbeatIntervalSeconds}");
}
