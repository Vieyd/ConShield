namespace ConShield.Application.Models;

public sealed record SensorProvisioningRequest(string DisplayName, int HeartbeatIntervalSeconds = 60);
