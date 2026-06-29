namespace ConShield.Application.Models;

public static class SensorTrustStatuses
{
    public const string Trusted = "Trusted";
    public const string Unknown = "Unknown";
    public const string Revoked = "Revoked";
    public const string Disabled = "Disabled";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        Trusted,
        Unknown,
        Revoked,
        Disabled
    };
}

public static class SensorTrustEnforcementActions
{
    public const string AcceptTrusted = "AcceptTrusted";
    public const string AcceptUnknownWithAlert = "AcceptUnknownWithAlert";
    public const string FlagRevokedWithAlert = "FlagRevokedWithAlert";
    public const string FlagDisabledWithAlert = "FlagDisabledWithAlert";
}

public static class SensorTrustEnforcement
{
    public static string ActionFor(string trustStatus) =>
        trustStatus switch
        {
            SensorTrustStatuses.Trusted => SensorTrustEnforcementActions.AcceptTrusted,
            SensorTrustStatuses.Revoked => SensorTrustEnforcementActions.FlagRevokedWithAlert,
            SensorTrustStatuses.Disabled => SensorTrustEnforcementActions.FlagDisabledWithAlert,
            _ => SensorTrustEnforcementActions.AcceptUnknownWithAlert
        };

    public static string ExpectedRuleFor(string trustStatus) =>
        trustStatus switch
        {
            SensorTrustStatuses.Trusted => "RTE-001",
            SensorTrustStatuses.Revoked or SensorTrustStatuses.Disabled => "SENSOR-002",
            _ => "SENSOR-001"
        };
}

public sealed record SensorTrustRegistryEntry(
    string SensorId,
    string DisplayName,
    string SourceSystem,
    string Environment,
    string Status,
    IReadOnlyList<string> ExpectedEventTypes,
    string? FingerprintSha256,
    string? Notes);

public sealed record SensorTrustRegistry(
    int Version,
    string ConfigSource,
    IReadOnlyList<SensorTrustRegistryEntry> Sensors)
{
    private readonly IReadOnlyDictionary<string, SensorTrustRegistryEntry> _bySourceSystem =
        Sensors
            .GroupBy(sensor => sensor.SourceSystem, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.Ordinal);

    public static SensorTrustRegistry Empty { get; } =
        new(1, "none", Array.Empty<SensorTrustRegistryEntry>());

    public SensorTrustRegistryEntry? FindBySourceSystem(string sourceSystem) =>
        _bySourceSystem.TryGetValue(sourceSystem, out var sensor) ? sensor : null;
}
