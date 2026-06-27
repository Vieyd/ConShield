namespace ConShield.RuntimeCollector;

public sealed class RuntimeCollectorOptions
{
    public bool Stdin { get; init; }
    public string? FilePath { get; init; }
    public bool Follow { get; init; }
    public string? Endpoint { get; init; }
    public string ApiKeyEnv { get; init; } = "CONSHIELD_RUNTIME_COLLECTOR_API_KEY";
    public Guid? SensorId { get; init; }
    public Guid? SensorCredentialId { get; init; }
    public int HeartbeatIntervalSeconds { get; init; } = 60;
    public string MappingPath { get; init; } = string.Empty;
    public bool NoSubmit { get; init; }
    public int MaxLineBytes { get; init; } = 262144;
    public int ReadTimeoutSeconds { get; init; } = 30;
    public int SubmitTimeoutSeconds { get; init; } = 30;
    public int MaxRetries { get; init; } = 3;
    public int MaxEventAgeDays { get; init; } = 30;
    public string SourceSystem { get; init; } = ConShield.RuntimeDetection.RuntimeDetectionConstants.SourceSystem;
}

public enum RuntimeCollectorExitCode
{
    Success = 0,
    InvalidArgs = 2,
    InvalidMapping = 3,
    InputFailure = 4,
    PartialFailure = 5,
    AuthFailure = 6,
    Cancelled = 7
}
