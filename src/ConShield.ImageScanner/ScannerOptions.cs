namespace ConShield.ImageScanner;

public sealed class ScannerOptions
{
    public const int MaxImageReferenceLength = 512;
    public const int DefaultTimeoutSeconds = 300;
    public const int MinTimeoutSeconds = 5;
    public const int MaxTimeoutSeconds = 900;
    public const int DefaultRunTimeoutSeconds = 60;
    public const int MinRunTimeoutSeconds = 1;
    public const int MaxRunTimeoutSeconds = 300;

    public string Command { get; init; } = "scan";
    public string ImageReference { get; init; } = string.Empty;
    public string? BaseUrl { get; init; }
    public string? ApiKey { get; init; }
    public string? TrivyPath { get; init; }
    public string? DockerPath { get; init; }
    public string? PolicyPath { get; init; }
    public Guid ExternalEventId { get; init; }
    public int TimeoutSeconds { get; init; } = DefaultTimeoutSeconds;
    public int RunTimeoutSeconds { get; init; } = DefaultRunTimeoutSeconds;
    public string SourceSystem { get; init; } = ScannerConstants.SourceSystem;
    public bool NoSubmit { get; init; }
    public bool Execute { get; init; }
    public bool AcceptWarning { get; init; }
}
