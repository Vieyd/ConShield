namespace ConShield.ImageScanner;

public sealed class ImageScanSummary
{
    public string Scanner { get; init; } = "trivy";
    public string ScannerVersion { get; init; } = "unknown";
    public string ImageReference { get; init; } = string.Empty;
    public string? ImageDigest { get; init; }
    public string? ArtifactType { get; init; }
    public int UnknownCount { get; init; }
    public int LowCount { get; init; }
    public int MediumCount { get; init; }
    public int HighCount { get; init; }
    public int CriticalCount { get; init; }
    public int TotalCount { get; init; }
    public int FixAvailableCount { get; init; }
    public int AffectedTargetCount { get; init; }
    public string ReportSha256 { get; init; } = string.Empty;
}
