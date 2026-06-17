namespace ConShield.ImageScanner;

public static class ScannerConstants
{
    public const string SourceSystem = "conshield.image-scanner";
    public const string ExternalEventType = "container.image.scan.completed";
    public const string PolicySourceSystem = "conshield.container-guard";
    public const string PolicyExternalEventType = "container.image.policy.evaluated";
    public const int MaxReportBytes = 4 * 1024 * 1024;
    public const int MaxStderrBytes = 64 * 1024;
    public const int StderrDisplayLimit = 2000;
}
