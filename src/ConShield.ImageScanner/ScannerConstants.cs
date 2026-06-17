namespace ConShield.ImageScanner;

public static class ScannerConstants
{
    public const string SourceSystem = "conshield.image-scanner";
    public const string ExternalEventType = "container.image.scan.completed";
    public const string PolicySourceSystem = "conshield.container-guard";
    public const string PolicyExternalEventType = "container.image.policy.evaluated";
    public const string RuntimeSourceSystem = "conshield.container-runtime";
    public const string LaunchResultExternalEventType = "container.image.launch.result";
    public const string RuntimeProfile = "docker-hardened-v1";
    public const int MaxReportBytes = 4 * 1024 * 1024;
    public const int MaxStderrBytes = 64 * 1024;
    public const int StderrDisplayLimit = 2000;
    public const int LaunchAuditTimeoutSeconds = 5;
}
