using System.Net;

namespace ConShield.ImageScanner;

public static class LaunchResultEventBuilder
{
    public static ImageScanIngestRequest Build(
        ScannerOptions options,
        ImageScanSummary summary,
        ContainerRuntimeResult runtimeResult)
    {
        var image = Redaction.RedactImageReference(summary.ImageReference);
        return new ImageScanIngestRequest
        {
            ExternalEventId = options.ExternalEventId,
            OccurredAtUtc = DateTime.UtcNow,
            SourceSystem = ScannerConstants.RuntimeSourceSystem,
            EventType = ScannerConstants.LaunchResultExternalEventType,
            Severity = MapSeverity(runtimeResult.Outcome),
            UserName = null,
            SourceHost = GetSafeHostName(),
            Description = $"Container launch outcome {runtimeResult.Outcome} for {image}.",
            AdditionalData = new LaunchResultAdditionalData
            {
                Outcome = runtimeResult.Outcome.ToString(),
                DockerRunInvoked = runtimeResult.DockerRunInvoked,
                ProcessExitCode = runtimeResult.ProcessExitCode,
                DurationMs = runtimeResult.DurationMs,
                RuntimeVersion = runtimeResult.RuntimeVersion,
                RuntimeProfile = ScannerConstants.RuntimeProfile,
                LaunchReference = runtimeResult.LaunchReference ?? Redaction.RedactImageReference(DockerContainerRuntime.SelectLaunchImage(summary) ?? summary.ImageReference),
                ImageReference = image,
                ImageDigest = summary.ImageDigest,
                ReportSha256 = summary.ReportSha256,
                SafeErrorCategory = runtimeResult.SafeErrorCategory
            }
        };
    }

    private static string MapSeverity(ContainerLaunchOutcome outcome)
    {
        return outcome switch
        {
            ContainerLaunchOutcome.Succeeded => "Info",
            ContainerLaunchOutcome.Unavailable => "Warning",
            ContainerLaunchOutcome.Cancelled => "Warning",
            _ => "High"
        };
    }

    private static string GetSafeHostName()
    {
        var host = Dns.GetHostName();
        if (string.IsNullOrWhiteSpace(host))
            return "unknown-host";

        var safe = new string(host.Where(x => !char.IsControl(x) && x is not '\\' and not '/').ToArray()).Trim();
        return safe.Length <= 256 ? safe : safe[..256];
    }
}

public sealed class LaunchResultAdditionalData
{
    public int SchemaVersion { get; set; } = 1;
    public string Runtime { get; set; } = "docker";
    public string RuntimeProfile { get; set; } = ScannerConstants.RuntimeProfile;
    public string Outcome { get; set; } = string.Empty;
    public bool DockerRunInvoked { get; set; }
    public int? ProcessExitCode { get; set; }
    public long DurationMs { get; set; }
    public string? RuntimeVersion { get; set; }
    public string LaunchReference { get; set; } = string.Empty;
    public string ImageReference { get; set; } = string.Empty;
    public string? ImageDigest { get; set; }
    public string ReportSha256 { get; set; } = string.Empty;
    public string? SafeErrorCategory { get; set; }
}
