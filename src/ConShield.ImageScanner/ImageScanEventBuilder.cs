using System.Net;
using ConShield.ContainerPolicy;

namespace ConShield.ImageScanner;

public static class ImageScanEventBuilder
{
    public static ImageScanIngestRequest Build(
        ScannerOptions options,
        ImageScanSummary summary,
        long durationMs)
    {
        return new ImageScanIngestRequest
        {
            ExternalEventId = options.ExternalEventId,
            OccurredAtUtc = DateTime.UtcNow,
            SourceSystem = options.SourceSystem,
            EventType = ScannerConstants.ExternalEventType,
            Severity = MapSeverity(summary),
            UserName = null,
            SourceHost = GetSafeHostName(),
            Description = BuildDescription(summary),
            AdditionalData = new ImageScanAdditionalData
            {
                ScannerVersion = summary.ScannerVersion,
                ImageReference = Redaction.RedactImageReference(summary.ImageReference),
                ImageDigest = summary.ImageDigest,
                ArtifactType = summary.ArtifactType,
                UnknownCount = summary.UnknownCount,
                LowCount = summary.LowCount,
                MediumCount = summary.MediumCount,
                HighCount = summary.HighCount,
                CriticalCount = summary.CriticalCount,
                TotalCount = summary.TotalCount,
                FixAvailableCount = summary.FixAvailableCount,
                AffectedTargetCount = summary.AffectedTargetCount,
                ReportSha256 = summary.ReportSha256,
                DurationMs = Math.Max(0, durationMs)
            }
        };
    }

    public static string MapSeverity(ImageScanSummary summary)
    {
        if (summary.CriticalCount > 0)
            return "Critical";

        if (summary.HighCount > 0)
            return "High";

        if (summary.MediumCount > 0)
            return "Warning";

        return "Info";
    }

    public static ImageScanIngestRequest BuildPolicyEvaluation(
        ScannerOptions options,
        ImageScanSummary summary,
        ContainerPolicyDocument policy,
        ContainerPolicyEvaluation evaluation)
    {
        return new ImageScanIngestRequest
        {
            ExternalEventId = options.ExternalEventId,
            OccurredAtUtc = DateTime.UtcNow,
            SourceSystem = ScannerConstants.PolicySourceSystem,
            EventType = ScannerConstants.PolicyExternalEventType,
            Severity = evaluation.Decision switch
            {
                ContainerPolicyDecision.Block => "High",
                ContainerPolicyDecision.Warn => "Warning",
                _ => "Info"
            },
            UserName = null,
            SourceHost = GetSafeHostName(),
            Description = $"Container policy {policy.PolicyId}/{policy.Version} evaluated {evaluation.Decision} for {Redaction.RedactImageReference(summary.ImageReference)}.",
            AdditionalData = new PolicyEvaluationAdditionalData
            {
                Decision = evaluation.Decision.ToString(),
                PolicyId = policy.PolicyId,
                PolicyVersion = policy.Version,
                PolicySha256 = policy.PolicySha256,
                ImageReference = Redaction.RedactImageReference(summary.ImageReference),
                ImageDigest = summary.ImageDigest,
                ReportSha256 = summary.ReportSha256,
                UnknownCount = summary.UnknownCount,
                LowCount = summary.LowCount,
                MediumCount = summary.MediumCount,
                HighCount = summary.HighCount,
                CriticalCount = summary.CriticalCount,
                TotalCount = summary.TotalCount,
                ReasonCodes = evaluation.ReasonCodes.ToArray(),
                ExecutionRequested = options.Execute,
                WarningAccepted = options.AcceptWarning
            }
        };
    }

    private static string BuildDescription(ImageScanSummary summary)
    {
        var image = Redaction.RedactImageReference(summary.ImageReference);
        return $"Trivy image scan completed for {image}: critical={summary.CriticalCount}, high={summary.HighCount}, total={summary.TotalCount}.";
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

public sealed class ImageScanIngestRequest
{
    public Guid ExternalEventId { get; set; }
    public DateTime OccurredAtUtc { get; set; }
    public string SourceSystem { get; set; } = string.Empty;
    public string EventType { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string? UserName { get; set; }
    public string SourceHost { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public object AdditionalData { get; set; } = new ImageScanAdditionalData();
}

public sealed class ImageScanAdditionalData
{
    public int SchemaVersion { get; set; } = 1;
    public string Scanner { get; set; } = "trivy";
    public string ScannerVersion { get; set; } = "unknown";
    public string ImageReference { get; set; } = string.Empty;
    public string? ImageDigest { get; set; }
    public string? ArtifactType { get; set; }
    public string ScanStatus { get; set; } = "completed";
    public int UnknownCount { get; set; }
    public int LowCount { get; set; }
    public int MediumCount { get; set; }
    public int HighCount { get; set; }
    public int CriticalCount { get; set; }
    public int TotalCount { get; set; }
    public int FixAvailableCount { get; set; }
    public int AffectedTargetCount { get; set; }
    public string ReportSha256 { get; set; } = string.Empty;
    public long DurationMs { get; set; }
}

public sealed class PolicyEvaluationAdditionalData
{
    public int SchemaVersion { get; set; } = 1;
    public string Decision { get; set; } = string.Empty;
    public string PolicyId { get; set; } = string.Empty;
    public string PolicyVersion { get; set; } = string.Empty;
    public string PolicySha256 { get; set; } = string.Empty;
    public string ImageReference { get; set; } = string.Empty;
    public string? ImageDigest { get; set; }
    public string ReportSha256 { get; set; } = string.Empty;
    public int UnknownCount { get; set; }
    public int LowCount { get; set; }
    public int MediumCount { get; set; }
    public int HighCount { get; set; }
    public int CriticalCount { get; set; }
    public int TotalCount { get; set; }
    public string[] ReasonCodes { get; set; } = [];
    public bool ExecutionRequested { get; set; }
    public bool WarningAccepted { get; set; }
}
