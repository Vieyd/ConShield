using ConShield.ContainerPolicy;

namespace ConShield.ImageScanner;

internal interface IGateAuditEventFactory
{
    GateAuditEventPair Build(
        ScannerOptions options,
        ImageScanSummary summary,
        long scanDurationMs,
        ContainerPolicyDocument policy,
        ContainerPolicyEvaluation evaluation);
}

internal sealed class GateAuditEventFactory : IGateAuditEventFactory
{
    public GateAuditEventPair Build(
        ScannerOptions options,
        ImageScanSummary summary,
        long scanDurationMs,
        ContainerPolicyDocument policy,
        ContainerPolicyEvaluation evaluation)
    {
        var scanOptions = new ScannerOptions
        {
            Command = options.Command,
            ImageReference = options.ImageReference,
            BaseUrl = options.BaseUrl,
            ApiKey = options.ApiKey,
            TrivyPath = options.TrivyPath,
            DockerPath = options.DockerPath,
            PolicyPath = options.PolicyPath,
            ExternalEventId = options.ExternalEventId,
            TimeoutSeconds = options.TimeoutSeconds,
            RunTimeoutSeconds = options.RunTimeoutSeconds,
            SourceSystem = ScannerConstants.SourceSystem,
            NoSubmit = options.NoSubmit,
            Execute = options.Execute,
            AcceptWarning = options.AcceptWarning
        };
        return new GateAuditEventPair(
            ImageScanEventBuilder.Build(scanOptions, summary, scanDurationMs),
            ImageScanEventBuilder.BuildPolicyEvaluation(options, summary, policy, evaluation));
    }
}

internal sealed record GateAuditEventPair(
    ImageScanIngestRequest ScanEvent,
    ImageScanIngestRequest PolicyEvent);

internal static class GateAuditInvariantValidator
{
    public static bool IsValid(GateAuditEventPair pair)
    {
        return pair.ScanEvent.SourceSystem != pair.PolicyEvent.SourceSystem
            && pair.ScanEvent.ExternalEventId == pair.PolicyEvent.ExternalEventId
            && pair.ScanEvent.EventType == ScannerConstants.ExternalEventType
            && pair.PolicyEvent.EventType == ScannerConstants.PolicyExternalEventType;
    }
}
