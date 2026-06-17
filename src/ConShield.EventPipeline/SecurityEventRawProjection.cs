namespace ConShield.EventPipeline;

public interface ISecurityEventRawProjection
{
    Task<SecurityEventRawProjectionResult> ProjectAsync(
        SecurityEventEnvelope envelope,
        byte[] body,
        string payloadSha256,
        DateTime nowUtc,
        CancellationToken cancellationToken);
}

public sealed class DisabledSecurityEventRawProjection : ISecurityEventRawProjection
{
    public Task<SecurityEventRawProjectionResult> ProjectAsync(
        SecurityEventEnvelope envelope,
        byte[] body,
        string payloadSha256,
        DateTime nowUtc,
        CancellationToken cancellationToken) =>
        Task.FromResult(SecurityEventRawProjectionResult.Inserted());
}

public sealed record SecurityEventRawProjectionResult(
    SecurityEventRawProjectionOutcome Outcome,
    string? ErrorCode = null,
    string? SafeErrorSummary = null)
{
    public static SecurityEventRawProjectionResult Inserted() => new(SecurityEventRawProjectionOutcome.Inserted);
    public static SecurityEventRawProjectionResult AlreadyProjected() => new(SecurityEventRawProjectionOutcome.AlreadyProjected);

    public static SecurityEventRawProjectionResult TransientFailure(string errorCode, string safeErrorSummary) =>
        new(SecurityEventRawProjectionOutcome.TransientFailure, OutboxSinkResult.Safe(errorCode, 64), OutboxSinkResult.Safe(safeErrorSummary, 512));

    public static SecurityEventRawProjectionResult PermanentFailure(string errorCode, string safeErrorSummary) =>
        new(SecurityEventRawProjectionOutcome.PermanentFailure, OutboxSinkResult.Safe(errorCode, 64), OutboxSinkResult.Safe(safeErrorSummary, 512));
}

public enum SecurityEventRawProjectionOutcome
{
    Inserted,
    AlreadyProjected,
    TransientFailure,
    PermanentFailure
}
