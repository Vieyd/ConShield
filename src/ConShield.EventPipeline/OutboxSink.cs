namespace ConShield.EventPipeline;

public interface ISecurityEventOutboxSink
{
    Task<OutboxSinkResult> DeliverAsync(SecurityEventEnvelope envelope, CancellationToken cancellationToken);
}

public sealed class OutboxSinkResult
{
    private OutboxSinkResult(OutboxSinkResultType type, string? errorCode, string? safeErrorSummary)
    {
        Type = type;
        ErrorCode = errorCode;
        SafeErrorSummary = safeErrorSummary;
    }

    public OutboxSinkResultType Type { get; }
    public string? ErrorCode { get; }
    public string? SafeErrorSummary { get; }

    public static OutboxSinkResult Succeeded() => new(OutboxSinkResultType.Succeeded, null, null);

    public static OutboxSinkResult TransientFailure(string errorCode, string safeErrorSummary) =>
        new(OutboxSinkResultType.TransientFailure, Safe(errorCode, 64), Safe(safeErrorSummary, 512));

    public static OutboxSinkResult PermanentFailure(string errorCode, string safeErrorSummary) =>
        new(OutboxSinkResultType.PermanentFailure, Safe(errorCode, 64), Safe(safeErrorSummary, 512));

    internal static string Safe(string? value, int maxLength)
    {
        var safe = new string((value ?? string.Empty).Where(ch => !char.IsControl(ch) || ch is ' ' or '\t').ToArray()).Trim();
        return safe.Length <= maxLength ? safe : safe[..maxLength];
    }
}

public enum OutboxSinkResultType
{
    Succeeded,
    TransientFailure,
    PermanentFailure
}
