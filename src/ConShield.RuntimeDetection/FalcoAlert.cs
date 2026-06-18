namespace ConShield.RuntimeDetection;

public sealed record FalcoAlert(
    DateTime OccurredAtUtc,
    string Rule,
    string Priority,
    string? Output,
    string? Hostname,
    string? Source,
    IReadOnlyList<string> Tags,
    IReadOnlyDictionary<string, object?> OutputFields,
    IReadOnlyList<string> Warnings);

public sealed record ParseResult(FalcoAlert? Alert, string? ErrorCode, string? SafeError)
{
    public bool Success => Alert is not null;
    public static ParseResult Ok(FalcoAlert alert) => new(alert, null, null);
    public static ParseResult Fail(string code, string safeError) => new(null, code, safeError);
}
