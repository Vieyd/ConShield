namespace ConShield.MongoProjection;

public enum MongoProjectionOutcome
{
    Inserted,
    AlreadyProjected,
    TransientFailure,
    PermanentFailure
}

public sealed record MongoProjectionResult(
    MongoProjectionOutcome Outcome,
    string? ErrorCode = null,
    string? SafeErrorSummary = null)
{
    public static MongoProjectionResult Inserted() => new(MongoProjectionOutcome.Inserted);
    public static MongoProjectionResult AlreadyProjected() => new(MongoProjectionOutcome.AlreadyProjected);
    public static MongoProjectionResult TransientFailure(string code, string summary) => new(MongoProjectionOutcome.TransientFailure, code, summary);
    public static MongoProjectionResult PermanentFailure(string code, string summary) => new(MongoProjectionOutcome.PermanentFailure, code, summary);
}
