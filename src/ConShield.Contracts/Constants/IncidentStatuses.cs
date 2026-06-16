namespace ConShield.Contracts.Constants;

public static class IncidentStatuses
{
    public const string New = "New";
    public const string InProgress = "InProgress";
    public const string Closed = "Closed";

    public static readonly string[] All = [New, InProgress, Closed];
}
