namespace ConShield.Contracts.Constants;

public static class AlertStatuses
{
    public const string New = "New";
    public const string Acknowledged = "Acknowledged";
    public const string Closed = "Closed";

    public static readonly string[] All = [New, Acknowledged, Closed];
}
