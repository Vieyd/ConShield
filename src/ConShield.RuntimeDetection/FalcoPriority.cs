namespace ConShield.RuntimeDetection;

public static class FalcoPriority
{
    private static readonly HashSet<string> Valid = new(StringComparer.OrdinalIgnoreCase)
    {
        "Emergency",
        "Alert",
        "Critical",
        "Error",
        "Warning",
        "Notice",
        "Informational",
        "Debug"
    };

    public static bool TryNormalize(string? value, out string priority)
    {
        priority = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
            return false;

        var trimmed = value.Trim();
        var match = Valid.FirstOrDefault(x => string.Equals(x, trimmed, StringComparison.OrdinalIgnoreCase));
        if (match is null)
            return false;

        priority = match;
        return true;
    }

    public static bool RequiresAtLeastHigh(string priority) =>
        string.Equals(priority, "Emergency", StringComparison.Ordinal)
        || string.Equals(priority, "Alert", StringComparison.Ordinal)
        || string.Equals(priority, "Critical", StringComparison.Ordinal);
}
