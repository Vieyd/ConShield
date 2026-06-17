namespace ConShield.ImageScanner;

public static class Redaction
{
    public static string RedactImageReference(string value)
    {
        var at = value.IndexOf('@');
        var slash = value.IndexOf('/');
        if (at > 0 && slash > at)
            return "***:***@" + value[(at + 1)..];

        return value;
    }

    public static string TrimForSafeOutput(string value, int maxLength)
    {
        var sanitized = value.Replace("\0", string.Empty, StringComparison.Ordinal)
            .Replace("\r", " ", StringComparison.Ordinal)
            .Replace("\n", " ", StringComparison.Ordinal);

        return sanitized.Length <= maxLength ? sanitized : sanitized[..maxLength] + "...";
    }
}
