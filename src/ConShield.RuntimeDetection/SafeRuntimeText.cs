using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace ConShield.RuntimeDetection;

public static class SafeRuntimeText
{
    private static readonly Regex UserInfoRegex = new(@"(?<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]+@", RegexOptions.Compiled);

    public static string? Clean(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        var safe = new string(value.Where(ch => !char.IsControl(ch)).ToArray()).Trim();
        if (safe.Length == 0)
            return null;
        return safe.Length <= maxLength ? safe : safe[..maxLength];
    }

    public static string? RedactCredentialLike(string? value, int maxLength)
    {
        var safe = Clean(value, maxLength);
        if (safe is null)
            return null;
        safe = UserInfoRegex.Replace(safe, "${scheme}***:***@");
        var at = safe.IndexOf('@');
        var slash = safe.IndexOf('/');
        if (at > 0 && slash > at)
            safe = "***:***@" + safe[(at + 1)..];
        return safe.Length <= maxLength ? safe : safe[..maxLength];
    }

    public static string Sha256Hex(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    public static string Sha256Hex(byte[] value) =>
        Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();
}
