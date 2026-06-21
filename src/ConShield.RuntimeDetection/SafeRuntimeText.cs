using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace ConShield.RuntimeDetection;

public static class SafeRuntimeText
{
    private static readonly Regex UserInfoRegex = new(@"(?<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]+@", RegexOptions.Compiled);
    private static readonly Regex UrlRegex = new(
        """[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'<>]+""",
        RegexOptions.Compiled);
    private static readonly Regex CredentialAssignmentRegex = new(
        """(?<name>\b(?:password|passwd|pwd|token|access_token|secret|apikey|api_key|authorization)\b)\s*[:=]\s*(?:"[^"]*"|'[^']*'|bearer\s+[^\s,;&]+|[^\s,;&]+)""",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex BearerRegex = new(
        """\bbearer\s+[a-zA-Z0-9._~+/=-]+""",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

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
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var safe = new string(value.Where(ch => !char.IsControl(ch)).ToArray()).Trim();
        if (safe.Length == 0)
            return null;

        safe = UrlRegex.Replace(safe, match => SanitizeUrl(match.Value));
        safe = UserInfoRegex.Replace(safe, "${scheme}***:***@");
        safe = CredentialAssignmentRegex.Replace(safe, "${name}=***");
        safe = BearerRegex.Replace(safe, "Bearer ***");
        return safe.Length <= maxLength ? safe : safe[..maxLength];
    }

    private static string SanitizeUrl(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
            return UserInfoRegex.Replace(value.Split('?', '#')[0], "${scheme}***:***@");

        try
        {
            var builder = new UriBuilder(uri)
            {
                UserName = string.Empty,
                Password = string.Empty,
                Query = string.Empty,
                Fragment = string.Empty
            };
            return builder.Uri.GetComponents(
                UriComponents.SchemeAndServer | UriComponents.Path,
                UriFormat.UriEscaped);
        }
        catch (UriFormatException)
        {
            return UserInfoRegex.Replace(value.Split('?', '#')[0], "${scheme}***:***@");
        }
    }

    public static string Sha256Hex(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    public static string Sha256Hex(byte[] value) =>
        Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();
}
