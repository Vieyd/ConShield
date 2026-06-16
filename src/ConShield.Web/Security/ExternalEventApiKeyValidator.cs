using System.Security.Cryptography;
using System.Text;

namespace ConShield.Web.Security;

public static class ExternalEventApiKeyValidator
{
    public static bool IsValid(string? providedApiKey, string configuredApiKey)
    {
        if (string.IsNullOrWhiteSpace(providedApiKey) || string.IsNullOrWhiteSpace(configuredApiKey))
            return false;

        var providedBytes = SHA256.HashData(Encoding.UTF8.GetBytes(providedApiKey));
        var configuredBytes = SHA256.HashData(Encoding.UTF8.GetBytes(configuredApiKey));
        return CryptographicOperations.FixedTimeEquals(providedBytes, configuredBytes);
    }

    public static string PartitionFingerprint(string? providedApiKey)
    {
        if (string.IsNullOrWhiteSpace(providedApiKey))
            return "missing";

        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(providedApiKey));
        return Convert.ToHexString(bytes, 0, 8);
    }
}
