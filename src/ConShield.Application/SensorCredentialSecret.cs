using System.Security.Cryptography;
using System.Text;

namespace ConShield.Application;

internal static class SensorCredentialSecret
{
    public static (string Credential, byte[] VerifierSha256) Create()
    {
        var credentialBytes = RandomNumberGenerator.GetBytes(SensorProvisioningService.CredentialEntropyBytes);
        try
        {
            var credential = Base64UrlEncode(credentialBytes);
            return (credential, Hash(credential));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(credentialBytes);
        }
    }

    public static byte[] Hash(string credential) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(credential));

    private static string Base64UrlEncode(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
