using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace ConShield.RuntimeDetection;

public sealed record SignedSensorEventEnvelope(
    string SensorId,
    string SourceSystem,
    string EventType,
    DateTime EventTimestampUtc,
    string Nonce,
    string SignatureAlgorithm,
    string SignatureKeyId,
    string? Signature,
    string CanonicalPayloadHash);

public sealed record SignedSensorEventVerificationResult(
    string Status,
    string Reason,
    RuntimeSignatureMetadata Metadata);

public static class SignedSensorEventVerifier
{
    public const string DemoSignatureAlgorithm = "HMAC-SHA256-DEMO";
    public const string DemoSignatureKeyId = "demo-signing-key-v1";
    public const string DemoSigningMaterial = "conshield-public-demo-signing-material-v1";
    private static readonly TimeSpan DefaultMaxAge = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan DefaultFutureSkew = TimeSpan.FromMinutes(5);

    public static string ComputeCanonicalPayloadHash(string value)
    {
        var normalized = value.Trim();
        return SafeRuntimeText.Sha256Hex(Encoding.UTF8.GetBytes(normalized));
    }

    public static string CreateSignature(SignedSensorEventEnvelope envelope, string signingMaterial)
    {
        var canonical = Canonicalize(envelope);
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(signingMaterial));
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    public static SignedSensorEventVerificationResult Verify(
        SignedSensorEventEnvelope? envelope,
        string? signingMaterial,
        DateTime? nowUtc = null,
        TimeSpan? maxAge = null,
        TimeSpan? futureSkew = null,
        bool signatureRequired = true,
        bool replayDetected = false)
    {
        var now = DateTime.SpecifyKind(nowUtc ?? DateTime.UtcNow, DateTimeKind.Utc);
        if (envelope is null)
        {
            return Result(
                sensorId: "-",
                timestampUtc: null,
                nonce: null,
                algorithm: null,
                keyId: null,
                canonicalPayloadHash: null,
                status: signatureRequired ? RuntimeSignatureStatuses.Missing : RuntimeSignatureStatuses.NotRequired,
                reason: signatureRequired ? "signature metadata is missing" : "signature is not required");
        }

        if (string.IsNullOrWhiteSpace(envelope.Signature))
            return Result(envelope, RuntimeSignatureStatuses.Missing, "signature value is missing");

        if (string.IsNullOrWhiteSpace(envelope.SignatureKeyId))
            return Result(envelope, RuntimeSignatureStatuses.UnknownKey, "signature key id is missing");

        if (!string.Equals(envelope.SignatureAlgorithm, DemoSignatureAlgorithm, StringComparison.Ordinal))
            return Result(envelope, RuntimeSignatureStatuses.Invalid, "signature algorithm is unsupported");

        if (string.IsNullOrWhiteSpace(signingMaterial))
            return Result(envelope, RuntimeSignatureStatuses.UnknownKey, "signing material is unavailable");

        if (replayDetected)
            return Result(envelope, RuntimeSignatureStatuses.ReplayDetected, "signature nonce was already observed");

        var age = now - DateTime.SpecifyKind(envelope.EventTimestampUtc, DateTimeKind.Utc);
        if (age > (maxAge ?? DefaultMaxAge) || age < -(futureSkew ?? DefaultFutureSkew))
            return Result(envelope, RuntimeSignatureStatuses.Stale, "signature timestamp is outside the accepted window");

        var expected = CreateSignature(envelope, signingMaterial);
        return FixedTimeEquals(expected, envelope.Signature)
            ? Result(envelope, RuntimeSignatureStatuses.Valid, "signature verified")
            : Result(envelope, RuntimeSignatureStatuses.Invalid, "signature mismatch");
    }

    public static string Canonicalize(SignedSensorEventEnvelope envelope)
    {
        var values = new[]
        {
            envelope.SensorId,
            envelope.SourceSystem,
            envelope.EventType,
            envelope.EventTimestampUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
            envelope.Nonce,
            envelope.SignatureAlgorithm,
            envelope.SignatureKeyId,
            envelope.CanonicalPayloadHash
        };
        return string.Join("\n", values.Select(value => value?.Trim() ?? string.Empty));
    }

    private static SignedSensorEventVerificationResult Result(
        SignedSensorEventEnvelope envelope,
        string status,
        string reason) =>
        Result(
            envelope.SensorId,
            envelope.EventTimestampUtc,
            envelope.Nonce,
            envelope.SignatureAlgorithm,
            envelope.SignatureKeyId,
            envelope.CanonicalPayloadHash,
            status,
            reason);

    private static SignedSensorEventVerificationResult Result(
        string sensorId,
        DateTime? timestampUtc,
        string? nonce,
        string? algorithm,
        string? keyId,
        string? canonicalPayloadHash,
        string status,
        string reason) =>
        new(
            status,
            reason,
            new RuntimeSignatureMetadata(
                sensorId,
                timestampUtc,
                nonce,
                algorithm,
                keyId,
                canonicalPayloadHash,
                status,
                reason));

    private static bool FixedTimeEquals(string left, string right)
    {
        var leftBytes = Encoding.ASCII.GetBytes(left);
        var rightBytes = Encoding.ASCII.GetBytes(right);
        return leftBytes.Length == rightBytes.Length && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }
}
