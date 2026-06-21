namespace ConShield.Web.Security;

public static class SensorRequestIdentity
{
    public const string SensorIdHeader = "X-ConShield-Sensor-Id";
    public const string CredentialIdHeader = "X-ConShield-Credential-Id";
    public const string ApiKeyHeader = "X-ConShield-Api-Key";

    public static bool HasAnySensorHeader(HttpRequest request) =>
        request.Headers.ContainsKey(SensorIdHeader)
        || request.Headers.ContainsKey(CredentialIdHeader);

    public static bool TryRead(HttpRequest request, out Guid sensorId, out Guid credentialId, out string? credential)
    {
        sensorId = Guid.Empty;
        credentialId = Guid.Empty;
        credential = request.Headers[ApiKeyHeader].FirstOrDefault();
        return Guid.TryParse(request.Headers[SensorIdHeader].FirstOrDefault(), out sensorId)
            && sensorId != Guid.Empty
            && Guid.TryParse(request.Headers[CredentialIdHeader].FirstOrDefault(), out credentialId)
            && credentialId != Guid.Empty
            && !string.IsNullOrWhiteSpace(credential);
    }
}
