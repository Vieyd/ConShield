namespace ConShield.Web.Options;

public sealed class ExternalEventIngestionOptions
{
    public bool Enabled { get; set; }
    public string ApiKey { get; set; } = string.Empty;
    public string RuntimeCollectorApiKey { get; set; } = string.Empty;
    public bool AllowLegacyRuntimeCollectorCredential { get; set; } = true;
    public long MaxRequestBodyBytes { get; set; } = 32 * 1024;
    public int AllowedFutureClockSkewMinutes { get; set; } = 5;
}
