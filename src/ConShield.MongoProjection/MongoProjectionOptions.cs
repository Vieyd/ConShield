namespace ConShield.MongoProjection;

public sealed class MongoProjectionOptions
{
    public bool Enabled { get; set; }
    public string ConnectionString { get; set; } = string.Empty;
    public string DatabaseName { get; set; } = "conshield_events";
    public string CollectionName { get; set; } = "security_event_raw_v1";
    public int RetentionDays { get; set; } = 30;
    public int ConnectTimeoutSeconds { get; set; } = 10;
    public int OperationTimeoutSeconds { get; set; } = 10;
    public int MaxDocumentBytes { get; set; } = 262144;
}
