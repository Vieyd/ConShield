namespace ConShield.RuntimeDetection;

public static class RuntimeDetectionConstants
{
    public const string SourceSystem = "conshield.falco-runtime-collector";
    public const string Provider = "falco-compatible";
    public const string SchemaName = "falco-compatible-v1";
    public const int AdditionalDataSchemaVersion = 1;
    public const int MaxLineBytes = 262144;
    public const int MaxJsonDepth = 16;
    public const int MaxTags = 32;
    public const int MaxOutputFields = 64;
    public const int MaxRuleLength = 256;
    public const int MaxOutputLengthBeforeRedaction = 16384;
    public const int MaxHostnameLength = 255;
    public const int MaxFieldValueLength = 512;
    public const int MaxPolicyBytes = 65536;
    public const string UnmappedEventType = "container.runtime.unmapped";
}
