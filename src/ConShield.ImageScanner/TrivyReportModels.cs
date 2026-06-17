using System.Text.Json.Serialization;

namespace ConShield.ImageScanner;

public sealed class TrivyReport
{
    public string? ArtifactName { get; set; }
    public string? ArtifactType { get; set; }
    public TrivyMetadata? Metadata { get; set; }
    public List<TrivyResult>? Results { get; set; }
}

public sealed class TrivyMetadata
{
    public string? ImageID { get; set; }
    public List<string>? RepoTags { get; set; }
    public List<string>? RepoDigests { get; set; }
}

public sealed class TrivyResult
{
    public string? Target { get; set; }
    public string? Class { get; set; }
    public string? Type { get; set; }
    public List<TrivyVulnerability>? Vulnerabilities { get; set; }
}

public sealed class TrivyVulnerability
{
    public string? VulnerabilityID { get; set; }
    public string? PkgName { get; set; }
    public string? InstalledVersion { get; set; }
    public string? FixedVersion { get; set; }
    public string? Severity { get; set; }
}

[JsonSerializable(typeof(TrivyReport))]
[JsonSerializable(typeof(ImageScanIngestRequest))]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true)]
internal partial class ImageScannerJsonContext : JsonSerializerContext
{
}
