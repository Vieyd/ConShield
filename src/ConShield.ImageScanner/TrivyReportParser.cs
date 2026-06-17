using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ConShield.ImageScanner;

public static class TrivyReportParser
{
    private const int MaxArrayItems = 10_000;
    private const int MaxStringLength = 2048;

    public static ImageScanSummary Parse(string reportJson, string scannerVersion, string requestedImageReference)
    {
        if (Encoding.UTF8.GetByteCount(reportJson) > ScannerConstants.MaxReportBytes)
            throw new TrivyReportParseException("Trivy JSON report exceeded the maximum allowed size.");

        TrivyReport? report;
        try
        {
            report = JsonSerializer.Deserialize(reportJson, ImageScannerJsonContext.Default.TrivyReport);
        }
        catch (JsonException ex)
        {
            throw new TrivyReportParseException("Malformed Trivy JSON report.", ex);
        }

        if (report is null)
            throw new TrivyReportParseException("Trivy JSON report is empty.");

        var findings = new List<NormalizedFinding>();
        var targets = new HashSet<string>(StringComparer.Ordinal);

        foreach (var result in Limit(report.Results))
        {
            var target = NormalizeString(result.Target, 512);
            var hasFindingsForTarget = false;

            foreach (var vulnerability in Limit(result.Vulnerabilities))
            {
                var finding = new NormalizedFinding(
                    NormalizeString(vulnerability.VulnerabilityID, MaxStringLength),
                    NormalizeString(vulnerability.PkgName, MaxStringLength),
                    NormalizeString(vulnerability.InstalledVersion, MaxStringLength),
                    NormalizeString(vulnerability.FixedVersion, MaxStringLength),
                    NormalizeSeverity(vulnerability.Severity),
                    target);

                findings.Add(finding);
                hasFindingsForTarget = true;
            }

            if (hasFindingsForTarget && !string.IsNullOrWhiteSpace(target))
                targets.Add(target);
        }

        var deduped = findings
            .DistinctBy(x => $"{x.Target}\u001f{x.VulnerabilityId}\u001f{x.PackageName}\u001f{x.InstalledVersion}")
            .ToList();

        return new ImageScanSummary
        {
            ScannerVersion = scannerVersion,
            ImageReference = SelectImageReference(report, requestedImageReference),
            ImageDigest = SelectImageDigest(report),
            ArtifactType = NormalizeString(report.ArtifactType, 128),
            UnknownCount = deduped.Count(x => x.Severity == "UNKNOWN"),
            LowCount = deduped.Count(x => x.Severity == "LOW"),
            MediumCount = deduped.Count(x => x.Severity == "MEDIUM"),
            HighCount = deduped.Count(x => x.Severity == "HIGH"),
            CriticalCount = deduped.Count(x => x.Severity == "CRITICAL"),
            TotalCount = deduped.Count,
            FixAvailableCount = deduped.Count(x => !string.IsNullOrWhiteSpace(x.FixedVersion)),
            AffectedTargetCount = targets.Count,
            ReportSha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(reportJson))).ToLowerInvariant()
        };
    }

    public static string? SelectImageDigest(TrivyReport report)
    {
        return Limit(report.Metadata?.RepoDigests)
            .Select(x => NormalizeString(x, 512))
            .FirstOrDefault(x => !string.IsNullOrWhiteSpace(x) && x.Contains("@sha256:", StringComparison.OrdinalIgnoreCase));
    }

    private static string SelectImageReference(TrivyReport report, string requestedImageReference)
    {
        var repoTag = Limit(report.Metadata?.RepoTags)
            .Select(x => NormalizeString(x, ScannerOptions.MaxImageReferenceLength))
            .FirstOrDefault(x => !string.IsNullOrWhiteSpace(x));

        return repoTag
            ?? NormalizeString(report.ArtifactName, ScannerOptions.MaxImageReferenceLength)
            ?? requestedImageReference;
    }

    private static string NormalizeSeverity(string? value)
    {
        return value?.Trim().ToUpperInvariant() switch
        {
            "LOW" => "LOW",
            "MEDIUM" => "MEDIUM",
            "HIGH" => "HIGH",
            "CRITICAL" => "CRITICAL",
            _ => "UNKNOWN"
        };
    }

    private static string? NormalizeString(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var normalized = value.Trim();
        if (normalized.Any(char.IsControl))
            normalized = new string(normalized.Where(x => !char.IsControl(x)).ToArray());

        return normalized.Length <= maxLength ? normalized : normalized[..maxLength];
    }

    private static IEnumerable<T> Limit<T>(IEnumerable<T>? values)
    {
        return values?.Take(MaxArrayItems) ?? [];
    }

    private sealed record NormalizedFinding(
        string? VulnerabilityId,
        string? PackageName,
        string? InstalledVersion,
        string? FixedVersion,
        string Severity,
        string? Target);
}

public sealed class TrivyReportParseException : Exception
{
    public TrivyReportParseException(string message) : base(message)
    {
    }

    public TrivyReportParseException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
