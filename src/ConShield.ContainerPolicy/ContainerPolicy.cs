using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ConShield.ContainerPolicy;

public enum ContainerPolicyDecision
{
    Allow,
    Warn,
    Block
}

public static class ContainerPolicyReasonCodes
{
    public const string ImageDenied = "IMAGE_DENIED";
    public const string CriticalThresholdReached = "CRITICAL_THRESHOLD_REACHED";
    public const string HighBlockThresholdReached = "HIGH_BLOCK_THRESHOLD_REACHED";
    public const string TotalBlockThresholdReached = "TOTAL_BLOCK_THRESHOLD_REACHED";
    public const string HighWarningThresholdReached = "HIGH_WARNING_THRESHOLD_REACHED";
    public const string MediumWarningThresholdReached = "MEDIUM_WARNING_THRESHOLD_REACHED";
    public const string UnknownWarningThresholdReached = "UNKNOWN_WARNING_THRESHOLD_REACHED";
    public const string WithinPolicy = "WITHIN_POLICY";
}

public sealed class ContainerPolicyDocument
{
    public int SchemaVersion { get; init; }
    public string PolicyId { get; init; } = string.Empty;
    public string Version { get; init; } = string.Empty;
    public ContainerPolicyThresholds Thresholds { get; init; } = new();
    public IReadOnlyList<string> DeniedImages { get; init; } = [];
    public string PolicySha256 { get; init; } = string.Empty;
}

public sealed class ContainerPolicyThresholds
{
    public int? CriticalBlock { get; init; }
    public int? HighBlock { get; init; }
    public int? TotalBlock { get; init; }
    public int? HighWarn { get; init; }
    public int? MediumWarn { get; init; }
    public int? UnknownWarn { get; init; }
}

public sealed class ContainerImageScanSummary
{
    public string ImageReference { get; init; } = string.Empty;
    public string? ImageDigest { get; init; }
    public string ReportSha256 { get; init; } = string.Empty;
    public int UnknownCount { get; init; }
    public int LowCount { get; init; }
    public int MediumCount { get; init; }
    public int HighCount { get; init; }
    public int CriticalCount { get; init; }
    public int TotalCount { get; init; }
}

public sealed class ContainerPolicyEvaluation
{
    public ContainerPolicyDecision Decision { get; init; }
    public IReadOnlyList<string> ReasonCodes { get; init; } = [];
    public string TriggerIdentity { get; init; } = string.Empty;
}

public sealed class ContainerPolicyLoadResult
{
    private ContainerPolicyLoadResult(ContainerPolicyDocument? policy, string? error)
    {
        Policy = policy;
        Error = error;
    }

    public bool Success => Policy is not null;
    public ContainerPolicyDocument? Policy { get; }
    public string? Error { get; }

    public static ContainerPolicyLoadResult Loaded(ContainerPolicyDocument policy) => new(policy, null);
    public static ContainerPolicyLoadResult Invalid(string error) => new(null, error);
}

public sealed class ContainerPolicyEvaluationResult
{
    private ContainerPolicyEvaluationResult(ContainerPolicyEvaluation? evaluation, string? error)
    {
        Evaluation = evaluation;
        Error = error;
    }

    public bool Success => Evaluation is not null;
    public ContainerPolicyEvaluation? Evaluation { get; }
    public string? Error { get; }

    public static ContainerPolicyEvaluationResult Evaluated(ContainerPolicyEvaluation evaluation) => new(evaluation, null);
    public static ContainerPolicyEvaluationResult Invalid(string error) => new(null, error);
}

public sealed class ContainerPolicyLoader
{
    public const int MaxPolicyBytes = 64 * 1024;
    private const int MaxTextLength = 128;
    private const int MaxDeniedImages = 64;
    private const int MaxThreshold = 100000;
    private static readonly JsonSerializerOptions Options = new()
    {
        AllowTrailingCommas = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public ContainerPolicyLoadResult LoadFromFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return ContainerPolicyLoadResult.Invalid("--policy is required.");

        if (Uri.TryCreate(path, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https")
            return ContainerPolicyLoadResult.Invalid("Policy path must be a local file path.");

        FileInfo file;
        try
        {
            file = new FileInfo(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return ContainerPolicyLoadResult.Invalid("Policy path is invalid.");
        }

        if (!file.Exists)
            return ContainerPolicyLoadResult.Invalid("Policy file was not found.");

        if (file.Length <= 0 || file.Length > MaxPolicyBytes)
            return ContainerPolicyLoadResult.Invalid($"Policy file must be between 1 and {MaxPolicyBytes} bytes.");

        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(file.FullName);
        }
        catch (IOException ex)
        {
            return ContainerPolicyLoadResult.Invalid($"Policy file could not be read: {ex.Message}");
        }

        return Load(bytes);
    }

    public ContainerPolicyLoadResult Load(byte[] bytes)
    {
        if (bytes.Length <= 0 || bytes.Length > MaxPolicyBytes)
            return ContainerPolicyLoadResult.Invalid($"Policy file must be between 1 and {MaxPolicyBytes} bytes.");

        string json;
        try
        {
            json = new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            return ContainerPolicyLoadResult.Invalid("Policy must be valid UTF-8.");
        }

        PolicyFile? file;
        try
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                return ContainerPolicyLoadResult.Invalid("Policy root must be a JSON object.");

            file = JsonSerializer.Deserialize<PolicyFile>(json, Options);
        }
        catch (JsonException ex)
        {
            return ContainerPolicyLoadResult.Invalid($"Policy JSON is invalid: {ex.Message}");
        }

        if (file is null)
            return ContainerPolicyLoadResult.Invalid("Policy JSON is invalid.");

        var validation = Validate(file);
        if (validation is not null)
            return ContainerPolicyLoadResult.Invalid(validation);

        return ContainerPolicyLoadResult.Loaded(new ContainerPolicyDocument
        {
            SchemaVersion = file.SchemaVersion,
            PolicyId = file.PolicyId!.Trim(),
            Version = file.Version!.Trim(),
            Thresholds = new ContainerPolicyThresholds
            {
                CriticalBlock = file.Thresholds!.CriticalBlock,
                HighBlock = file.Thresholds.HighBlock,
                TotalBlock = file.Thresholds.TotalBlock,
                HighWarn = file.Thresholds.HighWarn,
                MediumWarn = file.Thresholds.MediumWarn,
                UnknownWarn = file.Thresholds.UnknownWarn
            },
            DeniedImages = file.DeniedImages!.Select(NormalizeIdentity).ToArray(),
            PolicySha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()
        });
    }

    private static string? Validate(PolicyFile file)
    {
        if (file.SchemaVersion != 1)
            return "Only policy schemaVersion 1 is supported.";

        if (!IsSafeText(file.PolicyId, MaxTextLength))
            return "policyId is required and must contain safe text.";

        if (!IsSafeText(file.Version, MaxTextLength))
            return "version is required and must contain safe text.";

        if (file.Thresholds is null)
            return "thresholds is required.";

        var thresholds = new[]
        {
            file.Thresholds.CriticalBlock,
            file.Thresholds.HighBlock,
            file.Thresholds.TotalBlock,
            file.Thresholds.HighWarn,
            file.Thresholds.MediumWarn,
            file.Thresholds.UnknownWarn
        };

        if (thresholds.Any(x => x is <= 0 or > MaxThreshold))
            return $"threshold values must be between 1 and {MaxThreshold}.";

        if (file.Thresholds.HighWarn.HasValue && file.Thresholds.HighBlock.HasValue
            && file.Thresholds.HighWarn.Value > file.Thresholds.HighBlock.Value)
            return "highWarn must not be greater than highBlock.";

        if (file.DeniedImages is null)
            return "deniedImages is required.";

        if (file.DeniedImages.Count > MaxDeniedImages)
            return $"deniedImages must contain at most {MaxDeniedImages} entries.";

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var image in file.DeniedImages)
        {
            if (!IsSafeText(image, 512))
                return "deniedImages entries must contain safe text.";

            var normalized = NormalizeIdentity(image!);
            if (!seen.Add(normalized))
                return "deniedImages must not contain duplicates.";
        }

        return null;
    }

    private static bool IsSafeText(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        var trimmed = value.Trim();
        return trimmed.Length <= maxLength && trimmed.All(x => !char.IsControl(x));
    }

    private sealed class PolicyFile
    {
        public int SchemaVersion { get; set; }
        public string? PolicyId { get; set; }
        public string? Version { get; set; }
        public PolicyThresholdFile? Thresholds { get; set; }
        public List<string>? DeniedImages { get; set; }
    }

    private sealed class PolicyThresholdFile
    {
        public int? CriticalBlock { get; set; }
        public int? HighBlock { get; set; }
        public int? TotalBlock { get; set; }
        public int? HighWarn { get; set; }
        public int? MediumWarn { get; set; }
        public int? UnknownWarn { get; set; }
    }

    internal static string NormalizeIdentity(string value)
    {
        var normalized = value.Trim().ToLowerInvariant();
        normalized = new string(normalized.Where(x => !char.IsControl(x)).ToArray());
        return normalized.Length <= 512 ? normalized : normalized[..512];
    }
}

public sealed class ContainerPolicyEvaluator
{
    public ContainerPolicyEvaluationResult Evaluate(ContainerPolicyDocument policy, ContainerImageScanSummary summary)
    {
        if (string.IsNullOrWhiteSpace(summary.ImageReference))
            return ContainerPolicyEvaluationResult.Invalid("Scan summary imageReference is required.");

        if (new[] { summary.UnknownCount, summary.LowCount, summary.MediumCount, summary.HighCount, summary.CriticalCount, summary.TotalCount }.Any(x => x < 0))
            return ContainerPolicyEvaluationResult.Invalid("Scan summary counts must be non-negative.");

        if (summary.TotalCount < summary.UnknownCount + summary.LowCount + summary.MediumCount + summary.HighCount + summary.CriticalCount)
            return ContainerPolicyEvaluationResult.Invalid("Scan summary totalCount is lower than severity counts.");

        var imageReference = ContainerPolicyLoader.NormalizeIdentity(summary.ImageReference);
        var imageDigest = string.IsNullOrWhiteSpace(summary.ImageDigest)
            ? null
            : ContainerPolicyLoader.NormalizeIdentity(summary.ImageDigest);
        var identity = imageDigest ?? imageReference;
        var reasons = new List<string>();

        if (policy.DeniedImages.Contains(identity, StringComparer.Ordinal)
            || policy.DeniedImages.Contains(imageReference, StringComparer.Ordinal))
        {
            reasons.Add(ContainerPolicyReasonCodes.ImageDenied);
        }

        AddIfReached(reasons, ContainerPolicyReasonCodes.CriticalThresholdReached, summary.CriticalCount, policy.Thresholds.CriticalBlock);
        AddIfReached(reasons, ContainerPolicyReasonCodes.HighBlockThresholdReached, summary.HighCount, policy.Thresholds.HighBlock);
        AddIfReached(reasons, ContainerPolicyReasonCodes.TotalBlockThresholdReached, summary.TotalCount, policy.Thresholds.TotalBlock);

        if (reasons.Count > 0)
        {
            return ContainerPolicyEvaluationResult.Evaluated(new ContainerPolicyEvaluation
            {
                Decision = ContainerPolicyDecision.Block,
                ReasonCodes = reasons,
                TriggerIdentity = identity
            });
        }

        AddIfReached(reasons, ContainerPolicyReasonCodes.HighWarningThresholdReached, summary.HighCount, policy.Thresholds.HighWarn);
        AddIfReached(reasons, ContainerPolicyReasonCodes.MediumWarningThresholdReached, summary.MediumCount, policy.Thresholds.MediumWarn);
        AddIfReached(reasons, ContainerPolicyReasonCodes.UnknownWarningThresholdReached, summary.UnknownCount, policy.Thresholds.UnknownWarn);

        if (reasons.Count > 0)
        {
            return ContainerPolicyEvaluationResult.Evaluated(new ContainerPolicyEvaluation
            {
                Decision = ContainerPolicyDecision.Warn,
                ReasonCodes = reasons,
                TriggerIdentity = identity
            });
        }

        return ContainerPolicyEvaluationResult.Evaluated(new ContainerPolicyEvaluation
        {
            Decision = ContainerPolicyDecision.Allow,
            ReasonCodes = [ContainerPolicyReasonCodes.WithinPolicy],
            TriggerIdentity = identity
        });
    }

    private static void AddIfReached(List<string> reasons, string reasonCode, int actual, int? threshold)
    {
        if (threshold.HasValue && actual >= threshold.Value)
            reasons.Add(reasonCode);
    }
}
