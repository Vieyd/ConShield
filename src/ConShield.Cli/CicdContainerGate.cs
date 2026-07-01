using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ConShield.ImageScanner;

namespace ConShield.Cli;

internal static class CicdContainerGate
{
    public const int ExitPassed = 0;
    public const int ExitPolicyFailed = 1;
    public const int ExitUsageOrInput = 2;
    public const int ExitInfrastructure = 3;

    private const int MaxPolicyBytes = 64 * 1024;
    private const int MaxReportBytes = ScannerConstants.MaxReportBytes;
    private static readonly StringComparer OrdinalIgnoreCase = StringComparer.OrdinalIgnoreCase;

    public static int RunImageGate(string repoRoot, string[] args, TextWriter output, TextWriter error)
    {
        try
        {
            var options = GateOptions.Parse(repoRoot, args);
            var result = Evaluate(repoRoot, options);

            if (!string.IsNullOrWhiteSpace(options.ReportPath))
                WriteMarkdownReport(repoRoot, options.ReportPath!, result);

            if (!string.IsNullOrWhiteSpace(options.JsonReportPath))
                WriteJsonReport(repoRoot, options.JsonReportPath!, result);

            WriteSummary(output, result);

            if (options.Submit)
            {
                error.WriteLine("Submit: unsupported in CI/CD Container Gate v1. Use --no-submit for deterministic CI, or use existing scan/protected-run workflows for ingestion.");
                output.WriteLine("Gate: INFRASTRUCTURE_ERROR");
                output.WriteLine($"Exit code: {ExitInfrastructure}");
                output.WriteLine("Result: FAIL");
                return ExitInfrastructure;
            }

            output.WriteLine($"Gate: {result.Gate}");
            output.WriteLine($"Exit code: {result.ExitCode}");
            output.WriteLine($"Result: {(result.ExitCode == ExitPolicyFailed ? "FAIL" : "PASS")}");
            return result.ExitCode;
        }
        catch (GateUsageException ex)
        {
            error.WriteLine($"Usage error: {SafeText(ex.Message, 512)}");
            error.WriteLine("Usage: dotnet run --project .\\src\\ConShield.Cli -- gate image --image <image> --from-trivy-json <path> --fail-on block|warn|never --no-submit");
            error.WriteLine("Live:  dotnet run --project .\\src\\ConShield.Cli -- gate image --image <image> --live-trivy --fail-on block --no-submit");
            output.WriteLine("Result: FAIL");
            return ExitUsageOrInput;
        }
        catch (GateLiveTrivyException ex)
        {
            output.WriteLine("ConShield CI/CD image gate");
            output.WriteLine($"Image: {SafeText(ex.Image, 256)}");
            output.WriteLine("Scanner: Trivy");
            output.WriteLine("Mode: live");
            output.WriteLine($"Trivy: {ex.Status}");
            if (!string.IsNullOrWhiteSpace(ex.SafeError))
                output.WriteLine($"Scan: FAIL ({SafeText(ex.SafeError, 512)})");
            output.WriteLine($"Hint: {ex.Hint}");
            output.WriteLine("Gate: INFRASTRUCTURE_ERROR");
            output.WriteLine($"Exit code: {ExitInfrastructure}");
            output.WriteLine("Result: FAIL");
            return ExitInfrastructure;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or TrivyReportParseException)
        {
            error.WriteLine($"Input error: {SafeText(ex.Message, 512)}");
            output.WriteLine("Result: FAIL");
            return ExitUsageOrInput;
        }
    }

    public static GateResult Evaluate(string repoRoot, GateOptions options)
    {
        var scanInput = ReadScanInput(options);
        var summary = TrivyReportParser.Parse(scanInput.ReportJson, scanInput.ScannerVersion, options.Image);
        var extended = ReadExtendedCounts(scanInput.ReportJson);
        var policy = ContainerPolicyConfig.Load(repoRoot, options.PolicyPath);
        var evaluation = EvaluatePolicy(policy, summary, extended);
        var exitCode = GetExitCode(evaluation.Decision, options.FailOn);

        var gate = exitCode == ExitPolicyFailed
            ? "FAIL"
            : evaluation.Decision == "Allow" ? "PASS" : "PASS_WITH_FINDINGS";

        return new GateResult(
            options.Image,
            RedactImage(summary.ImageReference),
            options.FailOn,
            policy,
            summary,
            extended,
            evaluation,
            gate,
            exitCode,
            DisplayPath(repoRoot, options.ReportPath),
            DisplayPath(repoRoot, options.JsonReportPath),
            options.Submit,
            scanInput.Mode,
            scanInput.TrivyStatus);
    }

    private static GateScanInput ReadScanInput(GateOptions options)
    {
        if (!options.LiveTrivy)
        {
            return new GateScanInput(
                ReadFixtureJson(options.TrivyJsonPath!),
                "fixture",
                "fixture",
                "SKIP (fixture)");
        }

        var result = LiveTrivyScanner.ScanAsync(options.Image, options.TrivyPath, options.TimeoutSeconds)
            .GetAwaiter()
            .GetResult();

        if (result.IsSuccess)
            return new GateScanInput(result.ReportJson!, result.ScannerVersion ?? "unknown", "live", "OK");

        var status = result.FailureKind == LiveTrivyFailureKind.Unavailable ? "unavailable" : "failed";
        var hint = result.FailureKind == LiveTrivyFailureKind.Unavailable
            ? LiveTrivyScanner.UnavailableHint
            : LiveTrivyScanner.FailedHint;

        throw new GateLiveTrivyException(options.Image, status, hint, result.SafeError);
    }

    private static string ReadFixtureJson(string path)
    {
        var file = new FileInfo(path);
        if (!file.Exists)
            throw new GateUsageException("--from-trivy-json file does not exist.");

        if (file.Length <= 0 || file.Length > MaxReportBytes)
            throw new GateUsageException("--from-trivy-json file size is invalid.");

        return File.ReadAllText(file.FullName, Encoding.UTF8);
    }

    private static ExtendedScanCounts ReadExtendedCounts(string reportJson)
    {
        using var document = JsonDocument.Parse(reportJson);
        var secretCount = 0;
        var criticalSecretCount = 0;
        var misconfigurationCount = 0;

        if (document.RootElement.TryGetProperty("Results", out var results) && results.ValueKind == JsonValueKind.Array)
        {
            foreach (var result in results.EnumerateArray().Take(10_000))
            {
                if (result.TryGetProperty("Secrets", out var secrets) && secrets.ValueKind == JsonValueKind.Array)
                {
                    foreach (var secret in secrets.EnumerateArray().Take(10_000))
                    {
                        secretCount++;
                        if (secret.TryGetProperty("Severity", out var severity)
                            && string.Equals(severity.GetString(), "CRITICAL", StringComparison.OrdinalIgnoreCase))
                        {
                            criticalSecretCount++;
                        }
                    }
                }

                if (result.TryGetProperty("Misconfigurations", out var misconfigurations) && misconfigurations.ValueKind == JsonValueKind.Array)
                    misconfigurationCount += misconfigurations.EnumerateArray().Take(10_000).Count();
            }
        }

        return new ExtendedScanCounts(secretCount, criticalSecretCount, misconfigurationCount);
    }

    private static GatePolicyEvaluation EvaluatePolicy(
        ContainerPolicyConfig policy,
        ImageScanSummary summary,
        ExtendedScanCounts extended)
    {
        var imageReference = NormalizeIdentity(summary.ImageReference);
        var imageDigest = string.IsNullOrWhiteSpace(summary.ImageDigest) ? null : NormalizeIdentity(summary.ImageDigest);
        var triggerIdentity = imageDigest ?? imageReference;

        var matches = policy.Rules
            .Where(rule => rule.Enabled && RuleMatches(rule, summary, extended, triggerIdentity, imageReference))
            .ToList();

        var decision = matches.Any(x => x.Decision == "Block")
            ? "Block"
            : matches.Any(x => x.Decision == "Warn")
                ? "Warn"
                : matches.Any(x => x.Decision == "Allow")
                    ? "Allow"
                    : policy.DefaultDecision;

        var selectedRules = matches.Where(x => x.Decision == decision).ToList();
        var matchedIds = selectedRules.Select(x => x.Id).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray();
        var reasonSummary = selectedRules.Count == 0
            ? "No policy rule matched."
            : string.Join("; ", selectedRules.Select(x => SafeText(x.Reason, 160)).Where(x => !string.IsNullOrWhiteSpace(x)));

        return new GatePolicyEvaluation(
            decision,
            matchedIds.Length == 0 ? ["WITHIN_POLICY"] : matchedIds,
            matchedIds,
            reasonSummary,
            triggerIdentity);
    }

    private static bool RuleMatches(
        ContainerPolicyRule rule,
        ImageScanSummary summary,
        ExtendedScanCounts extended,
        string triggerIdentity,
        string imageReference)
    {
        var matchedAny = false;

        foreach (var image in rule.DeniedImages)
        {
            var normalized = NormalizeIdentity(image);
            if (normalized == triggerIdentity || normalized == imageReference)
                return true;
        }

        foreach (var threshold in new[]
        {
            (Value: rule.CriticalVulnerabilitiesAtLeast, Actual: summary.CriticalCount),
            (Value: rule.HighVulnerabilitiesAtLeast, Actual: summary.HighCount),
            (Value: rule.MediumVulnerabilitiesAtLeast, Actual: summary.MediumCount),
            (Value: rule.LowVulnerabilitiesAtLeast, Actual: summary.LowCount),
            (Value: rule.UnknownVulnerabilitiesAtLeast, Actual: summary.UnknownCount),
            (Value: rule.TotalFindingsAtLeast, Actual: summary.TotalCount),
            (Value: rule.SecretsAtLeast, Actual: extended.SecretCount),
            (Value: rule.MisconfigurationsAtLeast, Actual: extended.MisconfigurationCount)
        })
        {
            if (threshold.Value is null)
                continue;

            matchedAny = true;
            if (threshold.Actual < threshold.Value.Value)
                return false;
        }

        return matchedAny;
    }

    private static int GetExitCode(string decision, string failOn) =>
        failOn switch
        {
            "never" => ExitPassed,
            "warn" => decision is "Warn" or "Block" ? ExitPolicyFailed : ExitPassed,
            _ => decision == "Block" ? ExitPolicyFailed : ExitPassed
        };

    private static void WriteSummary(TextWriter output, GateResult result)
    {
        output.WriteLine("ConShield CI/CD image gate");
        output.WriteLine($"Image: {SafeText(result.Image, 256)}");
        output.WriteLine("Scanner: Trivy");
        output.WriteLine($"Mode: {result.ScanMode}");
        output.WriteLine($"Trivy: {result.TrivyStatus}");
        output.WriteLine($"Policy: {result.Evaluation.Decision}");
        output.WriteLine($"Matched policy rules: {(result.Evaluation.MatchedPolicyRuleIds.Count > 0 ? string.Join(",", result.Evaluation.MatchedPolicyRuleIds) : "-")}");
        output.WriteLine($"Fail on: {result.FailOn}");
        output.WriteLine($"Critical vulnerabilities: {result.Scan.CriticalCount}");
        output.WriteLine($"High vulnerabilities: {result.Scan.HighCount}");
        output.WriteLine($"Total findings: {result.Scan.TotalCount}");
        output.WriteLine($"Policy config: {result.Policy.ConfigSource}");
        output.WriteLine($"Submit: {(result.Submit ? "REQUESTED" : "SKIP")}");
        if (!string.IsNullOrWhiteSpace(result.ReportDisplayPath))
            output.WriteLine($"Report: {result.ReportDisplayPath}");
        if (!string.IsNullOrWhiteSpace(result.JsonReportDisplayPath))
            output.WriteLine($"JSON report: {result.JsonReportDisplayPath}");
    }

    private static void WriteMarkdownReport(string repoRoot, string path, GateResult result)
    {
        var fullPath = ResolveOutputPath(repoRoot, path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        var matched = result.Evaluation.MatchedPolicyRuleIds.Count == 0
            ? "-"
            : string.Join(", ", result.Evaluation.MatchedPolicyRuleIds.Select(x => SafeText(x, 128)));

        var lines = new[]
        {
            "# ConShield CI/CD Gate Report",
            "",
            $"- Image: {SafeText(result.Image, 256)}",
            $"- Decision: {result.Evaluation.Decision}",
            $"- Gate: {result.Gate}",
            $"- Fail on: {result.FailOn}",
            $"- Policy config: {result.Policy.ConfigSource}",
            $"- Policy version: {result.Policy.Version}",
            $"- Policy hash: {result.Policy.PolicySha256}",
            $"- Matched policy rules: {matched}",
            $"- Critical vulnerabilities: {result.Scan.CriticalCount}",
            $"- High vulnerabilities: {result.Scan.HighCount}",
            $"- Medium vulnerabilities: {result.Scan.MediumCount}",
            $"- Total findings: {result.Scan.TotalCount}",
            $"- Fixes available: {result.Scan.FixAvailableCount}",
            $"- Report hash: {result.Scan.ReportSha256}",
            "",
            "## Safety",
            "",
            "Raw scanner JSON, secrets, environment variables, Docker logs, raw payload JSON, raw additional data, certificates, private keys, signing keys, and local artifacts are not included."
        };

        File.WriteAllLines(fullPath, lines, Encoding.UTF8);
    }

    private static void WriteJsonReport(string repoRoot, string path, GateResult result)
    {
        var fullPath = ResolveOutputPath(repoRoot, path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        var safe = new
        {
            image = SafeText(result.Image, 256),
            decision = result.Evaluation.Decision,
            gate = result.Gate,
            failOn = result.FailOn,
            policyConfig = result.Policy.ConfigSource,
            policyVersion = result.Policy.Version,
            matchedPolicyRules = result.Evaluation.MatchedPolicyRuleIds,
            criticalVulnerabilities = result.Scan.CriticalCount,
            highVulnerabilities = result.Scan.HighCount,
            mediumVulnerabilities = result.Scan.MediumCount,
            totalFindings = result.Scan.TotalCount,
            reportSha256 = result.Scan.ReportSha256
        };

        File.WriteAllText(fullPath, JsonSerializer.Serialize(safe, new JsonSerializerOptions { WriteIndented = true }), Encoding.UTF8);
    }

    private static string ResolveExistingFile(string repoRoot, string path, string optionName)
    {
        var fullPath = Path.IsPathRooted(path)
            ? Path.GetFullPath(path)
            : Path.GetFullPath(Path.Combine(repoRoot, path));

        if (!File.Exists(fullPath))
            throw new GateUsageException($"{optionName} file does not exist.");

        return fullPath;
    }

    private static string ResolveOutputPath(string repoRoot, string path) =>
        Path.IsPathRooted(path) ? Path.GetFullPath(path) : Path.GetFullPath(Path.Combine(repoRoot, path));

    private static string DisplayPath(string repoRoot, string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return string.Empty;

        var fullPath = ResolveOutputPath(repoRoot, path);
        var relative = Path.GetRelativePath(repoRoot, fullPath);
        return relative.StartsWith("..", StringComparison.Ordinal) || Path.IsPathRooted(relative)
            ? Path.GetFileName(fullPath)
            : relative.Replace('\\', '/');
    }

    private static string Sha256Hex(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static string NormalizeIdentity(string value)
    {
        var normalized = SafeText(value, 512).ToLowerInvariant();
        return normalized;
    }

    private static string RedactImage(string value)
    {
        var safe = SafeText(value, 512);
        var at = safe.IndexOf('@');
        var slash = safe.IndexOf('/');
        if (at > 0 && slash > at)
            return "***:***@" + safe[(at + 1)..];

        return safe;
    }

    private static string SafeText(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return string.Empty;

        var safe = value.Trim();
        safe = Regex.Replace(safe, "(?i)(password|secret|token|api[_ -]?key|authorization|bearer|cookie|credential|connection string)\\s*[:=]\\s*[^;\\s,]+", "$1=[redacted]");
        safe = Regex.Replace(safe, @"[\r\n\t]+", " ");
        safe = new string(safe.Where(x => !char.IsControl(x)).ToArray());
        return safe.Length <= maxLength ? safe : safe[..Math.Max(0, maxLength - 3)] + "...";
    }

    internal sealed record GateOptions(
        string Image,
        string? TrivyJsonPath,
        string PolicyPath,
        string FailOn,
        string? ReportPath,
        string? JsonReportPath,
        bool Submit,
        bool LiveTrivy,
        string? TrivyPath,
        int TimeoutSeconds)
    {
        public static GateOptions Parse(string repoRoot, string[] args)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var flags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            for (var i = 0; i < args.Length; i++)
            {
                var option = args[i];
                if (!option.StartsWith("--", StringComparison.Ordinal))
                    throw new GateUsageException($"Unexpected value without option: {SafeText(option, 128)}");

                if (option is "--no-submit" or "--submit" or "--live-trivy")
                {
                    flags.Add(option);
                    continue;
                }

                if (option is not ("--image" or "--from-trivy-json" or "--policy-config" or "--fail-on" or "--report" or "--json-report" or "--trivy-path" or "--timeout-seconds"))
                    throw new GateUsageException($"Unknown option: {SafeText(option, 128)}");

                if (i + 1 >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]) || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    throw new GateUsageException($"{option} requires a value.");

                values[option] = args[++i];
            }

            if (!values.TryGetValue("--image", out var image) || string.IsNullOrWhiteSpace(image))
                throw new GateUsageException("--image is required.");

            var liveTrivy = flags.Contains("--live-trivy");
            values.TryGetValue("--from-trivy-json", out var trivyJsonPath);
            if (liveTrivy && !string.IsNullOrWhiteSpace(trivyJsonPath))
                throw new GateUsageException("Use either --from-trivy-json or --live-trivy, not both.");
            if (!liveTrivy && string.IsNullOrWhiteSpace(trivyJsonPath))
                throw new GateUsageException("--from-trivy-json is required for CI-safe gate mode, or use --live-trivy --image <image> for optional live mode.");

            var failOn = values.GetValueOrDefault("--fail-on", "block").Trim().ToLowerInvariant();
            if (failOn is not ("block" or "warn" or "never"))
                throw new GateUsageException("--fail-on must be block, warn, or never.");

            var submit = flags.Contains("--submit");
            if (submit && flags.Contains("--no-submit"))
                throw new GateUsageException("Use either --submit or --no-submit, not both.");

            var timeoutSeconds = LiveTrivyScanner.DefaultTimeoutSeconds;
            if (values.TryGetValue("--timeout-seconds", out var timeoutValue))
            {
                if (!int.TryParse(timeoutValue, out timeoutSeconds))
                    throw new GateUsageException("--timeout-seconds must be an integer.");
                LiveTrivyScanner.ValidateTimeout(timeoutSeconds);
            }

            return new GateOptions(
                SafeText(image, 512),
                liveTrivy ? null : ResolveExistingFile(repoRoot, trivyJsonPath!, "--from-trivy-json"),
                ResolveExistingFile(repoRoot, values.GetValueOrDefault("--policy-config", Path.Combine("config", "container-policy.default.json")), "--policy-config"),
                failOn,
                values.GetValueOrDefault("--report"),
                values.GetValueOrDefault("--json-report"),
                submit,
                liveTrivy,
                values.GetValueOrDefault("--trivy-path"),
                timeoutSeconds);
        }
    }

    internal sealed record GateResult(
        string Image,
        string ReportedImage,
        string FailOn,
        ContainerPolicyConfig Policy,
        ImageScanSummary Scan,
        ExtendedScanCounts ExtendedCounts,
        GatePolicyEvaluation Evaluation,
        string Gate,
        int ExitCode,
        string ReportDisplayPath,
        string JsonReportDisplayPath,
        bool Submit,
        string ScanMode,
        string TrivyStatus);

    private sealed record GateScanInput(
        string ReportJson,
        string ScannerVersion,
        string Mode,
        string TrivyStatus);

    internal sealed record GatePolicyEvaluation(
        string Decision,
        IReadOnlyList<string> ReasonCodes,
        IReadOnlyList<string> MatchedPolicyRuleIds,
        string ReasonSummary,
        string TriggerIdentity);

    internal sealed record ExtendedScanCounts(int SecretCount, int CriticalSecretCount, int MisconfigurationCount);

    internal sealed record ContainerPolicyConfig(
        string PolicyId,
        string Version,
        string PolicySha256,
        string ConfigSource,
        string DefaultDecision,
        IReadOnlyList<ContainerPolicyRule> Rules)
    {
        public static ContainerPolicyConfig Load(string repoRoot, string path)
        {
            var file = new FileInfo(path);
            if (!file.Exists)
                throw new GateUsageException("Container policy file was not found.");

            if (file.Length <= 0 || file.Length > MaxPolicyBytes)
                throw new GateUsageException("Container policy file size is invalid.");

            var json = File.ReadAllText(file.FullName, Encoding.UTF8);
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                throw new GateUsageException("Container policy root must be a JSON object.");

            if (!root.TryGetProperty("version", out var versionElement) || versionElement.GetInt32() != 1)
                throw new GateUsageException("Only container policy-as-code version 1 is supported.");

            var policyId = SafeText(GetString(root, "policyId"), 128);
            var policyVersion = SafeText(GetString(root, "policyVersion"), 128);
            var defaultDecision = SafeText(GetString(root, "defaultDecision"), 16);
            if (string.IsNullOrWhiteSpace(policyId) || string.IsNullOrWhiteSpace(policyVersion))
                throw new GateUsageException("Container policy id/version is invalid.");
            if (defaultDecision is not ("Allow" or "Warn" or "Block"))
                throw new GateUsageException("Container policy defaultDecision is invalid.");

            if (!root.TryGetProperty("rules", out var rulesElement) || rulesElement.ValueKind != JsonValueKind.Array)
                throw new GateUsageException("Container policy must contain rules.");

            var seen = new HashSet<string>(StringComparer.Ordinal);
            var rules = new List<ContainerPolicyRule>();
            foreach (var ruleElement in rulesElement.EnumerateArray())
            {
                var rule = ContainerPolicyRule.FromJson(ruleElement);
                if (string.IsNullOrWhiteSpace(rule.Id) || !seen.Add(rule.Id))
                    throw new GateUsageException("Container policy rule ids are required and unique.");
                rules.Add(rule);
            }

            if (rules.Count == 0)
                throw new GateUsageException("Container policy must contain at least one rule.");

            return new ContainerPolicyConfig(
                policyId,
                policyVersion,
                Sha256Hex(json),
                DisplayPath(repoRoot, file.FullName),
                defaultDecision,
                rules);
        }

        private static string? GetString(JsonElement element, string name) =>
            element.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String
                ? property.GetString()
                : null;
    }

    internal sealed record ContainerPolicyRule(
        string Id,
        bool Enabled,
        string Decision,
        string Reason,
        IReadOnlyList<string> DeniedImages,
        int? CriticalVulnerabilitiesAtLeast,
        int? HighVulnerabilitiesAtLeast,
        int? MediumVulnerabilitiesAtLeast,
        int? LowVulnerabilitiesAtLeast,
        int? UnknownVulnerabilitiesAtLeast,
        int? TotalFindingsAtLeast,
        int? SecretsAtLeast,
        int? MisconfigurationsAtLeast)
    {
        public static ContainerPolicyRule FromJson(JsonElement element)
        {
            var id = SafeText(GetString(element, "id"), 128);
            var enabled = !element.TryGetProperty("enabled", out var enabledElement)
                || enabledElement.ValueKind != JsonValueKind.False;
            var decision = SafeText(GetString(element, "decision"), 16);
            var reason = SafeText(GetString(element, "reason"), 160);

            if (decision is not ("Allow" or "Warn" or "Block"))
                throw new GateUsageException("Container policy rule decision is invalid.");
            if (decision is "Warn" or "Block" && string.IsNullOrWhiteSpace(reason))
                throw new GateUsageException("Container policy Warn/Block rules require a reason.");
            if (!element.TryGetProperty("match", out var match) || match.ValueKind != JsonValueKind.Object)
                throw new GateUsageException("Container policy rule match is required.");

            return new ContainerPolicyRule(
                id,
                enabled,
                decision,
                reason,
                GetStringArray(match, "deniedImages"),
                GetNullableInt(match, "criticalVulnerabilitiesAtLeast"),
                GetNullableInt(match, "highVulnerabilitiesAtLeast"),
                GetNullableInt(match, "mediumVulnerabilitiesAtLeast"),
                GetNullableInt(match, "lowVulnerabilitiesAtLeast"),
                GetNullableInt(match, "unknownVulnerabilitiesAtLeast"),
                GetNullableInt(match, "totalFindingsAtLeast"),
                GetNullableInt(match, "secretsAtLeast"),
                GetNullableInt(match, "misconfigurationsAtLeast"));
        }

        private static string? GetString(JsonElement element, string name) =>
            element.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String
                ? property.GetString()
                : null;

        private static int? GetNullableInt(JsonElement element, string name)
        {
            if (!element.TryGetProperty(name, out var property))
                return null;
            if (property.ValueKind != JsonValueKind.Number || !property.TryGetInt32(out var value) || value < 0)
                throw new GateUsageException("Container policy match thresholds must be non-negative integers.");
            return value;
        }

        private static IReadOnlyList<string> GetStringArray(JsonElement element, string name)
        {
            if (!element.TryGetProperty(name, out var property))
                return [];
            if (property.ValueKind != JsonValueKind.Array)
                throw new GateUsageException("Container policy deniedImages must be an array.");
            return property.EnumerateArray()
                .Where(x => x.ValueKind == JsonValueKind.String)
                .Select(x => SafeText(x.GetString(), 512))
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .ToArray();
        }
    }

    internal sealed class GateUsageException : Exception
    {
        public GateUsageException(string message) : base(message)
        {
        }
    }

    private sealed class GateLiveTrivyException : Exception
    {
        public GateLiveTrivyException(string image, string status, string hint, string? safeError)
            : base(status)
        {
            Image = image;
            Status = status;
            Hint = hint;
            SafeError = safeError;
        }

        public string Image { get; }
        public string Status { get; }
        public string Hint { get; }
        public string? SafeError { get; }
    }
}
