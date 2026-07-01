using System.Globalization;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ConShield.RuntimeDetection;

namespace ConShield.Cli;

internal static class RuntimeSensorStreamCollector
{
    public const string DefaultSensorId = "demo-falco-linux-01";
    public const string DefaultSourceSystem = "conshield.falco-linux-sensor";
    public const string UnknownSensorId = "demo-falco-unknown-01";
    public const string UnknownSourceSystem = "conshield.falco-unknown-sensor";
    public const string RevokedSensorId = "demo-falco-revoked-01";
    public const string RevokedSourceSystem = "conshield.falco-revoked-sensor";
    public const string DisabledSensorId = "demo-falco-disabled-01";
    public const string DisabledSourceSystem = "conshield.falco-disabled-sensor";

    private const int UsageError = 2;
    private const int RuntimeError = 1;
    private const int InfrastructureUnavailable = 3;
    private const int Success = 0;
    private const int DefaultMaxEvents = 1000;
    private const int MaxEventsLimit = 10000;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static async Task<int> RunAsync(
        string repoRoot,
        string[] args,
        TextReader stdin,
        TextWriter output,
        TextWriter error)
    {
        RuntimeSensorStreamOptions options;
        try
        {
            options = RuntimeSensorStreamOptions.Parse(repoRoot, args);
        }
        catch (CliUsageException ex)
        {
            error.WriteLine($"Usage error: {Safe(ex.Message)}");
            PrintHelp(output);
            return UsageError;
        }

        output.WriteLine("Command: sensor collect");
        output.WriteLine("ConShield runtime sensor stream collector");
        output.WriteLine($"Mode: {options.Mode}");
        output.WriteLine($"SensorId: {Safe(options.SensorId)}");
        output.WriteLine($"Sensor trust: {options.SensorTrust}");
        output.WriteLine($"Enforcement: {options.EnforcementAction}");
        output.WriteLine($"Signature mode: {options.SignatureMode}");

        var mapping = FalcoMappingPolicyLoader.Load(Path.Combine(repoRoot, "config", "runtime", "falco-mapping-v1.json"));
        if (!mapping.Success)
        {
            output.WriteLine("Mapping: FAIL");
            output.WriteLine("Hint: run scripts\\Test-ConShieldFullValidation.ps1 for safe configuration diagnostics.");
            output.WriteLine("Result: FAIL");
            return RuntimeError;
        }

        RuntimeSensorStreamResult result;
        try
        {
            result = await CollectAsync(options, stdin, mapping.Policy!, CancellationToken.None);
        }
        catch (IOException)
        {
            output.WriteLine("Input: FAIL");
            output.WriteLine("Hint: verify the JSON-lines fixture path or rerun with --stdin.");
            output.WriteLine("Result: FAIL");
            return RuntimeError;
        }

        output.WriteLine($"Events read: {result.EventsRead}");
        output.WriteLine($"Events normalized: {result.EventsNormalized.Count}");
        output.WriteLine($"Events skipped: {result.EventsSkipped}");
        output.WriteLine($"Skip reasons: {FormatReasons(result.SkipReasons)}");
        output.WriteLine($"Runtime event types: {FormatDistinct(result.EventsNormalized.Select(x => x.EventType))}");
        output.WriteLine($"Signature statuses: {FormatDistinct(result.EventsNormalized.Select(x => x.AdditionalData.Signature?.SignatureStatus))}");
        output.WriteLine($"ExternalEventIds: {FormatIds(result.EventsNormalized)}");

        if (!options.Submit)
        {
            output.WriteLine("Events submitted: 0");
            output.WriteLine("Ingestion: SKIP");
            output.WriteLine("Expected rules: RTE-001,SENSOR-001,SENSOR-002,SIGN-001,SIGN-002,SIGN-003");
            output.WriteLine("Result: PASS");
            return Success;
        }

        if (!await DockerLifecycleCollector.TestWebAsync(options.BaseUrl))
        {
            output.WriteLine("Web: FAIL");
            output.WriteLine("Events submitted: 0");
            output.WriteLine("Ingestion: FAIL");
            output.WriteLine("Hint: start local services with: pwsh -NoProfile -ExecutionPolicy Bypass -File .\\Start-ConShield.ps1 -StartApps -OpenRabbit");
            output.WriteLine("Result: FAIL");
            return InfrastructureUnavailable;
        }

        var apiKey = DockerLifecycleCollector.ReadLocalApiKey(repoRoot);
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            output.WriteLine("Web: OK");
            output.WriteLine("Events submitted: 0");
            output.WriteLine("Ingestion: FAIL");
            output.WriteLine("Hint: configure the local external ingestion key or rerun with --no-submit for offline validation.");
            output.WriteLine("Result: FAIL");
            return RuntimeError;
        }

        var submit = await SubmitAsync(result.EventsNormalized, options.BaseUrl, apiKey);
        output.WriteLine("Web: OK");
        output.WriteLine($"Events submitted: {submit.Accepted + submit.Duplicate}");
        output.WriteLine($"Ingestion: accepted={submit.Accepted} duplicate={submit.Duplicate} failed={submit.Failed}");
        output.WriteLine("Expected rules: RTE-001,SENSOR-001,SENSOR-002,SIGN-001,SIGN-002,SIGN-003");
        output.WriteLine($"Result: {(submit.Failed == 0 ? "PASS" : "FAIL")}");
        return submit.Failed == 0 ? Success : RuntimeError;
    }

    public static async Task<RuntimeSensorStreamResult> CollectAsync(
        RuntimeSensorStreamOptions options,
        TextReader stdin,
        FalcoMappingPolicy mapping,
        CancellationToken cancellationToken)
    {
        var parser = new FalcoAlertParser();
        var normalizer = new RuntimeEventNormalizer();
        var normalized = new List<RuntimeSecurityEvent>();
        var skipReasons = new SortedDictionary<string, int>(StringComparer.Ordinal);
        var read = 0;
        var skipped = 0;

        await foreach (var line in ReadLinesAsync(options, stdin, cancellationToken))
        {
            if (read >= options.MaxEvents)
                break;

            read++;
            var bytes = Encoding.UTF8.GetBytes(line);
            var parse = parser.Parse(
                bytes,
                DateTime.UtcNow,
                TimeSpan.FromMinutes(5),
                TimeSpan.FromDays(3650));
            if (!parse.Success)
            {
                skipped++;
                AddReason(skipReasons, parse.ErrorCode ?? "invalid_line");
                continue;
            }

            var runtimeEvent = normalizer.Normalize(parse.Alert!, mapping, options.SourceSystem);
            runtimeEvent = AttachSignature(runtimeEvent, options, line);
            normalized.Add(runtimeEvent);
        }

        return new RuntimeSensorStreamResult(read, normalized, skipped, skipReasons);
    }

    private static RuntimeSecurityEvent AttachSignature(RuntimeSecurityEvent runtimeEvent, RuntimeSensorStreamOptions options, string line)
    {
        var required = options.SignatureMode != RuntimeSensorStreamSignatureMode.NotRequired;
        SignedSensorEventEnvelope? envelope = null;
        string? signingMaterial = SignedSensorEventVerifier.DemoSigningMaterial;
        var replayDetected = false;
        var verificationNow = runtimeEvent.OccurredAtUtc.AddMinutes(1);

        if (options.SignatureMode != RuntimeSensorStreamSignatureMode.Missing
            && options.SignatureMode != RuntimeSensorStreamSignatureMode.NotRequired)
        {
            envelope = new SignedSensorEventEnvelope(
                options.SensorId,
                options.SourceSystem,
                runtimeEvent.EventType,
                runtimeEvent.OccurredAtUtc,
                $"stream-{runtimeEvent.ExternalEventId:D}",
                SignedSensorEventVerifier.DemoSignatureAlgorithm,
                SignedSensorEventVerifier.DemoSignatureKeyId,
                null,
                SignedSensorEventVerifier.ComputeCanonicalPayloadHash(line));

            var signature = SignedSensorEventVerifier.CreateSignature(envelope, SignedSensorEventVerifier.DemoSigningMaterial);
            if (options.SignatureMode == RuntimeSensorStreamSignatureMode.Invalid)
                signature = "invalid-demo-signature";
            if (options.SignatureMode == RuntimeSensorStreamSignatureMode.Stale)
                verificationNow = runtimeEvent.OccurredAtUtc.AddHours(1);
            if (options.SignatureMode == RuntimeSensorStreamSignatureMode.ReplayDetected)
                replayDetected = true;

            envelope = envelope with { Signature = signature };
        }

        var verification = SignedSensorEventVerifier.Verify(
            envelope,
            signingMaterial,
            verificationNow,
            TimeSpan.FromMinutes(15),
            TimeSpan.FromMinutes(5),
            required,
            replayDetected);

        var metadata = verification.Metadata with { SensorId = options.SensorId };
        return runtimeEvent with
        {
            AdditionalData = runtimeEvent.AdditionalData with
            {
                Signature = metadata
            }
        };
    }

    private static async IAsyncEnumerable<string> ReadLinesAsync(
        RuntimeSensorStreamOptions options,
        TextReader stdin,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (options.FromJsonLinesPath is not null)
        {
            using var reader = File.OpenText(options.FromJsonLinesPath);
            while (!reader.EndOfStream)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var line = await reader.ReadLineAsync(cancellationToken);
                if (line is not null)
                    yield return line;
            }

            yield break;
        }

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var line = await stdin.ReadLineAsync(cancellationToken);
            if (line is null)
                yield break;
            yield return line;
        }
    }

    private static async Task<SubmitSummary> SubmitAsync(
        IReadOnlyList<RuntimeSecurityEvent> events,
        string baseUrl,
        string apiKey,
        CancellationToken cancellationToken = default)
    {
        using var httpClient = new HttpClient
        {
            BaseAddress = new Uri(baseUrl.TrimEnd('/') + "/"),
            Timeout = TimeSpan.FromSeconds(30)
        };
        httpClient.DefaultRequestHeaders.Add("X-ConShield-Api-Key", apiKey);

        var accepted = 0;
        var duplicate = 0;
        var failed = 0;

        foreach (var runtimeEvent in events)
        {
            using var response = await httpClient.PostAsJsonAsync(
                "api/v1/security-events",
                ToIngestRequest(runtimeEvent),
                JsonOptions,
                cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                failed++;
                continue;
            }

            try
            {
                using var document = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(cancellationToken));
                var created = document.RootElement.TryGetProperty("created", out var createdElement)
                    && createdElement.ValueKind == JsonValueKind.True;
                if (created)
                    accepted++;
                else
                    duplicate++;
            }
            catch (JsonException)
            {
                accepted++;
            }
        }

        return new SubmitSummary(accepted, duplicate, failed);
    }

    private static object ToIngestRequest(RuntimeSecurityEvent runtimeEvent) => new
    {
        externalEventId = runtimeEvent.ExternalEventId,
        occurredAtUtc = runtimeEvent.OccurredAtUtc.ToString("O", CultureInfo.InvariantCulture),
        sourceSystem = runtimeEvent.SourceSystem,
        eventType = runtimeEvent.EventType,
        severity = runtimeEvent.Severity.ToString(),
        userName = (string?)null,
        sourceHost = runtimeEvent.SourceHost,
        description = runtimeEvent.Description,
        additionalData = runtimeEvent.AdditionalData
    };

    private static void AddReason(IDictionary<string, int> reasons, string reason)
    {
        reasons.TryGetValue(reason, out var count);
        reasons[reason] = count + 1;
    }

    private static string FormatReasons(IReadOnlyDictionary<string, int> reasons) =>
        reasons.Count == 0
            ? "-"
            : string.Join(",", reasons.Select(x => $"{x.Key}={x.Value}"));

    private static string FormatDistinct(IEnumerable<string?> values)
    {
        var distinct = values
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x!)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        return distinct.Length == 0 ? "-" : string.Join(",", distinct);
    }

    private static string FormatIds(IReadOnlyList<RuntimeSecurityEvent> events)
    {
        if (events.Count == 0)
            return "-";
        return string.Join(",", events.Select(x => x.ExternalEventId.ToString("D")).Take(5))
            + (events.Count > 5 ? ",..." : string.Empty);
    }

    public static void PrintHelp(TextWriter output)
    {
        output.WriteLine("Sensor collect commands:");
        output.WriteLine("  sensor collect --from-json-lines <path> --demo-signature --no-submit");
        output.WriteLine("  sensor collect --stdin --demo-signature --no-submit");
        output.WriteLine("  sensor collect --from-json-lines <path> --demo-signature --submit");
        output.WriteLine("  Simulation flags: --simulate-unknown-sensor, --simulate-revoked-sensor, --simulate-disabled-sensor, --simulate-missing-signature, --simulate-invalid-signature, --simulate-stale-signature, --simulate-replay-signature.");
        output.WriteLine("  Fixture/stdin modes are CI-safe and do not require real Fedora/Falco.");
    }

    private static string Safe(string value)
    {
        var redacted = Regex.Replace(
            value,
            "(?i)(password|secret|token|api[_ -]?key|authorization|bearer|cookie|credential|connection string)\\s*[:=]\\s*[^;\\s,]+",
            "$1=[redacted]");
        return redacted.Length <= 4000 ? redacted : redacted[..3997] + "...";
    }

    private static string NormalizeCliPath(string value) =>
        Path.DirectorySeparatorChar == '\\' ? value : value.Replace('\\', Path.DirectorySeparatorChar);

    private static string NormalizeExistingFilePath(string repoRoot, string value, string optionName)
    {
        var normalizedValue = NormalizeCliPath(value);
        var fullPath = Path.IsPathRooted(normalizedValue)
            ? Path.GetFullPath(normalizedValue)
            : Path.GetFullPath(Path.Combine(repoRoot, normalizedValue));

        if (!File.Exists(fullPath))
            throw new CliUsageException($"{optionName} file does not exist.");

        return fullPath;
    }

    private static int ParseInt(string? value, int defaultValue, string optionName)
    {
        if (string.IsNullOrWhiteSpace(value))
            return defaultValue;
        if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
            throw new CliUsageException($"{optionName} must be an integer.");
        return parsed;
    }

    private static string FindSensorTrust(string repoRoot, string sensorId, string sourceSystem)
    {
        var path = Path.Combine(repoRoot, "config", "sensor-registry.default.json");
        if (!File.Exists(path))
            return "Unknown";

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllBytes(path));
            if (!document.RootElement.TryGetProperty("sensors", out var sensors) || sensors.ValueKind != JsonValueKind.Array)
                return "Unknown";

            foreach (var sensor in sensors.EnumerateArray())
            {
                var id = TryReadString(sensor, "sensorId");
                var source = TryReadString(sensor, "sourceSystem");
                if (string.Equals(id, sensorId, StringComparison.Ordinal)
                    || string.Equals(source, sourceSystem, StringComparison.Ordinal))
                {
                    return TryReadString(sensor, "status") ?? "Unknown";
                }
            }
        }
        catch (JsonException)
        {
            return "Unknown";
        }

        return "Unknown";
    }

    private static string? TryReadString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string EnforcementActionFor(string trustStatus) =>
        trustStatus switch
        {
            "Trusted" => "AcceptTrusted",
            "Revoked" => "FlagRevokedWithAlert",
            "Disabled" => "FlagDisabledWithAlert",
            _ => "AcceptUnknownWithAlert"
        };

    internal sealed record RuntimeSensorStreamOptions(
        string Mode,
        string? FromJsonLinesPath,
        string SensorId,
        string SourceSystem,
        string SensorTrust,
        string EnforcementAction,
        RuntimeSensorStreamSignatureMode SignatureMode,
        int MaxEvents,
        bool Submit,
        string BaseUrl)
    {
        public static RuntimeSensorStreamOptions Parse(string repoRoot, string[] args)
        {
            string? fromJsonLines = null;
            var stdin = false;
            var sensorId = DefaultSensorId;
            var sourceSystem = DefaultSourceSystem;
            var signatureMode = RuntimeSensorStreamSignatureMode.NotRequired;
            var maxEvents = DefaultMaxEvents;
            var submit = false;
            var noSubmit = false;
            var baseUrl = "http://127.0.0.1:5080";
            var trustSimulations = 0;
            var signatureSimulations = 0;

            for (var index = 0; index < args.Length; index++)
            {
                var option = args[index];
                switch (option.ToLowerInvariant())
                {
                    case "--from-json-lines":
                        fromJsonLines = NormalizeExistingFilePath(repoRoot, TakeValue(args, ref index, option), option);
                        break;
                    case "--stdin":
                        stdin = true;
                        break;
                    case "--sensor-id":
                        sensorId = TakeValue(args, ref index, option);
                        break;
                    case "--source-system":
                        sourceSystem = TakeValue(args, ref index, option);
                        break;
                    case "--demo-signature":
                        signatureMode = RuntimeSensorStreamSignatureMode.Demo;
                        signatureSimulations++;
                        break;
                    case "--simulate-missing-signature":
                        signatureMode = RuntimeSensorStreamSignatureMode.Missing;
                        signatureSimulations++;
                        break;
                    case "--simulate-invalid-signature":
                        signatureMode = RuntimeSensorStreamSignatureMode.Invalid;
                        signatureSimulations++;
                        break;
                    case "--simulate-stale-signature":
                        signatureMode = RuntimeSensorStreamSignatureMode.Stale;
                        signatureSimulations++;
                        break;
                    case "--simulate-replay-signature":
                        signatureMode = RuntimeSensorStreamSignatureMode.ReplayDetected;
                        signatureSimulations++;
                        break;
                    case "--simulate-unknown-sensor":
                        sensorId = UnknownSensorId;
                        sourceSystem = UnknownSourceSystem;
                        trustSimulations++;
                        break;
                    case "--simulate-revoked-sensor":
                        sensorId = RevokedSensorId;
                        sourceSystem = RevokedSourceSystem;
                        trustSimulations++;
                        break;
                    case "--simulate-disabled-sensor":
                        sensorId = DisabledSensorId;
                        sourceSystem = DisabledSourceSystem;
                        trustSimulations++;
                        break;
                    case "--max-events":
                        maxEvents = ParseInt(TakeValue(args, ref index, option), DefaultMaxEvents, option);
                        break;
                    case "--duration-seconds":
                        _ = ParseInt(TakeValue(args, ref index, option), 0, option);
                        break;
                    case "--submit":
                        submit = true;
                        break;
                    case "--no-submit":
                        noSubmit = true;
                        break;
                    case "--base-url":
                        baseUrl = TakeValue(args, ref index, option);
                        break;
                    default:
                        throw new CliUsageException($"Unknown option: {option}");
                }
            }

            if ((fromJsonLines is null) == !stdin)
                throw new CliUsageException("Use exactly one input mode: --from-json-lines <path> or --stdin.");
            if (trustSimulations > 1)
                throw new CliUsageException("Use at most one sensor trust simulation flag.");
            if (signatureSimulations > 1)
                throw new CliUsageException("Use at most one signature simulation flag.");
            if (submit && noSubmit)
                throw new CliUsageException("Use either --submit or --no-submit, not both.");
            if (maxEvents < 1 || maxEvents > MaxEventsLimit)
                throw new CliUsageException($"--max-events must be between 1 and {MaxEventsLimit}.");

            var trust = FindSensorTrust(repoRoot, sensorId, sourceSystem);
            return new RuntimeSensorStreamOptions(
                stdin ? "stdin" : "json-lines",
                fromJsonLines,
                sensorId,
                sourceSystem,
                trust,
                EnforcementActionFor(trust),
                signatureMode,
                maxEvents,
                submit,
                baseUrl);
        }

        private static string TakeValue(string[] args, ref int index, string option)
        {
            if (index + 1 >= args.Length || string.IsNullOrWhiteSpace(args[index + 1]) || args[index + 1].StartsWith("--", StringComparison.Ordinal))
                throw new CliUsageException($"{option} requires a value.");
            index++;
            return args[index];
        }
    }
}

internal enum RuntimeSensorStreamSignatureMode
{
    NotRequired,
    Demo,
    Missing,
    Invalid,
    Stale,
    ReplayDetected
}

internal sealed record RuntimeSensorStreamResult(
    int EventsRead,
    IReadOnlyList<RuntimeSecurityEvent> EventsNormalized,
    int EventsSkipped,
    IReadOnlyDictionary<string, int> SkipReasons);
