using System.Diagnostics;
using System.Text.RegularExpressions;

namespace ConShield.Cli;

internal static class Program
{
    private const int Success = 0;
    private const int UsageError = 2;
    private const int RuntimeError = 1;
    private const int InfrastructureUnavailable = 3;

    private static readonly StringComparer OptionComparer = StringComparer.OrdinalIgnoreCase;

    public static async Task<int> Main(string[] args)
    {
        Console.WriteLine("ConShield CLI");

        if (args.Length == 0 || IsHelp(args[0]))
        {
            PrintHelp();
            return Success;
        }

        try
        {
            var repoRoot = FindRepositoryRoot();
            return args[0].ToLowerInvariant() switch
            {
                "validate" => await RunValidateAsync(repoRoot, args[1..]),
                "demo" => await RunDemoAsync(repoRoot, args[1..]),
                "scan" => await RunScanAsync(repoRoot, args[1..]),
                "gate" => await RunGateAsync(repoRoot, args[1..]),
                "run" => await RunProtectedRunAsync(repoRoot, args[1..]),
                "sensor" => await RunSensorAsync(repoRoot, args[1..]),
                "lifecycle" => await RunLifecycleAsync(repoRoot, args[1..]),
                "evidence" => await RunEvidenceAsync(repoRoot, args[1..]),
                _ => FailUsage($"Unknown command: {Safe(args[0])}")
            };
        }
        catch (CliUsageException ex)
        {
            return FailUsage(ex.Message);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {Safe(ex.Message)}");
            Console.Error.WriteLine("Hint: run `dotnet run --project .\\src\\ConShield.Cli -- --help`.");
            return RuntimeError;
        }
    }

    private static async Task<int> RunValidateAsync(string repoRoot, string[] args)
    {
        RejectUnexpectedArguments(args);
        Console.WriteLine("Command: validate");

        foreach (var step in new[]
        {
            ("SIEM rules", "Test-ConShieldSiemRules.ps1"),
            ("Container policy", "Test-ConShieldContainerPolicy.ps1"),
            ("Sensor registry", "Test-ConShieldSensorRegistry.ps1")
        })
        {
            Console.WriteLine($"Step: {step.Item1}");
            var exitCode = await RunPowerShellScriptAsync(repoRoot, step.Item2, []);
            if (exitCode != Success)
            {
                Console.Error.WriteLine($"Hint: run scripts\\{step.Item2} directly for safe diagnostics.");
                return exitCode;
            }
        }

        Console.WriteLine("Result: PASS");
        return Success;
    }

    private static async Task<int> RunDemoAsync(string repoRoot, string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            PrintDemoHelp();
            return Success;
        }

        return args[0].ToLowerInvariant() switch
        {
            "readiness" => await RunScriptCommandAsync(
                repoRoot,
                "demo readiness",
                "Test-ConShieldDemoReadiness.ps1",
                MapOptions(args[1..], new OptionSpec("--output", "-OutputMarkdownPath", RequiresValue: true))),
            "seed" => await RunScriptCommandAsync(
                repoRoot,
                "demo seed",
                "Seed-ConShieldDemoData.ps1",
                MapOptions(
                    args[1..],
                    new OptionSpec("--base-url", "-BaseUrl", RequiresValue: true),
                    new OptionSpec("--reset-first", "-ResetFirst", RequiresValue: false),
                    new OptionSpec("--skip-evidence-export", "-SkipEvidenceExport", RequiresValue: false),
                    new OptionSpec("--output-evidence", "-OutputEvidencePath", RequiresValue: true),
                    new OptionSpec("--continue-on-expected-findings", "-ContinueOnExpectedFindings", RequiresValue: false),
                    new OptionSpec("--timeout-seconds", "-TimeoutSeconds", RequiresValue: true))),
            "reset" => await RunDemoResetAsync(repoRoot, args[1..]),
            _ => FailUsage($"Unknown demo command: {Safe(args[0])}")
        };
    }

    private static async Task<int> RunDemoResetAsync(string repoRoot, string[] args)
    {
        var parser = new OptionParser(args);
        var confirmed = parser.TakeFlag("--confirm");
        var cleanLocalArtifacts = parser.TakeFlag("--clean-local-artifacts");
        var outputRoot = parser.TakeValue("--output-artifact-root");
        parser.ThrowIfRemaining();

        if (!confirmed)
        {
            Console.Error.WriteLine("Reset requires explicit --confirm.");
            Console.Error.WriteLine("Hint: preview first with scripts\\Reset-ConShieldLocalDemoData.ps1 -WhatIf, then rerun CLI with `demo reset --confirm`.");
            return UsageError;
        }

        var scriptArgs = new List<string> { "-ConfirmReset" };
        if (cleanLocalArtifacts)
            scriptArgs.Add("-CleanLocalArtifacts");
        if (!string.IsNullOrWhiteSpace(outputRoot))
        {
            scriptArgs.Add("-OutputArtifactRoot");
            scriptArgs.Add(NormalizeOutputPath(repoRoot, outputRoot));
        }

        return await RunScriptCommandAsync(repoRoot, "demo reset", "Reset-ConShieldLocalDemoData.ps1", scriptArgs);
    }

    private static async Task<int> RunScanAsync(string repoRoot, string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            PrintScanHelp();
            return Success;
        }

        if (!args[0].Equals("image", StringComparison.OrdinalIgnoreCase))
            return FailUsage($"Unknown scan command: {Safe(args[0])}");

        var mapped = MapOptions(
            args[1..],
            new OptionSpec("--from-trivy-json", "-FromTrivyJson", RequiresValue: true, ExistingFile: true),
            new OptionSpec("--image", "-Image", RequiresValue: true),
            new OptionSpec("--no-submit", "-NoSubmit", RequiresValue: false),
            new OptionSpec("--output", "-OutputMarkdownPath", RequiresValue: true),
            new OptionSpec("--timeout-seconds", "-TimeoutSeconds", RequiresValue: true));

        return await RunScriptCommandAsync(repoRoot, "scan image", "Invoke-ConShieldImageScan.ps1", mapped);
    }

    private static Task<int> RunGateAsync(string repoRoot, string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            PrintGateHelp();
            return Task.FromResult(Success);
        }

        if (!args[0].Equals("image", StringComparison.OrdinalIgnoreCase))
            return Task.FromResult(FailUsage($"Unknown gate command: {Safe(args[0])}"));

        return Task.FromResult(CicdContainerGate.RunImageGate(repoRoot, args[1..], Console.Out, Console.Error));
    }

    private static async Task<int> RunProtectedRunAsync(string repoRoot, string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            PrintRunHelp();
            return Success;
        }

        if (!args[0].Equals("protected", StringComparison.OrdinalIgnoreCase))
            return FailUsage($"Unknown run command: {Safe(args[0])}");

        var mapped = MapOptions(
            args[1..],
            new OptionSpec("--image", "-Image", RequiresValue: true),
            new OptionSpec("--container-name", "-ContainerName", RequiresValue: true),
            new OptionSpec("--command", "-Command", RequiresValue: true),
            new OptionSpec("--from-trivy-json", "-FromTrivyJson", RequiresValue: true, ExistingFile: true),
            new OptionSpec("--no-run", "-NoRun", RequiresValue: false),
            new OptionSpec("--no-submit", "-NoSubmit", RequiresValue: false),
            new OptionSpec("--execute", "-Execute", RequiresValue: false),
            new OptionSpec("--accept-warning", "-AcceptWarning", RequiresValue: false),
            new OptionSpec("--output", "-OutputMarkdownPath", RequiresValue: true));

        return await RunScriptCommandAsync(repoRoot, "run protected", "Invoke-ConShieldProtectedRun.ps1", mapped);
    }

    private static async Task<int> RunSensorAsync(string repoRoot, string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            PrintSensorHelp();
            return Success;
        }

        if (!args[0].Equals("replay", StringComparison.OrdinalIgnoreCase))
            return FailUsage($"Unknown sensor command: {Safe(args[0])}");

        var mapped = MapOptions(
            args[1..],
            new OptionSpec("--demo-signature", "-DemoSignature", RequiresValue: false),
            new OptionSpec("--simulate-missing-signature", "-SimulateMissingSignature", RequiresValue: false),
            new OptionSpec("--simulate-invalid-signature", "-SimulateInvalidSignature", RequiresValue: false),
            new OptionSpec("--simulate-stale-signature", "-SimulateStaleSignature", RequiresValue: false),
            new OptionSpec("--simulate-replay-signature", "-SimulateReplaySignature", RequiresValue: false),
            new OptionSpec("--simulate-unknown-sensor", "-SimulateUnknownSensor", RequiresValue: false),
            new OptionSpec("--simulate-revoked-sensor", "-SimulateRevokedSensor", RequiresValue: false),
            new OptionSpec("--simulate-disabled-sensor", "-SimulateDisabledSensor", RequiresValue: false),
            new OptionSpec("--no-submit", "-NoSubmit", RequiresValue: false),
            new OptionSpec("--fixture", "-FixturePath", RequiresValue: true, ExistingFile: true));

        return await RunScriptCommandAsync(repoRoot, "sensor replay", "Replay-ConShieldFalcoRuntimeEvent.ps1", mapped);
    }

    private static async Task<int> RunEvidenceAsync(string repoRoot, string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            PrintEvidenceHelp();
            return Success;
        }

        if (!args[0].Equals("export", StringComparison.OrdinalIgnoreCase))
            return FailUsage($"Unknown evidence command: {Safe(args[0])}");

        var mapped = MapOptions(
            args[1..],
            new OptionSpec("--output", "-OutputMarkdownPath", RequiresValue: true),
            new OptionSpec("--base-url", "-BaseUrl", RequiresValue: true),
            new OptionSpec("--run-scenario", "-RunScenario", RequiresValue: false));

        return await RunScriptCommandAsync(repoRoot, "evidence export", "Export-ConShieldDefenseEvidence.ps1", mapped);
    }

    private static async Task<int> RunLifecycleAsync(string repoRoot, string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            PrintLifecycleHelp();
            return Success;
        }

        return args[0].ToLowerInvariant() switch
        {
            "replay" => await RunLifecycleReplayAsync(repoRoot, args[1..]),
            "watch" => await RunLifecycleWatchAsync(repoRoot, args[1..]),
            _ => FailUsage($"Unknown lifecycle command: {Safe(args[0])}")
        };
    }

    private static async Task<int> RunLifecycleWatchAsync(string repoRoot, string[] args)
    {
        var parser = new OptionParser(args);
        var durationSeconds = ParseIntOption(parser.TakeValue("--duration-seconds"), 30, "--duration-seconds");
        var maxEvents = ParseIntOption(parser.TakeValue("--max-events"), 100, "--max-events");
        var submit = parser.TakeFlag("--submit");
        var noSubmit = parser.TakeFlag("--no-submit");
        var baseUrl = parser.TakeValue("--base-url") ?? "http://127.0.0.1:5080";
        parser.ThrowIfRemaining();

        if (submit && noSubmit)
            throw new CliUsageException("Use either --submit or --no-submit, not both.");

        DockerLifecycleWatch.Validate(durationSeconds, maxEvents);

        var shouldSubmit = submit;
        Console.WriteLine("Command: lifecycle watch");
        Console.WriteLine("ConShield Docker lifecycle watch");
        Console.WriteLine("Mode: live watch");
        Console.WriteLine($"Duration: {durationSeconds} seconds");
        Console.WriteLine($"Max events: {maxEvents}");
        Console.WriteLine($"Submit: {shouldSubmit.ToString().ToLowerInvariant()}");

        var watch = await DockerLifecycleWatch.WatchAsync(durationSeconds, maxEvents);
        if (!watch.DockerAvailable)
        {
            Console.WriteLine("Docker: unavailable");
            Console.WriteLine($"Hint: {watch.Hint}");
            Console.WriteLine($"Result: {(shouldSubmit ? "FAIL" : "SKIP")}");
            return shouldSubmit ? InfrastructureUnavailable : Success;
        }

        Console.WriteLine("Docker: OK");
        Console.WriteLine($"SourceSystem: {DockerLifecycleCollector.SourceSystem}");
        Console.WriteLine($"Events observed: {watch.EventsObserved}");
        Console.WriteLine($"Events normalized: {watch.Events.Count}");
        Console.WriteLine($"Lifecycle event types: {string.Join(",", watch.Events.Select(x => x.EventType).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))}");

        if (!shouldSubmit)
        {
            Console.WriteLine("Events submitted: 0");
            Console.WriteLine("Ingestion: SKIP");
            Console.WriteLine("Expected rules: LIFE-001,LIFE-002 unaffected");
            Console.WriteLine("Result: PASS");
            return Success;
        }

        if (!await DockerLifecycleCollector.TestWebAsync(baseUrl))
        {
            Console.WriteLine("Web: FAIL");
            Console.WriteLine("Events submitted: 0");
            Console.WriteLine("Ingestion: FAIL");
            Console.WriteLine("Hint: start local services with: pwsh -NoProfile -ExecutionPolicy Bypass -File .\\Start-ConShield.ps1 -StartApps -OpenRabbit");
            Console.WriteLine("Result: FAIL");
            return InfrastructureUnavailable;
        }

        var apiKey = DockerLifecycleCollector.ReadLocalApiKey(repoRoot);
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            Console.WriteLine("Web: OK");
            Console.WriteLine("Events submitted: 0");
            Console.WriteLine("Ingestion: FAIL");
            Console.WriteLine("Hint: configure the local external ingestion key or rerun with --no-submit for watch-only validation.");
            Console.WriteLine("Result: FAIL");
            return RuntimeError;
        }

        var submitResult = watch.Events.Count == 0
            ? new SubmitSummary(0, 0, 0)
            : await DockerLifecycleCollector.SubmitAsync(watch.Events, baseUrl, apiKey);

        Console.WriteLine("Web: OK");
        Console.WriteLine($"Events submitted: {submitResult.Accepted + submitResult.Duplicate}");
        Console.WriteLine($"Ingestion: accepted={submitResult.Accepted} duplicate={submitResult.Duplicate} failed={submitResult.Failed}");
        Console.WriteLine("Expected rules: LIFE-001,LIFE-002 unaffected");
        Console.WriteLine($"Result: {(submitResult.Failed == 0 ? "PASS" : "FAIL")}");
        return submitResult.Failed == 0 ? Success : RuntimeError;
    }

    private static async Task<int> RunLifecycleReplayAsync(string repoRoot, string[] args)
    {
        var parser = new OptionParser(args);
        var fixturePath = parser.TakeValue("--from-docker-events-json");
        var noSubmit = parser.TakeFlag("--no-submit");
        var baseUrl = parser.TakeValue("--base-url") ?? "http://127.0.0.1:5080";
        parser.ThrowIfRemaining();

        if (string.IsNullOrWhiteSpace(fixturePath))
            throw new CliUsageException("--from-docker-events-json is required.");

        var resolvedFixture = NormalizeExistingFilePath(repoRoot, fixturePath, "--from-docker-events-json");

        IReadOnlyList<NormalizedDockerLifecycleEvent> events;
        try
        {
            events = DockerLifecycleCollector.Normalize(DockerLifecycleCollector.ParseFixture(resolvedFixture));
        }
        catch (DockerLifecycleException ex)
        {
            Console.WriteLine("Command: lifecycle replay");
            Console.WriteLine($"Fixture: {Path.GetFileName(resolvedFixture)}");
            Console.WriteLine($"Validation: FAIL ({Safe(ex.Message)})");
            Console.WriteLine("Result: FAIL");
            return RuntimeError;
        }

        Console.WriteLine("Command: lifecycle replay");
        Console.WriteLine("ConShield Docker lifecycle replay");
        Console.WriteLine($"Web: {(noSubmit ? "SKIP" : "CHECK")}");
        Console.WriteLine($"Fixture: {Path.GetFileName(resolvedFixture)}");
        Console.WriteLine($"SourceSystem: {DockerLifecycleCollector.SourceSystem}");
        Console.WriteLine($"Parsed: {events.Count}");
        Console.WriteLine($"Mapped: {events.Count}");
        Console.WriteLine($"Lifecycle event types: {string.Join(",", events.Select(x => x.EventType).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))}");
        Console.WriteLine($"Actions: {string.Join(",", events.Select(x => x.AdditionalData.DockerAction).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))}");
        Console.WriteLine($"Latest container: {events.OrderByDescending(x => x.OccurredAtUtc).First().AdditionalData.ContainerName ?? "-"}");
        Console.WriteLine($"ExternalEventIds: {string.Join(",", events.Select(x => x.ExternalEventId.ToString("D")).Take(3))}{(events.Count > 3 ? ",..." : string.Empty)}");

        if (noSubmit)
        {
            Console.WriteLine("Ingestion: SKIP");
            Console.WriteLine("Expected rules: LIFE-001,LIFE-002 unaffected");
            Console.WriteLine("Result: PASS");
            return Success;
        }

        if (!await DockerLifecycleCollector.TestWebAsync(baseUrl))
        {
            Console.WriteLine("Web: FAIL");
            Console.WriteLine("Ingestion: FAIL");
            Console.WriteLine("Start local services first:");
            Console.WriteLine("pwsh -NoProfile -ExecutionPolicy Bypass -File .\\Start-ConShield.ps1 -StartApps -OpenRabbit");
            Console.WriteLine("Result: FAIL");
            return RuntimeError;
        }

        var apiKey = DockerLifecycleCollector.ReadLocalApiKey(repoRoot);
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            Console.WriteLine("Web: OK");
            Console.WriteLine("Ingestion: FAIL");
            Console.WriteLine("Configure the local external ingestion key or rerun with --no-submit for offline validation.");
            Console.WriteLine("Result: FAIL");
            return RuntimeError;
        }

        var submit = await DockerLifecycleCollector.SubmitAsync(events, baseUrl, apiKey);
        Console.WriteLine("Web: OK");
        Console.WriteLine($"Ingestion: accepted={submit.Accepted} duplicate={submit.Duplicate} failed={submit.Failed}");
        Console.WriteLine("Expected rules: LIFE-001,LIFE-002 unaffected");
        Console.WriteLine($"Result: {(submit.Failed == 0 ? "PASS" : "FAIL")}");
        return submit.Failed == 0 ? Success : RuntimeError;
    }

    private static async Task<int> RunScriptCommandAsync(string repoRoot, string command, string scriptName, IReadOnlyList<string> scriptArguments)
    {
        Console.WriteLine($"Command: {command}");
        var exitCode = await RunPowerShellScriptAsync(repoRoot, scriptName, scriptArguments);
        if (exitCode != Success)
            Console.Error.WriteLine($"Hint: run scripts\\{scriptName} directly for safe diagnostics.");
        return exitCode;
    }

    private static async Task<int> RunPowerShellScriptAsync(string repoRoot, string scriptName, IReadOnlyList<string> scriptArguments)
    {
        var scriptPath = Path.Combine(repoRoot, "scripts", scriptName);
        if (!File.Exists(scriptPath))
            throw new CliUsageException($"Script was not found: scripts\\{scriptName}");

        var startInfo = new ProcessStartInfo
        {
            FileName = "pwsh",
            WorkingDirectory = repoRoot,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-ExecutionPolicy");
        startInfo.ArgumentList.Add("Bypass");
        startInfo.ArgumentList.Add("-File");
        startInfo.ArgumentList.Add(scriptPath);

        foreach (var argument in scriptArguments)
            startInfo.ArgumentList.Add(argument);

        using var process = new Process { StartInfo = startInfo };
        process.OutputDataReceived += (_, e) => WriteSafeLine(Console.Out, e.Data);
        process.ErrorDataReceived += (_, e) => WriteSafeLine(Console.Error, e.Data);

        if (!process.Start())
            throw new InvalidOperationException("Failed to start PowerShell.");

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        await process.WaitForExitAsync();
        return process.ExitCode;
    }

    private static IReadOnlyList<string> MapOptions(string[] args, params OptionSpec[] specs)
    {
        var parser = new OptionParser(args);
        var mapped = new List<string>();

        while (parser.HasRemaining)
        {
            var option = parser.TakeOption();
            var spec = specs.SingleOrDefault(x => OptionComparer.Equals(x.Name, option));
            if (spec is null)
                throw new CliUsageException($"Unknown option: {Safe(option)}");

            mapped.Add(spec.ScriptName);
            if (spec.RequiresValue)
            {
                var value = parser.TakeRequiredValue(spec.Name);
                if (spec.ExistingFile)
                    value = NormalizeExistingFilePath(FindRepositoryRoot(), value, spec.Name);
                mapped.Add(value);
            }
        }

        return mapped;
    }

    private static void RejectUnexpectedArguments(string[] args)
    {
        if (args.Length == 0)
            return;
        if (args.Length == 1 && IsHelp(args[0]))
            return;

        throw new CliUsageException($"Unexpected argument: {Safe(args[0])}");
    }

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

    private static string NormalizeOutputPath(string repoRoot, string value)
    {
        var normalizedValue = NormalizeCliPath(value);
        return Path.IsPathRooted(normalizedValue)
            ? Path.GetFullPath(normalizedValue)
            : Path.GetFullPath(Path.Combine(repoRoot, normalizedValue));
    }

    private static string NormalizeCliPath(string value)
    {
        if (Path.DirectorySeparatorChar == '\\')
            return value;

        return value.Replace('\\', Path.DirectorySeparatorChar);
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(Directory.GetCurrentDirectory());
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "ConShield.sln")))
                return current.FullName;

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("Repository root was not found. Run from the ConShield repository.");
    }

    private static int FailUsage(string message)
    {
        Console.Error.WriteLine($"Usage error: {Safe(message)}");
        PrintHelp();
        return UsageError;
    }

    private static bool IsHelp(string value) =>
        value.Equals("--help", StringComparison.OrdinalIgnoreCase)
        || value.Equals("-h", StringComparison.OrdinalIgnoreCase)
        || value.Equals("help", StringComparison.OrdinalIgnoreCase);

    private static void PrintHelp()
    {
        Console.WriteLine();
        Console.WriteLine("Commands:");
        Console.WriteLine("  validate");
        Console.WriteLine("  demo readiness");
        Console.WriteLine("  demo seed");
        Console.WriteLine("  demo reset");
        Console.WriteLine("  scan image");
        Console.WriteLine("  gate image");
        Console.WriteLine("  run protected");
        Console.WriteLine("  sensor replay");
        Console.WriteLine("  lifecycle replay");
        Console.WriteLine("  lifecycle watch");
        Console.WriteLine("  evidence export");
        Console.WriteLine();
        Console.WriteLine("Examples:");
        Console.WriteLine("  dotnet run --project .\\src\\ConShield.Cli -- validate");
        Console.WriteLine("  dotnet run --project .\\src\\ConShield.Cli -- scan image --from-trivy-json .\\tests\\TestData\\Trivy\\sample-image-scan.json --no-submit");
        Console.WriteLine("  dotnet run --project .\\src\\ConShield.Cli -- gate image --image demo/insecure-api:latest --from-trivy-json .\\tests\\TestData\\Trivy\\sample-image-scan.json --fail-on never --no-submit");
        Console.WriteLine("  dotnet run --project .\\src\\ConShield.Cli -- run protected --image demo/insecure-api:latest --container-name conshield-demo-insecure --from-trivy-json .\\tests\\TestData\\Trivy\\sample-image-scan.json --no-run --no-submit");
        Console.WriteLine("  dotnet run --project .\\src\\ConShield.Cli -- sensor replay --demo-signature --no-submit");
        Console.WriteLine("  dotnet run --project .\\src\\ConShield.Cli -- lifecycle replay --from-docker-events-json .\\tests\\TestData\\DockerEvents\\container-lifecycle-events.json --no-submit");
        Console.WriteLine("  dotnet run --project .\\src\\ConShield.Cli -- lifecycle watch --duration-seconds 30 --no-submit");
    }

    private static void PrintDemoHelp()
    {
        Console.WriteLine("Demo commands:");
        Console.WriteLine("  demo readiness");
        Console.WriteLine("  demo seed");
        Console.WriteLine("  demo reset --confirm");
    }

    private static void PrintScanHelp()
    {
        Console.WriteLine("Scan commands:");
        Console.WriteLine("  scan image --from-trivy-json <path> --no-submit");
    }

    private static void PrintGateHelp()
    {
        Console.WriteLine("Gate commands:");
        Console.WriteLine("  gate image --image <image> --from-trivy-json <path> --fail-on block|warn|never --report <path> --no-submit");
        Console.WriteLine("  Exit codes: 0=passed, 1=failed by policy, 2=usage/input error, 3=infrastructure error.");
    }

    private static void PrintRunHelp()
    {
        Console.WriteLine("Run commands:");
        Console.WriteLine("  run protected --image <image> --container-name <name> --from-trivy-json <path> --no-run --no-submit");
        Console.WriteLine("  Live Docker execution remains opt-in with --execute.");
    }

    private static void PrintSensorHelp()
    {
        Console.WriteLine("Sensor commands:");
        Console.WriteLine("  sensor replay --demo-signature --no-submit");
        Console.WriteLine("  sensor replay --simulate-missing-signature --no-submit");
    }

    private static void PrintEvidenceHelp()
    {
        Console.WriteLine("Evidence commands:");
        Console.WriteLine("  evidence export --output .\\artifacts\\local\\defense-evidence-cli.md");
    }

    private static void PrintLifecycleHelp()
    {
        Console.WriteLine("Lifecycle commands:");
        Console.WriteLine("  lifecycle replay --from-docker-events-json <path> --no-submit");
        Console.WriteLine("  lifecycle watch --duration-seconds 30 --max-events 100 --no-submit");
        Console.WriteLine("  lifecycle watch --duration-seconds 30 --submit");
        Console.WriteLine("  Live watch is optional/manual and is not required for CI or full validation.");
    }

    private static int ParseIntOption(string? value, int defaultValue, string optionName)
    {
        if (string.IsNullOrWhiteSpace(value))
            return defaultValue;

        if (!int.TryParse(value, out var parsed))
            throw new CliUsageException($"{optionName} must be an integer.");

        return parsed;
    }

    private static void WriteSafeLine(TextWriter writer, string? line)
    {
        if (line is null)
            return;

        writer.WriteLine(Safe(line));
    }

    private static string Safe(string value)
    {
        var redacted = Regex.Replace(
            value,
            "(?i)(password|secret|token|api[_ -]?key|authorization|bearer|cookie|credential|connection string)\\s*[:=]\\s*[^;\\s,]+",
            "$1=[redacted]");

        return redacted.Length <= 4000 ? redacted : redacted[..3997] + "...";
    }

    private sealed record OptionSpec(string Name, string ScriptName, bool RequiresValue, bool ExistingFile = false);

    private sealed class OptionParser
    {
        private readonly string[] _args;
        private int _index;

        public OptionParser(string[] args) => _args = args;

        public bool HasRemaining => _index < _args.Length;

        public bool TakeFlag(string name)
        {
            var index = Array.FindIndex(_args, _index, x => OptionComparer.Equals(x, name));
            if (index < 0)
                return false;

            _args[index] = string.Empty;
            return true;
        }

        public string? TakeValue(string name)
        {
            for (var i = _index; i < _args.Length; i++)
            {
                if (!OptionComparer.Equals(_args[i], name))
                    continue;

                _args[i] = string.Empty;
                if (i + 1 >= _args.Length || string.IsNullOrWhiteSpace(_args[i + 1]) || _args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    throw new CliUsageException($"{name} requires a value.");

                var value = _args[i + 1];
                _args[i + 1] = string.Empty;
                return value;
            }

            return null;
        }

        public string TakeOption()
        {
            SkipRemoved();
            if (!HasRemaining)
                throw new InvalidOperationException("No remaining option.");

            var option = _args[_index++];
            if (!option.StartsWith("--", StringComparison.Ordinal))
                throw new CliUsageException($"Unexpected value without option: {Safe(option)}");

            return option;
        }

        public string TakeRequiredValue(string optionName)
        {
            if (!HasRemaining || string.IsNullOrWhiteSpace(_args[_index]) || _args[_index].StartsWith("--", StringComparison.Ordinal))
                throw new CliUsageException($"{optionName} requires a value.");

            return _args[_index++];
        }

        public void ThrowIfRemaining()
        {
            SkipRemoved();
            if (HasRemaining)
                throw new CliUsageException($"Unexpected argument: {Safe(_args[_index])}");
        }

        private void SkipRemoved()
        {
            while (_index < _args.Length && string.IsNullOrWhiteSpace(_args[_index]))
                _index++;
        }
    }

}
