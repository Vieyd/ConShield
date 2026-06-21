using ConShield.RuntimeDetection;

namespace ConShield.RuntimeCollector;

public static class RuntimeCollectorApp
{
    public static async Task<RuntimeCollectorExitCode> RunAsync(
        string[] args,
        TextReader stdin,
        TextWriter stdout,
        TextWriter stderr,
        CancellationToken cancellationToken)
    {
        var parsed = CommandLineParser.Parse(args);
        if (!parsed.IsValid)
        {
            await stderr.WriteLineAsync(parsed.Error);
            return RuntimeCollectorExitCode.InvalidArgs;
        }
        var options = parsed.Options!;
        var mapping = FalcoMappingPolicyLoader.Load(options.MappingPath);
        if (!mapping.Success)
        {
            await stderr.WriteLineAsync($"Invalid mapping: {mapping.Error}");
            return RuntimeCollectorExitCode.InvalidMapping;
        }
        var apiKey = options.NoSubmit ? null : Environment.GetEnvironmentVariable(options.ApiKeyEnv);
        if (!options.NoSubmit && string.IsNullOrWhiteSpace(apiKey))
        {
            await stderr.WriteLineAsync("API key environment variable is missing.");
            return RuntimeCollectorExitCode.AuthFailure;
        }

        RuntimeIngestionClient? client = null;
        if (!options.NoSubmit)
        {
            client = new RuntimeIngestionClient(new HttpClient
            {
                BaseAddress = new Uri(options.Endpoint!),
                Timeout = TimeSpan.FromSeconds(options.SubmitTimeoutSeconds)
            }, apiKey!);
        }

        var parser = new FalcoAlertParser();
        var normalizer = new RuntimeEventNormalizer();
        var counters = new Counters();
        try
        {
            await foreach (var line in BoundedRuntimeLineReader.ReadAsync(options, stdin, cancellationToken))
            {
                var parsedLine = parser.Parse(line, DateTime.UtcNow, TimeSpan.FromMinutes(5), TimeSpan.FromDays(30));
                if (!parsedLine.Success)
                {
                    counters.Invalid++;
                    continue;
                }
                counters.Parsed++;
                var runtimeEvent = normalizer.Normalize(parsedLine.Alert!, mapping.Policy!);
                counters.Mapped += runtimeEvent.AdditionalData.Correlate ? 1 : 0;
                counters.Unmapped += runtimeEvent.AdditionalData.Correlate ? 0 : 1;
                if (options.NoSubmit)
                {
                    counters.Accepted++;
                    continue;
                }
                var submit = await client!.SubmitAsync(runtimeEvent, options.MaxRetries, cancellationToken);
                if (submit.AuthFailure)
                    return RuntimeCollectorExitCode.AuthFailure;
                if (submit.Accepted)
                {
                    counters.Accepted++;
                    counters.Duplicate += submit.Duplicate ? 1 : 0;
                }
                else
                {
                    counters.Failed++;
                }
            }
        }
        catch (OperationCanceledException)
        {
            return RuntimeCollectorExitCode.Cancelled;
        }
        catch (IOException)
        {
            return RuntimeCollectorExitCode.InputFailure;
        }

        await stdout.WriteLineAsync($"parsed={counters.Parsed} mapped={counters.Mapped} unmapped={counters.Unmapped} accepted={counters.Accepted} duplicate={counters.Duplicate} invalid={counters.Invalid} failed={counters.Failed}");
        return counters.Failed > 0 || counters.Invalid > 0 ? RuntimeCollectorExitCode.PartialFailure : RuntimeCollectorExitCode.Success;
    }

    private sealed class Counters
    {
        public int Parsed { get; set; }
        public int Mapped { get; set; }
        public int Unmapped { get; set; }
        public int Accepted { get; set; }
        public int Duplicate { get; set; }
        public int Invalid { get; set; }
        public int Failed { get; set; }
    }
}
