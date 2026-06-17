using ConShield.ContainerPolicy;
using ConShield.ImageScanner;

namespace ConShield.Tests;

public class PolicyGateTests
{
    [Fact]
    public async Task Gate_MissingPolicy_ReturnsInvalidArgumentsBeforeScan()
    {
        var trivy = new FakeTrivyRunner();
        var result = await RunAsync(["gate", "--image", "repo/app:1", "--no-submit"], trivy);

        Assert.Equal(ExitCodes.InvalidArguments, result.ExitCode);
        Assert.Equal(0, trivy.Calls);
    }

    [Fact]
    public async Task Gate_InvalidPolicy_ReturnsInvalidPolicyBeforeScan()
    {
        var policy = WritePolicy("""{"schemaVersion":2}""");
        var trivy = new FakeTrivyRunner();
        var result = await RunAsync(["gate", "--image", "repo/app:1", "--policy", policy, "--no-submit"], trivy);

        Assert.Equal(ExitCodes.InvalidPolicy, result.ExitCode);
        Assert.Equal(0, trivy.Calls);
    }

    [Fact]
    public async Task Gate_BlockDryRun_DoesNotLaunch()
    {
        var runtime = new FakeContainerRuntime();
        var result = await RunAsync(["gate", "--image", "repo/app:1", "--policy", WritePolicy(), "--no-submit"], runtime: runtime);

        Assert.Equal(ExitCodes.PolicyBlocked, result.ExitCode);
        Assert.Equal(0, runtime.Calls);
        Assert.Contains("Policy decision: Block", result.Output);
        Assert.Contains("DRY RUN", result.Output);
    }

    [Fact]
    public async Task Gate_WarnDryRun_ReturnsWarningNotAccepted()
    {
        var result = await RunAsync(
            ["gate", "--image", "repo/app:1", "--policy", WritePolicy(), "--no-submit"],
            trivy: new FakeTrivyRunner(high: 1, total: 1));

        Assert.Equal(ExitCodes.WarningNotAccepted, result.ExitCode);
        Assert.Contains("Policy decision: Warn", result.Output);
    }

    [Fact]
    public async Task Gate_AllowDryRun_ReturnsSuccess()
    {
        var result = await RunAsync(
            ["gate", "--image", "repo/app:1", "--policy", WritePolicy(), "--no-submit"],
            trivy: new FakeTrivyRunner(low: 1, total: 1));

        Assert.Equal(ExitCodes.Success, result.ExitCode);
        Assert.Contains("Policy decision: Allow", result.Output);
    }

    [Fact]
    public async Task Gate_ExecuteBlock_NeverLaunches()
    {
        var runtime = new FakeContainerRuntime();
        var result = await RunAsync(["gate", "--image", "repo/app:1", "--policy", WritePolicy(), "--no-submit", "--execute"], runtime: runtime);

        Assert.Equal(ExitCodes.PolicyBlocked, result.ExitCode);
        Assert.Equal(0, runtime.Calls);
    }

    [Fact]
    public async Task Gate_ExecuteWarnWithoutAcceptance_DoesNotLaunch()
    {
        var runtime = new FakeContainerRuntime();
        var result = await RunAsync(
            ["gate", "--image", "repo/app:1", "--policy", WritePolicy(), "--no-submit", "--execute"],
            trivy: new FakeTrivyRunner(high: 1, total: 1),
            runtime: runtime);

        Assert.Equal(ExitCodes.WarningNotAccepted, result.ExitCode);
        Assert.Equal(0, runtime.Calls);
    }

    [Fact]
    public async Task Gate_ExecuteWarnWithAcceptance_Launches()
    {
        var runtime = new FakeContainerRuntime();
        var result = await RunAsync(
            ["gate", "--image", "repo/app:1", "--policy", WritePolicy(), "--no-submit", "--execute", "--accept-warning"],
            trivy: new FakeTrivyRunner(high: 1, total: 1),
            runtime: runtime);

        Assert.Equal(ExitCodes.Success, result.ExitCode);
        Assert.Equal(1, runtime.Calls);
    }

    [Fact]
    public async Task Gate_ApiFailureDeniesLaunch()
    {
        var runtime = new FakeContainerRuntime();
        var result = await RunAsync(
            ["gate", "--image", "repo/app:1", "--policy", WritePolicy(), "--base-url", "http://127.0.0.1:5000", "--api-key", "secret"],
            trivy: new FakeTrivyRunner(low: 1, total: 1),
            ingestion: new FakeIngestionClient(success: false),
            runtime: runtime);

        Assert.Equal(ExitCodes.ApiRejectedRequest, result.ExitCode);
        Assert.Equal(0, runtime.Calls);
    }

    [Fact]
    public async Task Gate_UsesSameExternalEventIdForScanAndPolicyEvents()
    {
        var ingestion = new FakeIngestionClient();
        var eventId = Guid.NewGuid().ToString();
        var result = await RunAsync(
            ["gate", "--image", "repo/app:1", "--policy", WritePolicy(), "--base-url", "http://127.0.0.1:5000", "--api-key", "secret", "--external-event-id", eventId],
            trivy: new FakeTrivyRunner(low: 1, total: 1),
            ingestion: ingestion);

        Assert.Equal(ExitCodes.Success, result.ExitCode);
        Assert.Equal(2, ingestion.Requests.Count);
        Assert.All(ingestion.Requests, x => Assert.Equal(Guid.Parse(eventId), x.ExternalEventId));
        Assert.Contains(ingestion.Requests, x => x.SourceSystem == ScannerConstants.SourceSystem);
        Assert.Contains(ingestion.Requests, x => x.SourceSystem == ScannerConstants.PolicySourceSystem);
    }

    [Fact]
    public void DockerLaunchImage_UsesDigestWhenPresent()
    {
        var image = DockerContainerRuntime.SelectLaunchImage(new ImageScanSummary
        {
            ImageReference = "repo/app:latest",
            ImageDigest = "repo/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        });

        Assert.Equal("repo/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", image);
    }

    [Fact]
    public void DockerLaunchImage_RejectsInvalidDigest()
    {
        var image = DockerContainerRuntime.SelectLaunchImage(new ImageScanSummary
        {
            ImageReference = "repo/app:latest",
            ImageDigest = "not-a-digest"
        });

        Assert.Null(image);
    }

    private static async Task<AppRunResult> RunAsync(
        string[] args,
        FakeTrivyRunner? trivy = null,
        FakeIngestionClient? ingestion = null,
        FakeContainerRuntime? runtime = null)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var app = new ImageScannerApp(
            trivy ?? new FakeTrivyRunner(critical: 1, total: 1),
            ingestion ?? new FakeIngestionClient(),
            runtime ?? new FakeContainerRuntime(),
            new ContainerPolicyLoader(),
            new ContainerPolicyEvaluator(),
            output,
            error);

        var exit = await app.RunInternalAsync(args, CancellationToken.None);
        return new AppRunResult(exit, output.ToString(), error.ToString());
    }

    private static string WritePolicy(string? json = null)
    {
        var path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.json");
        File.WriteAllText(path, json ?? """
        {
          "schemaVersion": 1,
          "policyId": "container-baseline",
          "version": "1.0.0",
          "thresholds": {
            "criticalBlock": 1,
            "highBlock": 10,
            "totalBlock": 100,
            "highWarn": 1,
            "mediumWarn": 10,
            "unknownWarn": 1
          },
          "deniedImages": []
        }
        """);
        return path;
    }

    private sealed class FakeTrivyRunner : ITrivyRunner
    {
        private readonly int _unknown;
        private readonly int _low;
        private readonly int _medium;
        private readonly int _high;
        private readonly int _critical;
        private readonly int _total;

        public FakeTrivyRunner(int unknown = 0, int low = 0, int medium = 0, int high = 0, int critical = 0, int total = 0)
        {
            _unknown = unknown;
            _low = low;
            _medium = medium;
            _high = high;
            _critical = critical;
            _total = total;
        }

        public int Calls { get; private set; }

        public Task<TrivyRunResult> ScanAsync(ScannerOptions options, CancellationToken cancellationToken)
        {
            Calls++;
            var severities = new List<string>();
            severities.AddRange(Enumerable.Repeat("UNKNOWN", _unknown));
            severities.AddRange(Enumerable.Repeat("LOW", _low));
            severities.AddRange(Enumerable.Repeat("MEDIUM", _medium));
            severities.AddRange(Enumerable.Repeat("HIGH", _high));
            severities.AddRange(Enumerable.Repeat("CRITICAL", _critical));
            if (severities.Count == 0 && _total > 0)
                severities.AddRange(Enumerable.Repeat("LOW", _total));

            var vulns = string.Join(",", severities.Select((severity, index) => $$"""{"VulnerabilityID":"CVE-{{index}}","PkgName":"pkg","InstalledVersion":"1","Severity":"{{severity}}"}"""));
            var report = $$"""
            {
              "ArtifactName": "{{options.ImageReference}}",
              "Metadata": {
                "RepoDigests": ["repo/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
              },
              "Results": [
                {
                  "Target": "os",
                  "Vulnerabilities": [{{vulns}}]
                }
              ]
            }
            """;

            return Task.FromResult(TrivyRunResult.Success("Version: 0.0.0", report));
        }
    }

    private sealed class FakeIngestionClient : IIngestionClient
    {
        private readonly bool _success;
        public List<ImageScanIngestRequest> Requests { get; } = new();

        public FakeIngestionClient(bool success = true)
        {
            _success = success;
        }

        public Task<IngestionSubmitResult> SubmitAsync(ScannerOptions options, ImageScanIngestRequest request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return Task.FromResult(_success
                ? IngestionSubmitResult.Accepted(201, Requests.Count.ToString(), true)
                : IngestionSubmitResult.Rejected(500, "failed"));
        }
    }

    private sealed class FakeContainerRuntime : IContainerRuntime
    {
        public int Calls { get; private set; }

        public Task<ContainerRuntimeResult> LaunchAsync(ScannerOptions options, ImageScanSummary summary, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(ContainerRuntimeResult.Started());
        }
    }

    private sealed record AppRunResult(ExitCodes ExitCode, string Output, string Error);
}
