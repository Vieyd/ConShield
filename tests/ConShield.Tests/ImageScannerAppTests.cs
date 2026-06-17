using ConShield.ImageScanner;
using ConShield.ContainerPolicy;

namespace ConShield.Tests;

public class ImageScannerAppTests
{
    [Fact]
    public async Task MissingImage_ReturnsInvalidArguments()
    {
        var result = await RunAsync(["scan"]);

        Assert.Equal(ExitCodes.InvalidArguments, result.ExitCode);
    }

    [Fact]
    public async Task InvalidUuid_ReturnsInvalidArgumentsBeforeScan()
    {
        var trivy = new FakeTrivyRunner();
        var result = await RunAsync(["scan", "--image", "repo/app:1", "--no-submit", "--external-event-id", "not-a-uuid"], trivy);

        Assert.Equal(ExitCodes.InvalidArguments, result.ExitCode);
        Assert.Equal(0, trivy.Calls);
    }

    [Fact]
    public async Task InvalidBaseUrl_ReturnsInvalidArguments()
    {
        var result = await RunAsync(["scan", "--image", "repo/app:1", "--base-url", "ftp://example.local", "--api-key", "local-key"]);

        Assert.Equal(ExitCodes.InvalidArguments, result.ExitCode);
    }

    [Fact]
    public async Task InvalidTimeout_ReturnsInvalidArguments()
    {
        var result = await RunAsync(["scan", "--image", "repo/app:1", "--no-submit", "--timeout-seconds", "1"]);

        Assert.Equal(ExitCodes.InvalidArguments, result.ExitCode);
    }

    [Fact]
    public async Task NoSubmit_DoesNotCallApi()
    {
        var ingestion = new FakeIngestionClient();
        var result = await RunAsync(["scan", "--image", "repo/app:1", "--no-submit"], ingestion: ingestion);

        Assert.Equal(ExitCodes.Success, result.ExitCode);
        Assert.Equal(0, ingestion.Calls);
        Assert.Contains("No-submit mode", result.Output);
    }

    [Fact]
    public async Task SeverityMapping_UsesCriticalHighWarningInfo()
    {
        Assert.Equal("Critical", ImageScanEventBuilder.MapSeverity(new ImageScanSummary { CriticalCount = 1 }));
        Assert.Equal("High", ImageScanEventBuilder.MapSeverity(new ImageScanSummary { HighCount = 1 }));
        Assert.Equal("Warning", ImageScanEventBuilder.MapSeverity(new ImageScanSummary { MediumCount = 1 }));
        Assert.Equal("Info", ImageScanEventBuilder.MapSeverity(new ImageScanSummary()));
    }

    [Fact]
    public async Task ApiError_ReturnsApiRejected()
    {
        var ingestion = new FakeIngestionClient(success: false);
        var result = await RunAsync([
            "scan", "--image", "repo/app:1", "--base-url", "http://127.0.0.1:5000", "--api-key", "local-key"
        ], ingestion: ingestion);

        Assert.Equal(ExitCodes.ApiRejectedRequest, result.ExitCode);
    }

    [Fact]
    public async Task ApiKey_IsAbsentFromOutput()
    {
        var result = await RunAsync([
            "scan", "--image", "repo/app:1", "--base-url", "http://127.0.0.1:5000", "--api-key", "secret-local-key"
        ]);

        Assert.DoesNotContain("secret-local-key", result.Output);
        Assert.DoesNotContain("secret-local-key", result.Error);
    }

    [Fact]
    public async Task CredentialLikeImage_IsRedactedInOutput()
    {
        var result = await RunAsync(["scan", "--image", "user:pass@registry.example.com/app:1", "--no-submit"]);

        Assert.DoesNotContain("user:pass", result.Output);
        Assert.Contains("***:***@registry.example.com/app:1", result.Output);
    }

    [Fact]
    public async Task UnknownOption_ReturnsInvalidArgumentsBeforeScan()
    {
        var trivy = new FakeTrivyRunner();
        var result = await RunAsync(["scan", "--image", "repo/app:1", "--no-submit", "--typo"], trivy);

        Assert.Equal(ExitCodes.InvalidArguments, result.ExitCode);
        Assert.Equal(0, trivy.Calls);
    }

    [Fact]
    public async Task DuplicateImage_ReturnsInvalidArgumentsBeforeScan()
    {
        var trivy = new FakeTrivyRunner();
        var result = await RunAsync(["scan", "--image", "repo/app:1", "--image", "repo/app:2", "--no-submit"], trivy);

        Assert.Equal(ExitCodes.InvalidArguments, result.ExitCode);
        Assert.Equal(0, trivy.Calls);
    }

    [Fact]
    public async Task PositionalGarbage_ReturnsInvalidArgumentsBeforeScan()
    {
        var trivy = new FakeTrivyRunner();
        var result = await RunAsync(["scan", "--image", "repo/app:1", "garbage", "--no-submit"], trivy);

        Assert.Equal(ExitCodes.InvalidArguments, result.ExitCode);
        Assert.Equal(0, trivy.Calls);
    }

    [Fact]
    public async Task ValidScan_WithCustomSourceSystem_StillWorks()
    {
        var ingestion = new FakeIngestionClient();
        var result = await RunAsync([
            "scan", "--image", "repo/app:1", "--base-url", "http://127.0.0.1:5000", "--api-key", "local-key", "--source-system", "custom-source"
        ], ingestion: ingestion);

        Assert.Equal(ExitCodes.Success, result.ExitCode);
        Assert.Equal(1, ingestion.Calls);
        Assert.Equal("custom-source", ingestion.Requests.Single().SourceSystem);
    }

    private static async Task<AppRunResult> RunAsync(
        string[] args,
        FakeTrivyRunner? trivy = null,
        FakeIngestionClient? ingestion = null)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var app = new ImageScannerApp(
            trivy ?? new FakeTrivyRunner(),
            ingestion ?? new FakeIngestionClient(),
            new FakeContainerRuntime(),
            new ContainerPolicyLoader(),
            new ContainerPolicyEvaluator(),
            new GateAuditEventFactory(),
            output,
            error);

        var exit = await app.RunInternalAsync(args, CancellationToken.None);
        return new AppRunResult(exit, output.ToString(), error.ToString());
    }

    private sealed class FakeTrivyRunner : ITrivyRunner
    {
        public int Calls { get; private set; }

        public Task<TrivyRunResult> ScanAsync(ScannerOptions options, CancellationToken cancellationToken)
        {
            Calls++;
            var report = $$"""
            {
              "ArtifactName": "{{options.ImageReference}}",
              "Results": [
                {
                  "Target": "os",
                  "Vulnerabilities": [
                    { "VulnerabilityID": "CVE-1", "PkgName": "openssl", "InstalledVersion": "1", "Severity": "CRITICAL" }
                  ]
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

        public FakeIngestionClient(bool success = true)
        {
            _success = success;
        }

        public int Calls { get; private set; }
        public List<ImageScanIngestRequest> Requests { get; } = new();

        public Task<IngestionSubmitResult> SubmitAsync(ScannerOptions options, ImageScanIngestRequest request, CancellationToken cancellationToken)
        {
            Calls++;
            Requests.Add(request);
            return Task.FromResult(_success
                ? IngestionSubmitResult.Accepted(201, "1", true)
                : IngestionSubmitResult.Rejected(400, "validation_failed"));
        }
    }

    private sealed class FakeContainerRuntime : IContainerRuntime
    {
        public Task<ContainerRuntimeResult> LaunchAsync(ScannerOptions options, ImageScanSummary summary, CancellationToken cancellationToken)
        {
            return Task.FromResult(ContainerRuntimeResult.Started());
        }
    }

    private sealed record AppRunResult(ExitCodes ExitCode, string Output, string Error);
}
