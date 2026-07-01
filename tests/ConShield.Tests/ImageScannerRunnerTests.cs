using ConShield.ImageScanner;

namespace ConShield.Tests;

public class ImageScannerRunnerTests
{
    [Fact]
    public async Task TrivyRunner_ReturnsTimeout()
    {
        var temp = CreateExecutablePlaceholder();
        var runner = new TrivyRunner(new FakeProcessRunner(timeout: true));
        var result = await runner.ScanAsync(Options(trivyPath: temp), CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal(ExitCodes.TimeoutOrCancellation, result.FailureExitCode);
    }

    [Fact]
    public async Task TrivyRunner_ReturnsUnavailableWhenExecutableMissing()
    {
        var runner = new TrivyRunner(new FakeProcessRunner());
        var result = await runner.ScanAsync(Options(trivyPath: "C:\\missing\\trivy.exe"), CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal(ExitCodes.TrivyUnavailable, result.FailureExitCode);
    }

    [Fact]
    public async Task TrivyRunner_ReturnsScanFailedOnNonZeroScanExit()
    {
        var temp = CreateExecutablePlaceholder();
        var runner = new TrivyRunner(new FakeProcessRunner(scanExitCode: 2, stderr: "database unavailable"));

        var result = await runner.ScanAsync(Options(trivyPath: temp), CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal(ExitCodes.ScanFailed, result.FailureExitCode);
    }

    [Fact]
    public async Task TrivyRunner_ReturnsParseFailureOnOversizedStdout()
    {
        var temp = CreateExecutablePlaceholder();
        var runner = new TrivyRunner(new FakeProcessRunner(outputTooLarge: true));

        var result = await runner.ScanAsync(Options(trivyPath: temp), CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal(ExitCodes.ReportParsingFailed, result.FailureExitCode);
    }

    [Fact]
    public async Task TrivyRunner_UsesNoShellAndSeparateArguments()
    {
        var temp = CreateExecutablePlaceholder();
        var fake = new FakeProcessRunner();
        var runner = new TrivyRunner(fake);

        var result = await runner.ScanAsync(Options(trivyPath: temp, image: "repo/app:1; rm -rf /"), CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Contains(fake.Calls, x => x.Arguments.SequenceEqual(["image", "--format", "json", "--quiet", "--scanners", "vuln,secret,misconfig", "repo/app:1; rm -rf /"]));
    }

    [Fact]
    public void Redaction_RemovesCredentialLikeImagePrefix()
    {
        Assert.Equal("***:***@registry.example.com/app:1", Redaction.RedactImageReference("user:pass@registry.example.com/app:1"));
    }

    private static ScannerOptions Options(string? trivyPath = null, string image = "repo/app:1") => new()
    {
        ImageReference = image,
        TrivyPath = trivyPath,
        TimeoutSeconds = 30,
        ExternalEventId = Guid.NewGuid(),
        NoSubmit = true
    };

    private static string CreateExecutablePlaceholder()
    {
        var file = Path.Combine(Path.GetTempPath(), $"trivy-test-{Guid.NewGuid():N}.exe");
        File.WriteAllText(file, string.Empty);
        return file;
    }

    private sealed class FakeProcessRunner : IProcessRunner
    {
        private readonly bool _timeout;
        private readonly int _scanExitCode;
        private readonly string _stderr;
        private readonly bool _outputTooLarge;
        private int _callIndex;

        public FakeProcessRunner(bool timeout = false, int scanExitCode = 0, string stderr = "", bool outputTooLarge = false)
        {
            _timeout = timeout;
            _scanExitCode = scanExitCode;
            _stderr = stderr;
            _outputTooLarge = outputTooLarge;
        }

        public List<(string FileName, IReadOnlyList<string> Arguments)> Calls { get; } = new();

        public Task<ProcessRunResult> RunAsync(string fileName, IReadOnlyList<string> arguments, int timeoutSeconds, int maxStdoutBytes, int maxStderrBytes, CancellationToken cancellationToken)
        {
            Calls.Add((fileName, arguments.ToArray()));
            _callIndex++;

            if (_timeout)
                return Task.FromResult(ProcessRunResult.TimedOutResult());

            if (_callIndex == 1)
                return Task.FromResult(new ProcessRunResult(true, 0, "Version: 0.0.0", "", null));

            if (_outputTooLarge)
                return Task.FromResult(ProcessRunResult.OversizedOutput("", ""));

            return Task.FromResult(new ProcessRunResult(true, _scanExitCode, """{"Results":[]}""", _stderr, null));
        }
    }
}
