using ConShield.ImageScanner;

namespace ConShield.Tests;

public class DockerContainerRuntimeTests
{
    [Fact]
    public async Task Launch_UsesFixedHardenedArguments()
    {
        var docker = WriteTempExecutable();
        var runner = new SpyProcessRunner();
        var runtime = new DockerContainerRuntime(runner);

        var result = await runtime.LaunchAsync(
            new ScannerOptions
            {
                ImageReference = "repo/app:latest",
                DockerPath = docker,
                RunTimeoutSeconds = 30
            },
            new ImageScanSummary { ImageReference = "repo/app:latest" },
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(2, runner.Calls.Count);
        var args = runner.Calls[1].Arguments;
        Assert.Equal("run", args[0]);
        Assert.Contains("--network=none", args);
        Assert.Contains("--read-only", args);
        Assert.Contains("--cap-drop=ALL", args);
        Assert.Contains("--security-opt=no-new-privileges", args);
        Assert.Contains("--pull=never", args);
        Assert.DoesNotContain("--privileged", args);
        Assert.DoesNotContain("--network=host", args);
        Assert.Equal("repo/app:latest", args[^1]);
    }

    [Fact]
    public async Task Launch_MissingExecutable_ReturnsUnavailable()
    {
        var runtime = new DockerContainerRuntime(new SpyProcessRunner());

        var result = await runtime.LaunchAsync(
            new ScannerOptions { DockerPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".exe") },
            new ImageScanSummary { ImageReference = "repo/app:latest" },
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.True(result.Unavailable);
    }

    [Fact]
    public async Task Launch_Timeout_ReturnsTimeout()
    {
        var docker = WriteTempExecutable();
        var runtime = new DockerContainerRuntime(new SpyProcessRunner(timeoutOnRun: true));

        var result = await runtime.LaunchAsync(
            new ScannerOptions { DockerPath = docker, RunTimeoutSeconds = 30 },
            new ImageScanSummary { ImageReference = "repo/app:latest" },
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.True(result.TimedOut);
        Assert.Equal(ContainerLaunchOutcome.TimedOut, result.Outcome);
    }

    private static string WriteTempExecutable()
    {
        var path = Path.Combine(Path.GetTempPath(), OperatingSystem.IsWindows() ? $"{Guid.NewGuid():N}.exe" : $"{Guid.NewGuid():N}");
        File.WriteAllText(path, string.Empty);
        return path;
    }

    private sealed class SpyProcessRunner : IProcessRunner
    {
        private readonly bool _timeoutOnRun;

        public SpyProcessRunner(bool timeoutOnRun = false)
        {
            _timeoutOnRun = timeoutOnRun;
        }

        public List<ProcessCall> Calls { get; } = new();

        public Task<ProcessRunResult> RunAsync(
            string fileName,
            IReadOnlyList<string> arguments,
            int timeoutSeconds,
            int maxStdoutBytes,
            int maxStderrBytes,
            CancellationToken cancellationToken)
        {
            Calls.Add(new ProcessCall(fileName, arguments.ToArray()));
            if (_timeoutOnRun && arguments.FirstOrDefault() == "run")
                return Task.FromResult(ProcessRunResult.TimedOutResult());

            return Task.FromResult(new ProcessRunResult(true, 0, "ok", string.Empty, null));
        }
    }

    private sealed record ProcessCall(string FileName, string[] Arguments);
}
