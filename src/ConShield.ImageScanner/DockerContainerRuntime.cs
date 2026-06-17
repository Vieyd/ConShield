namespace ConShield.ImageScanner;

public interface IContainerRuntime
{
    Task<ContainerRuntimeResult> LaunchAsync(ScannerOptions options, ImageScanSummary summary, CancellationToken cancellationToken);
}

public sealed class DockerContainerRuntime : IContainerRuntime
{
    private const int MaxOutputBytes = 64 * 1024;
    private readonly IProcessRunner _processRunner;

    public DockerContainerRuntime(IProcessRunner processRunner)
    {
        _processRunner = processRunner;
    }

    public async Task<ContainerRuntimeResult> LaunchAsync(ScannerOptions options, ImageScanSummary summary, CancellationToken cancellationToken)
    {
        var dockerPath = ResolveDocker(options.DockerPath);
        if (dockerPath is null)
            return ContainerRuntimeResult.NotAvailable("Docker executable was not found.");

        var version = await _processRunner.RunAsync(
            dockerPath,
            ["version", "--format", "{{.Server.Version}}"],
            Math.Min(options.RunTimeoutSeconds, 15),
            MaxOutputBytes,
            ScannerConstants.MaxStderrBytes,
            cancellationToken);

        if (version.TimedOutOrCanceled)
            return ContainerRuntimeResult.Timeout("Docker version check timed out.");

        if (!version.Started || version.ExitCode != 0)
            return ContainerRuntimeResult.NotAvailable(Redaction.TrimForSafeOutput(version.StartError ?? version.StandardError, ScannerConstants.StderrDisplayLimit));

        var launchImage = SelectLaunchImage(summary);
        if (launchImage is null)
            return ContainerRuntimeResult.Failed("Image digest was present but was not a valid sha256 digest reference.");

        var args = new[]
        {
            "run",
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=128",
            "--memory=256m",
            "--cpus=0.5",
            "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
            launchImage
        };

        var run = await _processRunner.RunAsync(
            dockerPath,
            args,
            options.RunTimeoutSeconds,
            MaxOutputBytes,
            ScannerConstants.MaxStderrBytes,
            cancellationToken);

        if (run.TimedOutOrCanceled)
            return ContainerRuntimeResult.Timeout("Docker run timed out or was canceled.");

        if (!run.Started || run.ExitCode != 0)
            return ContainerRuntimeResult.Failed(Redaction.TrimForSafeOutput(run.StartError ?? run.StandardError, ScannerConstants.StderrDisplayLimit));

        return ContainerRuntimeResult.Started();
    }

    internal static string? SelectLaunchImage(ImageScanSummary summary)
    {
        if (string.IsNullOrWhiteSpace(summary.ImageDigest))
            return summary.ImageReference;

        var digest = summary.ImageDigest.Trim();
        return IsSha256DigestReference(digest) ? digest : null;
    }

    private static string? ResolveDocker(string? configuredPath)
    {
        if (!string.IsNullOrWhiteSpace(configuredPath))
            return File.Exists(configuredPath) ? configuredPath : null;

        var names = OperatingSystem.IsWindows() ? new[] { "docker.exe" } : new[] { "docker" };
        var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var directory in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            if (directory == "." || string.Equals(Path.GetFullPath(directory), Environment.CurrentDirectory, StringComparison.OrdinalIgnoreCase))
                continue;

            foreach (var name in names)
            {
                var candidate = Path.Combine(directory, name);
                if (File.Exists(candidate))
                    return candidate;
            }
        }

        return null;
    }

    private static bool IsSha256DigestReference(string value)
    {
        const string marker = "@sha256:";
        var index = value.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (index <= 0 || index + marker.Length + 64 != value.Length)
            return false;

        return value[(index + marker.Length)..].All(Uri.IsHexDigit);
    }
}

public sealed class ContainerRuntimeResult
{
    private ContainerRuntimeResult(bool success, bool unavailable, bool timedOut, string? error)
    {
        Success = success;
        Unavailable = unavailable;
        TimedOut = timedOut;
        Error = error;
    }

    public bool Success { get; }
    public bool Unavailable { get; }
    public bool TimedOut { get; }
    public string? Error { get; }

    public static ContainerRuntimeResult Started() => new(true, false, false, null);
    public static ContainerRuntimeResult NotAvailable(string error) => new(false, true, false, error);
    public static ContainerRuntimeResult Timeout(string error) => new(false, false, true, error);
    public static ContainerRuntimeResult Failed(string error) => new(false, false, false, error);
}
