namespace ConShield.ImageScanner;

public enum ContainerLaunchOutcome
{
    Succeeded,
    Failed,
    TimedOut,
    Cancelled,
    Unavailable
}

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

        if (version.TimedOut)
            return ContainerRuntimeResult.Timeout("Docker version check timed out.");

        if (version.Canceled)
            return ContainerRuntimeResult.Cancelled("Docker version check was canceled.");

        if (!version.Started || version.ExitCode != 0)
            return ContainerRuntimeResult.NotAvailable(Redaction.TrimForSafeOutput(version.StartError ?? version.StandardError, ScannerConstants.StderrDisplayLimit));

        var runtimeVersion = Redaction.TrimForSafeOutput(version.StandardOutput.Trim(), 128);
        var launchImage = SelectLaunchImage(summary);
        if (launchImage is null)
            return ContainerRuntimeResult.Failed("Image digest was present but was not a valid sha256 digest reference.", launchReference: summary.ImageDigest, dockerRunInvoked: false);

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

        var startedAt = DateTime.UtcNow;
        var run = await _processRunner.RunAsync(
            dockerPath,
            args,
            options.RunTimeoutSeconds,
            MaxOutputBytes,
            ScannerConstants.MaxStderrBytes,
            cancellationToken);
        var durationMs = Math.Max(0, (long)(DateTime.UtcNow - startedAt).TotalMilliseconds);

        if (run.TimedOut)
            return ContainerRuntimeResult.Timeout("Docker run timed out.", runtimeVersion, launchImage, durationMs, dockerRunInvoked: true);

        if (run.Canceled)
            return ContainerRuntimeResult.Cancelled("Docker run was canceled.", runtimeVersion, launchImage, durationMs, dockerRunInvoked: true);

        if (!run.Started || run.ExitCode != 0)
        {
            return ContainerRuntimeResult.Failed(
                Redaction.TrimForSafeOutput(run.StartError ?? run.StandardError, ScannerConstants.StderrDisplayLimit),
                run.ExitCode,
                runtimeVersion,
                launchImage,
                durationMs,
                dockerRunInvoked: true);
        }

        return ContainerRuntimeResult.Started(run.ExitCode, runtimeVersion, launchImage, durationMs);
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
    private ContainerRuntimeResult(
        ContainerLaunchOutcome outcome,
        int? processExitCode,
        long durationMs,
        string? runtimeVersion,
        string? launchReference,
        string? safeErrorCategory,
        bool dockerRunInvoked,
        string? error)
    {
        Outcome = outcome;
        ProcessExitCode = processExitCode;
        DurationMs = Math.Max(0, durationMs);
        RuntimeVersion = string.IsNullOrWhiteSpace(runtimeVersion) ? null : runtimeVersion.Trim();
        LaunchReference = string.IsNullOrWhiteSpace(launchReference) ? null : Redaction.RedactImageReference(launchReference.Trim());
        SafeErrorCategory = safeErrorCategory;
        DockerRunInvoked = dockerRunInvoked;
        Error = error;
    }

    public ContainerLaunchOutcome Outcome { get; }
    public bool Success => Outcome == ContainerLaunchOutcome.Succeeded;
    public bool Unavailable => Outcome == ContainerLaunchOutcome.Unavailable;
    public bool TimedOut => Outcome == ContainerLaunchOutcome.TimedOut;
    public bool Canceled => Outcome == ContainerLaunchOutcome.Cancelled;
    public int? ProcessExitCode { get; }
    public long DurationMs { get; }
    public string? RuntimeVersion { get; }
    public string? LaunchReference { get; }
    public string? SafeErrorCategory { get; }
    public bool DockerRunInvoked { get; }
    public string? Error { get; }

    public static ContainerRuntimeResult Started(
        int? processExitCode = 0,
        string? runtimeVersion = null,
        string? launchReference = null,
        long durationMs = 0) =>
        new(ContainerLaunchOutcome.Succeeded, processExitCode, durationMs, runtimeVersion, launchReference, null, dockerRunInvoked: true, null);

    public static ContainerRuntimeResult NotAvailable(string error) =>
        new(ContainerLaunchOutcome.Unavailable, null, 0, null, null, "runtime_unavailable", dockerRunInvoked: false, error);

    public static ContainerRuntimeResult Timeout(
        string error,
        string? runtimeVersion = null,
        string? launchReference = null,
        long durationMs = 0,
        bool dockerRunInvoked = false) =>
        new(ContainerLaunchOutcome.TimedOut, null, durationMs, runtimeVersion, launchReference, "timeout", dockerRunInvoked, error);

    public static ContainerRuntimeResult Cancelled(
        string error,
        string? runtimeVersion = null,
        string? launchReference = null,
        long durationMs = 0,
        bool dockerRunInvoked = false) =>
        new(ContainerLaunchOutcome.Cancelled, null, durationMs, runtimeVersion, launchReference, "cancelled", dockerRunInvoked, error);

    public static ContainerRuntimeResult Failed(
        string error,
        int? processExitCode = null,
        string? runtimeVersion = null,
        string? launchReference = null,
        long durationMs = 0,
        bool dockerRunInvoked = false) =>
        new(ContainerLaunchOutcome.Failed, processExitCode, durationMs, runtimeVersion, launchReference, "non_zero_exit", dockerRunInvoked, error);
}
