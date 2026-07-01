using ConShield.ImageScanner;

namespace ConShield.Cli;

internal static class LiveTrivyScanner
{
    public const int MinTimeoutSeconds = ScannerOptions.MinTimeoutSeconds;
    public const int MaxTimeoutSeconds = 600;
    public const int DefaultTimeoutSeconds = ScannerOptions.DefaultTimeoutSeconds;
    public const string UnavailableHint = "install Trivy or use --from-trivy-json fixture mode.";
    public const string FailedHint = "verify image name, image source access, local cache/network, or use fixture mode.";

    public static void ValidateTimeout(int timeoutSeconds)
    {
        if (timeoutSeconds is < MinTimeoutSeconds or > MaxTimeoutSeconds)
            throw new CliUsageException($"--timeout-seconds must be between {MinTimeoutSeconds} and {MaxTimeoutSeconds}.");
    }

    public static async Task<LiveTrivyScanResult> ScanAsync(
        string image,
        string? trivyPath,
        int timeoutSeconds,
        CancellationToken cancellationToken = default)
    {
        ValidateTimeout(timeoutSeconds);

        var result = await new TrivyRunner(new ProcessRunner()).ScanAsync(
            new ScannerOptions
            {
                ImageReference = image,
                TrivyPath = trivyPath,
                TimeoutSeconds = timeoutSeconds,
                NoSubmit = true
            },
            cancellationToken);

        if (result.IsSuccess)
            return LiveTrivyScanResult.Success(result.ScannerVersion ?? "unknown", result.ReportJson ?? "{}");

        var failure = result.FailureExitCode switch
        {
            ExitCodes.TrivyUnavailable => LiveTrivyFailureKind.Unavailable,
            ExitCodes.TimeoutOrCancellation => LiveTrivyFailureKind.Timeout,
            _ => LiveTrivyFailureKind.Failed
        };

        return LiveTrivyScanResult.Failure(
            failure,
            Redaction.TrimForSafeOutput(result.Error ?? "Trivy scan failed.", ScannerConstants.StderrDisplayLimit));
    }
}

internal sealed record LiveTrivyScanResult(
    bool IsSuccess,
    LiveTrivyFailureKind FailureKind,
    string? ScannerVersion,
    string? ReportJson,
    string? SafeError)
{
    public static LiveTrivyScanResult Success(string scannerVersion, string reportJson) =>
        new(true, LiveTrivyFailureKind.None, scannerVersion, reportJson, null);

    public static LiveTrivyScanResult Failure(LiveTrivyFailureKind kind, string safeError) =>
        new(false, kind, null, null, safeError);
}

internal enum LiveTrivyFailureKind
{
    None,
    Unavailable,
    Timeout,
    Failed
}
