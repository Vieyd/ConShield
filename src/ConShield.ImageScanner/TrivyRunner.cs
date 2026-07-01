namespace ConShield.ImageScanner;

public interface ITrivyRunner
{
    Task<TrivyRunResult> ScanAsync(ScannerOptions options, CancellationToken cancellationToken);
}

public sealed class TrivyRunner : ITrivyRunner
{
    private readonly IProcessRunner _processRunner;

    public TrivyRunner(IProcessRunner processRunner)
    {
        _processRunner = processRunner;
    }

    public async Task<TrivyRunResult> ScanAsync(ScannerOptions options, CancellationToken cancellationToken)
    {
        var trivyPath = TrivyExecutableResolver.Resolve(options.TrivyPath);
        if (trivyPath is null)
            return TrivyRunResult.Unavailable("Trivy executable was not found.");

        var versionResult = await _processRunner.RunAsync(
            trivyPath,
            ["--version"],
            timeoutSeconds: 15,
            maxStdoutBytes: 16 * 1024,
            maxStderrBytes: 16 * 1024,
            cancellationToken);

        if (versionResult.TimedOutOrCanceled)
            return TrivyRunResult.Timeout();

        if (!versionResult.Started)
            return TrivyRunResult.Unavailable(versionResult.StartError ?? "Trivy did not start.");

        if (versionResult.ExitCode != 0)
            return TrivyRunResult.Unavailable(Redaction.TrimForSafeOutput(versionResult.StandardError, ScannerConstants.StderrDisplayLimit));

        var scannerVersion = ParseVersion(versionResult.StandardOutput);
        var scanResult = await _processRunner.RunAsync(
            trivyPath,
            ["image", "--format", "json", "--quiet", "--scanners", "vuln,secret,misconfig", options.ImageReference],
            options.TimeoutSeconds,
            ScannerConstants.MaxReportBytes,
            ScannerConstants.MaxStderrBytes,
            cancellationToken);

        if (scanResult.TimedOutOrCanceled)
            return TrivyRunResult.Timeout();

        if (!scanResult.Started)
            return TrivyRunResult.Unavailable(scanResult.StartError ?? "Trivy did not start.");

        if (scanResult.OutputTooLarge)
            return TrivyRunResult.ParseFailed("Trivy JSON report exceeded the maximum allowed size.");

        if (scanResult.ExitCode != 0)
        {
            return TrivyRunResult.ScanFailed(
                Redaction.TrimForSafeOutput(scanResult.StandardError, ScannerConstants.StderrDisplayLimit));
        }

        return TrivyRunResult.Success(scannerVersion, scanResult.StandardOutput);
    }

    private static string ParseVersion(string value)
    {
        var firstLine = value.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        return string.IsNullOrWhiteSpace(firstLine) ? "unknown" : Redaction.TrimForSafeOutput(firstLine.Trim(), 128);
    }
}

public sealed class TrivyRunResult
{
    private TrivyRunResult(
        bool isSuccess,
        ExitCodes? failureExitCode,
        string? scannerVersion,
        string? reportJson,
        string? error)
    {
        IsSuccess = isSuccess;
        FailureExitCode = failureExitCode;
        ScannerVersion = scannerVersion;
        ReportJson = reportJson;
        Error = error;
    }

    public bool IsSuccess { get; }
    public ExitCodes? FailureExitCode { get; }
    public string? ScannerVersion { get; }
    public string? ReportJson { get; }
    public string? Error { get; }

    public static TrivyRunResult Success(string scannerVersion, string reportJson) => new(true, null, scannerVersion, reportJson, null);
    public static TrivyRunResult Unavailable(string error) => new(false, ExitCodes.TrivyUnavailable, null, null, error);
    public static TrivyRunResult ScanFailed(string error) => new(false, ExitCodes.ScanFailed, null, null, error);
    public static TrivyRunResult ParseFailed(string error) => new(false, ExitCodes.ReportParsingFailed, null, null, error);
    public static TrivyRunResult Timeout() => new(false, ExitCodes.TimeoutOrCancellation, null, null, "Trivy scan timed out or was canceled.");
}
