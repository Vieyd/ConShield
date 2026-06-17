using System.Diagnostics;
using System.Text.Json;

namespace ConShield.ImageScanner;

public sealed class ImageScannerApp
{
    private readonly ITrivyRunner _trivyRunner;
    private readonly IIngestionClient _ingestionClient;
    private readonly TextWriter _output;
    private readonly TextWriter _error;

    public ImageScannerApp(
        ITrivyRunner trivyRunner,
        IIngestionClient ingestionClient,
        TextWriter output,
        TextWriter error)
    {
        _trivyRunner = trivyRunner;
        _ingestionClient = ingestionClient;
        _output = output;
        _error = error;
    }

    public static Task<ExitCodes> RunAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        var app = new ImageScannerApp(
            new TrivyRunner(new ProcessRunner()),
            new IngestionClient(),
            output,
            error);

        return app.RunInternalAsync(args, cancellationToken);
    }

    public async Task<ExitCodes> RunInternalAsync(string[] args, CancellationToken cancellationToken)
    {
        var parse = CommandLineParser.Parse(args);
        if (!parse.IsValid)
        {
            await _error.WriteLineAsync(parse.Error);
            await _error.WriteLineAsync("Usage: dotnet run --project src/ConShield.ImageScanner -- scan --image <image-reference> [--base-url <url>] [--trivy-path <path>] [--external-event-id <uuid>] [--timeout-seconds <number>] [--source-system <value>] [--no-submit]");
            return ExitCodes.InvalidArguments;
        }

        var options = parse.Options!;
        var stopwatch = Stopwatch.StartNew();
        TrivyRunResult trivyResult;

        try
        {
            trivyResult = await _trivyRunner.ScanAsync(options, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            await _error.WriteLineAsync("Scan was canceled.");
            return ExitCodes.TimeoutOrCancellation;
        }

        if (!trivyResult.IsSuccess)
        {
            await _error.WriteLineAsync(Redaction.TrimForSafeOutput(trivyResult.Error ?? "Trivy scan failed.", ScannerConstants.StderrDisplayLimit));
            return trivyResult.FailureExitCode ?? ExitCodes.ScanFailed;
        }

        ImageScanSummary summary;
        try
        {
            summary = TrivyReportParser.Parse(
                trivyResult.ReportJson!,
                trivyResult.ScannerVersion ?? "unknown",
                options.ImageReference);
        }
        catch (TrivyReportParseException ex)
        {
            await _error.WriteLineAsync(ex.Message);
            return ExitCodes.ReportParsingFailed;
        }

        stopwatch.Stop();
        var request = ImageScanEventBuilder.Build(options, summary, stopwatch.ElapsedMilliseconds);

        await _output.WriteLineAsync($"Image scan completed: image={Redaction.RedactImageReference(summary.ImageReference)}, critical={summary.CriticalCount}, high={summary.HighCount}, total={summary.TotalCount}");

        if (options.NoSubmit)
        {
            await _output.WriteLineAsync("No-submit mode: normalized event was not sent.");
            await _output.WriteLineAsync(JsonSerializer.Serialize(request, ImageScannerJsonContext.Default.ImageScanIngestRequest));
            return ExitCodes.Success;
        }

        try
        {
            var submit = await _ingestionClient.SubmitAsync(options, request, cancellationToken);
            if (!submit.Success)
            {
                await _error.WriteLineAsync($"API rejected event: HTTP {submit.StatusCode}. {submit.Error}");
                return ExitCodes.ApiRejectedRequest;
            }

            await _output.WriteLineAsync(submit.Created
                ? $"Event accepted. securityEventId={submit.SecurityEventId}"
                : $"Event already exists. securityEventId={submit.SecurityEventId}");
            return ExitCodes.Success;
        }
        catch (OperationCanceledException)
        {
            await _error.WriteLineAsync("API request was canceled.");
            return ExitCodes.TimeoutOrCancellation;
        }
        catch (HttpRequestException ex)
        {
            await _error.WriteLineAsync($"API request failed: {Redaction.TrimForSafeOutput(ex.Message, ScannerConstants.StderrDisplayLimit)}");
            return ExitCodes.ApiRejectedRequest;
        }
    }
}
