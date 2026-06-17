using System.Diagnostics;
using System.Text.Json;
using ConShield.ContainerPolicy;

namespace ConShield.ImageScanner;

public sealed class ImageScannerApp
{
    private readonly ITrivyRunner _trivyRunner;
    private readonly IIngestionClient _ingestionClient;
    private readonly IContainerRuntime _containerRuntime;
    private readonly ContainerPolicyLoader _policyLoader;
    private readonly ContainerPolicyEvaluator _policyEvaluator;
    private readonly IGateAuditEventFactory _gateAuditEventFactory;
    private readonly TextWriter _output;
    private readonly TextWriter _error;
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web) { WriteIndented = false };

    internal ImageScannerApp(
        ITrivyRunner trivyRunner,
        IIngestionClient ingestionClient,
        IContainerRuntime containerRuntime,
        ContainerPolicyLoader policyLoader,
        ContainerPolicyEvaluator policyEvaluator,
        IGateAuditEventFactory gateAuditEventFactory,
        TextWriter output,
        TextWriter error)
    {
        _trivyRunner = trivyRunner;
        _ingestionClient = ingestionClient;
        _containerRuntime = containerRuntime;
        _policyLoader = policyLoader;
        _policyEvaluator = policyEvaluator;
        _gateAuditEventFactory = gateAuditEventFactory;
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
            new DockerContainerRuntime(new ProcessRunner()),
            new ContainerPolicyLoader(),
            new ContainerPolicyEvaluator(),
            new GateAuditEventFactory(),
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
        if (options.Command == "gate")
            return await RunGateAsync(options, cancellationToken);

        return await RunScanAsync(options, cancellationToken);
    }

    private async Task<ExitCodes> RunScanAsync(ScannerOptions options, CancellationToken cancellationToken)
    {
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
            await _output.WriteLineAsync(JsonSerializer.Serialize(request, SerializerOptions));
            return ExitCodes.Success;
        }

        return await SubmitEventAsync(options, request, "Event", cancellationToken);
    }

    private async Task<ExitCodes> RunGateAsync(ScannerOptions options, CancellationToken cancellationToken)
    {
        var policyResult = _policyLoader.LoadFromFile(options.PolicyPath);
        if (!policyResult.Success)
        {
            await _error.WriteLineAsync(policyResult.Error);
            return ExitCodes.InvalidPolicy;
        }

        var scanExit = await RunScanForGateAsync(options, cancellationToken);
        if (scanExit.ExitCode != ExitCodes.Success)
            return scanExit.ExitCode;

        var evaluationResult = _policyEvaluator.Evaluate(policyResult.Policy!, ToPolicySummary(scanExit.Summary!));
        if (!evaluationResult.Success)
        {
            await _error.WriteLineAsync(evaluationResult.Error);
            return ExitCodes.PolicyEvaluationFailed;
        }

        var evaluation = evaluationResult.Evaluation!;
        var auditEvents = _gateAuditEventFactory.Build(
            options,
            scanExit.Summary!,
            scanExit.ScanDurationMs,
            policyResult.Policy!,
            evaluation);

        if (!GateAuditInvariantValidator.IsValid(auditEvents))
        {
            await _error.WriteLineAsync("Gate audit invariant failed; no events were submitted and launch is denied.");
            return ExitCodes.PolicyEvaluationFailed;
        }

        await _output.WriteLineAsync($"Policy decision: {evaluation.Decision}; reasons={string.Join(",", evaluation.ReasonCodes)}");

        if (options.NoSubmit)
        {
            await _output.WriteLineAsync("No-submit mode: scan event was not sent.");
            await _output.WriteLineAsync(JsonSerializer.Serialize(auditEvents.ScanEvent, SerializerOptions));
            await _output.WriteLineAsync("No-submit mode: policy evaluation event was not sent.");
            await _output.WriteLineAsync(JsonSerializer.Serialize(auditEvents.PolicyEvent, SerializerOptions));
        }
        else
        {
            var scanSubmitExit = await SubmitEventAsync(options, auditEvents.ScanEvent, "Scan event", cancellationToken);
            if (scanSubmitExit != ExitCodes.Success)
            {
                await _error.WriteLineAsync("Container launch denied because scan audit submission failed.");
                return scanSubmitExit;
            }

            var policySubmitExit = await SubmitEventAsync(options, auditEvents.PolicyEvent, "Policy event", cancellationToken);
            if (policySubmitExit != ExitCodes.Success)
            {
                await _error.WriteLineAsync("Container launch denied because audit submission failed.");
                return policySubmitExit;
            }
        }

        if (!options.Execute)
        {
            await _output.WriteLineAsync("DRY RUN: Docker launch was not requested.");
            return evaluation.Decision switch
            {
                ContainerPolicyDecision.Block => ExitCodes.PolicyBlocked,
                ContainerPolicyDecision.Warn => ExitCodes.WarningNotAccepted,
                _ => ExitCodes.Success
            };
        }

        if (evaluation.Decision == ContainerPolicyDecision.Block)
        {
            await _error.WriteLineAsync("Container launch blocked by policy.");
            return ExitCodes.PolicyBlocked;
        }

        if (evaluation.Decision == ContainerPolicyDecision.Warn && !options.AcceptWarning)
        {
            await _error.WriteLineAsync("Container launch requires --accept-warning for Warn decisions.");
            return ExitCodes.WarningNotAccepted;
        }

        try
        {
            var launch = await _containerRuntime.LaunchAsync(options, scanExit.Summary!, cancellationToken);
            if (launch.Success)
            {
                await _output.WriteLineAsync("Container launched through hardened docker run.");
                return ExitCodes.Success;
            }

            await _error.WriteLineAsync(Redaction.TrimForSafeOutput(launch.Error ?? "Container launch failed.", ScannerConstants.StderrDisplayLimit));
            if (launch.TimedOut)
                return ExitCodes.LaunchTimeoutOrCancellation;

            return launch.Unavailable ? ExitCodes.DockerUnavailable : ExitCodes.LaunchFailed;
        }
        catch (OperationCanceledException)
        {
            await _error.WriteLineAsync("Container launch was canceled.");
            return ExitCodes.LaunchTimeoutOrCancellation;
        }
    }

    private async Task<GateScanResult> RunScanForGateAsync(ScannerOptions options, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        TrivyRunResult trivyResult;

        try
        {
            trivyResult = await _trivyRunner.ScanAsync(options, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            await _error.WriteLineAsync("Scan was canceled.");
            return new GateScanResult(ExitCodes.TimeoutOrCancellation, null);
        }

        if (!trivyResult.IsSuccess)
        {
            await _error.WriteLineAsync(Redaction.TrimForSafeOutput(trivyResult.Error ?? "Trivy scan failed.", ScannerConstants.StderrDisplayLimit));
            return new GateScanResult(trivyResult.FailureExitCode ?? ExitCodes.ScanFailed, null);
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
            return new GateScanResult(ExitCodes.ReportParsingFailed, null);
        }

        stopwatch.Stop();
        var durationMs = stopwatch.ElapsedMilliseconds;
        await _output.WriteLineAsync($"Image scan completed: image={Redaction.RedactImageReference(summary.ImageReference)}, critical={summary.CriticalCount}, high={summary.HighCount}, total={summary.TotalCount}");

        return new GateScanResult(ExitCodes.Success, summary, durationMs);
    }

    private static ContainerImageScanSummary ToPolicySummary(ImageScanSummary summary)
    {
        return new ContainerImageScanSummary
        {
            ImageReference = summary.ImageReference,
            ImageDigest = summary.ImageDigest,
            ReportSha256 = summary.ReportSha256,
            UnknownCount = summary.UnknownCount,
            LowCount = summary.LowCount,
            MediumCount = summary.MediumCount,
            HighCount = summary.HighCount,
            CriticalCount = summary.CriticalCount,
            TotalCount = summary.TotalCount
        };
    }

    private async Task<ExitCodes> SubmitEventAsync(
        ScannerOptions options,
        ImageScanIngestRequest request,
        string label,
        CancellationToken cancellationToken)
    {
        try
        {
            var submit = await _ingestionClient.SubmitAsync(options, request, cancellationToken);
            if (!submit.Success)
            {
                await _error.WriteLineAsync($"API rejected event: HTTP {submit.StatusCode}. {submit.Error}");
                return ExitCodes.ApiRejectedRequest;
            }

            await _output.WriteLineAsync(submit.Created
                ? $"{label} accepted. securityEventId={submit.SecurityEventId}"
                : $"{label} already exists. securityEventId={submit.SecurityEventId}");
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

    private sealed record GateScanResult(ExitCodes ExitCode, ImageScanSummary? Summary, long ScanDurationMs = 0);
}
