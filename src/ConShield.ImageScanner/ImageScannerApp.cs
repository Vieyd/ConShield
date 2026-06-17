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
            var scanSubmit = await SubmitEventDetailedAsync(options, auditEvents.ScanEvent, "Scan event", cancellationToken);
            if (!scanSubmit.Accepted)
            {
                await _error.WriteLineAsync("Container launch denied because scan audit submission failed.");
                return scanSubmit.ExitCode;
            }

            var policySubmit = await SubmitEventDetailedAsync(options, auditEvents.PolicyEvent, "Policy event", cancellationToken);
            if (!policySubmit.Accepted)
            {
                await _error.WriteLineAsync("Container launch denied because audit submission failed.");
                return policySubmit.ExitCode;
            }

            if (options.Execute)
            {
                var reservation = ValidateLaunchReservation(scanSubmit, policySubmit);
                if (reservation != ExitCodes.Success)
                {
                    await _error.WriteLineAsync(reservation == ExitCodes.OperationAlreadyProcessed
                        ? "Container launch denied because this gate operation was already processed."
                        : "Container launch denied because audit idempotency state is inconsistent.");
                    return reservation;
                }
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
            var launchEvent = LaunchResultEventBuilder.Build(options, scanExit.Summary!, launch);
            var launchAudit = await SubmitLaunchResultWithRetryAsync(options, launchEvent, cancellationToken);
            if (!launchAudit.Accepted)
            {
                await _error.WriteLineAsync("Container launch result audit submission failed.");
                return launch.Success ? ExitCodes.LaunchSucceededAuditFailed : ExitCodes.LaunchOutcomeAuditFailed;
            }

            if (launch.Success)
            {
                await _output.WriteLineAsync("Container launched through hardened docker run.");
                return ExitCodes.Success;
            }

            await _error.WriteLineAsync(Redaction.TrimForSafeOutput(launch.Error ?? "Container launch failed.", ScannerConstants.StderrDisplayLimit));
            if (launch.TimedOut)
                return ExitCodes.LaunchTimeoutOrCancellation;

            if (launch.Canceled)
                return ExitCodes.LaunchTimeoutOrCancellation;

            return launch.Unavailable ? ExitCodes.DockerUnavailable : ExitCodes.LaunchFailed;
        }
        catch (OperationCanceledException)
        {
            await _error.WriteLineAsync("Container launch was canceled.");
            var canceled = ContainerRuntimeResult.Cancelled("Container launch was canceled.", launchReference: DockerContainerRuntime.SelectLaunchImage(scanExit.Summary!));
            var launchEvent = LaunchResultEventBuilder.Build(options, scanExit.Summary!, canceled);
            var launchAudit = await SubmitLaunchResultWithRetryAsync(options, launchEvent, CancellationToken.None);
            if (!launchAudit.Accepted)
                return ExitCodes.LaunchOutcomeAuditFailed;

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
        var result = await SubmitEventDetailedAsync(options, request, label, cancellationToken);
        return result.Accepted ? ExitCodes.Success : result.ExitCode;
    }

    private async Task<AuditSubmissionResult> SubmitEventDetailedAsync(
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
                return AuditSubmissionResult.Failed(ExitCodes.ApiRejectedRequest, submit.StatusCode);
            }

            if (submit.StatusCode == StatusCodes.Created && submit.Created)
            {
                await _output.WriteLineAsync($"{label} accepted. securityEventId={submit.SecurityEventId}");
                return AuditSubmissionResult.Created(submit.SecurityEventId, submit.StatusCode);
            }

            if (submit.StatusCode == StatusCodes.Existing && !submit.Created)
            {
                await _output.WriteLineAsync($"{label} already exists. securityEventId={submit.SecurityEventId}");
                return AuditSubmissionResult.Existing(submit.SecurityEventId, submit.StatusCode);
            }

            await _error.WriteLineAsync($"API returned ambiguous idempotency state: HTTP {submit.StatusCode}.");
            return AuditSubmissionResult.Failed(ExitCodes.ApiRejectedRequest, submit.StatusCode);
        }
        catch (OperationCanceledException)
        {
            await _error.WriteLineAsync("API request was canceled.");
            return AuditSubmissionResult.Failed(ExitCodes.TimeoutOrCancellation, StatusCodes.TransportFailure, transportFailure: true);
        }
        catch (HttpRequestException ex)
        {
            await _error.WriteLineAsync($"API request failed: {Redaction.TrimForSafeOutput(ex.Message, ScannerConstants.StderrDisplayLimit)}");
            return AuditSubmissionResult.Failed(ExitCodes.ApiRejectedRequest, StatusCodes.TransportFailure, transportFailure: true);
        }
    }

    private async Task<AuditSubmissionResult> SubmitLaunchResultWithRetryAsync(
        ScannerOptions options,
        ImageScanIngestRequest request,
        CancellationToken cancellationToken)
    {
        var delays = new[] { TimeSpan.Zero, TimeSpan.FromMilliseconds(200), TimeSpan.FromMilliseconds(500) };
        using var auditCts = new CancellationTokenSource(TimeSpan.FromSeconds(ScannerConstants.LaunchAuditTimeoutSeconds));
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(auditCts.Token);

        AuditSubmissionResult? last = null;
        for (var attempt = 0; attempt < delays.Length; attempt++)
        {
            try
            {
                if (delays[attempt] > TimeSpan.Zero)
                    await Task.Delay(delays[attempt], linkedCts.Token);
            }
            catch (OperationCanceledException)
            {
                return AuditSubmissionResult.Failed(ExitCodes.TimeoutOrCancellation, StatusCodes.TransportFailure, transportFailure: true);
            }

            last = await SubmitEventDetailedAsync(options, request, "Launch result event", linkedCts.Token);
            if (last.Accepted || !last.IsTransient)
                return last;
        }

        return last ?? AuditSubmissionResult.Failed(ExitCodes.ApiRejectedRequest, StatusCodes.TransportFailure, transportFailure: true);
    }

    private static ExitCodes ValidateLaunchReservation(AuditSubmissionResult scanSubmit, AuditSubmissionResult policySubmit)
    {
        if (scanSubmit.State == AuditSubmissionState.Created && policySubmit.State == AuditSubmissionState.Created)
            return ExitCodes.Success;

        if (scanSubmit.State == AuditSubmissionState.Existing && policySubmit.State == AuditSubmissionState.Created)
            return ExitCodes.Success;

        if (scanSubmit.State == AuditSubmissionState.Existing && policySubmit.State == AuditSubmissionState.Existing)
            return ExitCodes.OperationAlreadyProcessed;

        if (scanSubmit.State == AuditSubmissionState.Created && policySubmit.State == AuditSubmissionState.Existing)
            return ExitCodes.InconsistentAuditState;

        return ExitCodes.ApiRejectedRequest;
    }

    private sealed record GateScanResult(ExitCodes ExitCode, ImageScanSummary? Summary, long ScanDurationMs = 0);

    private enum AuditSubmissionState
    {
        Failed,
        Created,
        Existing
    }

    private sealed record AuditSubmissionResult(
        AuditSubmissionState State,
        ExitCodes ExitCode,
        int StatusCode,
        string? SecurityEventId,
        bool TransportFailure)
    {
        public bool Accepted => State is AuditSubmissionState.Created or AuditSubmissionState.Existing;
        public bool IsTransient => TransportFailure || StatusCode >= 500;

        public static AuditSubmissionResult Created(string? securityEventId, int statusCode) =>
            new(AuditSubmissionState.Created, ExitCodes.Success, statusCode, securityEventId, TransportFailure: false);

        public static AuditSubmissionResult Existing(string? securityEventId, int statusCode) =>
            new(AuditSubmissionState.Existing, ExitCodes.Success, statusCode, securityEventId, TransportFailure: false);

        public static AuditSubmissionResult Failed(ExitCodes exitCode, int statusCode, bool transportFailure = false) =>
            new(AuditSubmissionState.Failed, exitCode, statusCode, null, transportFailure);
    }

    private static class StatusCodes
    {
        public const int TransportFailure = 0;
        public const int Created = 201;
        public const int Existing = 200;
    }
}
