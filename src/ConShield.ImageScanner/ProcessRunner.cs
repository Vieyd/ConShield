using System.Diagnostics;
using System.Text;

namespace ConShield.ImageScanner;

public interface IProcessRunner
{
    Task<ProcessRunResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        int timeoutSeconds,
        int maxStdoutBytes,
        int maxStderrBytes,
        CancellationToken cancellationToken);
}

public sealed class ProcessRunner : IProcessRunner
{
    public async Task<ProcessRunResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        int timeoutSeconds,
        int maxStdoutBytes,
        int maxStderrBytes,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);

        using var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };

        try
        {
            if (!process.Start())
                return ProcessRunResult.Failed("Process did not start.");
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return ProcessRunResult.Failed(ex.Message);
        }

        var stdoutTask = ReadLimitedAsync(process.StandardOutput, maxStdoutBytes, cancellationToken);
        var stderrTask = ReadLimitedAsync(process.StandardError, maxStderrBytes, cancellationToken);

        var waitTask = process.WaitForExitAsync(CancellationToken.None);
        var delayTask = Task.Delay(TimeSpan.FromSeconds(timeoutSeconds), cancellationToken);
        var completed = await Task.WhenAny(waitTask, delayTask);
        if (completed != waitTask)
        {
            TryKill(process);
            return cancellationToken.IsCancellationRequested
                ? ProcessRunResult.CanceledResult()
                : ProcessRunResult.TimedOutResult();
        }

        await waitTask;

        var stdout = await stdoutTask;
        var stderr = await stderrTask;

        if (stdout.Oversized || stderr.Oversized)
            return ProcessRunResult.OversizedOutput(stdout.Text, stderr.Text);

        return new ProcessRunResult(
            Started: true,
            ExitCode: process.ExitCode,
            StandardOutput: stdout.Text,
            StandardError: stderr.Text,
            StartError: null)
        { TerminationReason = ProcessTerminationReason.Completed };
    }

    private static async Task<LimitedReadResult> ReadLimitedAsync(
        StreamReader reader,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        var buffer = new char[4096];
        var builder = new StringBuilder();
        var bytes = 0;

        while (!reader.EndOfStream)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
            if (read == 0)
                break;

            var chunk = new string(buffer, 0, read);
            bytes += Encoding.UTF8.GetByteCount(chunk);
            if (bytes > maxBytes)
                return new LimitedReadResult(builder.ToString(), Oversized: true);

            builder.Append(chunk);
        }

        return new LimitedReadResult(builder.ToString(), Oversized: false);
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
        }
        catch
        {
        }
    }
}

public sealed record ProcessRunResult(
    bool Started,
    int ExitCode,
    string StandardOutput,
    string StandardError,
    string? StartError)
{
    public ProcessTerminationReason TerminationReason { get; init; } = ProcessTerminationReason.Completed;
    public bool TimedOutOrCanceled => TerminationReason is ProcessTerminationReason.TimedOut or ProcessTerminationReason.Canceled;
    public bool TimedOut => TerminationReason == ProcessTerminationReason.TimedOut;
    public bool Canceled => TerminationReason == ProcessTerminationReason.Canceled;
    public bool OutputTooLarge => TerminationReason == ProcessTerminationReason.OutputTooLarge;

    public static ProcessRunResult Failed(string error) =>
        new(false, -1, string.Empty, string.Empty, error) { TerminationReason = ProcessTerminationReason.StartFailed };

    public static ProcessRunResult TimedOutResult() =>
        new(true, -1, string.Empty, string.Empty, null) { TerminationReason = ProcessTerminationReason.TimedOut };

    public static ProcessRunResult CanceledResult() =>
        new(true, -1, string.Empty, string.Empty, null) { TerminationReason = ProcessTerminationReason.Canceled };

    public static ProcessRunResult OversizedOutput(string stdout, string stderr) =>
        new(true, -1, stdout, stderr, null) { TerminationReason = ProcessTerminationReason.OutputTooLarge };
}

internal sealed record LimitedReadResult(string Text, bool Oversized);

public enum ProcessTerminationReason
{
    Completed,
    StartFailed,
    TimedOut,
    Canceled,
    OutputTooLarge
}
