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
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

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

        var stdoutTask = ReadLimitedAsync(process.StandardOutput, maxStdoutBytes, linkedCts.Token);
        var stderrTask = ReadLimitedAsync(process.StandardError, maxStderrBytes, linkedCts.Token);

        try
        {
            await process.WaitForExitAsync(linkedCts.Token);
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            return ProcessRunResult.TimedOut();
        }

        var stdout = await stdoutTask;
        var stderr = await stderrTask;

        if (stdout.Oversized)
            return ProcessRunResult.OversizedOutput(stdout.Text, stderr.Text);

        return new ProcessRunResult(
            Started: true,
            ExitCode: process.ExitCode,
            StandardOutput: stdout.Text,
            StandardError: stderr.Text,
            TimedOutOrCanceled: false,
            OutputTooLarge: false,
            StartError: null);
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
    bool TimedOutOrCanceled,
    bool OutputTooLarge,
    string? StartError)
{
    public static ProcessRunResult Failed(string error) => new(false, -1, string.Empty, string.Empty, false, false, error);
    public static ProcessRunResult TimedOut() => new(true, -1, string.Empty, string.Empty, true, false, null);
    public static ProcessRunResult OversizedOutput(string stdout, string stderr) => new(true, -1, stdout, stderr, false, true, null);
}

internal sealed record LimitedReadResult(string Text, bool Oversized);
