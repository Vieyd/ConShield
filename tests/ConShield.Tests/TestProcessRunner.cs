using System.Diagnostics;

namespace ConShield.Tests;

internal static class TestProcessRunner
{
    public static CommandResult Run(ProcessStartInfo startInfo, TimeSpan timeout)
    {
        startInfo.RedirectStandardOutput = true;
        startInfo.RedirectStandardError = true;
        startInfo.UseShellExecute = false;

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException($"{startInfo.FileName} was not started.");

        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();

        if (!process.WaitForExit((int)timeout.TotalMilliseconds))
        {
            TryKill(process);
            var timedOutOutput = SafeRead(outputTask) + SafeRead(errorTask);
            return new CommandResult(
                -1,
                timedOutOutput + $"{Environment.NewLine}Process timed out after {timeout.TotalSeconds:0} seconds: {startInfo.FileName}");
        }

        var output = SafeRead(outputTask);
        var error = SafeRead(errorTask);
        return new CommandResult(process.ExitCode, output + error);
    }

    private static string SafeRead(Task<string> task)
    {
        try
        {
            return task.GetAwaiter().GetResult();
        }
        catch
        {
            return string.Empty;
        }
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
            // Best-effort cleanup for test infrastructure only.
        }

        try
        {
            process.WaitForExit(5000);
        }
        catch
        {
            // Best-effort cleanup for test infrastructure only.
        }
    }
}

internal sealed record CommandResult(int ExitCode, string Output);
