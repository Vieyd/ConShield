using System.ComponentModel;
using System.Diagnostics;

namespace ConShield.Cli;

internal static class DockerLifecycleWatch
{
    public const int MinDurationSeconds = 1;
    public const int MaxDurationSeconds = 300;
    public const int MinMaxEvents = 1;
    public const int MaxMaxEvents = 1000;
    public const string DockerUnavailableHint = "start Docker Desktop or use lifecycle replay fixture mode.";

    public static async Task<DockerLifecycleWatchResult> WatchAsync(
        int durationSeconds,
        int maxEvents,
        string dockerCliPath = "docker",
        CancellationToken cancellationToken = default)
    {
        Validate(durationSeconds, maxEvents);

        if (!await IsDockerAvailableAsync(dockerCliPath, cancellationToken))
        {
            return DockerLifecycleWatchResult.Unavailable(DockerUnavailableHint);
        }

        var rawEvents = new List<DockerLifecycleEvent>();
        var observed = 0;

        var startInfo = new ProcessStartInfo
        {
            FileName = dockerCliPath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        startInfo.ArgumentList.Add("events");
        startInfo.ArgumentList.Add("--format");
        startInfo.ArgumentList.Add("{{json .}}");
        startInfo.ArgumentList.Add("--filter");
        startInfo.ArgumentList.Add("type=container");

        using var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start())
                return DockerLifecycleWatchResult.Unavailable(DockerUnavailableHint);
        }
        catch (Win32Exception)
        {
            return DockerLifecycleWatchResult.Unavailable(DockerUnavailableHint);
        }
        catch (InvalidOperationException)
        {
            return DockerLifecycleWatchResult.Unavailable(DockerUnavailableHint);
        }

        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        var deadline = DateTime.UtcNow.AddSeconds(durationSeconds);

        try
        {
            while (rawEvents.Count < maxEvents && DateTime.UtcNow < deadline && !cancellationToken.IsCancellationRequested)
            {
                var remaining = deadline - DateTime.UtcNow;
                if (remaining <= TimeSpan.Zero)
                    break;

                var readTask = process.StandardOutput.ReadLineAsync(cancellationToken).AsTask();
                var delayTask = Task.Delay(remaining, cancellationToken);
                var completed = await Task.WhenAny(readTask, delayTask);
                if (completed != readTask)
                    break;

                var line = await readTask;
                if (line is null)
                    break;

                observed++;
                try
                {
                    rawEvents.Add(DockerLifecycleCollector.ParseJsonLine(line));
                }
                catch (DockerLifecycleException)
                {
                    // Ignore malformed or unsupported live lines without echoing raw Docker JSON.
                }
            }
        }
        finally
        {
            if (!process.HasExited)
            {
                try { process.Kill(entireProcessTree: true); }
                catch { try { process.Kill(); } catch { } }
            }

            try { await stderrTask; } catch { }
        }

        IReadOnlyList<NormalizedDockerLifecycleEvent> normalized = [];
        if (rawEvents.Count > 0)
        {
            try
            {
                normalized = DockerLifecycleCollector.Normalize(rawEvents);
            }
            catch (DockerLifecycleException)
            {
                normalized = [];
            }
        }

        return DockerLifecycleWatchResult.Available(observed, normalized);
    }

    public static void Validate(int durationSeconds, int maxEvents)
    {
        if (durationSeconds is < MinDurationSeconds or > MaxDurationSeconds)
            throw new CliUsageException($"--duration-seconds must be between {MinDurationSeconds} and {MaxDurationSeconds}.");

        if (maxEvents is < MinMaxEvents or > MaxMaxEvents)
            throw new CliUsageException($"--max-events must be between {MinMaxEvents} and {MaxMaxEvents}.");
    }

    private static async Task<bool> IsDockerAvailableAsync(string dockerCliPath, CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = dockerCliPath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        startInfo.ArgumentList.Add("version");
        startInfo.ArgumentList.Add("--format");
        startInfo.ArgumentList.Add("{{.Server.Version}}");

        using var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start())
                return false;
        }
        catch (Win32Exception)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }

        var waitTask = process.WaitForExitAsync(cancellationToken);
        var completed = await Task.WhenAny(waitTask, Task.Delay(TimeSpan.FromSeconds(8), cancellationToken));
        if (completed != waitTask || !waitTask.IsCompletedSuccessfully)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            return false;
        }

        return process.ExitCode == 0;
    }
}

internal sealed record DockerLifecycleWatchResult(
    bool DockerAvailable,
    int EventsObserved,
    IReadOnlyList<NormalizedDockerLifecycleEvent> Events,
    string Hint)
{
    public static DockerLifecycleWatchResult Unavailable(string hint) => new(false, 0, [], hint);

    public static DockerLifecycleWatchResult Available(int observed, IReadOnlyList<NormalizedDockerLifecycleEvent> events) =>
        new(true, observed, events, string.Empty);
}
