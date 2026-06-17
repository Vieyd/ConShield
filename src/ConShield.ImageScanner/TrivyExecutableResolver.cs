namespace ConShield.ImageScanner;

public static class TrivyExecutableResolver
{
    public static string? Resolve(string? configuredPath)
    {
        if (!string.IsNullOrWhiteSpace(configuredPath))
            return File.Exists(configuredPath) ? configuredPath : null;

        var executableNames = OperatingSystem.IsWindows()
            ? new[] { "trivy.exe" }
            : new[] { "trivy" };

        var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var directory in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            if (IsCurrentDirectory(directory))
                continue;

            foreach (var name in executableNames)
            {
                var candidate = Path.Combine(directory, name);
                if (File.Exists(candidate))
                    return candidate;
            }
        }

        return null;
    }

    private static bool IsCurrentDirectory(string directory)
    {
        return directory == "."
            || string.Equals(Path.GetFullPath(directory), Environment.CurrentDirectory, StringComparison.OrdinalIgnoreCase);
    }
}
