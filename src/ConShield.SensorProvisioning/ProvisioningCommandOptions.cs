namespace ConShield.SensorProvisioning;

public sealed record ProvisioningCommandOptions(
    bool IsValid,
    string? DisplayName,
    int HeartbeatIntervalSeconds,
    string? Error)
{
    public static ProvisioningCommandOptions Parse(string[] args)
    {
        if (args.Length == 0 || !string.Equals(args[0], "provision", StringComparison.OrdinalIgnoreCase))
            return Invalid("Expected the 'provision' command.");

        string? displayName = null;
        var heartbeatInterval = 60;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 1; index < args.Length; index++)
        {
            var option = args[index];
            if (option is not ("--display-name" or "--heartbeat-interval-seconds") || !seen.Add(option))
                return Invalid("Unknown or duplicate option.");
            if (++index >= args.Length || args[index].StartsWith("--", StringComparison.Ordinal))
                return Invalid("An option value is missing.");

            if (option == "--display-name")
            {
                displayName = args[index];
            }
            else if (!int.TryParse(args[index], out heartbeatInterval))
            {
                return Invalid("Heartbeat interval must be an integer.");
            }
        }

        return string.IsNullOrWhiteSpace(displayName)
            ? Invalid("--display-name is required.")
            : new ProvisioningCommandOptions(true, displayName, heartbeatInterval, null);
    }

    private static ProvisioningCommandOptions Invalid(string error) => new(false, null, 60, error);
}
