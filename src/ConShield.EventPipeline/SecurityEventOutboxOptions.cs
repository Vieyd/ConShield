using Microsoft.Extensions.Options;

namespace ConShield.EventPipeline;

public sealed class SecurityEventOutboxOptions
{
    public bool Enabled { get; set; } = true;
    public int PollIntervalMilliseconds { get; set; } = 1000;
    public int BatchSize { get; set; } = 20;
    public int LockSeconds { get; set; } = 30;
    public int MaxAttempts { get; set; } = 5;
    public int BaseRetrySeconds { get; set; } = 1;
    public int MaxRetrySeconds { get; set; } = 60;
    public string JsonlRelativePath { get; set; } = "logs/security-events.jsonl";
    public int DegradedPendingAgeSeconds { get; set; } = 300;
}

public sealed class SecurityEventOutboxOptionsValidator : IValidateOptions<SecurityEventOutboxOptions>
{
    public ValidateOptionsResult Validate(string? name, SecurityEventOutboxOptions options)
    {
        var errors = new List<string>();
        if (options.PollIntervalMilliseconds is < 250 or > 60000)
            errors.Add("PollIntervalMilliseconds must be between 250 and 60000.");
        if (options.BatchSize is < 1 or > 200)
            errors.Add("BatchSize must be between 1 and 200.");
        if (options.LockSeconds is < 5 or > 600)
            errors.Add("LockSeconds must be between 5 and 600.");
        if (options.MaxAttempts is < 1 or > 20)
            errors.Add("MaxAttempts must be between 1 and 20.");
        if (options.BaseRetrySeconds is < 1 or > 300)
            errors.Add("BaseRetrySeconds must be between 1 and 300.");
        if (options.MaxRetrySeconds < options.BaseRetrySeconds || options.MaxRetrySeconds > 3600)
            errors.Add("MaxRetrySeconds must be greater than BaseRetrySeconds and at most 3600.");
        if (options.DegradedPendingAgeSeconds is < 1 or > 86400)
            errors.Add("DegradedPendingAgeSeconds must be between 1 and 86400.");
        if (!OutboxPathPolicy.IsSafeRelativePath(options.JsonlRelativePath))
            errors.Add("JsonlRelativePath must be a safe relative path inside the content root.");

        return errors.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(errors);
    }
}

internal static class OutboxPathPolicy
{
    public static bool IsSafeRelativePath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        if (Path.IsPathRooted(value))
            return false;

        var parts = value.Split(['/', '\\'], StringSplitOptions.RemoveEmptyEntries);
        return parts.Length > 0
            && parts.All(part => part != "." && part != ".." && part.IndexOfAny(Path.GetInvalidFileNameChars()) < 0);
    }
}
