using Microsoft.Extensions.Options;

namespace ConShield.EventPipeline;

public sealed class DeadLetterReplayOptions
{
    public bool Enabled { get; set; } = true;
    public int MaxReplayRequestsPerMessage { get; set; } = 3;
    public int MinimumIntervalSeconds { get; set; } = 60;
    public int MaxMessageAgeDays { get; set; } = 30;
    public int BatchSize { get; set; } = 10;
    public int LockSeconds { get; set; } = 30;
    public int MaxPublishAttempts { get; set; } = 5;
    public int BaseRetrySeconds { get; set; } = 2;
    public int MaxRetrySeconds { get; set; } = 60;
    public int MaxReasonLength { get; set; } = 500;
    public int MaxPayloadBytes { get; set; } = 262144;
    public int PollIntervalMilliseconds { get; set; } = 1000;
}

public sealed class DeadLetterReplayOptionsValidator : IValidateOptions<DeadLetterReplayOptions>
{
    public ValidateOptionsResult Validate(string? name, DeadLetterReplayOptions options)
    {
        var errors = new List<string>();
        if (options.MaxReplayRequestsPerMessage is < 1 or > 20)
            errors.Add("MaxReplayRequestsPerMessage must be between 1 and 20.");
        if (options.MinimumIntervalSeconds is < 0 or > 86400)
            errors.Add("MinimumIntervalSeconds must be between 0 and 86400.");
        if (options.MaxMessageAgeDays is < 1 or > 3650)
            errors.Add("MaxMessageAgeDays must be between 1 and 3650.");
        if (options.BatchSize is < 1 or > 100)
            errors.Add("BatchSize must be between 1 and 100.");
        if (options.LockSeconds is < 5 or > 600)
            errors.Add("LockSeconds must be between 5 and 600.");
        if (options.MaxPublishAttempts is < 1 or > 20)
            errors.Add("MaxPublishAttempts must be between 1 and 20.");
        if (options.BaseRetrySeconds is < 1 or > 600)
            errors.Add("BaseRetrySeconds must be between 1 and 600.");
        if (options.MaxRetrySeconds < options.BaseRetrySeconds || options.MaxRetrySeconds > 3600)
            errors.Add("MaxRetrySeconds must be at least BaseRetrySeconds and at most 3600.");
        if (options.MaxReasonLength is < 1 or > 1000)
            errors.Add("MaxReasonLength must be between 1 and 1000.");
        if (options.MaxPayloadBytes is < 4096 or > 1048576)
            errors.Add("MaxPayloadBytes must be between 4096 and 1048576.");
        if (options.PollIntervalMilliseconds is < 100 or > 60000)
            errors.Add("PollIntervalMilliseconds must be between 100 and 60000.");
        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
