using Microsoft.Extensions.Options;

namespace ConShield.EventPipeline;

public sealed class RabbitMqOptions
{
    public bool Enabled { get; set; }
    public string HostName { get; set; } = "localhost";
    public int Port { get; set; } = 5672;
    public string VirtualHost { get; set; } = "/conshield";
    public string UserName { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string ExchangeName { get; set; } = "conshield.security.events.v1";
    public string RoutingKey { get; set; } = "security.event.created";
    public string QueueName { get; set; } = "conshield.security-events.consumer.v1";
    public string DeadLetterExchangeName { get; set; } = "conshield.security.events.dlx.v1";
    public string DeadLetterRoutingKey { get; set; } = "security.event.dead";
    public string DeadLetterQueueName { get; set; } = "conshield.security-events.dead.v1";
    public ushort PrefetchCount { get; set; } = 20;
    public int ConnectionTimeoutSeconds { get; set; } = 10;
    public int PublishTimeoutSeconds { get; set; } = 10;
    public int ConsumerShutdownTimeoutSeconds { get; set; } = 10;
    public bool UseTls { get; set; }
}

public sealed class RabbitMqOptionsValidator : IValidateOptions<RabbitMqOptions>
{
    private readonly IOptions<SecurityEventOutboxOptions> _outboxOptions;

    public RabbitMqOptionsValidator(IOptions<SecurityEventOutboxOptions> outboxOptions)
    {
        _outboxOptions = outboxOptions;
    }

    public ValidateOptionsResult Validate(string? name, RabbitMqOptions options)
    {
        var errors = new List<string>();
        var required = options.Enabled || _outboxOptions.Value.Transport == SecurityEventOutboxTransport.RabbitMq;
        ValidateName(options.HostName, nameof(options.HostName), errors, maxLength: 253, allowSlash: false);
        ValidateName(options.VirtualHost, nameof(options.VirtualHost), errors, maxLength: 128, allowSlash: true);
        ValidateName(options.ExchangeName, nameof(options.ExchangeName), errors, maxLength: 128, allowSlash: false);
        ValidateName(options.RoutingKey, nameof(options.RoutingKey), errors, maxLength: 128, allowSlash: false);
        ValidateName(options.QueueName, nameof(options.QueueName), errors, maxLength: 128, allowSlash: false);
        ValidateName(options.DeadLetterExchangeName, nameof(options.DeadLetterExchangeName), errors, maxLength: 128, allowSlash: false);
        ValidateName(options.DeadLetterRoutingKey, nameof(options.DeadLetterRoutingKey), errors, maxLength: 128, allowSlash: false);
        ValidateName(options.DeadLetterQueueName, nameof(options.DeadLetterQueueName), errors, maxLength: 128, allowSlash: false);
        if (options.Port is < 1 or > 65535)
            errors.Add("Port must be between 1 and 65535.");
        if (options.PrefetchCount is < 1 or > 200)
            errors.Add("PrefetchCount must be between 1 and 200.");
        if (options.ConnectionTimeoutSeconds is < 1 or > 60)
            errors.Add("ConnectionTimeoutSeconds must be between 1 and 60.");
        if (options.PublishTimeoutSeconds is < 1 or > 60)
            errors.Add("PublishTimeoutSeconds must be between 1 and 60.");
        if (options.ConsumerShutdownTimeoutSeconds is < 1 or > 60)
            errors.Add("ConsumerShutdownTimeoutSeconds must be between 1 and 60.");
        if (required)
        {
            ValidateName(options.UserName, nameof(options.UserName), errors, maxLength: 128, allowSlash: false);
            if (string.IsNullOrWhiteSpace(options.Password) || options.Password.Length > 512 || options.Password.Any(char.IsControl))
                errors.Add("Password is required and must be bounded when RabbitMQ is enabled.");
        }

        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }

    private static void ValidateName(string? value, string optionName, ICollection<string> errors, int maxLength, bool allowSlash)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maxLength)
        {
            errors.Add($"{optionName} is required and must be at most {maxLength} characters.");
            return;
        }

        if (value.Any(ch => char.IsControl(ch) || (!allowSlash && ch == '/')))
            errors.Add($"{optionName} contains invalid characters.");
    }
}
