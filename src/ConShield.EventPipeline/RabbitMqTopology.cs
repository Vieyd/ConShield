using RabbitMQ.Client;

namespace ConShield.EventPipeline;

public sealed class RabbitMqTopology
{
    private readonly RabbitMqOptions _options;

    public RabbitMqTopology(Microsoft.Extensions.Options.IOptions<RabbitMqOptions> options)
    {
        _options = options.Value;
    }

    public async Task DeclareAsync(IChannel channel, CancellationToken cancellationToken)
    {
        await channel.ExchangeDeclareAsync(
            _options.ExchangeName,
            ExchangeType.Topic,
            durable: true,
            autoDelete: false,
            arguments: null,
            passive: false,
            noWait: false,
            cancellationToken);

        await channel.ExchangeDeclareAsync(
            _options.DeadLetterExchangeName,
            ExchangeType.Topic,
            durable: true,
            autoDelete: false,
            arguments: null,
            passive: false,
            noWait: false,
            cancellationToken);

        var queueArguments = new Dictionary<string, object?>
        {
            ["x-queue-type"] = "quorum",
            ["x-dead-letter-exchange"] = _options.DeadLetterExchangeName,
            ["x-dead-letter-routing-key"] = _options.DeadLetterRoutingKey,
            ["x-delivery-limit"] = 5
        };

        await channel.QueueDeclareAsync(
            _options.QueueName,
            durable: true,
            exclusive: false,
            autoDelete: false,
            arguments: queueArguments!,
            passive: false,
            noWait: false,
            cancellationToken);

        await channel.QueueDeclareAsync(
            _options.DeadLetterQueueName,
            durable: true,
            exclusive: false,
            autoDelete: false,
            arguments: null,
            passive: false,
            noWait: false,
            cancellationToken);

        await channel.QueueBindAsync(_options.QueueName, _options.ExchangeName, _options.RoutingKey, null, false, cancellationToken);
        await channel.QueueBindAsync(_options.DeadLetterQueueName, _options.DeadLetterExchangeName, _options.DeadLetterRoutingKey, null, false, cancellationToken);
    }
}
