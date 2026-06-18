using ConShield.EventPipeline;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;

namespace ConShield.EventConsumer;

public sealed class RabbitMqSecurityEventConsumerService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IRabbitMqConnectionProvider _connectionProvider;
    private readonly RabbitMqTopology _topology;
    private readonly RabbitMqOptions _options;
    private readonly ILogger<RabbitMqSecurityEventConsumerService> _logger;

    public RabbitMqSecurityEventConsumerService(
        IServiceScopeFactory scopeFactory,
        IRabbitMqConnectionProvider connectionProvider,
        RabbitMqTopology topology,
        IOptions<RabbitMqOptions> options,
        ILogger<RabbitMqSecurityEventConsumerService> logger)
    {
        _scopeFactory = scopeFactory;
        _connectionProvider = connectionProvider;
        _topology = topology;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            _logger.LogInformation("RabbitMQ event consumer is disabled.");
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var connection = await _connectionProvider.GetConnectionAsync("conshield-event-consumer", stoppingToken);
                await using var channel = await connection.CreateChannelAsync(
                    new CreateChannelOptions(
                        publisherConfirmationsEnabled: false,
                        publisherConfirmationTrackingEnabled: false,
                        outstandingPublisherConfirmationsRateLimiter: null,
                        consumerDispatchConcurrency: 1),
                    stoppingToken);

                await _topology.DeclareAsync(channel, stoppingToken);
                await channel.BasicQosAsync(0, _options.PrefetchCount, global: false, cancellationToken: stoppingToken);

                var consumer = new AsyncEventingBasicConsumer(channel);
                consumer.ReceivedAsync += async (_, args) => await HandleDeliveryAsync(channel, args, stoppingToken);
                var deadLetterConsumer = new AsyncEventingBasicConsumer(channel);
                deadLetterConsumer.ReceivedAsync += async (_, args) => await HandleDeadLetterDeliveryAsync(channel, args, stoppingToken);

                await channel.BasicConsumeAsync(
                    _options.QueueName,
                    autoAck: false,
                    consumerTag: "conshield-event-consumer",
                    noLocal: false,
                    exclusive: false,
                    arguments: null,
                    consumer: consumer,
                    cancellationToken: stoppingToken);
                await channel.BasicConsumeAsync(
                    _options.DeadLetterQueueName,
                    autoAck: false,
                    consumerTag: "conshield-dead-letter-capture-consumer",
                    noLocal: false,
                    exclusive: false,
                    arguments: null,
                    consumer: deadLetterConsumer,
                    cancellationToken: stoppingToken);

                await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception)
            {
                _logger.LogWarning("RabbitMQ consumer loop failed; retrying after a bounded delay.");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }
    }

    private async Task HandleDeliveryAsync(IChannel channel, BasicDeliverEventArgs args, CancellationToken cancellationToken)
    {
        var body = args.Body.ToArray();
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var processor = scope.ServiceProvider.GetRequiredService<SecurityEventDeliveryProcessor>();
            var result = await processor.ProcessAsync(body, args.BasicProperties, args.RoutingKey, args.Redelivered, cancellationToken);

            if (result.Outcome is InboxProcessOutcome.Processed or InboxProcessOutcome.Duplicate)
            {
                await channel.BasicAckAsync(args.DeliveryTag, multiple: false, cancellationToken);
                return;
            }

            await channel.BasicNackAsync(
                args.DeliveryTag,
                multiple: false,
                requeue: result.Outcome == InboxProcessOutcome.TransientFailure,
                cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            await channel.BasicNackAsync(args.DeliveryTag, multiple: false, requeue: true, CancellationToken.None);
        }
    }

    private async Task HandleDeadLetterDeliveryAsync(IChannel channel, BasicDeliverEventArgs args, CancellationToken cancellationToken)
    {
        var body = args.Body.ToArray();
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var processor = scope.ServiceProvider.GetRequiredService<DeadLetterCaptureProcessor>();
            var result = await processor.CaptureAsync(body, args.BasicProperties, args.RoutingKey, cancellationToken);
            if (result.Outcome == DeadLetterCaptureOutcome.Captured)
            {
                await channel.BasicAckAsync(args.DeliveryTag, multiple: false, cancellationToken);
                return;
            }

            await channel.BasicNackAsync(args.DeliveryTag, multiple: false, requeue: true, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            await channel.BasicNackAsync(args.DeliveryTag, multiple: false, requeue: true, CancellationToken.None);
        }
    }
}
