using ConShield.Data;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ConShield.EventPipeline;

public sealed class SecurityEventOutboxBackgroundService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IOptions<SecurityEventOutboxOptions> _options;
    private readonly ILogger<SecurityEventOutboxBackgroundService> _logger;

    public SecurityEventOutboxBackgroundService(
        IServiceScopeFactory scopeFactory,
        IOptions<SecurityEventOutboxOptions> options,
        ILogger<SecurityEventOutboxBackgroundService> logger)
    {
        _scopeFactory = scopeFactory;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var delay = TimeSpan.FromMilliseconds(Math.Clamp(_options.Value.PollIntervalMilliseconds, 250, 60000));
            try
            {
                if (_options.Value.Enabled)
                {
                    using var scope = _scopeFactory.CreateScope();
                    var dispatcher = scope.ServiceProvider.GetRequiredService<SecurityEventOutboxDispatcher>();
                    var result = await dispatcher.DispatchOnceAsync(stoppingToken);
                    if (result.Claimed > 0)
                    {
                        _logger.LogInformation(
                            "Security event outbox dispatched batch: claimed={Claimed}, delivered={Delivered}, failed={Failed}, deadLettered={DeadLettered}.",
                            result.Claimed,
                            result.Delivered,
                            result.Failed,
                            result.DeadLettered);
                    }
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Security event outbox dispatcher iteration failed.");
            }

            try
            {
                await Task.Delay(delay, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }
}
