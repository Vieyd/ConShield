using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ConShield.EventPipeline;

public sealed class DeadLetterReplayBackgroundService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly DeadLetterReplayOptions _options;
    private readonly ILogger<DeadLetterReplayBackgroundService> _logger;

    public DeadLetterReplayBackgroundService(
        IServiceScopeFactory scopeFactory,
        IOptions<DeadLetterReplayOptions> options,
        ILogger<DeadLetterReplayBackgroundService> logger)
    {
        _scopeFactory = scopeFactory;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            _logger.LogInformation("Dead-letter replay dispatcher is disabled.");
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _scopeFactory.CreateScope();
                var dispatcher = scope.ServiceProvider.GetRequiredService<DeadLetterReplayDispatcher>();
                await dispatcher.DispatchOnceAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception)
            {
                _logger.LogWarning("Dead-letter replay dispatcher loop failed; retrying after a bounded delay.");
            }

            await Task.Delay(TimeSpan.FromMilliseconds(_options.PollIntervalMilliseconds), stoppingToken);
        }
    }
}
