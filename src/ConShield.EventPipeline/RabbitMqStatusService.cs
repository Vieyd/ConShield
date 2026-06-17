using ConShield.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace ConShield.EventPipeline;

public sealed class RabbitMqStatusService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly IRabbitMqConnectionProvider _connectionProvider;
    private readonly RabbitMqTopology _topology;
    private readonly RabbitMqOptions _options;

    public RabbitMqStatusService(
        ApplicationDbContext dbContext,
        IRabbitMqConnectionProvider connectionProvider,
        RabbitMqTopology topology,
        IOptions<RabbitMqOptions> options)
    {
        _dbContext = dbContext;
        _connectionProvider = connectionProvider;
        _topology = topology;
        _options = options.Value;
    }

    public async Task<RabbitMqStatusSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        var inboxCount = await _dbContext.SecurityEventInboxReceipts.CountAsync(cancellationToken);
        var lastProcessed = await _dbContext.SecurityEventInboxReceipts
            .OrderByDescending(x => x.ProcessedAtUtc)
            .Select(x => x.ProcessedAtUtc)
            .FirstOrDefaultAsync(cancellationToken);

        if (!_options.Enabled)
            return new RabbitMqStatusSnapshot(false, false, inboxCount, lastProcessed, null, null, null, "disabled");

        try
        {
            var connection = await _connectionProvider.GetConnectionAsync("conshield-web-outbox-publisher", cancellationToken);
            await using var channel = await connection.CreateChannelAsync(cancellationToken: cancellationToken);
            await _topology.DeclareAsync(channel, cancellationToken);
            var mainCount = await channel.MessageCountAsync(_options.QueueName, cancellationToken);
            var consumerCount = await channel.ConsumerCountAsync(_options.QueueName, cancellationToken);
            var dlqCount = await channel.MessageCountAsync(_options.DeadLetterQueueName, cancellationToken);
            return new RabbitMqStatusSnapshot(true, true, inboxCount, lastProcessed, mainCount, consumerCount, dlqCount, null);
        }
        catch
        {
            return new RabbitMqStatusSnapshot(true, false, inboxCount, lastProcessed, null, null, null, "unavailable");
        }
    }
}

public sealed record RabbitMqStatusSnapshot(
    bool Enabled,
    bool Connected,
    int InboxReceiptCount,
    DateTime? LastInboxProcessedAtUtc,
    uint? MainQueueCount,
    uint? ConsumerCount,
    uint? DeadLetterQueueCount,
    string? ErrorCode);
