using ConShield.Data.Entities;
using ConShield.EventPipeline;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;

namespace ConShield.Tests;

public class DeadLetterReplayTests
{
    [Fact]
    public void DeadLetterHeaderParser_ParsesAllowlistedXDeathFieldsOnly()
    {
        var properties = new BasicProperties
        {
            Headers = new Dictionary<string, object?>
            {
                ["x-death"] = new List<object?>
                {
                    new Dictionary<string, object?>
                    {
                        ["reason"] = "delivery_limit",
                        ["queue"] = "conshield.security-events.consumer.v1",
                        ["exchange"] = "conshield.security.events.v1",
                        ["routing-keys"] = new List<object?> { "security.event.created", "ignored.extra" },
                        ["count"] = 9L,
                        ["time"] = new AmqpTimestamp(1_700_000_000),
                        ["stackTrace"] = "must-not-be-serialized"
                    }
                }
            }
        };

        var summary = DeadLetterHeaderParser.Parse(properties);
        var json = summary.ToJson();

        Assert.Equal("delivery_limit", summary.Reason);
        Assert.Equal("conshield.security-events.consumer.v1", summary.Queue);
        Assert.Equal(9, summary.Count);
        Assert.DoesNotContain("stackTrace", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DeadLetterHeaderParser_ToleratesMalformedXDeath()
    {
        var properties = new BasicProperties
        {
            Headers = new Dictionary<string, object?> { ["x-death"] = "not-a-list" }
        };

        var summary = DeadLetterHeaderParser.Parse(properties);

        Assert.Equal("unknown", summary.Reason);
        Assert.Empty(summary.RoutingKeys);
    }

    [Fact]
    public void ReplayPublisher_UsesOriginalMessageIdAndDoesNotCopyXDeath()
    {
        var quarantine = new DeadLetterQuarantineMessage
        {
            QuarantineId = Guid.NewGuid(),
            OriginalMessageId = Guid.NewGuid(),
            ContentType = "application/json"
        };
        var request = new DeadLetterReplayRequest
        {
            ReplayRequestId = Guid.NewGuid(),
            ReplaySequence = 2
        };

        var properties = DeadLetterReplayPublisher.CreateProperties(quarantine, request);

        Assert.Equal(quarantine.OriginalMessageId.Value.ToString("D"), properties.MessageId);
        Assert.Equal(SecurityEventEnvelope.SecurityEventCreatedMessageType, properties.Type);
        Assert.NotNull(properties.Headers);
        Assert.Contains("x-conshield-replay-request-id", properties.Headers.Keys);
        Assert.Contains("x-conshield-replay-sequence", properties.Headers.Keys);
        Assert.Contains("x-conshield-original-quarantine-id", properties.Headers.Keys);
        Assert.DoesNotContain("x-death", properties.Headers.Keys);
    }

    [Fact]
    public void DeadLetterReplayOptionsValidator_RejectsUnsafeValues()
    {
        var validator = new DeadLetterReplayOptionsValidator();
        var result = validator.Validate(null, new DeadLetterReplayOptions { MaxPayloadBytes = 1, BatchSize = 0 });

        Assert.True(result.Failed);
    }

    [Fact]
    public void DeadLetterReplayDispatcher_BackoffIsCapped()
    {
        var dispatcher = new DeadLetterReplayDispatcher(
            dbContext: null!,
            publisher: null!,
            eventWriter: null!,
            clock: new FakeClock(DateTime.UtcNow),
            options: Options.Create(new DeadLetterReplayOptions { BaseRetrySeconds = 2, MaxRetrySeconds = 10 }),
            logger: NullLogger<DeadLetterReplayDispatcher>.Instance);

        Assert.Equal(2, dispatcher.CalculateBackoffSeconds(1));
        Assert.Equal(4, dispatcher.CalculateBackoffSeconds(2));
        Assert.Equal(10, dispatcher.CalculateBackoffSeconds(10));
    }

    private sealed class FakeClock : IOutboxClock
    {
        public FakeClock(DateTime utcNow) => UtcNow = DateTime.SpecifyKind(utcNow, DateTimeKind.Utc);
        public DateTime UtcNow { get; }
    }
}
