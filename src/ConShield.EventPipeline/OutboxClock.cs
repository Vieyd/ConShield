namespace ConShield.EventPipeline;

public interface IOutboxClock
{
    DateTime UtcNow { get; }
}

public sealed class SystemOutboxClock : IOutboxClock
{
    public DateTime UtcNow => DateTime.UtcNow;
}
