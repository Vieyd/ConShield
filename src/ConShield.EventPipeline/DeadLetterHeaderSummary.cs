using System.Text.Json;
using RabbitMQ.Client;

namespace ConShield.EventPipeline;

public sealed record DeadLetterHeaderSummary(
    string Reason,
    string? Queue,
    string? Exchange,
    IReadOnlyList<string> RoutingKeys,
    long Count,
    DateTime? TimeUtc)
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    public string ToJson() => JsonSerializer.Serialize(this, SerializerOptions);
}

public static class DeadLetterHeaderParser
{
    private static readonly HashSet<string> AllowedReasons = new(StringComparer.OrdinalIgnoreCase)
    {
        "rejected",
        "delivery_limit",
        "expired",
        "maxlen"
    };

    public static DeadLetterHeaderSummary Parse(IReadOnlyBasicProperties properties)
    {
        if (properties.Headers is null || !properties.Headers.TryGetValue("x-death", out var xDeath))
            return new DeadLetterHeaderSummary("unknown", null, null, Array.Empty<string>(), 0, null);

        try
        {
            if (xDeath is null)
                return new DeadLetterHeaderSummary("unknown", null, null, Array.Empty<string>(), 0, null);

            var entry = AsList(xDeath).OfType<IDictionary<string, object?>>().FirstOrDefault();
            if (entry is null)
                return new DeadLetterHeaderSummary("unknown", null, null, Array.Empty<string>(), 0, null);

            var reason = NormalizeReason(ReadString(entry, "reason"));
            var queue = Safe(ReadString(entry, "queue"), 128);
            var exchange = Safe(ReadString(entry, "exchange"), 128);
            var routingKeys = ReadRoutingKeys(entry).Select(x => Safe(x, 128)).Where(x => x.Length > 0).Take(5).ToArray();
            var count = Math.Clamp(ReadLong(entry, "count"), 0, 1_000_000);
            var time = ReadTimeUtc(entry, "time");
            return new DeadLetterHeaderSummary(reason, EmptyToNull(queue), EmptyToNull(exchange), routingKeys, count, time);
        }
        catch
        {
            return new DeadLetterHeaderSummary("unknown", null, null, Array.Empty<string>(), 0, null);
        }
    }

    private static IEnumerable<object?> AsList(object value) =>
        value as IEnumerable<object?> ?? Array.Empty<object?>();

    private static IEnumerable<string> ReadRoutingKeys(IDictionary<string, object?> entry)
    {
        if (!entry.TryGetValue("routing-keys", out var value) || value is null)
            return Array.Empty<string>();
        if (value is string text)
            return new[] { text };
        if (value is byte[] bytes)
            return new[] { Decode(bytes) };
        return AsList(value).Select(x => x is byte[] b ? Decode(b) : x?.ToString() ?? string.Empty);
    }

    private static string? ReadString(IDictionary<string, object?> entry, string key)
    {
        if (!entry.TryGetValue(key, out var value) || value is null)
            return null;
        return value is byte[] bytes ? Decode(bytes) : value.ToString();
    }

    private static long ReadLong(IDictionary<string, object?> entry, string key)
    {
        if (!entry.TryGetValue(key, out var value) || value is null)
            return 0;
        return value switch
        {
            long l => l,
            int i => i,
            uint u => u,
            byte b => b,
            _ => long.TryParse(value.ToString(), out var parsed) ? parsed : 0
        };
    }

    private static DateTime? ReadTimeUtc(IDictionary<string, object?> entry, string key)
    {
        if (!entry.TryGetValue(key, out var value) || value is null)
            return null;
        if (value is AmqpTimestamp timestamp)
            return DateTimeOffset.FromUnixTimeSeconds(timestamp.UnixTime).UtcDateTime;
        return DateTime.TryParse(value.ToString(), out var parsed)
            ? DateTime.SpecifyKind(parsed.ToUniversalTime(), DateTimeKind.Utc)
            : null;
    }

    private static string Decode(byte[] bytes) => System.Text.Encoding.UTF8.GetString(bytes);

    private static string NormalizeReason(string? reason)
    {
        var safe = Safe(reason, 64).ToLowerInvariant();
        return AllowedReasons.Contains(safe) ? safe : "unknown";
    }

    private static string Safe(string? value, int maxLength)
    {
        var safe = new string((value ?? string.Empty).Where(ch => !char.IsControl(ch)).ToArray()).Trim();
        return safe.Length <= maxLength ? safe : safe[..maxLength];
    }

    private static string? EmptyToNull(string value) => value.Length == 0 ? null : value;
}
