using System.Text;
using System.Text.Json;

namespace ConShield.RuntimeDetection;

public sealed class FalcoAlertParser
{
    private static readonly JsonReaderOptions ReaderOptions = new()
    {
        MaxDepth = RuntimeDetectionConstants.MaxJsonDepth,
        CommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false
    };

    private static readonly HashSet<string> AllowedOutputFields = new(StringComparer.Ordinal)
    {
        "container.id",
        "container.name",
        "container.image.repository",
        "container.image.tag",
        "container.image.digest",
        "proc.name",
        "proc.pname",
        "proc.exepath",
        "proc.tty",
        "proc.cmdline",
        "user.name",
        "user.uid",
        "evt.type",
        "evt.time",
        "fd.name",
        "fd.sip",
        "fd.sport",
        "fd.dip",
        "fd.dport",
        "thread.vtid",
        "proc.vpid"
    };

    public ParseResult Parse(ReadOnlySpan<byte> line, DateTime nowUtc, TimeSpan maxFutureSkew, TimeSpan maxAge)
    {
        if (line.Length == 0)
            return ParseResult.Fail("empty_line", "Input line is empty.");
        if (line.Length > RuntimeDetectionConstants.MaxLineBytes)
            return ParseResult.Fail("line_too_large", "Input line exceeds the maximum size.");

        string text;
        try
        {
            text = new UTF8Encoding(false, true).GetString(line);
        }
        catch (DecoderFallbackException)
        {
            return ParseResult.Fail("invalid_utf8", "Input line is not valid UTF-8.");
        }

        try
        {
            var reader = new Utf8JsonReader(line, ReaderOptions);
            using var document = JsonDocument.ParseValue(ref reader);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                return ParseResult.Fail("non_object_json", "Falco alert line must be a JSON object.");

            var root = document.RootElement;
            var warnings = new List<string>();
            var timeText = ReadRequiredString(root, "time", 128);
            var rule = SafeRuntimeText.Clean(ReadRequiredString(root, "rule", RuntimeDetectionConstants.MaxRuleLength), RuntimeDetectionConstants.MaxRuleLength);
            var priorityRaw = ReadRequiredString(root, "priority", 64);
            if (timeText is null || rule is null || priorityRaw is null)
                return ParseResult.Fail("missing_required_field", "Falco alert requires time, rule and priority.");
            if (!DateTimeOffset.TryParse(timeText, out var occurred))
                return ParseResult.Fail("invalid_timestamp", "Falco alert time is not a valid timestamp.");
            var occurredUtc = occurred.UtcDateTime;
            if (occurredUtc > nowUtc.Add(maxFutureSkew))
                return ParseResult.Fail("future_timestamp", "Falco alert time is too far in the future.");
            if (occurredUtc < nowUtc.Subtract(maxAge))
                return ParseResult.Fail("old_timestamp", "Falco alert time is older than the configured limit.");
            if (!FalcoPriority.TryNormalize(priorityRaw, out var priority))
                return ParseResult.Fail("invalid_priority", "Falco priority is not supported.");

            var tags = ReadTags(root, warnings);
            var fields = ReadOutputFields(root, warnings);
            var output = SafeRuntimeText.Clean(ReadOptionalString(root, "output", RuntimeDetectionConstants.MaxOutputLengthBeforeRedaction), RuntimeDetectionConstants.MaxOutputLengthBeforeRedaction);
            var hostname = SafeRuntimeText.Clean(ReadOptionalString(root, "hostname", RuntimeDetectionConstants.MaxHostnameLength), RuntimeDetectionConstants.MaxHostnameLength);
            var source = SafeRuntimeText.Clean(ReadOptionalString(root, "source", 128), 128);

            return ParseResult.Ok(new FalcoAlert(occurredUtc, rule, priority, output, hostname, source, tags, fields, warnings));
        }
        catch (JsonException)
        {
            return ParseResult.Fail("malformed_json", "Falco alert line is malformed JSON.");
        }
    }

    private static string? ReadRequiredString(JsonElement root, string name, int maxLength)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String)
            return null;
        return SafeRuntimeText.Clean(value.GetString(), maxLength);
    }

    private static string? ReadOptionalString(JsonElement root, string name, int maxLength)
    {
        if (!root.TryGetProperty(name, out var value))
            return null;
        return value.ValueKind == JsonValueKind.String ? SafeRuntimeText.Clean(value.GetString(), maxLength) : null;
    }

    private static IReadOnlyList<string> ReadTags(JsonElement root, List<string> warnings)
    {
        if (!root.TryGetProperty("tags", out var value))
            return Array.Empty<string>();
        if (value.ValueKind != JsonValueKind.Array)
        {
            warnings.Add("tags_invalid_type");
            return Array.Empty<string>();
        }

        var tags = new List<string>();
        foreach (var item in value.EnumerateArray())
        {
            if (tags.Count >= RuntimeDetectionConstants.MaxTags)
            {
                warnings.Add("tags_truncated");
                break;
            }
            if (item.ValueKind != JsonValueKind.String)
            {
                warnings.Add("tag_invalid_type");
                continue;
            }
            var tag = SafeRuntimeText.Clean(item.GetString(), 64);
            if (tag is not null)
                tags.Add(tag);
        }
        return tags;
    }

    private static IReadOnlyDictionary<string, object?> ReadOutputFields(JsonElement root, List<string> warnings)
    {
        if (!root.TryGetProperty("output_fields", out var value))
            return new Dictionary<string, object?>(StringComparer.Ordinal);
        if (value.ValueKind != JsonValueKind.Object)
        {
            warnings.Add("output_fields_invalid_type");
            return new Dictionary<string, object?>(StringComparer.Ordinal);
        }

        var result = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (result.Count >= RuntimeDetectionConstants.MaxOutputFields)
            {
                warnings.Add("output_fields_truncated");
                break;
            }
            if (!AllowedOutputFields.Contains(property.Name))
                continue;
            var scalar = ReadScalar(property.Value);
            if (scalar == Disallowed.Value)
            {
                warnings.Add($"output_field_nested_ignored:{property.Name}");
                continue;
            }
            result[property.Name] = scalar;
        }
        return result;
    }

    private static object? ReadScalar(JsonElement value)
    {
        return value.ValueKind switch
        {
            JsonValueKind.String => SafeRuntimeText.RedactCredentialLike(value.GetString(), RuntimeDetectionConstants.MaxFieldValueLength),
            JsonValueKind.Number => value.GetRawText(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null,
            _ => Disallowed.Value
        };
    }

    private sealed class Disallowed
    {
        public static readonly Disallowed Value = new();
    }
}
