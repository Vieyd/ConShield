using System.Globalization;
using System.Text;
using System.Text.Json;
using ConShield.Contracts.Enums;

namespace ConShield.RuntimeDetection;

public sealed record RuntimeSecurityEvent(
    Guid ExternalEventId,
    DateTime OccurredAtUtc,
    string SourceSystem,
    string EventType,
    EventSeverity Severity,
    string? SourceHost,
    string Description,
    RuntimeAdditionalData AdditionalData);

public sealed record RuntimeAdditionalData(
    int SchemaVersion,
    string Provider,
    string MappingId,
    string MappingVersion,
    string MappingSha256,
    string MappingKey,
    bool Correlate,
    string FalcoRule,
    string FalcoPriority,
    string? FalcoSource,
    IReadOnlyList<string> FalcoTags,
    string EventFingerprintSha256,
    string? ContainerId,
    string? ContainerName,
    string? ImageReference,
    string? ImageDigest,
    string? ProcessName,
    string? ParentProcessName,
    string? ProcessExecutable,
    string? ProcessCommandName,
    int? ArgumentCount,
    string? UserName,
    string? UserId,
    string? EventType,
    string? FilePath,
    RuntimeNetworkData? Network,
    string? RawOutputSha256,
    string? CommandLineSha256);

public sealed record RuntimeNetworkData(string? SourceIp, string? SourcePort, string? DestinationIp, string? DestinationPort);

public sealed class RuntimeEventNormalizer
{
    public RuntimeSecurityEvent Normalize(FalcoAlert alert, FalcoMappingPolicy policy)
    {
        var rule = FindRule(alert, policy);
        var mapped = rule is not null;
        var eventType = mapped ? rule!.EventType : RuntimeDetectionConstants.UnmappedEventType;
        var severity = mapped ? ApplyPriorityFloor(rule!.Severity, alert.Priority) : EventSeverity.Info;
        var mappingKey = mapped ? rule!.MappingKey : "unmapped";
        var correlate = mapped && rule!.Correlate;
        var fields = alert.OutputFields;
        var containerId = Field(fields, "container.id");
        var containerName = Field(fields, "container.name");
        var imageRepository = Field(fields, "container.image.repository");
        var imageTag = Field(fields, "container.image.tag");
        var imageDigest = Field(fields, "container.image.digest");
        var imageReference = BuildImageReference(imageRepository, imageTag);
        var procName = Field(fields, "proc.name");
        var parentProc = Field(fields, "proc.pname");
        var executable = Field(fields, "proc.exepath");
        var cmdline = Field(fields, "proc.cmdline");
        var command = ParseCommand(cmdline);
        var rawOutputSha = alert.Output is null ? null : SafeRuntimeText.Sha256Hex(alert.Output);
        var commandSha = cmdline is null ? null : SafeRuntimeText.Sha256Hex(cmdline);
        var fingerprint = RuntimeFingerprint.Create(alert, rawOutputSha);
        var safeRule = SafeRuntimeText.RedactCredentialLike(alert.Rule, RuntimeDetectionConstants.MaxRuleLength)!;
        var additionalData = new RuntimeAdditionalData(
            RuntimeDetectionConstants.AdditionalDataSchemaVersion,
            RuntimeDetectionConstants.Provider,
            policy.MappingId,
            policy.Version,
            policy.Sha256,
            mappingKey,
            correlate,
            safeRule,
            alert.Priority,
            SafeRuntimeText.RedactCredentialLike(alert.Source, 128),
            alert.Tags
                .Take(RuntimeDetectionConstants.MaxTags)
                .Select(tag => SafeRuntimeText.RedactCredentialLike(tag, 64))
                .Where(tag => tag is not null)
                .Select(tag => tag!)
                .ToArray(),
            fingerprint.Sha256,
            containerId,
            containerName,
            imageReference,
            imageDigest,
            procName,
            parentProc,
            executable,
            command.CommandName,
            command.ArgumentCount,
            Field(fields, "user.name"),
            Field(fields, "user.uid"),
            Field(fields, "evt.type"),
            Field(fields, "fd.name"),
            new RuntimeNetworkData(Field(fields, "fd.sip"), Field(fields, "fd.sport"), Field(fields, "fd.dip"), Field(fields, "fd.dport")),
            rawOutputSha,
            commandSha);
        var description = BuildDescription(eventType, safeRule, containerId, containerName, imageReference, procName);
        return new RuntimeSecurityEvent(
            fingerprint.EventId,
            alert.OccurredAtUtc,
            RuntimeDetectionConstants.SourceSystem,
            eventType,
            severity,
            SafeRuntimeText.RedactCredentialLike(alert.Hostname, RuntimeDetectionConstants.MaxHostnameLength),
            description,
            additionalData);
    }

    private static FalcoMappingRule? FindRule(FalcoAlert alert, FalcoMappingPolicy policy)
    {
        return policy.Rules.FirstOrDefault(rule =>
            rule.MatchRuleNames.Contains(alert.Rule, StringComparer.Ordinal)
            && rule.RequiredTags.All(required => alert.Tags.Contains(required, StringComparer.Ordinal)));
    }

    private static EventSeverity ApplyPriorityFloor(EventSeverity mapped, string falcoPriority) =>
        FalcoPriority.RequiresAtLeastHigh(falcoPriority) && mapped < EventSeverity.High ? EventSeverity.High : mapped;

    private static string? Field(IReadOnlyDictionary<string, object?> fields, string name)
    {
        if (!fields.TryGetValue(name, out var value) || value is null)
            return null;
        return SafeRuntimeText.RedactCredentialLike(Convert.ToString(value, CultureInfo.InvariantCulture), RuntimeDetectionConstants.MaxFieldValueLength);
    }

    private static string? BuildImageReference(string? repository, string? tag)
    {
        if (repository is null)
            return null;
        return tag is null ? repository : $"{repository}:{tag}";
    }

    private static (string? CommandName, int? ArgumentCount) ParseCommand(string? cmdline)
    {
        if (string.IsNullOrWhiteSpace(cmdline))
            return (null, null);
        var parts = cmdline.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length == 0)
            return (null, null);
        return (SafeRuntimeText.Clean(parts[0], 128), Math.Max(0, parts.Length - 1));
    }

    private static string BuildDescription(string eventType, string rule, string? containerId, string? containerName, string? image, string? process)
    {
        var identity = containerId ?? containerName ?? image ?? "unknown-container";
        var proc = process is null ? string.Empty : $" process={process}";
        return SafeRuntimeText.Clean($"Falco-compatible runtime event {eventType}: rule={rule}, container={identity}{proc}.", 512)!;
    }
}

public sealed record RuntimeFingerprint(string Sha256, Guid EventId)
{
    public static RuntimeFingerprint Create(FalcoAlert alert, string? rawOutputSha)
    {
        var fields = alert.OutputFields;
        var values = new[]
        {
            RuntimeDetectionConstants.SchemaName,
            alert.OccurredAtUtc.ToString("O", CultureInfo.InvariantCulture),
            alert.Rule,
            alert.Source,
            alert.Hostname,
            Get(fields, "container.id"),
            Get(fields, "evt.type"),
            Get(fields, "proc.name"),
            Get(fields, "thread.vtid") ?? Get(fields, "proc.vpid"),
            rawOutputSha
        };
        var bytes = EncodeLengthPrefixed(values);
        var sha = SafeRuntimeText.Sha256Hex(bytes);
        return new RuntimeFingerprint(sha, CreateUuidFromSha(sha));
    }

    private static string? Get(IReadOnlyDictionary<string, object?> fields, string name) =>
        fields.TryGetValue(name, out var value) ? Convert.ToString(value, CultureInfo.InvariantCulture) : null;

    private static byte[] EncodeLengthPrefixed(IEnumerable<string?> values)
    {
        using var stream = new MemoryStream();
        foreach (var value in values)
        {
            var bytes = Encoding.UTF8.GetBytes(value ?? string.Empty);
            var len = Encoding.ASCII.GetBytes(bytes.Length.ToString(CultureInfo.InvariantCulture));
            stream.Write(len);
            stream.WriteByte((byte)':');
            stream.Write(bytes);
            stream.WriteByte((byte)'|');
        }
        return stream.ToArray();
    }

    private static Guid CreateUuidFromSha(string sha)
    {
        var bytes = Convert.FromHexString(sha[..32]);
        bytes[7] = (byte)((bytes[7] & 0x0F) | 0x50);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);
        return new Guid(bytes);
    }
}
