using System.Text;
using System.Text.Json;
using ConShield.Contracts.Enums;
using ConShield.RuntimeDetection;

namespace ConShield.Tests;

public class FalcoRuntimeDetectionTests
{
    [Fact]
    public void FalcoParser_ValidOfficialStyleJson_NormalizesSafeFields()
    {
        var parser = new FalcoAlertParser();
        var result = parser.Parse(Encoding.UTF8.GetBytes(ValidAlert()), Now, TimeSpan.FromMinutes(5), TimeSpan.FromDays(30));

        Assert.True(result.Success);
        Assert.Equal("Terminal shell in container", result.Alert!.Rule);
        Assert.Equal("Critical", result.Alert.Priority);
        Assert.Equal("demo-container", result.Alert.OutputFields["container.id"]);
        Assert.Equal("sh", result.Alert.OutputFields["proc.name"]);
    }

    [Theory]
    [InlineData("Emergency")]
    [InlineData("Alert")]
    [InlineData("Critical")]
    [InlineData("Error")]
    [InlineData("Warning")]
    [InlineData("Notice")]
    [InlineData("Informational")]
    [InlineData("Debug")]
    public void FalcoParser_AllPriorities_AreAccepted(string priority)
    {
        var json = ValidAlert().Replace("\"Critical\"", $"\"{priority}\"", StringComparison.Ordinal);
        var result = new FalcoAlertParser().Parse(Encoding.UTF8.GetBytes(json), Now, TimeSpan.FromMinutes(5), TimeSpan.FromDays(30));

        Assert.True(result.Success);
        Assert.Equal(priority, result.Alert!.Priority);
    }

    [Fact]
    public void FalcoParser_MalformedAndNonObjectJson_AreRejected()
    {
        var parser = new FalcoAlertParser();

        Assert.Equal("malformed_json", parser.Parse(Encoding.UTF8.GetBytes("{"), Now, TimeSpan.FromMinutes(5), TimeSpan.FromDays(30)).ErrorCode);
        Assert.Equal("non_object_json", parser.Parse(Encoding.UTF8.GetBytes("[]"), Now, TimeSpan.FromMinutes(5), TimeSpan.FromDays(30)).ErrorCode);
    }

    [Fact]
    public void FalcoParser_InvalidUtf8AndOversizedLine_AreRejected()
    {
        var parser = new FalcoAlertParser();

        Assert.Equal("invalid_utf8", parser.Parse([0xff, 0xfe], Now, TimeSpan.FromMinutes(5), TimeSpan.FromDays(30)).ErrorCode);
        Assert.Equal("line_too_large", parser.Parse(new byte[RuntimeDetectionConstants.MaxLineBytes + 1], Now, TimeSpan.FromMinutes(5), TimeSpan.FromDays(30)).ErrorCode);
    }

    [Fact]
    public void FalcoParser_RejectsFutureAndOldTimestamps()
    {
        var parser = new FalcoAlertParser();
        var future = ValidAlert().Replace("2026-06-18T10:00:00.000000000Z", "2026-06-19T10:00:00Z", StringComparison.Ordinal);
        var old = ValidAlert().Replace("2026-06-18T10:00:00.000000000Z", "2026-01-01T10:00:00Z", StringComparison.Ordinal);

        Assert.Equal("future_timestamp", parser.Parse(Encoding.UTF8.GetBytes(future), Now, TimeSpan.FromMinutes(5), TimeSpan.FromDays(30)).ErrorCode);
        Assert.Equal("old_timestamp", parser.Parse(Encoding.UTF8.GetBytes(old), Now, TimeSpan.FromMinutes(5), TimeSpan.FromDays(30)).ErrorCode);
    }

    [Fact]
    public void FalcoParser_IgnoresNestedAndUnknownFields_AndDoesNotExposeRawOutput()
    {
        var json = """
        {"time":"2026-06-18T10:00:00Z","rule":"Terminal shell in container","priority":"Critical","output":"sensitive-looking output","unknown":"ignored","tags":["container"],"output_fields":{"container.id":"demo","nested":{"bad":true},"proc.cmdline":"sh token"}}
        """;
        var alert = new FalcoAlertParser().Parse(Encoding.UTF8.GetBytes(json), Now, TimeSpan.FromMinutes(5), TimeSpan.FromDays(30)).Alert!;
        var policy = BaselinePolicy();
        var normalized = new RuntimeEventNormalizer().Normalize(alert, policy);
        var serialized = JsonSerializer.Serialize(normalized.AdditionalData, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.DoesNotContain("sensitive-looking output", serialized);
        Assert.DoesNotContain("sh token", serialized);
        Assert.Equal(SafeRuntimeText.Sha256Hex("sensitive-looking output"), normalized.AdditionalData.RawOutputSha256);
        Assert.NotNull(normalized.AdditionalData.CommandLineSha256);
    }

    [Fact]
    public void FalcoMapping_ValidBaselineLoadsWithDeterministicSha()
    {
        var bytes = File.ReadAllBytes(MappingPath());
        var first = FalcoMappingPolicyLoader.Load(bytes);
        var second = FalcoMappingPolicyLoader.Load(bytes);

        Assert.True(first.Success);
        Assert.Equal(first.Policy!.Sha256, second.Policy!.Sha256);
        Assert.Contains(first.Policy.Rules, x => x.MappingKey == "shell-in-container");
    }

    [Fact]
    public void FalcoMapping_RejectsUnknownDuplicateAndInvalidPolicy()
    {
        Assert.False(FalcoMappingPolicyLoader.Load(Encoding.UTF8.GetBytes("""{"schemaVersion":1,"unknown":true,"mappingId":"x","version":"1","unmappedAction":"IngestWithoutCorrelation","rules":[]}""")).Success);
        Assert.False(FalcoMappingPolicyLoader.Load(Encoding.UTF8.GetBytes("""{"schemaVersion":1,"mappingId":"x","version":"1","unmappedAction":"IngestWithoutCorrelation","rules":[{"mappingKey":"a","matchRuleNames":["r"],"eventType":"bad","severity":"High","correlate":true}]}""")).Success);
        Assert.False(FalcoMappingPolicyLoader.Load(Encoding.UTF8.GetBytes("""{"schemaVersion":1,"mappingId":"x","version":"1","unmappedAction":"IngestWithoutCorrelation","rules":[{"mappingKey":"a","matchRuleNames":["r"],"eventType":"container.runtime.a","severity":"Nope","correlate":true}]}""")).Success);
    }

    [Fact]
    public void FalcoFingerprint_IsStableAndChangesWithIdentity()
    {
        var parser = new FalcoAlertParser();
        var one = parser.Parse(Encoding.UTF8.GetBytes(ValidAlert()), Now, TimeSpan.FromMinutes(5), TimeSpan.FromDays(30)).Alert!;
        var two = parser.Parse(Encoding.UTF8.GetBytes(ValidAlert()), Now, TimeSpan.FromMinutes(5), TimeSpan.FromDays(30)).Alert!;
        var changed = parser.Parse(Encoding.UTF8.GetBytes(ValidAlert().Replace("demo-container", "other-container", StringComparison.Ordinal)), Now, TimeSpan.FromMinutes(5), TimeSpan.FromDays(30)).Alert!;

        var first = RuntimeFingerprint.Create(one, SafeRuntimeText.Sha256Hex(one.Output!));
        var second = RuntimeFingerprint.Create(two, SafeRuntimeText.Sha256Hex(two.Output!));
        var third = RuntimeFingerprint.Create(changed, SafeRuntimeText.Sha256Hex(changed.Output!));

        Assert.Equal(first.Sha256, second.Sha256);
        Assert.Equal(first.EventId, second.EventId);
        Assert.NotEqual(first.Sha256, third.Sha256);
        Assert.Equal(5, first.EventId.ToByteArray()[7] >> 4);
    }

    [Fact]
    public void FalcoNormalizer_UnknownRule_IsUnmappedWithoutCorrelation()
    {
        var json = ValidAlert().Replace("Terminal shell in container", "Unknown runtime rule", StringComparison.Ordinal);
        var alert = new FalcoAlertParser().Parse(Encoding.UTF8.GetBytes(json), Now, TimeSpan.FromMinutes(5), TimeSpan.FromDays(30)).Alert!;

        var normalized = new RuntimeEventNormalizer().Normalize(alert, BaselinePolicy());

        Assert.Equal(RuntimeDetectionConstants.UnmappedEventType, normalized.EventType);
        Assert.False(normalized.AdditionalData.Correlate);
        Assert.Equal(EventSeverity.Info, normalized.Severity);
    }

    private static readonly DateTime Now = new(2026, 06, 18, 10, 0, 0, DateTimeKind.Utc);

    private static string ValidAlert() => """
    {"time":"2026-06-18T10:00:00.000000000Z","rule":"Terminal shell in container","priority":"Critical","output":"Shell spawned in demo container","hostname":"runtime-node","source":"syscall","tags":["container","shell"],"output_fields":{"container.id":"demo-container","container.name":"demo","container.image.repository":"alpine","container.image.tag":"3.20","proc.name":"sh","proc.pname":"runc","proc.cmdline":"sh","user.name":"root","user.uid":"0","evt.type":"execve","thread.vtid":"101"}}
    """;

    private static FalcoMappingPolicy BaselinePolicy() =>
        FalcoMappingPolicyLoader.Load(File.ReadAllBytes(MappingPath())).Policy!;

    private static string MappingPath() => Path.Combine(FindRepoRoot(), "config", "runtime", "falco-mapping-v1.json");

    private static string FindRepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "ConShield.sln")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new InvalidOperationException("Repository root was not found.");
    }
}
