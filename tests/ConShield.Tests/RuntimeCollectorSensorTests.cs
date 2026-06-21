using System.Net;
using ConShield.RuntimeCollector;
using ConShield.RuntimeDetection;

namespace ConShield.Tests;

public sealed class RuntimeCollectorSensorTests
{
    private const string Credential = "runtime-collector-test-credential-not-secret";
    private static readonly Guid SensorId = Guid.Parse("22222222-3333-4444-8555-666666666666");
    private static readonly Guid CredentialId = Guid.Parse("bbbbbbbb-cccc-4ddd-8eee-ffffffffffff");

    [Fact]
    public async Task RuntimeCollector_AddsSensorIdentityHeaders()
    {
        var handler = new RecordingHandler(HttpStatusCode.Created);
        var client = CreateClient(handler);

        var result = await client.SubmitAsync(RuntimeEvent(), 1, CancellationToken.None);

        Assert.True(result.Accepted);
        Assert.Equal("/api/v1/security-events", handler.Path);
        Assert.Equal(SensorId.ToString("D"), handler.SensorId);
        Assert.Equal(CredentialId.ToString("D"), handler.CredentialId);
        Assert.Equal(Credential, handler.ApiKey);
    }

    [Fact]
    public async Task RuntimeCollector_HeartbeatUsesConfiguredIdentity()
    {
        var handler = new RecordingHandler(HttpStatusCode.NoContent);
        var client = CreateClient(handler);

        var result = await client.SendHeartbeatAsync(1, CancellationToken.None);

        Assert.True(result.Accepted);
        Assert.Equal("/api/v1/sensors/heartbeat", handler.Path);
        Assert.Equal(SensorId.ToString("D"), handler.SensorId);
        Assert.Equal(CredentialId.ToString("D"), handler.CredentialId);
        Assert.Equal(Credential, handler.ApiKey);
    }

    [Fact]
    public async Task RuntimeCollector_DoesNotPrintCredentialOnAuthenticationFailure()
    {
        var handler = new RecordingHandler(HttpStatusCode.Unauthorized);
        var client = CreateClient(handler);
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var result = await client.SendHeartbeatAsync(1, CancellationToken.None);

        Assert.True(result.AuthFailure);
        Assert.DoesNotContain(Credential, stdout.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Credential, stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task RuntimeCollector_HeartbeatCancellation_DoesNotBreakFollowMode()
    {
        var handler = new RecordingHandler(HttpStatusCode.NoContent);
        var client = CreateClient(handler);
        using var cancellation = new CancellationTokenSource();
        var loop = client.RunHeartbeatLoopAsync(TimeSpan.FromMinutes(1), 1, cancellation.Token);
        await handler.RequestObserved.Task.WaitAsync(TimeSpan.FromSeconds(2));

        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => loop);
    }

    private static RuntimeIngestionClient CreateClient(HttpMessageHandler handler) => new(
        new HttpClient(handler) { BaseAddress = new Uri("http://127.0.0.1:5080") },
        Credential,
        SensorId,
        CredentialId);

    private static RuntimeSecurityEvent RuntimeEvent()
    {
        var alert = new FalcoAlert(
            DateTime.UtcNow,
            "Terminal shell in container",
            "Critical",
            "test",
            "runtime-node",
            "syscall",
            ["container"],
            new Dictionary<string, object?>
            {
                ["container.id"] = "test-container",
                ["proc.name"] = "sh",
                ["evt.type"] = "execve"
            },
            []);
        var mapping = FalcoMappingPolicyLoader.Load(MappingPath());
        Assert.True(mapping.Success);
        return new RuntimeEventNormalizer().Normalize(alert, mapping.Policy!);
    }

    private static string MappingPath() => Path.Combine(FindRepoRoot(), "config", "runtime", "falco-mapping-v1.json");

    private static string FindRepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "ConShield.sln")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new InvalidOperationException("Repository root was not found.");
    }

    private sealed class RecordingHandler(HttpStatusCode statusCode) : HttpMessageHandler
    {
        public TaskCompletionSource RequestObserved { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public string? Path { get; private set; }
        public string? SensorId { get; private set; }
        public string? CredentialId { get; private set; }
        public string? ApiKey { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Path = request.RequestUri?.AbsolutePath;
            SensorId = Header(request, "X-ConShield-Sensor-Id");
            CredentialId = Header(request, "X-ConShield-Credential-Id");
            ApiKey = Header(request, "X-ConShield-Api-Key");
            RequestObserved.TrySetResult();
            return Task.FromResult(new HttpResponseMessage(statusCode));
        }

        private static string? Header(HttpRequestMessage request, string name) =>
            request.Headers.TryGetValues(name, out var values) ? values.SingleOrDefault() : null;
    }
}
