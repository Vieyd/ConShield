using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ConShield.Application;
using ConShield.Contracts.Enums;
using ConShield.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace ConShield.Tests;

[Collection("PostgreSql")]
public class ExternalSecurityEventApiTests
{
    private const string ApiKey = "test-api-key-not-secret";
    private const string ApiKeyHeader = "X-ConShield-Api-Key";

    [PostgreSqlFact]
    public async Task ValidRequest_CreatesOneSecurityEvent()
    {
        await using var factory = await CreateFactoryAsync();
        using var client = factory.CreateClient();
        AddApiKey(client);
        var payload = ValidPayload();

        var response = await client.PostAsJsonAsync("/api/v1/security-events", payload);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Null(response.Headers.Location);
        await using var db = factory.Services.CreateScope().ServiceProvider.GetRequiredService<ApplicationDbContext>();
        Assert.Equal(1, await db.SecurityEvents.CountAsync(x => x.SourceSystem == "collector-tests"));
    }

    [PostgreSqlFact]
    public async Task DuplicateSourceSystemAndExternalEventId_ReturnsExistingEvent()
    {
        await using var factory = await CreateFactoryAsync();
        using var client = factory.CreateClient();
        AddApiKey(client);
        var payload = ValidPayload();

        var first = await client.PostAsJsonAsync("/api/v1/security-events", payload);
        var second = await client.PostAsJsonAsync("/api/v1/security-events", payload);

        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        await using var db = factory.Services.CreateScope().ServiceProvider.GetRequiredService<ApplicationDbContext>();
        Assert.Equal(1, await db.SecurityEvents.CountAsync(x => x.SourceSystem == "collector-tests"));
    }

    [PostgreSqlFact]
    public async Task ConcurrentDuplicate_DoesNotCreateDuplicates()
    {
        await using var factory = await CreateFactoryAsync();
        var payload = ValidPayload();

        var tasks = Enumerable.Range(0, 5).Select(async _ =>
        {
            using var client = factory.CreateClient();
            AddApiKey(client);
            return await client.PostAsJsonAsync("/api/v1/security-events", payload);
        });

        var responses = await Task.WhenAll(tasks);

        Assert.All(responses, x => Assert.True(x.StatusCode is HttpStatusCode.Created or HttpStatusCode.OK));
        await using var db = factory.Services.CreateScope().ServiceProvider.GetRequiredService<ApplicationDbContext>();
        Assert.Equal(1, await db.SecurityEvents.CountAsync(x => x.SourceSystem == "collector-tests"));
    }

    [PostgreSqlFact]
    public async Task MissingApiKey_ReturnsUnauthorized()
    {
        await using var factory = await CreateFactoryAsync();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/security-events", ValidPayload());

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [PostgreSqlFact]
    public async Task InvalidApiKey_ReturnsUnauthorized()
    {
        await using var factory = await CreateFactoryAsync();
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(ApiKeyHeader, "wrong-key");

        var response = await client.PostAsJsonAsync("/api/v1/security-events", ValidPayload());

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [PostgreSqlFact]
    public async Task InvalidSeverity_ReturnsBadRequest()
    {
        await using var factory = await CreateFactoryAsync();
        using var client = factory.CreateClient();
        AddApiKey(client);

        var response = await client.PostAsJsonAsync("/api/v1/security-events", ValidPayload(severity: "BadSeverity"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [PostgreSqlFact]
    public async Task NumericSeverityValues_ReturnBadRequest()
    {
        await using var factory = await CreateFactoryAsync();
        using var client = factory.CreateClient();
        AddApiKey(client);
        var severities = new[] { "999", "-1", "4", "" };

        foreach (var severity in severities)
        {
            var response = await client.PostAsJsonAsync("/api/v1/security-events", ValidPayload(severity: severity));
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    [PostgreSqlFact]
    public async Task EmptySourceSystem_ReturnsBadRequest()
    {
        await using var factory = await CreateFactoryAsync();
        using var client = factory.CreateClient();
        AddApiKey(client);

        var response = await client.PostAsJsonAsync("/api/v1/security-events", ValidPayload(sourceSystem: "   "));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [PostgreSqlFact]
    public async Task TooLongDescription_ReturnsBadRequest()
    {
        await using var factory = await CreateFactoryAsync();
        using var client = factory.CreateClient();
        AddApiKey(client);

        var response = await client.PostAsJsonAsync("/api/v1/security-events", ValidPayload(description: new string('x', 2001)));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [PostgreSqlFact]
    public async Task NonObjectAdditionalData_ReturnsBadRequest()
    {
        await using var factory = await CreateFactoryAsync();
        using var client = factory.CreateClient();
        AddApiKey(client);
        var payload = JsonSerializer.Serialize(ValidPayload()).Replace("\"additionalData\":{\"test\":true}", "\"additionalData\":[1,2]");

        var response = await client.PostAsync(
            "/api/v1/security-events",
            new StringContent(payload, Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [PostgreSqlFact]
    public async Task FutureTimestamp_ReturnsBadRequest()
    {
        await using var factory = await CreateFactoryAsync();
        using var client = factory.CreateClient();
        AddApiKey(client);

        var response = await client.PostAsJsonAsync("/api/v1/security-events", ValidPayload(occurredAtUtc: DateTime.UtcNow.AddHours(1)));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [PostgreSqlFact]
    public async Task RateLimit_ReturnsTooManyRequests()
    {
        await using var factory = await CreateFactoryAsync();
        using var client = factory.CreateClient();
        AddApiKey(client);

        var responses = new List<HttpResponseMessage>();
        for (var i = 0; i < 25; i++)
        {
            responses.Add(await client.PostAsJsonAsync("/api/v1/security-events", ValidPayload()));
        }

        Assert.Contains(responses, x => x.StatusCode == HttpStatusCode.TooManyRequests);
    }

    [PostgreSqlFact]
    public async Task RateLimit_UsesRemoteIpForDifferentInvalidApiKeys()
    {
        await using var factory = await CreateFactoryAsync();
        using var client = factory.CreateClient();
        var responses = new List<HttpResponseMessage>();

        for (var i = 0; i < 25; i++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/security-events")
            {
                Content = JsonContent.Create(ValidPayload())
            };
            request.Headers.Add(ApiKeyHeader, $"wrong-key-{Guid.NewGuid()}");

            responses.Add(await client.SendAsync(request));
        }

        Assert.Contains(responses, x => x.StatusCode == HttpStatusCode.TooManyRequests);
        await using var db = factory.Services.CreateScope().ServiceProvider.GetRequiredService<ApplicationDbContext>();
        Assert.Equal(0, await db.SecurityEvents.CountAsync(x => x.SourceSystem == "collector-tests"));
    }

    [PostgreSqlFact]
    public async Task OversizedRequestWithContentLength_ReturnsPayloadTooLargeAndDoesNotCreateEvent()
    {
        await using var factory = await CreateFactoryAsync(maxRequestBodyBytes: 512);
        using var client = factory.CreateClient();
        AddApiKey(client);

        var response = await client.PostAsync(
            "/api/v1/security-events",
            new StringContent(LargePayload(), Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        await using var db = factory.Services.CreateScope().ServiceProvider.GetRequiredService<ApplicationDbContext>();
        Assert.Equal(0, await db.SecurityEvents.CountAsync(x => x.SourceSystem == "collector-tests"));
    }

    [PostgreSqlFact]
    public async Task OversizedStreamedRequestWithoutContentLength_ReturnsPayloadTooLargeAndDoesNotCreateEvent()
    {
        await using var factory = await CreateFactoryAsync(maxRequestBodyBytes: 512);
        using var client = factory.CreateClient();
        AddApiKey(client);
        using var content = new StreamContent(new NonSeekableUtf8Stream(LargePayload()));
        content.Headers.ContentType = new("application/json");

        var response = await client.PostAsync("/api/v1/security-events", content);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        await using var db = factory.Services.CreateScope().ServiceProvider.GetRequiredService<ApplicationDbContext>();
        Assert.Equal(0, await db.SecurityEvents.CountAsync(x => x.SourceSystem == "collector-tests"));
    }

    [PostgreSqlFact]
    public async Task OversizedRequestWithTrailingSlash_ReturnsPayloadTooLargeAndDoesNotCreateEvent()
    {
        await using var factory = await CreateFactoryAsync(maxRequestBodyBytes: 512);
        using var client = factory.CreateClient();
        AddApiKey(client);

        var response = await client.PostAsync(
            "/api/v1/security-events/",
            new StringContent(LargePayload(), Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        await using var db = factory.Services.CreateScope().ServiceProvider.GetRequiredService<ApplicationDbContext>();
        Assert.Equal(0, await db.SecurityEvents.CountAsync(x => x.SourceSystem == "collector-tests"));
    }

    [PostgreSqlFact]
    public async Task ApiErrors_ReturnSafeJson()
    {
        await using var factory = await CreateFactoryAsync();
        using var client = factory.CreateClient();
        AddApiKey(client);

        var malformed = await client.PostAsync(
            "/api/v1/security-events",
            new StringContent("{", Encoding.UTF8, "application/json"));
        var wrongType = await client.PostAsync(
            "/api/v1/security-events",
            new StringContent("[]", Encoding.UTF8, "application/json"));
        var empty = await client.PostAsync(
            "/api/v1/security-events",
            new StringContent("", Encoding.UTF8, "application/json"));
        var unsupported = await client.PostAsync(
            "/api/v1/security-events",
            new StringContent("{}", Encoding.UTF8, "text/plain"));

        foreach (var (name, response) in new[]
        {
            ("malformed", malformed),
            ("wrongType", wrongType),
            ("empty", empty),
            ("unsupported", unsupported)
        })
        {
            var body = await response.Content.ReadAsStringAsync();
            Assert.False(response.IsSuccessStatusCode);
            Assert.DoesNotContain("System.", body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("<html", body, StringComparison.OrdinalIgnoreCase);
            var mediaType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;
            Assert.True(
                mediaType.Contains("application/", StringComparison.Ordinal),
                $"{name} returned {response.StatusCode} with content type '{mediaType}' and body: {body}");
        }
    }

    [PostgreSqlFact]
    public async Task ApiKey_IsNotReturnedInResponseBody()
    {
        await using var factory = await CreateFactoryAsync();
        using var client = factory.CreateClient();
        AddApiKey(client);

        var response = await client.PostAsJsonAsync("/api/v1/security-events", ValidPayload());
        var body = await response.Content.ReadAsStringAsync();

        Assert.DoesNotContain(ApiKey, body, StringComparison.Ordinal);
    }

    [PostgreSqlFact]
    public async Task ImageScanEvent_IngestsAndTriggersImg001WithoutDuplicates()
    {
        await using var factory = await CreateFactoryAsync();
        using var client = factory.CreateClient();
        AddApiKey(client);
        var externalEventId = Guid.NewGuid();

        var first = await client.PostAsJsonAsync("/api/v1/security-events", ImageScanPayload(externalEventId));
        var second = await client.PostAsJsonAsync("/api/v1/security-events", ImageScanPayload(externalEventId));

        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        Assert.Equal(1, await db.SecurityEvents.CountAsync(x =>
            x.SourceSystem == "conshield.image-scanner"
            && x.ExternalEventType == "container.image.scan.completed"
            && x.ExternalEventId == externalEventId));

        var correlation = scope.ServiceProvider.GetRequiredService<ISiemCorrelationService>();
        var firstRun = await correlation.RunAsync();
        var secondRun = await correlation.RunAsync();

        Assert.Equal(1, firstRun.CreatedAlerts);
        Assert.Equal(1, firstRun.CreatedIncidents);
        Assert.Equal(0, secondRun.CreatedAlerts);
        Assert.Equal(0, secondRun.CreatedIncidents);
        Assert.Equal(1, await db.SiemAlerts.CountAsync(x => x.RuleCode == "IMG-001"));
        Assert.Equal(0, await db.SiemAlerts.CountAsync(x => x.RuleCode == "CR-001"));
        Assert.Equal(1, await db.Incidents.CountAsync(x => x.Name.Contains("IMG-001")));
    }

    [PostgreSqlFact]
    public async Task PolicyGateEvents_IngestAndTriggerImg001AndPol001WithoutDuplicates()
    {
        await using var factory = await CreateFactoryAsync();
        using var client = factory.CreateClient();
        AddApiKey(client);
        var externalEventId = Guid.NewGuid();

        var scanFirst = await client.PostAsJsonAsync("/api/v1/security-events", ImageScanPayload(externalEventId));
        var policyFirst = await client.PostAsJsonAsync("/api/v1/security-events", PolicyGatePayload(externalEventId));
        var scanSecond = await client.PostAsJsonAsync("/api/v1/security-events", ImageScanPayload(externalEventId));
        var policySecond = await client.PostAsJsonAsync("/api/v1/security-events", PolicyGatePayload(externalEventId));

        Assert.Equal(HttpStatusCode.Created, scanFirst.StatusCode);
        Assert.Equal(HttpStatusCode.Created, policyFirst.StatusCode);
        Assert.Equal(HttpStatusCode.OK, scanSecond.StatusCode);
        Assert.Equal(HttpStatusCode.OK, policySecond.StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        Assert.Equal(2, await db.SecurityEvents.CountAsync(x => x.ExternalEventId == externalEventId));

        var correlation = scope.ServiceProvider.GetRequiredService<ISiemCorrelationService>();
        var firstRun = await correlation.RunAsync();
        var secondRun = await correlation.RunAsync();

        Assert.Equal(2, firstRun.CreatedAlerts);
        Assert.Equal(2, firstRun.CreatedIncidents);
        Assert.Equal(0, secondRun.CreatedAlerts);
        Assert.Equal(0, secondRun.CreatedIncidents);
        Assert.Equal(1, await db.SiemAlerts.CountAsync(x => x.RuleCode == "IMG-001"));
        Assert.Equal(1, await db.SiemAlerts.CountAsync(x => x.RuleCode == "POL-001"));
        Assert.Equal(0, await db.SiemAlerts.CountAsync(x => x.RuleCode == "CR-001"));
    }

    private static async Task<WebApplicationFactory<Program>> CreateFactoryAsync(int maxRequestBodyBytes = 32768)
    {
        var connectionString = Environment.GetEnvironmentVariable("CONSHIELD_TEST_POSTGRES_CONNECTION")
            ?? throw new InvalidOperationException("CONSHIELD_TEST_POSTGRES_CONNECTION is required.");

        var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Development");
                builder.ConfigureAppConfiguration((_, configuration) =>
                {
                    configuration.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["ConnectionStrings:DefaultConnection"] = connectionString,
                        ["ExternalEventIngestion:Enabled"] = "true",
                        ["ExternalEventIngestion:ApiKey"] = ApiKey,
                        ["ExternalEventIngestion:MaxRequestBodyBytes"] = maxRequestBodyBytes.ToString(),
                        ["ExternalEventIngestion:AllowedFutureClockSkewMinutes"] = "5"
                    });
                });
            });

        await using var db = factory.Services.CreateScope().ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await db.Database.EnsureDeletedAsync();
        await db.Database.MigrateAsync();
        return factory;
    }

    private static void AddApiKey(HttpClient client)
    {
        client.DefaultRequestHeaders.Add(ApiKeyHeader, ApiKey);
    }

    private static object ValidPayload(
        string sourceSystem = "collector-tests",
        string severity = "Info",
        string description = "External event from API tests.",
        DateTime? occurredAtUtc = null)
    {
        return new
        {
            externalEventId = Guid.NewGuid(),
            occurredAtUtc = occurredAtUtc ?? DateTime.UtcNow,
            sourceSystem,
            eventType = "ApiTestEvent",
            severity,
            userName = "api-test",
            sourceHost = "test-host",
            description,
            additionalData = new { test = true }
        };
    }

    private static object ImageScanPayload(Guid externalEventId)
    {
        return new
        {
            externalEventId,
            occurredAtUtc = DateTime.UtcNow,
            sourceSystem = "conshield.image-scanner",
            eventType = "container.image.scan.completed",
            severity = "Critical",
            userName = (string?)null,
            sourceHost = "test-host",
            description = "Trivy image scan completed for repo/app:latest: critical=1, high=2, total=3.",
            additionalData = new
            {
                schemaVersion = 1,
                scanner = "trivy",
                scannerVersion = "Version: 0.0.0",
                imageReference = "repo/app:latest",
                imageDigest = "repo/app@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                artifactType = "container_image",
                scanStatus = "completed",
                unknownCount = 0,
                lowCount = 0,
                mediumCount = 0,
                highCount = 2,
                criticalCount = 1,
                totalCount = 3,
                fixAvailableCount = 2,
                affectedTargetCount = 1,
                reportSha256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                durationMs = 1000
            }
        };
    }

    private static object PolicyGatePayload(Guid externalEventId)
    {
        return new
        {
            externalEventId,
            occurredAtUtc = DateTime.UtcNow,
            sourceSystem = "conshield.container-guard",
            eventType = "container.image.policy.evaluated",
            severity = "High",
            userName = (string?)null,
            sourceHost = "test-host",
            description = "Container policy container-baseline/1.0.0 evaluated Block for repo/app:latest.",
            additionalData = new
            {
                schemaVersion = 1,
                decision = "Block",
                policyId = "container-baseline",
                policyVersion = "1.0.0",
                policySha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                imageReference = "repo/app:latest",
                imageDigest = "repo/app@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                reportSha256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                unknownCount = 0,
                lowCount = 0,
                mediumCount = 0,
                highCount = 2,
                criticalCount = 1,
                totalCount = 3,
                reasonCodes = new[] { "CRITICAL_THRESHOLD_REACHED" },
                executionRequested = false,
                warningAccepted = false
            }
        };
    }

    private static string LargePayload()
    {
        return JsonSerializer.Serialize(ValidPayload(description: new string('x', 5000)));
    }

    private sealed class NonSeekableUtf8Stream : Stream
    {
        private readonly byte[] _bytes;
        private int _position;

        public NonSeekableUtf8Stream(string value)
        {
            _bytes = Encoding.UTF8.GetBytes(value);
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_position >= _bytes.Length)
                return 0;

            var length = Math.Min(count, _bytes.Length - _position);
            Array.Copy(_bytes, _position, buffer, offset, length);
            _position += length;
            return length;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_position >= _bytes.Length)
                return ValueTask.FromResult(0);

            var length = Math.Min(buffer.Length, _bytes.Length - _position);
            _bytes.AsMemory(_position, length).CopyTo(buffer);
            _position += length;
            return ValueTask.FromResult(length);
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
