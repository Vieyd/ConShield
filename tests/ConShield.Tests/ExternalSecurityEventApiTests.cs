using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
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
    public async Task ApiKey_IsNotReturnedInResponseBody()
    {
        await using var factory = await CreateFactoryAsync();
        using var client = factory.CreateClient();
        AddApiKey(client);

        var response = await client.PostAsJsonAsync("/api/v1/security-events", ValidPayload());
        var body = await response.Content.ReadAsStringAsync();

        Assert.DoesNotContain(ApiKey, body, StringComparison.Ordinal);
    }

    private static async Task<WebApplicationFactory<Program>> CreateFactoryAsync()
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
                        ["ExternalEventIngestion:MaxRequestBodyBytes"] = "32768",
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
}
