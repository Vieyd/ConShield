using ConShield.Application;
using System.Globalization;
using ConShield.Data;
using ConShield.EventPipeline;
using ConShield.MongoProjection;
using ConShield.SecurityEvents;
using ConShield.Web.Options;
using ConShield.Web.Security;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<List<DemoUserOptions>>(builder.Configuration.GetSection("DemoUsers"));
builder.Services.Configure<ExternalEventIngestionOptions>(builder.Configuration.GetSection("ExternalEventIngestion"));
builder.Services
    .AddOptions<SecurityEventOutboxOptions>()
    .Bind(builder.Configuration.GetSection("SecurityEventOutbox"))
    .ValidateOnStart();
builder.Services
    .AddOptions<RabbitMqOptions>()
    .Bind(builder.Configuration.GetSection("RabbitMq"))
    .ValidateOnStart();
builder.Services
    .AddOptions<DeadLetterReplayOptions>()
    .Bind(builder.Configuration.GetSection("DeadLetterReplay"))
    .ValidateOnStart();
builder.Services.AddSingleton<Microsoft.Extensions.Options.IValidateOptions<SecurityEventOutboxOptions>, SecurityEventOutboxOptionsValidator>();
builder.Services.AddSingleton<Microsoft.Extensions.Options.IValidateOptions<RabbitMqOptions>, RabbitMqOptionsValidator>();
builder.Services.AddSingleton<Microsoft.Extensions.Options.IValidateOptions<DeadLetterReplayOptions>, DeadLetterReplayOptionsValidator>();

builder.Services.AddControllersWithViews()
    .ConfigureApiBehaviorOptions(options =>
    {
        options.InvalidModelStateResponseFactory = context => new BadRequestObjectResult(new
        {
            error = "invalid_request",
            errors = context.ModelState
                .Where(x => x.Value?.Errors.Count > 0)
                .ToDictionary(
                    x => x.Key,
                    x => x.Value!.Errors.Select(error => error.ErrorMessage).ToArray())
        });
    })
    .AddViewLocalization();

builder.Services.AddLocalization();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.AccessDeniedPath = "/Account/AccessDenied";
        options.Cookie.Name = "ConShield.Auth";
    });

builder.Services.AddAuthorization();
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("ExternalEventIngestion", httpContext =>
    {
        var remoteIp = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown-ip";

        return RateLimitPartition.GetFixedWindowLimiter(remoteIp, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 20,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        });
    });
});

builder.Services.AddScoped<IUserExceptionService, UserExceptionService>();
builder.Services.AddScoped<ISiemCorrelationService, SiemCorrelationService>();
builder.Services.AddScoped<IExternalSecurityEventIngestionService, ExternalSecurityEventIngestionService>();
builder.Services.AddScoped<ISecurityEventWriter, SecurityEventWriter>();
builder.Services.AddSingleton<IOutboxClock, SystemOutboxClock>();
builder.Services.AddSingleton<IRabbitMqConnectionProvider, RabbitMqConnectionProvider>();
builder.Services.AddSingleton<RabbitMqTopology>();
builder.Services.AddMongoProjection(builder.Configuration);
builder.Services.AddScoped<SecurityEventOutboxDispatcher>();
builder.Services.AddScoped<SecurityEventOutboxStatusService>();
builder.Services.AddScoped<RabbitMqStatusService>();
builder.Services.AddScoped<DeadLetterStatusService>();
builder.Services.AddScoped<DeadLetterReplayRequestService>();
builder.Services.AddScoped<DeadLetterReplayPublisher>();
builder.Services.AddScoped<DeadLetterReplayDispatcher>();
builder.Services.AddScoped<ISecurityEventOutboxSink>(serviceProvider =>
{
    var outboxOptions = serviceProvider.GetRequiredService<Microsoft.Extensions.Options.IOptions<SecurityEventOutboxOptions>>().Value;
    if (outboxOptions.Transport == SecurityEventOutboxTransport.RabbitMq)
    {
        return new RabbitMqSecurityEventOutboxSink(
            serviceProvider.GetRequiredService<IRabbitMqConnectionProvider>(),
            serviceProvider.GetRequiredService<RabbitMqTopology>(),
            serviceProvider.GetRequiredService<Microsoft.Extensions.Options.IOptions<RabbitMqOptions>>(),
            serviceProvider.GetRequiredService<ILogger<RabbitMqSecurityEventOutboxSink>>());
    }

    var env = serviceProvider.GetRequiredService<IWebHostEnvironment>();
    var options = serviceProvider.GetRequiredService<Microsoft.Extensions.Options.IOptions<SecurityEventOutboxOptions>>();
    return new JsonlSecurityEventOutboxSink(env.ContentRootPath, options);
});
builder.Services.AddHostedService<SecurityEventOutboxBackgroundService>();
builder.Services.AddHostedService<DeadLetterReplayBackgroundService>();

var app = builder.Build();

var supportedCultures = new[] { new CultureInfo("ru-RU") };
app.UseRequestLocalization(new RequestLocalizationOptions
{
    DefaultRequestCulture = new Microsoft.AspNetCore.Localization.RequestCulture("ru-RU"),
    SupportedCultures = supportedCultures,
    SupportedUICultures = supportedCultures
});

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    if (app.Environment.IsDevelopment())
    {
        await db.Database.MigrateAsync();
        await DbSeeder.SeedAsync(db);
    }
}

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
}

app.UseStaticFiles();
app.UseRouting();
app.Use(async (context, next) =>
{
    if (context.GetEndpoint()?.Metadata.GetMetadata<ExternalEventIngestionEndpointAttribute>() is not null)
    {
        try
        {
            await next();
        }
        catch
        {
            if (!context.Response.HasStarted)
            {
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                await context.Response.WriteAsJsonAsync(new { error = "internal_error" });
            }
        }

        return;
    }

    await next();
});
app.UseRateLimiter();
app.Use(async (context, next) =>
{
    if (context.GetEndpoint()?.Metadata.GetMetadata<ExternalEventIngestionEndpointAttribute>() is null)
    {
        await next();
        return;
    }

    var options = context.RequestServices
        .GetRequiredService<Microsoft.Extensions.Options.IOptions<ExternalEventIngestionOptions>>()
        .Value;

    if (!options.Enabled)
    {
        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        await context.Response.WriteAsJsonAsync(new { error = "external_event_ingestion_disabled" });
        return;
    }

    var providedApiKey = context.Request.Headers["X-ConShield-Api-Key"].FirstOrDefault();
    if (!ExternalEventApiKeyValidator.IsValidForAny(
            providedApiKey,
            options.ApiKey,
            options.RuntimeCollectorApiKey))
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsJsonAsync(new { error = "unauthorized" });
        return;
    }

    if (!IsJsonContentType(context.Request.ContentType))
    {
        context.Response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
        await context.Response.WriteAsJsonAsync(new { error = "unsupported_media_type" });
        return;
    }

    if (context.Request.ContentLength == 0)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsJsonAsync(new { error = "invalid_request" });
        return;
    }

    if (context.Request.ContentLength.HasValue && context.Request.ContentLength.Value > options.MaxRequestBodyBytes)
    {
        context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
        await context.Response.WriteAsJsonAsync(new { error = "payload_too_large" });
        return;
    }

    var maxRequestBodySizeFeature = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
    if (maxRequestBodySizeFeature is { IsReadOnly: false })
        maxRequestBodySizeFeature.MaxRequestBodySize = options.MaxRequestBodyBytes;

    var originalBody = context.Request.Body;
    context.Request.Body = new LimitedRequestBodyStream(originalBody, options.MaxRequestBodyBytes);

    try
    {
        await next();
        if (!context.Response.HasStarted
            && string.IsNullOrWhiteSpace(context.Response.ContentType)
            && context.Response.StatusCode is StatusCodes.Status400BadRequest or StatusCodes.Status415UnsupportedMediaType)
        {
            var error = context.Response.StatusCode == StatusCodes.Status415UnsupportedMediaType
                ? "unsupported_media_type"
                : "invalid_request";
            await context.Response.WriteAsJsonAsync(new { error });
        }
    }
    catch (BadHttpRequestException ex) when (ex.StatusCode == StatusCodes.Status413PayloadTooLarge)
    {
        if (!context.Response.HasStarted)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            await context.Response.WriteAsJsonAsync(new { error = "payload_too_large" });
        }
    }
    finally
    {
        context.Request.Body = originalBody;
    }
});
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

static bool IsJsonContentType(string? contentType)
{
    if (string.IsNullOrWhiteSpace(contentType))
        return false;

    var mediaType = contentType.Split(';', 2)[0].Trim();
    return mediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase)
        || mediaType.EndsWith("+json", StringComparison.OrdinalIgnoreCase);
}

public partial class Program
{
}
