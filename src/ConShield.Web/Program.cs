using ConShield.Application;
using System.Globalization;
using ConShield.Data;
using ConShield.SecurityEvents;
using ConShield.Web.Options;
using ConShield.Web.Security;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<List<DemoUserOptions>>(builder.Configuration.GetSection("DemoUsers"));
builder.Services.Configure<ExternalEventIngestionOptions>(builder.Configuration.GetSection("ExternalEventIngestion"));

builder.Services.AddControllersWithViews()
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
        var apiKeyFingerprint = ExternalEventApiKeyValidator.PartitionFingerprint(
            httpContext.Request.Headers["X-ConShield-Api-Key"].FirstOrDefault());
        var remoteIp = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown-ip";
        var partitionKey = $"{remoteIp}:{apiKeyFingerprint}";

        return RateLimitPartition.GetFixedWindowLimiter(partitionKey, _ => new FixedWindowRateLimiterOptions
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

builder.Services.AddScoped<ISecurityEventWriter>(serviceProvider =>
{
    var dbContext = serviceProvider.GetRequiredService<ApplicationDbContext>();
    var env = serviceProvider.GetRequiredService<IWebHostEnvironment>();
    return new SecurityEventWriter(dbContext, env.ContentRootPath);
});

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
    if (context.Request.Path.StartsWithSegments("/api/v1/security-events"))
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
app.Use(async (context, next) =>
{
    if (HttpMethods.IsPost(context.Request.Method)
        && context.Request.Path.Equals("/api/v1/security-events", StringComparison.OrdinalIgnoreCase))
    {
        var options = context.RequestServices
            .GetRequiredService<Microsoft.Extensions.Options.IOptions<ExternalEventIngestionOptions>>()
            .Value;

        if (context.Request.ContentLength.HasValue && context.Request.ContentLength.Value > options.MaxRequestBodyBytes)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            await context.Response.WriteAsJsonAsync(new { error = "payload_too_large" });
            return;
        }
    }

    await next();
});
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

public partial class Program
{
}
