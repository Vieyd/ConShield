using ConShield.Application;
using System.Globalization;
using ConShield.Data;
using ConShield.SecurityEvents;
using ConShield.Web.Options;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<List<DemoUserOptions>>(builder.Configuration.GetSection("DemoUsers"));

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

builder.Services.AddScoped<IUserExceptionService, UserExceptionService>();
builder.Services.AddScoped<ISiemCorrelationService, SiemCorrelationService>();

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
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
