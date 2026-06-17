using ConShield.Data;
using ConShield.EventConsumer;
using ConShield.EventPipeline;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

var builder = Host.CreateApplicationBuilder(args);
builder.Services
    .AddOptions<RabbitMqOptions>()
    .Bind(builder.Configuration.GetSection("RabbitMq"))
    .ValidateOnStart();
builder.Services
    .AddOptions<SecurityEventOutboxOptions>()
    .Bind(builder.Configuration.GetSection("SecurityEventOutbox"))
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<SecurityEventOutboxOptions>, SecurityEventOutboxOptionsValidator>();
builder.Services.AddSingleton<IValidateOptions<RabbitMqOptions>, RabbitMqOptionsValidator>();
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));
builder.Services.AddSingleton<IOutboxClock, SystemOutboxClock>();
builder.Services.AddSingleton<IRabbitMqConnectionProvider, RabbitMqConnectionProvider>();
builder.Services.AddSingleton<RabbitMqTopology>();
builder.Services.AddScoped<SecurityEventInboxProcessor>();
builder.Services.AddHostedService<RabbitMqSecurityEventConsumerService>();

var host = builder.Build();
host.Run();
