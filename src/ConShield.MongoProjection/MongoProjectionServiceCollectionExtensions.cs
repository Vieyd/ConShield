using ConShield.EventPipeline;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace ConShield.MongoProjection;

public static class MongoProjectionServiceCollectionExtensions
{
    public static IServiceCollection AddMongoProjection(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<MongoProjectionOptions>()
            .Bind(configuration.GetSection("MongoProjection"))
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<MongoProjectionOptions>, MongoProjectionOptionsValidator>();
        services.AddSingleton<IMongoClient>(provider =>
        {
            var options = provider.GetRequiredService<IOptions<MongoProjectionOptions>>().Value;
            if (!options.Enabled)
                return new MongoClient("mongodb://localhost:27017/?serverSelectionTimeoutMS=1");

            var settings = MongoClientSettings.FromConnectionString(options.ConnectionString);
            settings.ApplicationName = "conshield-event-consumer";
            settings.ConnectTimeout = TimeSpan.FromSeconds(options.ConnectTimeoutSeconds);
            settings.ServerSelectionTimeout = TimeSpan.FromSeconds(options.ConnectTimeoutSeconds);
            settings.SocketTimeout = TimeSpan.FromSeconds(options.OperationTimeoutSeconds);
            settings.RetryWrites = true;
            return new MongoClient(settings);
        });
        services.AddSingleton<MongoProjectionIndexInitializer>();
        services.AddSingleton<MongoProjectionStatusService>();
        services.AddScoped<ISecurityEventRawProjection>(provider =>
        {
            var options = provider.GetRequiredService<IOptions<MongoProjectionOptions>>().Value;
            return options.Enabled
                ? provider.GetRequiredService<MongoSecurityEventProjection>()
                : new DisabledSecurityEventRawProjection();
        });
        services.AddScoped<MongoSecurityEventProjection>();
        return services;
    }
}
