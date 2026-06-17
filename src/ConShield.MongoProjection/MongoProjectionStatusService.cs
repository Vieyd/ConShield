using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace ConShield.MongoProjection;

public sealed class MongoProjectionStatusService
{
    private readonly IMongoClient _client;
    private readonly MongoProjectionOptions _options;

    public MongoProjectionStatusService(IMongoClient client, IOptions<MongoProjectionOptions> options)
    {
        _client = client;
        _options = options.Value;
    }

    public async Task<MongoProjectionStatusSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        if (!_options.Enabled)
            return new MongoProjectionStatusSnapshot(false, false, _options.DatabaseName, _options.CollectionName, _options.RetentionDays, null, null, "disabled");

        try
        {
            var database = _client.GetDatabase(_options.DatabaseName);
            await database.RunCommandAsync<BsonDocument>(new BsonDocument("ping", 1), cancellationToken: cancellationToken);
            var collection = database.GetCollection<BsonDocument>(_options.CollectionName);
            var count = await collection.EstimatedDocumentCountAsync(cancellationToken: cancellationToken);
            var last = await collection
                .Find(FilterDefinition<BsonDocument>.Empty)
                .Sort(Builders<BsonDocument>.Sort.Descending("projectedAtUtc"))
                .Project(Builders<BsonDocument>.Projection.Include("projectedAtUtc").Exclude("_id"))
                .FirstOrDefaultAsync(cancellationToken);
            var lastProjected = last is null || !last.Contains("projectedAtUtc")
                ? null
                : (DateTime?)last["projectedAtUtc"].ToUniversalTime();

            return new MongoProjectionStatusSnapshot(true, true, _options.DatabaseName, _options.CollectionName, _options.RetentionDays, count, lastProjected, null);
        }
        catch (Exception)
        {
            return new MongoProjectionStatusSnapshot(true, false, _options.DatabaseName, _options.CollectionName, _options.RetentionDays, null, null, "unavailable");
        }
    }
}

public sealed record MongoProjectionStatusSnapshot(
    bool Enabled,
    bool Connected,
    string DatabaseName,
    string CollectionName,
    int RetentionDays,
    long? EstimatedDocumentCount,
    DateTime? LastProjectedAtUtc,
    string? ErrorCode);
