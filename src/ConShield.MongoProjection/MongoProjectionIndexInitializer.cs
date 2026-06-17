using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace ConShield.MongoProjection;

public sealed class MongoProjectionIndexInitializer
{
    private readonly IMongoCollection<BsonDocument> _collection;

    public MongoProjectionIndexInitializer(IMongoClient client, IOptions<MongoProjectionOptions> options)
    {
        var value = options.Value;
        _collection = client.GetDatabase(value.DatabaseName).GetCollection<BsonDocument>(value.CollectionName);
    }

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        try
        {
            var indexes = new[]
            {
                new CreateIndexModel<BsonDocument>(
                    Builders<BsonDocument>.IndexKeys.Ascending("expiresAtUtc"),
                    new CreateIndexOptions { Name = "ttl_expires_at_utc", ExpireAfter = TimeSpan.Zero }),
                new CreateIndexModel<BsonDocument>(
                    Builders<BsonDocument>.IndexKeys.Ascending("securityEvent.id"),
                    new CreateIndexOptions { Name = "idx_security_event_id" }),
                new CreateIndexModel<BsonDocument>(
                    Builders<BsonDocument>.IndexKeys.Descending("securityEvent.occurredAtUtc"),
                    new CreateIndexOptions { Name = "idx_security_event_occurred_desc" }),
                new CreateIndexModel<BsonDocument>(
                    Builders<BsonDocument>.IndexKeys
                        .Ascending("securityEvent.eventType")
                        .Ascending("securityEvent.severity")
                        .Descending("securityEvent.occurredAtUtc"),
                    new CreateIndexOptions { Name = "idx_security_event_type_severity_occurred" }),
                new CreateIndexModel<BsonDocument>(
                    Builders<BsonDocument>.IndexKeys
                        .Ascending("securityEvent.sourceSystem")
                        .Ascending("securityEvent.externalEventId"),
                    new CreateIndexOptions<BsonDocument>
                    {
                        Name = "idx_security_event_source_external_id",
                        PartialFilterExpression = Builders<BsonDocument>.Filter.And(
                            Builders<BsonDocument>.Filter.Type("securityEvent.sourceSystem", BsonType.String),
                            Builders<BsonDocument>.Filter.Type("securityEvent.externalEventId", BsonType.String))
                    })
            };

            await _collection.Indexes.CreateManyAsync(indexes, cancellationToken);
        }
        catch (MongoCommandException ex) when (ex.CodeName is "IndexOptionsConflict" or "IndexKeySpecsConflict")
        {
            throw new InvalidOperationException("Mongo projection index conflict.", ex);
        }
    }
}
