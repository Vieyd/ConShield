using ConShield.EventPipeline;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace ConShield.MongoProjection;

public sealed class MongoSecurityEventProjection : ISecurityEventRawProjection
{
    private readonly IMongoCollection<BsonDocument> _collection;
    private readonly MongoProjectionOptions _options;

    public MongoSecurityEventProjection(IMongoClient client, IOptions<MongoProjectionOptions> options)
    {
        _options = options.Value;
        _collection = client.GetDatabase(_options.DatabaseName).GetCollection<BsonDocument>(_options.CollectionName);
    }

    public async Task<SecurityEventRawProjectionResult> ProjectAsync(
        SecurityEventEnvelope envelope,
        byte[] body,
        string payloadSha256,
        DateTime nowUtc,
        CancellationToken cancellationToken)
    {
        if (!_options.Enabled)
            return SecurityEventRawProjectionResult.Inserted();

        var result = await ProjectMongoAsync(envelope, payloadSha256, nowUtc, cancellationToken);
        return result.Outcome switch
        {
            MongoProjectionOutcome.Inserted => SecurityEventRawProjectionResult.Inserted(),
            MongoProjectionOutcome.AlreadyProjected => SecurityEventRawProjectionResult.AlreadyProjected(),
            MongoProjectionOutcome.TransientFailure => SecurityEventRawProjectionResult.TransientFailure(result.ErrorCode!, result.SafeErrorSummary!),
            _ => SecurityEventRawProjectionResult.PermanentFailure(result.ErrorCode!, result.SafeErrorSummary!)
        };
    }

    public async Task<MongoProjectionResult> ProjectMongoAsync(
        SecurityEventEnvelope envelope,
        string payloadSha256,
        DateTime nowUtc,
        CancellationToken cancellationToken)
    {
        MongoSecurityEventDocument projected;
        BsonDocument document;
        try
        {
            projected = MongoSecurityEventDocument.FromEnvelope(envelope, payloadSha256, nowUtc, _options.RetentionDays);
            document = projected.ToBsonDocument();
            if (document.ToBson().Length > _options.MaxDocumentBytes)
                return MongoProjectionResult.PermanentFailure("mongo_document_too_large", "Mongo projection document exceeds configured size limit.");
        }
        catch (Exception ex) when (ex is InvalidOperationException or FormatException or ArgumentException)
        {
            return MongoProjectionResult.PermanentFailure("mongo_invalid_document", "Mongo projection document is invalid.");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(_options.OperationTimeoutSeconds));

        try
        {
            await _collection.InsertOneAsync(document, cancellationToken: timeout.Token);
            return MongoProjectionResult.Inserted();
        }
        catch (MongoWriteException ex) when (ex.WriteError?.Category == ServerErrorCategory.DuplicateKey)
        {
            return await CompareDuplicateAsync(projected, timeout.Token);
        }
        catch (Exception ex)
        {
            return ClassifyFailure(ex);
        }
    }

    public static MongoProjectionResult ClassifyFailure(Exception ex)
    {
        if (ex is OperationCanceledException or TimeoutException or MongoExecutionTimeoutException or MongoConnectionException or MongoConnectionPoolPausedException)
            return MongoProjectionResult.TransientFailure("mongo_timeout", "Mongo projection operation timed out or MongoDB is unavailable.");
        if (ex is MongoWriteConcernException)
            return MongoProjectionResult.TransientFailure("mongo_write_concern", "MongoDB write concern was not satisfied.");
        if (ex is MongoCommandException command && command.CodeName is "IndexOptionsConflict" or "IndexKeySpecsConflict")
            return MongoProjectionResult.PermanentFailure("mongo_index_conflict", "MongoDB projection index conflict.");
        if (ex is MongoException)
            return MongoProjectionResult.TransientFailure("mongo_unavailable", "MongoDB projection is temporarily unavailable.");
        return MongoProjectionResult.PermanentFailure("mongo_unknown", "Mongo projection failed.");
    }

    private async Task<MongoProjectionResult> CompareDuplicateAsync(
        MongoSecurityEventDocument projected,
        CancellationToken cancellationToken)
    {
        var existing = await _collection
            .Find(Builders<BsonDocument>.Filter.Eq("_id", projected.Id))
            .FirstOrDefaultAsync(cancellationToken);

        if (existing is null)
            return MongoProjectionResult.TransientFailure("mongo_unavailable", "Mongo duplicate insert could not reload existing document.");

        try
        {
            var existingDocument = MongoSecurityEventDocument.FromBsonDocument(existing);
            return existingDocument.HasSameIdentity(projected)
                ? MongoProjectionResult.AlreadyProjected()
                : MongoProjectionResult.PermanentFailure("mongo_duplicate_payload_mismatch", "Mongo projection duplicate message id has different payload identity.");
        }
        catch (Exception)
        {
            return MongoProjectionResult.PermanentFailure("mongo_invalid_document", "Existing Mongo projection document is invalid.");
        }
    }
}
