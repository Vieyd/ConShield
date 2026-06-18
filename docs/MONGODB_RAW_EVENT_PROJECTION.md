# MongoDB Raw Event Projection

ConShield can project validated RabbitMQ security event envelopes into MongoDB before completing the PostgreSQL inbox checkpoint:

```text
RabbitMQ delivery -> validated envelope -> MongoDB projection -> PostgreSQL Inbox checkpoint -> ACK
```

PostgreSQL remains the system of record for current application state. MongoDB is a read/raw-event projection of normalized security event envelopes.

## Document

Collection: `security_event_raw_v1`.

Each document uses `_id = MessageId` in canonical lowercase GUID format. It stores schema version, message type, payload SHA-256, UTC projection timestamps, TTL expiration time, and a structured `securityEvent` object. `additionalData` is stored as a BSON object or `null`, not as double-encoded JSON text.

The projection does not store AMQP headers, API keys, connection strings, registry credentials, raw HTTP requests, stack traces, or local paths. Document size is checked before insert and defaults to 256 KiB.

## Replay Semantics

MongoDB uses immutable `InsertOneAsync`; no replace or upsert is used.

| Case | Behavior |
| --- | --- |
| New `MessageId` | Insert Mongo document, create PostgreSQL Inbox receipt, ACK. |
| Same `MessageId` and same payload identity | Treat as already projected or duplicate receipt, ACK. |
| Same `MessageId` with changed payload/hash/event identity | Permanent failure and NACK without requeue; RabbitMQ DLQ receives it. |
| Mongo success then PostgreSQL failure | Requeue; redelivery sees Mongo duplicate, creates Inbox receipt, ACKs. |
| PostgreSQL success then ACK lost | Redelivery sees matching Inbox receipt and ACKs without reprojecting. |
| Mongo unavailable | No Inbox receipt is created; NACK with requeue. |

This is a replay-safe idempotent Mongo projection with PostgreSQL completion checkpoint. It is not a distributed transaction and not distributed exactly-once.

DLQ replay preserves the original `MessageId`, so replay after a transient failure is deduplicated by the same Mongo and PostgreSQL Inbox identity checks. A duplicate replay publish after a dispatcher crash can redeliver the same message, but payload mismatch remains a permanent DLQ condition.

## Indexes and TTL

The consumer initializes:

- TTL index `ttl_expires_at_utc` on `expiresAtUtc` with `expireAfterSeconds = 0`;
- `idx_security_event_id`;
- `idx_security_event_occurred_desc`;
- `idx_security_event_type_severity_occurred`;
- partial `idx_security_event_source_external_id`.

TTL deletion is asynchronous and approximate. PostgreSQL Inbox receipts may live longer than Mongo documents. Redelivery after Mongo TTL deletion with an existing Inbox receipt is ACKed without automatic Mongo backfill.

## Configuration

```json
"MongoProjection": {
  "Enabled": false,
  "ConnectionString": "",
  "DatabaseName": "conshield_events",
  "CollectionName": "security_event_raw_v1",
  "RetentionDays": 30,
  "ConnectTimeoutSeconds": 10,
  "OperationTimeoutSeconds": 10,
  "MaxDocumentBytes": 262144
}
```

Use `MongoProjection__ConnectionString` for real credentials. Do not log or commit Mongo connection strings.

## Docker Compose

```powershell
$env:CONSHIELD_MONGO_ROOT_USERNAME = "mongo_admin"
$env:CONSHIELD_MONGO_ROOT_PASSWORD = "<ASCII-local-secret>"
$env:CONSHIELD_MONGO_APP_USERNAME = "conshield_projection"
$env:CONSHIELD_MONGO_APP_PASSWORD = "<ASCII-local-secret>"

docker compose -f .\infra\docker-compose.yml `
  --profile messaging `
  --profile projection `
  up -d postgres rabbitmq mongo
```

The init script creates `conshield_projection` with `readWrite` only on `conshield_events`. Mongo auth remains enabled.

## Limits

There is no projection backfill, automatic DLQ replay, payload editing, MongoDB cluster automation, production TLS certificate provisioning, or cross-store distributed transaction.
