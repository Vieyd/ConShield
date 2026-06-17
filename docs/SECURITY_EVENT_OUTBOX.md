# Security Event Outbox

## Purpose

ConShield uses a PostgreSQL transactional outbox for security event delivery:

```text
ISecurityEventWriter
-> PostgreSQL transaction: SecurityEvents + SecurityEventOutbox
-> background dispatcher
-> JSONL audit sink or RabbitMQ publisher sink
-> Delivered / retry / DeadLetter
```

The goal is durable background delivery. JSONL is the default local transport; RabbitMQ is available as an explicit transport mode.

## Atomicity Boundary

`SecurityEventWriter` writes the `SecurityEvents` row and one `SecurityEventOutbox` row in the same database transaction. If the outbox payload cannot be serialized or inserted, the transaction rolls back and the security event is not left without a delivery message.

Existing external-event idempotency still uses `sourceSystem + externalEventId`. Duplicate external events do not create a second event or outbox message.

Outbox applies to events written after the `AddSecurityEventOutbox` migration. Older `SecurityEvents` are not backfilled.

## Envelope Schema

Each outbox row contains a bounded JSON envelope:

```json
{
  "schemaVersion": 1,
  "messageId": "uuid",
  "messageType": "security.event.created",
  "createdAtUtc": "UTC timestamp",
  "securityEvent": {
    "id": 123,
    "occurredAtUtc": "UTC timestamp",
    "eventType": "ExternalEvent",
    "severity": "High",
    "userName": "string-or-null",
    "sourceIp": "string-or-null",
    "externalEventId": "uuid-or-null",
    "sourceSystem": "string-or-null",
    "externalEventType": "string-or-null",
    "sourceHost": "string-or-null",
    "description": "string",
    "additionalData": {}
  }
}
```

`additionalData` remains a JSON object or `null`; it is not double-encoded as a string. The envelope does not include API keys, connection strings, request headers, full HTTP requests, or response bodies.

## Statuses

```text
Pending
Processing
Delivered
DeadLetter
```

`Delivered` and `DeadLetter` rows are not automatically claimed. Delivered rows are retained in this stage; automatic cleanup is future work.

## Claim And Locking

The dispatcher claims a limited batch with PostgreSQL `FOR UPDATE SKIP LOCKED`, sets `Processing`, assigns a `LockToken`, and sets `LockedUntilUtc`. File I/O happens after the claim transaction commits, so row locks are not held during sink writes.

Completion updates require the same `LockToken`. Expired `Processing` locks can be reclaimed by another dispatcher instance.

## Retry And DeadLetter

Transient sink failures increment `AttemptCount`, return the row to `Pending`, and schedule `AvailableAtUtc` using capped exponential backoff:

```text
1s, 2s, 4s, ... capped at MaxRetrySeconds
```

Permanent failures or exhausted attempts move the row to `DeadLetter`. Error code and summary are bounded and sanitized; raw exceptions and stack traces are not stored.

## Transport Modes

`SecurityEventOutbox:Transport` controls delivery:

- `Jsonl`: default local sink.
- `RabbitMq`: broker-confirmed publish to `conshield.security.events.v1`.

There is no composite mode. One outbox attempt writes to one sink only.

## JSONL Sink

The current sink writes one UTF-8 JSON line per envelope to:

```text
<ContentRoot>/logs/security-events.jsonl
```

Only safe relative paths inside `ContentRoot` are accepted. Absolute paths and `..` traversal are rejected. Writes are serialized inside the process with `SemaphoreSlim`.

## Delivery Semantics

Delivery is at-least-once. If the process crashes after appending a JSONL line but before marking the row `Delivered`, the dispatcher may write the same envelope again after lock recovery.

Each line contains a stable `messageId`; future consumers must deduplicate by `messageId`. ConShield does not claim distributed exactly-once delivery.

In RabbitMQ mode, `Delivered` means the broker confirmed and routed the persistent message. Consumer processing is tracked separately by PostgreSQL inbox receipts.

## Background Service

`SecurityEventOutboxBackgroundService` runs inside `ConShield.Web`. It creates a scoped `ApplicationDbContext` per iteration, dispatches bounded batches, and logs only counts and safe metadata.

If the worker is disabled, `SecurityEventWriter` still creates durable outbox rows. Pending backlog will grow until the worker is enabled or another dispatcher is connected.

## Admin Status Page

`GET /Outbox` is available only to `AdminIB`. It shows counts, oldest pending age, last delivered time, and recent message metadata. It does not show `PayloadJson`, `AdditionalData`, API keys, full exceptions, or local absolute paths.

## Configuration

```json
{
  "SecurityEventOutbox": {
    "Enabled": true,
    "Transport": "Jsonl",
    "PollIntervalMilliseconds": 1000,
    "BatchSize": 20,
    "LockSeconds": 30,
    "MaxAttempts": 5,
    "BaseRetrySeconds": 1,
    "MaxRetrySeconds": 60,
    "JsonlRelativePath": "logs/security-events.jsonl",
    "DegradedPendingAgeSeconds": 300
  }
}
```

Options are validated on startup. The path must be relative and contained inside the content root.

## Troubleshooting

- `Pending` grows: check whether the background worker is enabled and whether Web is running.
- `Processing` stays old: lock recovery should reclaim it after `LockSeconds`.
- `DeadLetter` appears: inspect `LastErrorCode` and bounded summary on `/Outbox`.
- JSONL missing lines: verify path permissions and disk space.
- Duplicate JSONL message: deduplicate by `messageId`.

## Not Implemented

- MongoDB raw event store.
- Distributed exactly-once delivery.
- Automatic retention cleanup.
- Manual DeadLetter retry UI.
