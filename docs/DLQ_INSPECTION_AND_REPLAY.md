# DLQ Inspection And Replay

ConShield adds a controlled administrative path for RabbitMQ dead-lettered security-event messages:

```text
RabbitMQ DLQ
-> Dead-letter capture consumer
-> PostgreSQL DeadLetterQuarantineMessages
-> AdminIB inspection
-> DeadLetterReplayRequests
-> background replay dispatcher
-> original RabbitMQ exchange/routing key
-> normal consumer pipeline
```

`ConShield.EventConsumer` runs a second manual-ack consumer on `conshield.security-events.dead.v1`. It copies the body inside the callback, parses only bounded allowlisted `x-death` fields, classifies replay eligibility, stores an immutable PostgreSQL quarantine row, commits, and only then ACKs the DLQ message.

Duplicate captures with the same valid `OriginalMessageId + PayloadSha256` update `CaptureCount`. Messages without a valid `MessageId` use a synthetic fingerprint. Oversized payloads are not stored in full; ConShield stores SHA-256, original length, bounded prefix bytes, and `NotEligible`.

MVC never publishes RabbitMQ messages directly. `POST /DeadLetters/Replay/{id}` creates a durable request and audit event in one PostgreSQL transaction. A background dispatcher claims pending requests with `FOR UPDATE SKIP LOCKED`, commits the claim, publishes outside the DB transaction with mandatory routing and publisher confirms, then completes the row using the matching lock token.

Replay preserves the original `MessageId`, publishes the captured body byte-for-byte to server-side RabbitMQ exchange/routing-key constants, and adds only bounded ConShield replay headers. It never copies `x-death` or arbitrary headers.

Replay publishing is at-least-once. If the process crashes after broker-confirmed publish but before status update, the dispatcher can publish the same captured message again after lock recovery. This is acceptable because the original `MessageId` is preserved and the existing Inbox/Mongo pipeline deduplicates by message identity and payload hash. ConShield does not claim distributed exactly-once replay.

`/DeadLetters` is restricted to `AdminIB`; `Operator` receives 403 through normal role authorization. Replay POST uses ASP.NET Core anti-forgery validation and bounded server-side reason validation. The list UI never renders raw payload.

Replay audit events:

- `DeadLetterReplayRequested` as `Warning`;
- `DeadLetterReplayPublished` as `Info`;
- `DeadLetterReplayRejected` as `Warning`;
- `DeadLetterReplayFailed` as `High`.

Implemented:

- controlled AdminIB replay request;
- durable quarantine;
- bounded replay dispatcher;
- immutable replay audit.

Not implemented:

- payload editing or fixing;
- bulk replay;
- automatic replay;
- quarantine retention cleanup;
- cross-cluster replay;
- RabbitMQ management API integration.
