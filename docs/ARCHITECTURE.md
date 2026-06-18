# Architecture

ConShield is organized as a layered ASP.NET Core MVC application. The current structure keeps the UI, application logic, data access, shared contracts, and security event writing in separate projects.

## Projects

```text
src/ConShield.Web
```

MVC application with controllers, Razor Views, view models, authentication setup, authorization checks, and presentation logic.

```text
src/ConShield.Application
```

Application services and SIEM correlation logic. This layer contains use cases such as user exception operations and alert generation from event patterns.

```text
src/ConShield.Data
```

Entity Framework Core DbContext and persistent entities for user exceptions, security events, outbox/inbox records, incidents, and SIEM alerts.
PostgreSQL is the current database and Npgsql is the EF Core provider.

```text
src/ConShield.Contracts
```

Shared constants, enums, and DTO models used across the solution.

```text
src/ConShield.RuntimeDetection
```

Pure library for Falco-compatible JSON parsing, runtime mapping policy validation, safe field minimization, normalization, and deterministic event identity.

```text
src/ConShield.RuntimeCollector
```

Console collector that reads Falco-compatible alerts from stdin or JSONL files and submits normalized external events to the existing ingestion API.

```text
src/ConShield.SecurityEvents
```

Audit event writer that stores security events in the database and appends runtime JSONL logs for local inspection.

```text
src/ConShield.EventPipeline
```

Outbox dispatcher, JSONL and RabbitMQ transports, RabbitMQ topology, retry/DeadLetter handling, inbox receipt processing, DLQ quarantine classification, and bounded replay dispatch.

```text
src/ConShield.EventConsumer
```

Standalone RabbitMQ consumer that records idempotent PostgreSQL inbox receipts, optionally projects to MongoDB, captures DLQ messages into PostgreSQL quarantine, and manually acknowledges deliveries.

## Current Flow

1. A user signs in with local demo credentials.
2. MVC actions enforce role-based access.
3. Important operations write security events through `ISecurityEventWriter`.
4. Security events are stored in PostgreSQL with a durable outbox row.
5. The outbox dispatcher delivers through JSONL by default or RabbitMQ when configured.
6. RabbitMQ deliveries are consumed by `ConShield.EventConsumer` and deduplicated by inbox `MessageId`.
7. RabbitMQ DLQ deliveries are captured into immutable quarantine rows; `AdminIB` can request bounded replay, and a background dispatcher republishes to the original route.
8. Falco-compatible runtime alerts can be normalized by `ConShield.RuntimeCollector` and ingested as external security events.
9. The SIEM correlation service scans recent events and creates alerts, including `RTE-001` for approved runtime mappings.
10. Alerts can create linked incidents for investigation.

## Future Direction

The intended long-term direction is to split event collection from event analysis:

```text
Web app -> Security event writer -> PostgreSQL outbox -> RabbitMQ -> EventConsumer -> PostgreSQL inbox -> projections
```

The existing `infra/docker-compose.yml` runs PostgreSQL, RabbitMQ, and optional MongoDB raw-event projection infrastructure for the current event pipeline. PostgreSQL remains the system of record; MongoDB stores replay-safe normalized raw-event projections when enabled.
