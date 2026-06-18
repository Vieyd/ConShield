# Report Mapping

This document maps ConShield features to topics that can be described in a portfolio report, course paper, or GitHub project overview.

## Project Goal

ConShield demonstrates a small security monitoring workflow:

- collect security events;
- preserve audit context;
- detect suspicious event patterns;
- create SIEM-style alerts;
- escalate alerts into incidents;
- separate administrator and operator permissions.

## Feature Mapping

| Area | Current implementation | Evidence in repository |
| --- | --- | --- |
| Role-based access | `AdminIB` can perform critical actions, `Operator` is read-only for critical flows | Controllers in `src/ConShield.Web/Controllers` |
| Audit logging | Security events are written through `ISecurityEventWriter` and delivered through a PostgreSQL outbox | `src/ConShield.SecurityEvents`, `src/ConShield.EventPipeline` |
| Event storage | Security events are persisted through EF Core | `ApplicationDbContext.SecurityEvents` |
| User exception governance | Create, edit, delete, list, and details flows | `UserExceptionsController`, `UserExceptionService` |
| Incident handling | Incidents have severity, status, source event, and notes | `IncidentRecord`, `IncidentsController` |
| Database provider | PostgreSQL through Npgsql | `ConShield.Data`, `Program.cs`, EF Core migrations |
| SIEM correlation | Rules generate alerts and incidents from event windows | `SiemCorrelationService` |
| Detection catalog | Human-readable rule definitions | `SiemRuleCatalog` |
| Container image scanning | Trivy scan summaries are ingested as external security events | `ConShield.ImageScanner` |
| Container policy gate | Local Allow/Warn/Block policy decision with replay-safe optional hardened Docker launch audit | `ConShield.ContainerPolicy`, `ConShield.ImageScanner gate` |
| Event pipeline | Transactional outbox, background dispatcher, retry, DeadLetter, JSONL and RabbitMQ transports | `ConShield.EventPipeline`, `SecurityEventOutbox` |
| Consumer idempotency | RabbitMQ consumer records one PostgreSQL inbox receipt per `MessageId` before ack | `ConShield.EventConsumer`, `SecurityEventInboxReceipts` |
| Raw event projection | Optional MongoDB immutable projection stores normalized envelopes before Inbox completion | `ConShield.MongoProjection`, `docs/MONGODB_RAW_EVENT_PROJECTION.md` |
| DLQ inspection/replay | AdminIB reviews PostgreSQL quarantine rows and requests bounded background replay without raw payload exposure | `DeadLettersController`, `DeadLetterReplayDispatcher`, `docs/DLQ_INSPECTION_AND_REPLAY.md` |
| Runtime detection ingestion | Falco-compatible JSON alerts are normalized, deduplicated, minimized, and correlated by RTE-001 | `ConShield.RuntimeDetection`, `ConShield.RuntimeCollector`, `docs/FALCO_RUNTIME_EVENT_INGESTION.md` |
| Local demo | Scenario generation for repeatable walkthroughs | `SiemController.GenerateScenario` |

## Detection Rule Mapping

| Rule | Meaning | Current trigger |
| --- | --- | --- |
| `BF-001` | Possible brute-force attempt | 3 or more login failures for one user in 2 minutes |
| `UE-001` | Suspicious user exception activity | 5 or more user exception update/delete events by one user in 30 seconds |
| `CR-001` | Repeated critical events from one source | 2 or more critical events from one source IP in 5 minutes |
| `IMG-001` | Critical vulnerabilities in container image | Trivy scan summary with `criticalCount >= 1` |
| `POL-001` | Container image blocked by policy | Policy evaluation event with `decision == Block` |
| `RTE-001` | Container runtime threat detected | Approved mapped Falco-compatible runtime event with `correlate == true` |

External events ingested through `POST /api/v1/security-events` are stored as `SecurityEventType.ExternalEvent` with the source-specific type preserved separately as `ExternalEventType`. `CR-001` can trigger for an external critical event when another critical event shares the same `SourceIp`; `BF-001` and `UE-001` do not yet map arbitrary external event types into their built-in rule semantics.

## Portfolio Strengths

- The project is domain-specific to information security.
- It includes both preventive access control and detective monitoring.
- It contains testable detection logic.
- It includes a working container image scanning vertical.
- It includes a local policy gate that turns vulnerability summaries into enforceable decisions.
- It audits guarded Docker launch outcomes without replaying the Docker side effect for duplicate operations.
- It includes durable PostgreSQL outbox delivery through JSONL or RabbitMQ, plus inbox deduplication.
- It has a roadmap toward event-driven SIEM architecture.
- It demonstrates controlled DLQ quarantine/replay with auditability, CSRF/role controls, and at-least-once delivery semantics.

## Future Report Sections

- Threat model.
- Detection engineering approach.
- Incident lifecycle.
- Audit event taxonomy.
- Role model and access boundaries.
- MongoDB raw-event projection and retention semantics.
