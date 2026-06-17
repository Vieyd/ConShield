# Decisions

This document records project decisions that should guide future development.

## 001. Keep the Application Layer as the Business Logic Boundary

Business rules, correlation logic, and application use cases should live in `ConShield.Application`. MVC controllers should orchestrate input/output only.

Reason: this keeps the UI replaceable and makes security rules easier to test.

## 002. Keep Persistent Entities in the Data Layer

EF Core entities and `ApplicationDbContext` stay in `ConShield.Data`.

Reason: persistence details should not leak into the web layer more than necessary.

## 003. Use `ISecurityEventWriter` for Security Events

Security-relevant operations should create events through `ISecurityEventWriter`.

Reason: a single event-writing boundary makes audit behavior easier to extend later with queues, external storage, or structured export.

## 004. Store Time in UTC

Database timestamps should be stored in UTC. The current UI displays GMT+3.

Reason: UTC storage avoids ambiguous timestamps and keeps future integrations predictable.

## 005. Use PostgreSQL as the Prototype Database

PostgreSQL is the current supported relational database. Entity Framework Core uses `Npgsql.EntityFrameworkCore.PostgreSQL`.

Reason: PostgreSQL is cross-platform, easy to run in containers, and aligns better with a public portfolio prototype than a Windows-only local database.

For deployment in a regulated Russian organization, a compatible domestic PostgreSQL edition may be considered. Do not claim certification for a specific product without current source verification.

## 006. Use MongoDB as an Optional Raw-Event Projection

MongoDB stores immutable normalized RabbitMQ security event envelopes only after validation and before PostgreSQL Inbox completion when `MongoProjection:Enabled` is true.

Reason: the projection preserves raw event context for future analytics without making MongoDB the source of truth for current SIEM state. PostgreSQL remains the completion checkpoint and application database.

## 007. Keep Demo Authentication Until Replaced Deliberately

The current authentication mechanism remains unchanged for now. Hardening should happen as a separate task.

Reason: replacing authentication touches user flows, authorization, tests, and documentation and should not be mixed with project context/test setup work.

## 008. Use a Separate API Key for External Event Ingestion

The first external ingestion endpoint uses `X-ConShield-Api-Key`, configured only through local settings or environment variables.

Reason: this creates a clear trust boundary for the local prototype without mixing Collector access with demo user cookies or introducing a full identity system too early.

This is not a production machine identity solution. Future hardening should consider key rotation, mTLS, centralized secret management, and per-source credentials.

## 009. Enforce Idempotency in the Database

External security events are idempotent by `sourceSystem + externalEventId`.

Reason: Collector retries should be safe, and the PostgreSQL unique index remains the final protection against concurrent duplicate submissions.

## 010. Rate Limit Only the Ingestion Endpoint

The external ingestion endpoint has its own ASP.NET Core rate limiting policy.

Reason: Collector abuse controls should not change MVC dashboard behavior or operator workflows.

The current partition key is only the transport `RemoteIpAddress`. It does not include the submitted API key and does not trust `X-Forwarded-For`.

Reason: unauthenticated callers can change invalid API-key values on every request, so using the header value would allow limiter bypass and unbounded partition growth. Reverse-proxy headers should only be trusted after explicit trusted proxy configuration.

## 011. Keep External Event Type Mapping as Future Work

External ingestion saves events as `SecurityEventType.ExternalEvent` and stores the source-specific type in `ExternalEventType`.

Reason: the first ingestion stage should preserve external context without changing the semantics of existing SIEM rules. `CR-001` can still match external critical events by source IP, while `BF-001` and `UE-001` remain tied to built-in ConShield event types until an explicit mapping layer is designed.

## 012. Run Container Image Scanning Outside the Web Process

`ConShield.ImageScanner` is a separate console project that starts Trivy locally and submits normalized scan summaries through the existing ingestion API.

Reason: starting local security tools from MVC requests would increase the web application's privilege and denial-of-service risk. A console scanner keeps process execution, timeouts, and registry credentials outside the Web/MVC boundary.

## 013. Store Only Normalized Image Scan Summaries

The scanner submits counts, image metadata, duration, and `reportSha256`; it does not submit the full Trivy report or full CVE list.

Reason: normalized summaries are enough for `IMG-001`, reduce data exposure, avoid large database records, and keep registry credential leakage risk lower.

## 014. Exclude SIEM-Generated Events from CR-001

`CR-001` analyzes only critical source events with a real `SourceIp`. It excludes SIEM-generated audit events such as `CorrelationAlert`, `IncidentCreated`, and `IncidentUpdated`.

Reason: correlation and incident audit events can themselves be critical. Treating them as inputs would create self-correlation loops and false `CR-001` alerts.

## 015. Keep Container Policy Evaluation Pure

`ConShield.ContainerPolicy` contains only policy models, validation, hashing, and deterministic evaluation. It has no ASP.NET, EF Core, PostgreSQL, Trivy, Docker, or HTTP dependencies.

Reason: policy behavior should be easy to test, safe to reuse, and independent from process execution or storage concerns.

## 016. Fail Closed for Container Policy Gate

Invalid policy files, invalid scan summaries, failed audit submission, Block decisions, and technical launch failures must not result in container launch. Block decisions have no CLI bypass.

Reason: the gate is a security control. Demonstration convenience must not weaken the policy decision.

## 017. Keep Docker Launch Local, Fixed, and Hardened

`ConShield.ImageScanner gate --execute` is the only component that may launch Docker. It uses a fixed `docker run` argument set and does not support arbitrary Docker flags, host volumes, host networking, privileged mode, or Docker socket mounts.

Reason: arbitrary runtime flags would turn the gate into an unsafe command launcher and undermine the portfolio security story.

## 018. Treat Policy Audit Creation as the Docker Launch Reservation

For `ConShield.ImageScanner gate --execute`, the scan, policy, and launch-result events share one `externalEventId` but use distinct reserved source systems: `conshield.image-scanner`, `conshield.container-guard`, and `conshield.container-runtime`.

Docker may run only when the policy event is created by the current command. If the policy event already exists, the operation is treated as already processed and Docker is not launched again.

Reason: ingestion idempotency is keyed by `sourceSystem + externalEventId`. Using the policy event as an at-most-once reservation preserves retry safety without changing the database uniqueness model or generating a second operation id.

## 019. Use PostgreSQL Transactional Outbox for Security Event Delivery

`ISecurityEventWriter` writes `SecurityEvents` and `SecurityEventOutbox` rows in one PostgreSQL transaction. The HTTP/MVC request path no longer appends JSONL directly.

Reason: a file sink failure must not roll back accepted security events, and a committed security event should not be left without a durable delivery message.

The initial sink is local JSONL with at-least-once delivery. RabbitMQ is implemented as another outbox transport without changing the writer contract.

## 020. Use RabbitMQ As A Selectable Outbox Transport

`SecurityEventOutbox:Transport` selects either `Jsonl` or `RabbitMq`. ConShield deliberately does not publish to both sinks in one attempt.

Reason: if JSONL succeeded and RabbitMQ failed, a retry would duplicate JSONL even though the outbox row was not delivered. One transport per attempt keeps delivery semantics understandable.

## 021. Use PostgreSQL Inbox Receipts For RabbitMQ Idempotency

`ConShield.EventConsumer` records one `SecurityEventInboxReceipts` row per RabbitMQ `MessageId` before acking the delivery.

Reason: RabbitMQ redelivers after consumer crashes. A unique `MessageId` gives replay-safe consumer side effects without claiming distributed exactly-once.

## 022. Project MongoDB Before PostgreSQL Inbox Completion

When MongoDB projection is enabled, the consumer writes or confirms the immutable Mongo document before inserting the PostgreSQL Inbox receipt.

Reason: if the Inbox receipt were committed first, a later Mongo failure could be hidden by redelivery duplicate detection and the Mongo document would never appear.
