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

## 006. Treat RabbitMQ and MongoDB as Planned Infrastructure

`infra/docker-compose.yml` currently describes future infrastructure. RabbitMQ and MongoDB are not part of the running application flow yet.

Reason: public documentation must not overstate implemented capabilities.

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
