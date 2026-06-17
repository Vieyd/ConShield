# Current State

ConShield is a lightweight SOC/SIEM-style ASP.NET Core MVC application for a cybersecurity portfolio. The current product scope is a local demo application with security event logging, user exception management, incident tracking, and rule-based SIEM alert correlation.

## Implemented Components

- MVC web interface in `ConShield.Web`.
- Cookie authentication with demo users from local development configuration.
- Role-based authorization for `AdminIB` and `Operator`.
- User exception CRUD flow with administrative write operations.
- Security event journal stored in PostgreSQL through Entity Framework Core and Npgsql.
- Local JSONL event log written by `SecurityEventWriter`.
- Incident registry with status changes.
- SIEM alert list, details page, rule catalog, correlation trigger, and demo scenario generation.
- PostgreSQL schema creation through EF Core migrations.
- Protected external security event ingestion endpoint with local API-key authentication.
- Request validation, endpoint-scoped request size limit, IP-partitioned rate limiting, and idempotency for external events.
- First `ConShield.Collector` console client for sending external events.
- `ConShield.ImageScanner` console client for local Trivy container image scans.
- `ConShield.ContainerPolicy` pure class library for local container policy evaluation.
- `ConShield.ImageScanner gate` command for scan, policy decision, audit, and optional hardened local Docker launch.
- Correlation rules:
  - `BF-001`: repeated login failures for one account.
  - `UE-001`: repeated user exception changes by one actor.
- `CR-001`: repeated critical source events from one real source IP. SIEM-generated audit events are not inputs for this rule.
- `IMG-001`: critical vulnerabilities in a container image scan summary.
- `POL-001`: blocked container image policy decisions.
- External ingested events are stored as `SecurityEventType.ExternalEvent`. `CR-001` can trigger for external critical events when the source-IP conditions match. `BF-001` and `UE-001` do not yet interpret arbitrary external event types.

## Not Implemented Yet

- RabbitMQ event transport.
- MongoDB event store.
- Background event consumer.
- ASP.NET Core Identity or production authentication.
- Long-term API key rotation.
- External event-type mapping to SIEM rules.
- Production machine identity, mTLS, and centralized secret management.
- Full policy engine language, waivers, policy signing, runtime monitoring, Falco, and Kubernetes integration.
- Full Dockerized application stack.
- MITRE ATT&CK mapping.
- UI screenshots and release assets.

## Constraints for Further Work

- Keep MVC behavior stable unless a task explicitly changes it.
- Keep controllers thin and move non-trivial business rules to `ConShield.Application`.
- Keep persistent entities in `ConShield.Data`.
- Store timestamps in UTC and convert for the UI at the presentation boundary.
- Treat demo authentication as a local development mechanism.
- Do not document RabbitMQ or MongoDB as active application components until they are wired into the runtime flow.
