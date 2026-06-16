# Current State

ConShield is a lightweight SOC/SIEM-style ASP.NET Core MVC application for a cybersecurity portfolio. The current product scope is a local demo application with security event logging, user exception management, incident tracking, and rule-based SIEM alert correlation.

## Implemented Components

- MVC web interface in `ConShield.Web`.
- Cookie authentication with demo users from local development configuration.
- Role-based authorization for `AdminIB` and `Operator`.
- User exception CRUD flow with administrative write operations.
- Security event journal stored in SQL Server through Entity Framework Core.
- Local JSONL event log written by `SecurityEventWriter`.
- Incident registry with status changes.
- SIEM alert list, details page, rule catalog, correlation trigger, and demo scenario generation.
- Correlation rules:
  - `BF-001`: repeated login failures for one account.
  - `UE-001`: repeated user exception changes by one actor.
  - `CR-001`: repeated critical events from one source IP.

## Not Implemented Yet

- RabbitMQ event transport.
- MongoDB event store.
- Background event consumer.
- ASP.NET Core Identity or production authentication.
- EF Core migrations.
- Full Dockerized application stack.
- MITRE ATT&CK mapping.
- UI screenshots and release assets.

## Constraints for Further Work

- Keep MVC behavior stable unless a task explicitly changes it.
- Keep controllers thin and move non-trivial business rules to `ConShield.Application`.
- Keep persistent entities in `ConShield.Data`.
- Store timestamps in UTC and convert for the UI at the presentation boundary.
- Treat demo authentication as a local development mechanism.
