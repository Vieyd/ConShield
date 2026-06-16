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

Entity Framework Core DbContext and persistent entities for user exceptions, security events, incidents, and SIEM alerts.

```text
src/ConShield.Contracts
```

Shared constants, enums, and DTO models used across the solution.

```text
src/ConShield.SecurityEvents
```

Audit event writer that stores security events in the database and appends runtime JSONL logs for local inspection.

## Current Flow

1. A user signs in with local demo credentials.
2. MVC actions enforce role-based access.
3. Important operations write security events through `ISecurityEventWriter`.
4. Security events are stored in SQL Server and appended to a local JSONL log.
5. The SIEM correlation service scans recent events and creates alerts.
6. Alerts can create linked incidents for investigation.

## Future Direction

The intended long-term direction is to split event collection from event analysis:

```text
Web app -> Security event writer -> Queue -> Worker -> Event store -> Correlation engine -> Alerts -> Incidents
```

The existing `infra/docker-compose.yml` already reserves RabbitMQ and MongoDB as possible infrastructure for this pipeline.
