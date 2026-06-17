# Development Guide

ConShield development rules:

- `ConShield.Web` contains only the MVC interface, API endpoints, controllers, view models, and configuration.
- `ConShield.ImageScanner` is the only current component that starts Trivy; Web/MVC must not start local scanner processes.
- Business logic must live in `ConShield.Application`.
- Data access and persistent entities live in `ConShield.Data`.
- PostgreSQL is the current relational database for the prototype.
- Npgsql is the EF Core provider for PostgreSQL.
- All security events are created through `ISecurityEventWriter` or a documented application service that preserves the same audit boundary.
- Controllers and API endpoints must stay thin.
- Time is stored in UTC, and the interface displays GMT+3.
- `Operator` has read-only access to critical functions.
- Do not use internal course/archive labels in the interface.
- Do not treat RabbitMQ and MongoDB as implemented components until they are actually connected.
- Do not reintroduce SQL Server or LocalDB as working dependencies.
- Do not commit Trivy binaries, archives, vulnerability databases, full reports, scanner local config, registry credentials, or API keys.
- After changes, run restore, build, and tests.
