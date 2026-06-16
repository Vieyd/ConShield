# Roadmap

## v0.1 Public Portfolio Baseline

- Clean public repository packaging.
- Keep local secrets and development settings out of Git.
- Add English and Russian README sections.
- Add security notes, architecture notes, license, and CI build.
- Keep the current Russian UI stable for continued development.

## v0.2 Security Foundation

- Replace `EnsureCreated` with Entity Framework migrations.
- Add automated tests for SIEM correlation rules.
- Add authorization boundary tests for `AdminIB` and `Operator`.
- Document audit event taxonomy.
- Add password hashing or replace demo authentication with ASP.NET Core Identity.
- Add rate limiting for login attempts.

## v0.3 SIEM and Event Pipeline

- Add a background event dispatcher.
- Use RabbitMQ for security event transport.
- Use MongoDB or another event store for raw events.
- Convert correlation rules into independent rule classes.
- Add MITRE ATT&CK mapping for detection scenarios.

## v0.4 Portfolio Release

- Add screenshots and a guided demo script.
- Provide a full Docker Compose setup for app and dependencies.
- Add dashboard visualizations for severity, timelines, and incident states.
- Add sample attack/detection scenarios.
- Publish a tagged GitHub release.

## Backlog

- Export security events to JSON/CSV.
- Add incident comments and assignment.
- Add alert deduplication history.
- Add richer filtering and pagination.
- Add localization resources for UI text.
- Add deployment notes for a non-production demo environment.
