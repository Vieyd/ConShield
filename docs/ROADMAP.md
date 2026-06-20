# Roadmap

## v0.1 Public Portfolio Baseline

- Clean public repository packaging.
- Keep local secrets and development settings out of Git.
- Add English and Russian README sections.
- Add security notes, architecture notes, license, and CI build.
- Keep the current Russian UI stable for continued development.

## v0.2 Security Foundation

- Add automated tests for SIEM correlation rules.
- Add authorization boundary tests for `AdminIB` and `Operator`.
- Document audit event taxonomy.
- Add password hashing or replace demo authentication with ASP.NET Core Identity.
- Add rate limiting for login attempts.

## v0.3 SIEM and Event Pipeline

- Extend the current Container Policy Gate into a richer policy engine with explicit Allow/Warn/Block rules and reviewable policy test fixtures.
- Add a demonstration policy gate flow that can explain why a container launch was blocked.
- Extend the PostgreSQL outbox with retention cleanup and operational DeadLetter handling.
- Harden RabbitMQ operations with DLQ review/replay procedures and production TLS guidance.
- Add projection backfill. Controlled DLQ review/replay for raw event pipelines is implemented; future work should add retention cleanup and richer operations.
- Convert correlation rules into independent rule classes.
- Add MITRE ATT&CK mapping for detection scenarios.
- Deploy a real Falco sensor on a dedicated Linux test host and feed JSON output into `ConShield.RuntimeCollector`.

## v0.4 Portfolio Release

- Add screenshots and a guided demo script.
- Provide a full Docker Compose setup for app and dependencies.
- Add dashboard visualizations for severity, timelines, and incident states.
- Add sample attack/detection scenarios.
- Add a guided container image scanning demo.
- Add a guided Container Policy Gate demo.
- Publish a tagged GitHub release.

## Backlog

- Export security events to JSON/CSV.
- Add incident comments and assignment.
- Add alert deduplication history.
- Add richer filtering and pagination.
- Add localization resources for UI text.
- Add deployment notes for a non-production demo environment.

## Completed Real Sensor Stage

- Real Falco 0.44.1 sensor validated on a single Fedora 44 VM.
- BTF `modern_ebpf`, protected JSONL, hardened non-root collector, and safe Podman demo implemented.
- End-to-end runtime detection verified through RTE-001 alert and incident creation.

## Recommended Next Stage

- Add multi-host sensor enrollment and source inventory.
- Issue per-source credentials and heartbeat events.
- Introduce mTLS-ready sensor identity and rotation workflows.
- Preserve Windows as the central workstation/server while expanding protected Linux nodes.
