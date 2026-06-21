# Development Guide

ConShield development rules:

- `ConShield.Web` contains only the MVC interface, API endpoints, controllers, view models, and configuration.
- `ConShield.ImageScanner` is the only current component that starts Trivy; Web/MVC must not start local scanner processes.
- `ConShield.RuntimeCollector` is the runtime-alert ingestion CLI; Web/MVC must not execute Falco or read runtime log files directly.
- `ConShield.SensorProvisioning` is a local operator-only database tool; it must not expose enrollment over HTTP or accept credentials through argv.
- `ConShield.ImageScanner gate` is the only current component that may start Docker, and only after policy evaluation.
- `ConShield.ContainerPolicy` must stay a pure class library: no ASP.NET, EF Core, PostgreSQL, Trivy, Docker, or HTTP dependencies.
- Business logic must live in `ConShield.Application`.
- Data access and persistent entities live in `ConShield.Data`.
- PostgreSQL is the current relational database for the prototype.
- Npgsql is the EF Core provider for PostgreSQL.
- All security events are created through `ISecurityEventWriter` or a documented application service that preserves the same audit boundary.
- `ISecurityEventWriter` must create `SecurityEvents` and `SecurityEventOutbox` rows atomically; do not write JSONL directly from HTTP/MVC requests.
- `ConShield.EventPipeline` owns outbox dispatch, retry, DeadLetter transitions, JSONL/RabbitMQ sink abstractions, topology declaration, and inbox processing.
- `ConShield.EventConsumer` is the standalone RabbitMQ consumer process and must remain independent from MVC/Razor.
- DLQ inspection/replay must keep MVC thin: controllers may create durable replay requests, but RabbitMQ replay publish must run in a background dispatcher or worker.
- DLQ capture must store only bounded allowlisted metadata and must not render raw payload in list UI.
- Controllers and API endpoints must stay thin.
- Time is stored in UTC, and the interface displays GMT+3.
- `Operator` has read-only access to critical functions.
- Do not use internal course/archive labels in the interface.
- MongoDB is implemented only as the optional raw-event projection after RabbitMQ consumer validation; PostgreSQL remains the system of record.
- RabbitMQ transport must use RabbitMQ.Client 7.x async APIs, publisher confirms, mandatory routing, quorum queues, and manual acknowledgements.
- Do not reintroduce SQL Server or LocalDB as working dependencies.
- Do not commit Trivy binaries, archives, vulnerability databases, full reports, scanner local config, registry credentials, or API keys.
- Do not add a CLI bypass for Container Policy `Block` decisions.
- Do not allow `gate --execute` to run Docker unless policy audit creation reserved the operation in the current command.
- Keep scan, policy, and launch result source systems reserved as `conshield.image-scanner`, `conshield.container-guard`, and `conshield.container-runtime`.
- Keep runtime ingestion source system reserved as `conshield.falco-runtime-collector`.
- Do not add arbitrary Docker arguments, host networking, host volumes, privileged mode, or Docker socket mounts to the gate command.
- After changes, run restore, build, and tests.
- Keep Windows as the primary development workstation and central ConShield server; Fedora is a protected sensor node.
- Keep real Falco deployment in `deploy/falco-linux`; Web must never start Falco or read its JSONL directly.
- Falco deployments must keep SELinux enforcing, prefer BTF `modern_ebpf`, and must not weaken Secure Boot.
- RuntimeCollector must run non-root and receive API keys only through a protected environment file.
- Do not commit sensor environment files, Falco JSONL, artifacts, host IDs, container IDs, or generated verification output.
- Safe Falco demonstrations must be container-scoped, non-privileged, deterministic, and bounded.
