# ConShield code map

## 1. Purpose

This map helps Codex and maintainers find the relevant part of the repository before doing broad inspection. It is a compact, human-maintained index, not a generated file inventory and not a substitute for reading the code that is actually being changed.

Future prompts should normally start with: read `docs/CONSHIELD_CODEMAP.md` and `docs/CODEX_WORKFLOWS.md`, then inspect only the relevant sections and files.

## 2. Solution/project overview

| Area | Purpose | Inspect first | Do not change casually | Related tests/docs |
| --- | --- | --- | --- | --- |
| `src/ConShield.Web` | MVC Web UI, auth, controllers, API endpoints, Razor views, local diagnostics, report export, operational pages. | `Controllers`, `Views`, `ViewModels`, `Infrastructure`, `Security`, `Options`, `Program.cs`, `wwwroot`. | Auth behavior, demo login config handling, ingestion endpoint checks, report secret-safety, UI routes used by demos. | UI tests, API tests, report tests, `docs/DEMO_EVIDENCE_PACK.md`, `docs/OPERATIONS_AND_SIEM_RUNBOOK.md`. |
| `src/ConShield.Data` | EF Core DbContext, entities, migrations, PostgreSQL schema. | `ApplicationDbContext`, `Entities`, `Migrations`, seeding code. | Schema shape or migrations unless the task explicitly asks for data changes. | `PostgreSqlIntegrationTests`, EF pending model check, architecture docs. |
| `src/ConShield.EventConsumer` | RabbitMQ consumer host, inbox checkpointing, Mongo projection integration. | `Program.cs`, `RabbitMqSecurityEventConsumerService.cs`, `appsettings.json`. | Delivery semantics, ack/nack behavior, inbox idempotency, projection identity. | `RabbitMqEventPipelineTests`, `MongoProjectionTests`, `docs/RABBITMQ_SECURITY_EVENT_PIPELINE.md`. |
| `src/ConShield.ImageScanner` | Trivy wrapper and image scan event generation. | Scanner app, parser, event builders, redaction helpers. | Exit codes, redaction behavior, event identity, scanner command semantics. | Image scanner tests, `docs/CONTAINER_IMAGE_SCANNING.md`. |
| `src/ConShield.ContainerPolicy` | Pure policy gate evaluation library. | Policy models and evaluator. | Policy decision semantics unless requested. | `PolicyGateTests`, `ContainerPolicyTests`, `docs/CONTAINER_POLICY_GATE.md`. |
| `scripts` | Local diagnostics and demo validation PowerShell scripts. | `Test-LocalDemoLogin.ps1`, `Test-LocalDemoUserPassword.ps1`, `Validate-DemoScenario.ps1`. | Password output, local env handling, generated logs. | Local demo login tests, demo scenario validation tests. |
| `deploy/falco-linux` | Fedora/Falco runtime sensor deployment, verification, demo, systemd, logrotate. | `install-fedora.sh`, `verify-host.sh`, `verify-pipeline.sh`, `demo-safe.sh`, service/env examples. | Real credentials, SELinux disabling, enrolled sensor rotation/revocation, systemd permissions. | Runtime collector tests, Falco runtime tests, `docs/REAL_FALCO_FEDORA_DEPLOYMENT.md`, `docs/FALCO_RUNTIME_EVENT_INGESTION.md`. |
| `tests/ConShield.Tests` | Unit, integration, script, docs, UI regression, and security-safety tests. | Test file matching the touched area. | Test skips/fixtures that encode external-service assumptions. | This project is the main regression suite. |
| `docs` | Architecture, operations, demo evidence, roadmap, deployment, SIEM/runbook documentation. | Existing doc nearest the feature before adding a new one. | Generated reports, screenshots, local logs, secrets. | Documentation tests and gitleaks. |
| `infra` | Local Docker Compose infrastructure and Mongo init. | `docker-compose.yml`, `mongo-init`. | Ports, credentials, volume semantics unless local infra task asks for it. | Startup scripts and integration tests. |

## 3. Web UI map

The Web UI lives mostly in `src/ConShield.Web`:

- Razor views: `Views/<Area>/*.cshtml` for dashboard, security events, sensors, incidents, SIEM, outbox, DLQ, operations health, reports, and account login.
- Layout and shared imports: `Views/Shared/_Layout.cshtml`, `Views/_ViewImports.cshtml`, `Views/_ViewStart.cshtml`.
- Styling and client assets: `wwwroot/css/site.css` and `wwwroot/js/site.js` when present.
- Display/localization helpers: `Infrastructure/DisplayText.cs` and time/display helpers under `Infrastructure`.
- Controllers and view models: `Controllers/*Controller.cs`, `ViewModels/*`.
- Login diagnostics surfaces: account controller diagnostics views plus local scripts in `scripts`.
- UI tests: `WebUiLocalizationPolishTests`, `SecurityEventsUiTests`, `SensorFleetUiTests`, `OperationsHealthTests`, `SecuritySummaryReportTests`, and similar view/report tests.
- `docs/UI_DESIGN_SYSTEM.md`: read it first if it exists in a future revision.

UI tasks should normally touch only Web views, Web infrastructure display helpers, CSS/JS, UI tests, and user-facing docs. They should not touch EF, RabbitMQ, Mongo, SIEM correlation logic, Fedora deployment, or credentials unless the prompt explicitly says so.

## 4. Authentication/demo login map

Authentication and demo login are config-driven:

- `Controllers/AccountController.cs` handles login/logout/access denied and diagnostics.
- `ViewModels/LoginViewModel.cs` defines login form shape.
- `Options/DemoUserOptions.cs`, `Program.cs`, and local environment/config provide demo users.
- DemoUsers are not DB-backed users.
- Local diagnostics scripts live in `scripts/Test-LocalDemoLogin.ps1` and `scripts/Test-LocalDemoUserPassword.ps1`.

Secret-safety rules:

- Do not print passwords, API keys, connection strings, tokens, verifier values, or sensor secrets.
- Do not commit `appsettings.Development.json` or local `.env` files.
- Prefer redacted diagnostics and tests that prove secrets are absent from output.

## 5. Data/PostgreSQL/EF map

Data lives in `src/ConShield.Data`:

- DbContext and entity configuration define the PostgreSQL model.
- Migrations live under the EF migrations folder in the data project.
- Seed data is initialized through Web startup in development and dedicated seeding helpers.

Use this check whenever schema risk exists:

```powershell
dotnet ef migrations has-pending-model-changes `
  --project ./src/ConShield.Data `
  --startup-project ./src/ConShield.Web
```

Only add migrations when the task explicitly asks for a schema change. UI/docs/SIEM-display changes should normally have no pending model changes.

## 6. SIEM/correlation map

SIEM logic is split between correlation behavior and display:

- Rule definitions/display text: `src/ConShield.Application/SiemRuleCatalog.cs` and Web display helpers.
- Correlation logic: `src/ConShield.Application/SiemCorrelationService.cs`.
- Alerts/incidents UI: `src/ConShield.Web/Controllers/SiemController.cs`, `IncidentsController.cs`, and corresponding views/view models.
- Tests: `SiemCorrelationServiceTests`, incident/UI display tests, and report tests.

Rule codes such as `BF-001`, `UE-001`, `CR-001`, `IMG-001`, `POL-001`, `RTE-001`, `LIFE-001`, and `LIFE-002` are stable identifiers. Do not rename or repurpose them unless that is the explicit goal.

## 7. RabbitMQ/outbox/inbox map

Durable event delivery is centered in `src/ConShield.EventPipeline` and `src/ConShield.EventConsumer`:

- Outbox writer and dispatch path: `ConShield.SecurityEvents`, `SecurityEventOutboxDispatcher`, JSONL/RabbitMQ sinks.
- RabbitMQ publishing: `RabbitMqSecurityEventOutboxSink`, topology/options/status services.
- Consumer and inbox receipts: `ConShield.EventConsumer` and `SecurityEventInboxProcessor`.
- Dead-letter/replay: `DeadLetter*` services, `DeadLettersController`, `Views/DeadLetters`, and `/Outbox`.
- Docs: `docs/SECURITY_EVENT_OUTBOX.md`, `docs/RABBITMQ_SECURITY_EVENT_PIPELINE.md`, `docs/DLQ_INSPECTION_AND_REPLAY.md`.
- Tests: `SecurityEventOutboxTests`, `RabbitMqEventPipelineTests`, `DeadLetterReplayTests`.

Do not alter idempotency, retry, ack/nack, mandatory return, or DLQ semantics as part of unrelated UI/docs tasks.

## 8. Mongo projection map

MongoDB projection is a read model, not the PostgreSQL source of truth:

- Projection library: `src/ConShield.MongoProjection`.
- Integration path: RabbitMQ consumer invokes projection services after inbox processing.
- UI/docs surfaces: Operations health, outbox/projection status, `docs/MONGODB_RAW_EVENT_PROJECTION.md`.
- Tests: `MongoProjectionTests` and RabbitMQ/Mongo integration tests.

Do not change ingestion identity or source-of-truth semantics unless the prompt explicitly asks for projection behavior changes.

## 9. Runtime/Fedora/Falco map

Runtime sensor work spans local .NET collectors and Fedora deployment scripts:

- Deployment scripts and systemd assets: `deploy/falco-linux`.
- Runtime collector: `src/ConShield.RuntimeCollector`.
- Runtime detection mapping: `src/ConShield.RuntimeDetection`.
- Sensor enrollment/heartbeat/credential lifecycle: Web API controllers, application sensor services, sensor provisioning CLI.
- Docs: `docs/FALCO_RUNTIME_EVENT_INGESTION.md`, `docs/REAL_FALCO_FEDORA_DEPLOYMENT.md`, `docs/SENSOR_PROVISIONING_AND_FEDORA_ROLLOUT.md`, `docs/SENSOR_CREDENTIAL_LIFECYCLE.md`.

No-go: do not rotate, revoke, print, or replace real Fedora sensor credentials unless explicitly requested. Do not disable SELinux as a workaround.

## 10. Demo/local scripts map

Local workflow starts with:

- `Start-ConShield.ps1` for local infrastructure, app startup, tests, status, and shutdown.
- `tools/ConShield.DemoScenario` for synthetic demo data.
- `scripts/Validate-DemoScenario.ps1` for demo validation.
- `scripts/Test-LocalDemoLogin.ps1` and `scripts/Test-LocalDemoUserPassword.ps1` for local login diagnostics.

Safe startup usually begins with `pwsh -NoProfile -ExecutionPolicy Bypass -File ./Start-ConShield.ps1 -StartApps`, after local secrets are configured. Do not paste secrets into chat or docs.

Common Windows issue: stale `dotnet.exe`, `ConShield.Web.exe`, or `ConShield.EventConsumer` processes can lock `bin/Debug` or `bin/Release` DLLs. Identify the exact PID and ask for an elevated `taskkill /PID <pid> /F /T` only when necessary.

## 11. Tests map

`tests/ConShield.Tests` is organized by feature area:

- UI regression tests: Web localization/polish, security events UI, sensor fleet UI, operations health, report rendering/export.
- SIEM tests: correlation service, lifecycle rules, alert/incident behavior.
- Outbox/RabbitMQ tests: outbox writer/dispatcher, RabbitMQ delivery, inbox idempotency, DLQ replay.
- Mongo tests: projection insertion, duplicate handling, index behavior.
- Runtime/Falco tests: collector, sensor-bound collector, runtime detection mapping.
- Script/docs tests: local demo login, demo scenario validation, evidence docs, context-map docs.

Prefer the narrowest relevant tests first, then run the full suite before PR.

## 12. High-risk files/areas

Use extra care around:

- Auth/login: `AccountController`, `LoginViewModel`, cookie auth setup, demo-user config.
- Demo-user config and local env parsing.
- EF migrations and DbContext/entity changes.
- RabbitMQ/outbox/inbox delivery, retry, and DLQ semantics.
- Sensor credentials, credential verifier values, rotation/revocation flows.
- Fedora deploy scripts and systemd units.
- Security event ingestion API and request validation.
- Secret handling, redaction, logs, screenshots, generated reports, and local artifacts.
