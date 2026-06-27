# ConShield

ConShield is a student cybersecurity portfolio project: a lightweight SOC/SIEM training web application for security event monitoring, user exception governance, incident tracking, and rule-based alert correlation.

The project is intentionally practical. It demonstrates how a security team can collect audit events, review suspicious activity, manage exceptions, and turn correlated signals into incidents.

For the product-level architecture, scalability model, and implementation roadmap, see [docs/CONSHIELD_ARCHITECTURE_AND_ROADMAP.md](docs/CONSHIELD_ARCHITECTURE_AND_ROADMAP.md). For a safe presentation package, see [docs/DEMO_EVIDENCE_PACK.md](docs/DEMO_EVIDENCE_PACK.md), [docs/DIPLOMA_FEATURE_MAP.md](docs/DIPLOMA_FEATURE_MAP.md), [docs/CONSHIELD_FINAL_HANDOFF_SNAPSHOT.md](docs/CONSHIELD_FINAL_HANDOFF_SNAPSHOT.md), and [docs/DIPLOMA_TEXT_SECTIONS_DRAFT_RU.md](docs/DIPLOMA_TEXT_SECTIONS_DRAFT_RU.md).

## Codex context maps

Future Codex prompts should read [docs/CONSHIELD_CODEMAP.md](docs/CONSHIELD_CODEMAP.md) and [docs/CODEX_WORKFLOWS.md](docs/CODEX_WORKFLOWS.md) before broad repository inspection. These files are compact human-maintained indexes and workflows, not generated inventories of every file.

## Features

- Role-based access for `AdminIB` and `Operator`.
- Security event journal with filtering and a JSON endpoint for recent events.
- User exception management with audit events for create, update, and delete operations.
- Incident registry with severity, status, source event links, and lifecycle actions.
- SIEM-style correlation rules for repeated login failures, suspicious exception changes, and repeated critical events from one source.
- PostgreSQL transactional outbox for durable security event delivery to JSONL or RabbitMQ.
- `ConShield.EventConsumer`, an idempotent RabbitMQ consumer with PostgreSQL inbox receipts and optional MongoDB raw-event projection.
- AdminIB-only operational health dashboard with read-only aggregate counts for sensor heartbeat freshness, security event freshness, lifecycle audit activity, outbox backlog, and inbox/projection receipts.
- AdminIB-only security summary report with safe aggregate Markdown export for daily review handoff.
- Controlled AdminIB DLQ inspection and replay through PostgreSQL quarantine records and a background RabbitMQ replay dispatcher.
- Protected external security event ingestion endpoint: `POST /api/v1/security-events`.
- API-key authentication, request validation, request size limit, rate limiting, and idempotency for external events.
- `ConShield.Collector`, a small console client for sending generated or JSON-file security events.
- `ConShield.ImageScanner`, a Trivy-based console scanner for container image vulnerability summaries.
- `ConShield.RuntimeCollector`, a Falco-compatible JSON alert collector for safe runtime-event ingestion from stdin or JSONL fixtures.
- `IMG-001` SIEM correlation for critical vulnerabilities in container images.
- `ConShield.ContainerPolicy`, a pure local evaluator for container policy decisions.
- `POL-001` SIEM correlation for Block decisions from Container Policy Gate.
- `RTE-001` SIEM correlation for mapped high-risk Falco-compatible runtime container events.
- Local-only demo scenario runner for portfolio walkthroughs with marked resettable synthetic data.
- UTC storage with GMT+3 display for the current Russian-language UI.

## Tech Stack

- .NET 8
- ASP.NET Core MVC and Razor Views
- Entity Framework Core
- PostgreSQL 16 for the current relational database
- Npgsql Entity Framework Core provider
- Cookie authentication with role-based authorization
- Docker Compose for PostgreSQL, RabbitMQ, and optional MongoDB raw-event projection

## Architecture

```text
ConShield.Web              MVC UI, controllers, authentication, view models
ConShield.Application      Use cases, SIEM correlation, application services
ConShield.Data             EF Core DbContext and domain entities
ConShield.Contracts        Shared constants, enums, DTO models
ConShield.SecurityEvents   Security event writer and outbox message creation
ConShield.EventPipeline    Outbox dispatcher, JSONL/RabbitMQ sinks, retry and DeadLetter handling
ConShield.EventConsumer    RabbitMQ consumer, MongoDB projection, and PostgreSQL inbox checkpoint
ConShield.MongoProjection  Immutable MongoDB raw-event projection and TTL indexes
ConShield.ImageScanner     Trivy-based container image scanner CLI
ConShield.ContainerPolicy  Pure policy validation and evaluation library
ConShield.RuntimeDetection Falco-compatible parser, mapping, normalization, and deterministic identity
ConShield.RuntimeCollector CLI for stdin/file/follow runtime alert ingestion
ConShield.SensorProvisioning Local operator-only enrolled sensor credential provisioning
tools/ConShield.DemoScenario Local-only synthetic demo scenario runner
scripts/Run-ConShieldDefenseScenario.ps1 Safe local end-to-end defense scenario evidence runner
infra/                     Future infrastructure for message/event pipeline
docs/                      Architecture, roadmap, security notes
```

## Security Model

ConShield currently uses demo authentication from local configuration. This is enough for a portfolio demo and local development, but it is not a production identity system.

Current security controls:

- Authentication cookie for signed-in users.
- Role checks on administrative operations.
- Anti-forgery tokens on mutating MVC actions.
- Audit events for login attempts and key business operations.
- Durable security event outbox with background JSONL delivery under `src/ConShield.Web/logs/`.

Known limitations are tracked in [SECURITY.md](SECURITY.md).

## Local Setup

Requirements:

- .NET 8 SDK
- Visual Studio 2022 or another .NET-capable IDE
- Docker Desktop or another local PostgreSQL 16 instance

Steps:

1. Set a local PostgreSQL password in your shell. Do not commit it.

```powershell
$env:CONSHIELD_POSTGRES_PASSWORD = "your-local-password"
```

2. Start PostgreSQL:

```powershell
docker compose -f infra/docker-compose.yml up -d postgres
```

3. Copy `src/ConShield.Web/appsettings.Development.example.json` to `src/ConShield.Web/appsettings.Development.json`.
4. Replace `CHANGE_ME` in the local development file with the same local password.
5. Open `ConShield.sln`.
6. Set `ConShield.Web` as the startup project.
7. Set a local ingestion API key in `src/ConShield.Web/appsettings.Development.json` under `ExternalEventIngestion:ApiKey`.
8. Keep `ExternalEventIngestion:AllowLegacyRuntimeCollectorCredential` set to `false` for enrolled-sensor-only runtime operation. The legacy `RuntimeCollectorApiKey` is not required after sensor enrollment.
9. Run the application from Visual Studio or with:

```powershell
dotnet run --project src/ConShield.Web/ConShield.Web.csproj
```

In `Development`, pending EF Core migrations are applied at startup and `DbSeeder` creates reproducible demo data on a clean PostgreSQL database.

The development configuration is intentionally ignored by Git. Keep real local connection strings only in `appsettings.Development.json` or environment variables.

## External Event Ingestion

The current prototype includes a protected HTTP ingestion endpoint. General collectors use `ExternalEventIngestion:ApiKey`. The reserved `conshield.falco-runtime-collector` source is intended to use enrolled sensor identity headers; legacy runtime collector fallback remains disabled in the enrolled-sensor-only operating mode.

```http
POST /api/v1/security-events
X-ConShield-Api-Key: <local-api-key>
```

Minimal request shape:

```json
{
  "externalEventId": "11111111-1111-1111-1111-111111111111",
  "occurredAtUtc": "2026-06-16T10:00:00Z",
  "sourceSystem": "ConShield.Collector",
  "eventType": "CollectorTestEvent",
  "severity": "Info",
  "userName": "collector",
  "sourceHost": "dev-host",
  "description": "Test event from Collector.",
  "additionalData": {
    "demo": true
  }
}
```

Run the Collector with environment variables:

```powershell
$env:CONSHIELD_BASE_URL = "http://127.0.0.1:56895"
$env:CONSHIELD_API_KEY = "your-local-api-key"
dotnet run --project src/ConShield.Collector -- --generate --external-event-id "11111111-1111-1111-1111-111111111111"
dotnet run --project src/ConShield.Collector -- --generate --external-event-id "11111111-1111-1111-1111-111111111111"
```

The second command returns the same saved security event id and does not create a duplicate. Use `--file path-to-event.json` to send an event from a JSON file.

Prefer `CONSHIELD_API_KEY` over `--api-key` so the key is not left in shell history or process listings. The Collector accepts only `http` and `https` base URLs.

Ingested external events are saved as `SecurityEventType.ExternalEvent`. The current Правила SIEM do not interpret arbitrary `externalEventType` values: `BF-001` and `UE-001` are still based on built-in ConShield event types. `CR-001` can match an external critical event when the normal source-IP conditions are met. Full mapping from external event types to Правила SIEM is planned as a separate future stage.

Implemented now:

- protected HTTP ingestion endpoint;
- local prototype API-key authentication;
- schema validation;
- request size limit;
- rate limiting for this endpoint only;
- idempotency by `sourceSystem + externalEventId`;
- first `ConShield.Collector`.

Not implemented yet:

- projection backfill;
- automatic DLQ replay;
- distributed exactly-once delivery;
- multi-destination fanout;
- automatic DLQ replay;
- automatic outbox retention cleanup;
- long-term key rotation;
- production machine identity;
- mTLS;
- centralized secret manager;
- full policy language;
- policy signing;
- waivers/exceptions;
- remote policy distribution;
- runtime monitoring;
- Falco;
- Kubernetes integration.

## Container Image Scanning

ConShield includes a first working container image scanning vertical based on Trivy:

```text
Trivy -> ConShield.ImageScanner -> ingestion API -> PostgreSQL -> IMG-001 -> alert and incident
```

Run without submitting:

```powershell
dotnet run --project src/ConShield.ImageScanner -- scan --image alpine:3.20 --no-submit
```

Run and submit:

```powershell
$env:CONSHIELD_BASE_URL = "http://127.0.0.1:56895"
$env:CONSHIELD_API_KEY = "your-local-api-key"
$env:CONSHIELD_TRIVY_PATH = "C:\Tools\trivy\trivy.exe"
dotnet run --project src/ConShield.ImageScanner -- scan --image alpine:3.20
```

See [docs/CONTAINER_IMAGE_SCANNING.md](docs/CONTAINER_IMAGE_SCANNING.md).

## Container Policy Gate

ConShield includes a local policy gate on top of Trivy scan summaries:

```text
Trivy -> ConShield.ImageScanner gate -> ConShield.ContainerPolicy -> ingestion API -> PostgreSQL -> optional Docker launch -> launch result audit
```

Dry run without submitting:

```powershell
dotnet run --project src/ConShield.ImageScanner -- gate --image alpine:3.20 --policy config/policies/container-baseline-v1.json --no-submit
```

Submit scan and policy audit events:

```powershell
$env:CONSHIELD_BASE_URL = "http://127.0.0.1:56895"
$env:CONSHIELD_API_KEY = "your-local-api-key"
dotnet run --project src/ConShield.ImageScanner -- gate --image alpine:3.20 --policy config/policies/container-baseline-v1.json
```

`Block` decisions cannot be bypassed by CLI flag. `Warn` decisions launch only with `--execute --accept-warning`. See [docs/CONTAINER_POLICY_GATE.md](docs/CONTAINER_POLICY_GATE.md).

The gate reserves three source systems for one operation: `conshield.image-scanner` for the scan event, `conshield.container-guard` for the policy event, and `conshield.container-runtime` for the launch result event. Records share one `externalEventId`; ingestion idempotency stays safe because `sourceSystem` values differ. For `--execute`, the policy event is the at-most-once launch reservation: a retry that finds an existing policy event does not run Docker again. `--source-system` remains supported only by the `scan` command.

## Очередь отправки событий

Security events are written atomically with a PostgreSQL outbox message. A background dispatcher delivers those messages to the local JSONL sink with at-least-once semantics:

```text
SecurityEventWriter -> SecurityEvents + SecurityEventOutbox -> dispatcher -> JSONL
```

The JSONL line contains a stable `messageId`; duplicate lines are possible after a crash between append and `Delivered`, so downstream consumers must deduplicate by `messageId`.

RabbitMQ mode publishes persistent messages with publisher confirms, mandatory routing, a durable quorum queue, DLQ, and an idempotent PostgreSQL inbox consumer. See [docs/SECURITY_EVENT_OUTBOX.md](docs/SECURITY_EVENT_OUTBOX.md) and [docs/RABBITMQ_SECURITY_EVENT_PIPELINE.md](docs/RABBITMQ_SECURITY_EVENT_PIPELINE.md).

MongoDB raw-event projection can be enabled for RabbitMQ consumers:

```text
RabbitMQ -> MongoDB raw-event projection -> PostgreSQL Inbox checkpoint -> ACK
```

It stores normalized envelopes immutably with `_id = MessageId`, TTL retention, and duplicate payload mismatch protection. See [docs/MONGODB_RAW_EVENT_PROJECTION.md](docs/MONGODB_RAW_EVENT_PROJECTION.md).

RabbitMQ DLQ messages can be captured into immutable PostgreSQL quarantine rows, inspected by `AdminIB`, and replayed only through a bounded background dispatcher. MVC requests never publish RabbitMQ messages directly, raw payload is not shown in the list UI, and replay preserves the original `MessageId` for Inbox/Mongo deduplication. See [docs/DLQ_INSPECTION_AND_REPLAY.md](docs/DLQ_INSPECTION_AND_REPLAY.md).

Falco-compatible runtime JSON alerts can be normalized by `ConShield.RuntimeCollector` and submitted to the existing external ingestion API. The local replay path uses safe fixtures and does not install or require Fedora, Falco, Falco Operator, or Kubernetes components. See [docs/FALCO_RUNTIME_EVENT_INGESTION.md](docs/FALCO_RUNTIME_EVENT_INGESTION.md) and [docs/FALCO_RUNTIME_SENSOR.md](docs/FALCO_RUNTIME_SENSOR.md).

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 -NoSubmit
```

## Demo Accounts

Local demo accounts are configured in `src/ConShield.Web/appsettings.Development.json`.

For a new machine, copy `src/ConShield.Web/appsettings.Development.example.json` to `src/ConShield.Web/appsettings.Development.json` and set local demo usernames and passwords there. The development file is ignored by Git and must not be committed.

### Local Login Troubleshooting

ConShield Web login uses `DemoUsers` from configuration; `adminib` and `operator` are configuration users, not database users. If login fails after changing local passwords, restart the Web process so it reloads `appsettings.Development.json` or inherited environment variables.

Save `appsettings.Development.json` as UTF-8 when Cyrillic display names are used. Environment variables may override file values; if a browser JSON viewer shows mojibake for display names after setting values from PowerShell, prefer the UTF-8 local JSON file and restart Web.

In `Development`, open the secret-free diagnostics endpoint:

```text
http://127.0.0.1:5080/Account/DemoUserDiagnostics
```

It shows the environment, configured demo-user count, user names, display names, roles, and `HasPassword`; it never returns passwords, password length, hashes, cookies, tokens, API keys, or connection strings.

To test the real login form without printing the password:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-LocalDemoUserPassword.ps1 -UserName adminib
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-LocalDemoLogin.ps1 -UserName adminib
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-LocalDemoLogin.ps1 -UserName adminib -BaseUrl http://127.0.0.1:5080
```

The password verification script (`scripts/Test-LocalDemoUserPassword.ps1`) posts to `/Account/DemoUserDiagnostics/VerifyPassword` in `Development` only and prints `password_match=True/False` without returning the password, password length, hashes, cookies, tokens, API keys, or connection strings. The login script reads the diagnostics endpoint first, optionally verifies the entered password, submits the real login form with an antiforgery token, and then probes `/Operations/Health` with the same session. It tolerates missing redirect headers and still relies on the authenticated health probe.

Troubleshooting matrix:

- Diagnostics shows `adminib` + `HasPassword=True`, `password_match=False`: the running Web process has a different configured password than the one entered.
- `password_match=True`, `login_result=failed`: the password is correct, but login form/session flow needs investigation.
- `password_match=True`, `login_result=success`, browser still fails: clear cookies or use incognito.
- Diagnostics endpoint unavailable: Web is not running in `Development`, or the wrong URL/port is used.

For stable local demo credentials, store User-level environment variables with the helper script. It prompts for passwords securely, writes only Windows User/current-process environment variables, and prints only variable names plus password-present booleans:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Set-LocalDemoUsers.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StopApps
pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-LocalDemoUserPassword.ps1 -UserName adminib
```

`Start-ConShield.ps1` launches Web with explicit Development environment, URL, database connection string, and any configured `DemoUsers__*` overrides. If it prints different `Web launcher PID` and `Web port owner PID` values, the port owner is the process actually serving `http://127.0.0.1:5080`; this can be normal when `dotnet run` starts a child process. Use `-StopApps` after changing environment variables so stale Web/EventConsumer processes cannot keep old config.

Temporary shell-only configuration can be set with placeholders like this:

```powershell
$env:DemoUsers__0__UserName = "adminib"
$env:DemoUsers__0__Password = "CHANGE_ME"
$env:DemoUsers__0__DisplayName = "Администратор ИБ"
$env:DemoUsers__0__Role = "AdminIB"
```

After changing `DemoUsers`, restart Web. Environment variables may override `appsettings.Development.json`. If the diagnostics endpoint and scripts succeed but browser login still fails, use an incognito window or clear ConShield cookies. Do not paste passwords into chat, screenshots, logs, GitHub, or committed local config.

## Demo Flow

1. Sign in as `adminib`.
2. Review dashboard metrics.
3. Open security events and confirm login audit entries.
4. Create or edit a user exception.
5. Generate a SIEM demo scenario with the local demo runner.
6. Run correlation and inspect created alerts.
7. Open the related incident and change its status.
8. Sign in as `operator` and verify read-only access boundaries.

### Demo Scenario Runner

`tools/ConShield.DemoScenario` seeds clearly marked synthetic data for local walkthroughs only. It never reads Fedora sensor env files, never prints connection strings, and requires an explicit local development connection string for writes:

```powershell
$env:CONSHIELD_DEMO_CONNECTION_STRING = "Host=127.0.0.1;Port=5432;Database=conshield;Username=conshield;Password=<local-dev-password>"
dotnet run --project tools/ConShield.DemoScenario -- --scenario healthy --dry-run
dotnet run --project tools/ConShield.DemoScenario -- --scenario full-demo --yes
```

Supported scenarios are `healthy`, `defense-demo`, `full-demo`, `lifecycle-alerts`, `runtime-incident`, and `outbox-backlog`. The `defense-demo` scenario demonstrates `IMG-001`, `POL-001`, `RTE-001`, `LIFE-001`, and `LIFE-002` without real Fedora sensor operations; the runtime scenario uses synthetic Falco-compatible data only.

Reset only marked demo records:

```powershell
dotnet run --project tools/ConShield.DemoScenario -- --reset-demo-data --dry-run
dotnet run --project tools/ConShield.DemoScenario -- --reset-demo-data --yes
```

### Demo Scenario Validation

`scripts/Validate-DemoScenario.ps1` is a safe local wrapper around the demo runner. It defaults to dry-run mode, can optionally check unauthenticated Web route behavior, and requires explicit `-Apply` before any demo data write.

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Validate-DemoScenario.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Validate-DemoScenario.ps1 -Scenario full-demo -DryRun -SkipWebChecks
```

To seed local demo data, set `CONSHIELD_DEMO_CONNECTION_STRING` in your shell without printing its value and then opt in explicitly:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Validate-DemoScenario.ps1 -Scenario full-demo -Apply
```

To preview and remove only marked synthetic demo data:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Validate-DemoScenario.ps1 -ResetDemoData -DryRun
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Validate-DemoScenario.ps1 -ResetDemoData -Apply -Yes
```

Do not run `-Apply` against a production database. After seeding, inspect `/Operations/Health`, `/SecurityEvents`, `/Sensors`, `/Reports/SecuritySummary`, `/Siem`, and `/Incidents`.

### Local Defense Scenario Runner

`scripts/Run-ConShieldDefenseScenario.ps1` is the one-command local defense walkthrough for demo/protection review. It checks the repo, Web routes, PostgreSQL availability, RabbitMQ/EventConsumer/Mongo projection signals where available, then uses marked synthetic demo data to demonstrate image scan (`IMG-001`), policy gate (`POL-001`), runtime (`RTE-001`), lifecycle (`LIFE-001`/`LIFE-002`), SIEM correlation, alerts/incidents, outbox/inbox evidence, and the Security Summary report. The default scenario does not require a real Fedora VM and does not rotate or revoke a real sensor.

Prepare local demo users and start apps first:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Set-LocalDemoUsers.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Run-ConShieldDefenseScenario.ps1
```

Optional safe Markdown evidence can be written outside committed files:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Run-ConShieldDefenseScenario.ps1 -OutputMarkdownPath .\artifacts\local\defense-scenario.md
```

Result meanings: `PASS` means all required demo evidence was demonstrated, `WARN` means the core scenario ran but an optional local service was unavailable or degraded, and `FAIL` means the scenario could not prove required evidence. The runner prints only counts, rule codes, statuses, timestamps, and UI routes; it intentionally excludes secrets, raw event JSON, `AdditionalDataJson`, connection strings, API keys, tokens, cookies, credentials, and verifier values. Do not commit generated evidence, logs, screenshots, `.env` files, or `appsettings.Development.json`.

For a defense-ready evidence pack that combines health, scenario summary, SIEM alerts, incidents, security events, outbox/inbox summary, and demo checklists, export to an ignored local artifact path:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Export-ConShieldDefenseEvidence.ps1 -RunScenario -OutputMarkdownPath .\artifacts\local\defense-evidence.md
```

The evidence exporter writes only safe aggregate and metadata fields, including a Runtime Sensor Evidence section when Falco-compatible runtime events are present. It excludes sensitive local configuration, raw event bodies, local logs, and generated reports from source control; keep the generated Markdown under `artifacts/local/` or another ignored path.

Runtime Sensor Health is available at `/RuntimeSensors`. It derives source health from existing security events, `RTE-001` alerts, and incidents, showing SourceSystem, last seen time, event count, latest event metadata, related alert/incident counts, and `Active` / `Stale` / `NoData` status. Local validation can use `Replay-ConShieldFalcoRuntimeEvent.ps1`; real Fedora/Falco is optional for this check.

Operator workflow demo:

1. Run local apps.
2. Run the defense scenario.
3. Open Security Summary.
4. Open a SIEM alert.
5. Acknowledge/review the alert.
6. Open the linked incident.
7. Move the incident to In Progress.
8. Open the linked source Security Event.
9. Close the incident with a non-empty conclusion.
10. Export defense evidence and confirm the Operator Workflow section.

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Run-ConShieldDefenseScenario.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Export-ConShieldDefenseEvidence.ps1 -OutputMarkdownPath .\artifacts\local\defense-evidence.md
```

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) and the product-level [architecture and roadmap](docs/CONSHIELD_ARCHITECTURE_AND_ROADMAP.md).

## GitHub Topics

`dotnet`, `aspnet-core`, `mvc`, `entity-framework-core`, `cybersecurity`, `information-security`, `siem`, `soc`, `incident-response`, `security-monitoring`, `audit-log`, `rbac`, `docker`, `rabbitmq`, `mongodb`, `portfolio-project`

## Русская версия

ConShield — студенческий portfolio-проект по информационной безопасности: легкое SOC/SIEM-like веб-приложение для мониторинга событий безопасности, управления пользовательскими исключениями, ведения инцидентов и корреляции оповещений по правилам.

Проект показывает практический сценарий работы ИБ-команды: сбор audit events, анализ подозрительной активности, управление исключениями и превращение связанных событий в инциденты.

### Возможности

- Ролевой доступ для `AdminIB` и `Operator`.
- Журнал событий безопасности с фильтрами и JSON endpoint.
- Управление пользовательскими исключениями с аудитом операций.
- Реестр инцидентов со статусами, критичностью и связью с исходным событием.
- SIEM-корреляция: повторные ошибки входа, массовые изменения исключений, повторные критические события с одного источника.
- Генерация демо-сценария для показа проекта.
- Хранение времени в UTC и отображение в GMT+3 в текущем русскоязычном UI.

### Локальный запуск

1. Задайте локальный пароль PostgreSQL в переменной окружения. Не коммитьте его.

```powershell
$env:CONSHIELD_POSTGRES_PASSWORD = "your-local-password"
```

2. Запустите PostgreSQL:

```powershell
docker compose -f infra/docker-compose.yml up -d postgres
```

3. Скопируйте `src/ConShield.Web/appsettings.Development.example.json` в `src/ConShield.Web/appsettings.Development.json`.
4. Замените `CHANGE_ME` в локальном файле на свой локальный пароль.
5. Откройте `ConShield.sln`.
6. Выберите стартовым проектом `ConShield.Web`.
7. Задайте локальный API key в `src/ConShield.Web/appsettings.Development.json` в секции `ExternalEventIngestion:ApiKey`.
8. Запустите проект из Visual Studio или командой:

```powershell
dotnet run --project src/ConShield.Web/ConShield.Web.csproj
```

Файл `appsettings.Development.json` не должен попадать в GitHub. При запуске в `Development` приложение применяет ожидающие PostgreSQL-миграции и создаёт воспроизводимые демо-данные через `DbSeeder`.

### Важно

Текущая авторизация является демонстрационной. Для production-подхода нужно заменить ее на полноценную систему учетных записей, хеширование паролей, rate limiting и безопасное управление секретами.

## Real Falco Fedora Sensor

ConShield has a deployment kit for a protected Fedora 44 sensor node in [`deploy/falco-linux`](deploy/falco-linux). Windows remains the primary developer workstation and central ConShield server. The Fedora VM represents a protected Linux node; clients do not need to replace Windows desktops.

The validated path is:

```text
Falco 0.44.1 modern_ebpf -> protected JSONL -> RuntimeCollector
-> Windows ingestion API -> PostgreSQL Outbox -> RabbitMQ
-> MongoDB + PostgreSQL Inbox -> RTE-001 -> Alert + Incident
```

The deployment keeps SELinux enforcing, reuses Podman, runs RuntimeCollector as a non-login user, and does not install Kubernetes. See [`docs/REAL_FALCO_FEDORA_DEPLOYMENT.md`](docs/REAL_FALCO_FEDORA_DEPLOYMENT.md).

Enrolled sensor credentials are created with the local operator-only `ConShield.SensorProvisioning` tool. Follow [`docs/SENSOR_PROVISIONING_AND_FEDORA_ROLLOUT.md`](docs/SENSOR_PROVISIONING_AND_FEDORA_ROLLOUT.md) for protected credential transfer, heartbeat and event verification, legacy fallback disablement, and rollback.

Credential rotation and revocation should follow the design in [`docs/SENSOR_CREDENTIAL_LIFECYCLE.md`](docs/SENSOR_CREDENTIAL_LIFECYCLE.md). Operators can interpret lifecycle audit events with [`docs/SENSOR_LIFECYCLE_AUDIT_PLAYBOOK.md`](docs/SENSOR_LIFECYCLE_AUDIT_PLAYBOOK.md), and use [`docs/OPERATIONS_AND_SIEM_RUNBOOK.md`](docs/OPERATIONS_AND_SIEM_RUNBOOK.md) for the Состояние системы, Security Events, Оповещения SIEM, and Сенсоры workflow.
