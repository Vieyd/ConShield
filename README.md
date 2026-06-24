# ConShield

ConShield is a student cybersecurity portfolio project: a lightweight SOC/SIEM training web application for security event monitoring, user exception governance, incident tracking, and rule-based alert correlation.

The project is intentionally practical. It demonstrates how a security team can collect audit events, review suspicious activity, manage exceptions, and turn correlated signals into incidents.

For the product-level architecture, scalability model, and implementation roadmap, see [docs/CONSHIELD_ARCHITECTURE_AND_ROADMAP.md](docs/CONSHIELD_ARCHITECTURE_AND_ROADMAP.md).

## Features

- Role-based access for `AdminIB` and `Operator`.
- Security event journal with filtering and a JSON endpoint for recent events.
- User exception management with audit events for create, update, and delete operations.
- Incident registry with severity, status, source event links, and lifecycle actions.
- SIEM-style correlation rules for repeated login failures, suspicious exception changes, and repeated critical events from one source.
- PostgreSQL transactional outbox for durable security event delivery to JSONL or RabbitMQ.
- `ConShield.EventConsumer`, an idempotent RabbitMQ consumer with PostgreSQL inbox receipts and optional MongoDB raw-event projection.
- AdminIB-only operational health dashboard with read-only aggregate counts for sensor heartbeat freshness, security event freshness, lifecycle audit activity, outbox backlog, and inbox/projection receipts.
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
- Demo scenario generation for portfolio walkthroughs.
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

Ingested external events are saved as `SecurityEventType.ExternalEvent`. The current SIEM rules do not interpret arbitrary `externalEventType` values: `BF-001` and `UE-001` are still based on built-in ConShield event types. `CR-001` can match an external critical event when the normal source-IP conditions are met. Full mapping from external event types to SIEM rules is planned as a separate future stage.

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

## Security Event Outbox

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

Falco-compatible runtime JSON alerts can be normalized by `ConShield.RuntimeCollector` and submitted to the existing external ingestion API. This stage uses safe JSONL fixtures and does not install Falco, Falco Operator, or Kubernetes components. See [docs/FALCO_RUNTIME_EVENT_INGESTION.md](docs/FALCO_RUNTIME_EVENT_INGESTION.md).

## Demo Accounts

Local demo accounts are configured in `src/ConShield.Web/appsettings.Development.json`.

For a new machine, copy `src/ConShield.Web/appsettings.Development.example.json` to `src/ConShield.Web/appsettings.Development.json` and set local demo usernames and passwords there. The development file is ignored by Git and must not be committed.

## Demo Flow

1. Sign in as `adminib`.
2. Review dashboard metrics.
3. Open security events and confirm login audit entries.
4. Create or edit a user exception.
5. Generate a SIEM demo scenario.
6. Run correlation and inspect created alerts.
7. Open the related incident and change its status.
8. Sign in as `operator` and verify read-only access boundaries.

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

Credential rotation and revocation should follow the design in [`docs/SENSOR_CREDENTIAL_LIFECYCLE.md`](docs/SENSOR_CREDENTIAL_LIFECYCLE.md). Operators can interpret lifecycle audit events with [`docs/SENSOR_LIFECYCLE_AUDIT_PLAYBOOK.md`](docs/SENSOR_LIFECYCLE_AUDIT_PLAYBOOK.md).
