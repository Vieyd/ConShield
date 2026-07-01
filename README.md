# ConShield

[English](#english) | [Русский](#русский)

<a id="english"></a>

## English

### What is ConShield?

ConShield is a student cybersecurity portfolio project: a lightweight SOC/SIEM training web application for security event monitoring, user exception governance, incident tracking, rule-based alert correlation, and safe defense-demo evidence.

It demonstrates a practical security-team workflow: collect audit and external security events, correlate suspicious activity into SIEM alerts, link alerts to incidents, review runtime sensor signals, and export a safe Markdown evidence pack for project defense or portfolio review.

### Architecture

```text
ConShield.Web              MVC UI, controllers, authentication, view models
ConShield.Application      Use cases, SIEM correlation, application services
ConShield.Data             EF Core DbContext and domain entities
ConShield.Contracts        Shared constants, enums, DTO models
ConShield.SecurityEvents   Security event writer and outbox message creation
ConShield.EventPipeline    Outbox dispatcher, JSONL/RabbitMQ sinks, retry and DeadLetter handling
ConShield.EventConsumer    RabbitMQ consumer, MongoDB projection, PostgreSQL inbox checkpoint
ConShield.MongoProjection  Immutable MongoDB raw-event projection and TTL indexes
ConShield.ImageScanner     Trivy-based container image scanner CLI
ConShield.ContainerPolicy  Container policy validation and evaluation library
ConShield.RuntimeDetection Falco-compatible parser, mapping, normalization, identity
ConShield.RuntimeCollector CLI for stdin/file/follow runtime alert ingestion
ConShield.Cli              Unified local CLI wrapper for demo/operator workflows
ConShield.SensorProvisioning Local operator-only enrolled sensor credential provisioning
tools/ConShield.DemoScenario Local synthetic demo scenario runner
scripts/                  Local automation, validation, replay, and evidence export
docs/                     Architecture, operations, SIEM, runtime sensor, and security notes
```

Main flow:

```text
Security source -> ConShield ingestion -> PostgreSQL SecurityEvents
-> SIEM correlation -> Alert -> Incident -> Operator workflow -> Evidence export
```

External delivery can use the PostgreSQL outbox, JSONL, RabbitMQ, PostgreSQL inbox receipts, and optional MongoDB raw-event projection. Runtime events can be replayed locally with safe Falco-compatible fixtures; a real Fedora/Falco node is optional for the local demo.

### Local prerequisites

- .NET 8 SDK.
- PowerShell 7.
- Docker Desktop or another local PostgreSQL 16 instance.
- GitHub CLI if you want to publish PRs from the command line.
- Optional: RabbitMQ and MongoDB via the local Docker Compose stack.

Local development configuration is intentionally ignored by Git. Keep real local connection strings, API keys, demo passwords, and environment values in ignored local files or user/process environment variables only.

### Quick start

Prepare local demo users, start the application stack, and open the local UI:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Set-LocalDemoUsers.ps1

pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit
```

Useful local URLs:

```text
Web: http://127.0.0.1:5080
RabbitMQ UI: http://localhost:15672
Runtime Sensor Health: http://127.0.0.1:5080/RuntimeSensors
Security Summary: http://127.0.0.1:5080/Reports/SecuritySummary
Security Events: http://127.0.0.1:5080/SecurityEvents
SIEM: http://127.0.0.1:5080/Siem
Incidents: http://127.0.0.1:5080/Incidents
```

In `Development`, ConShield applies pending EF Core migrations and seeds reproducible demo data on a clean local PostgreSQL database.

### Local defense demo

Run the safe local defense scenario:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Run-ConShieldDefenseScenario.ps1
```

The default scenario does not require Fedora, Falco, Kubernetes, or a real enrolled runtime sensor. It uses marked synthetic demo data to demonstrate image scan (`IMG-001`), policy gate (`POL-001`), Docker lifecycle collector replay, runtime (`RTE-001`), sensor trust enforcement (`SENSOR-001`/`SENSOR-002`), signed sensor events (`SIGN-001`/`SIGN-002`/`SIGN-003`), lifecycle (`LIFE-001`/`LIFE-002`), SIEM alerts, incidents, outbox/inbox evidence, and the Security Summary report.

### Configurable SIEM rules

ConShield loads the configurable demo SIEM rules from [`config/siem-rules.default.json`](config/siem-rules.default.json). The committed default config preserves the existing `IMG-001`, `POL-001`, `RTE-001`, `SENSOR-001`, `SENSOR-002`, `SIGN-001`, `SIGN-002`, `SIGN-003`, `LIFE-001`, and `LIFE-002` behavior. Optional local overrides can use `config/siem-rules.local.json`, which is ignored by Git and must not contain secrets.

Validate the rules without Docker, Fedora/Falco, live Trivy DB, network access, or real credentials:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldSiemRules.ps1
```

For the field reference and safety notes, see [`docs/SIEM_RULES.md`](docs/SIEM_RULES.md).

### Container policy-as-code

Protected container run decisions are loaded from [`config/container-policy.default.json`](config/container-policy.default.json). The committed default policy preserves the existing fixture behavior: critical findings block, high findings warn, and clean fixtures allow. Optional local overrides can use `config/container-policy.local.json`, which is ignored by Git.

Validate the policy offline:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldContainerPolicy.ps1
```

The protected runner prints the safe policy decision, matched policy rule IDs, and policy config source. Details are documented in [`docs/CONTAINER_POLICY.md`](docs/CONTAINER_POLICY.md).

Result meanings:

- `PASS`: required demo evidence was demonstrated.
- `WARN`: the core scenario ran, but an optional local service was unavailable or degraded.
- `FAIL`: required evidence could not be proven.

### Demo readiness check

Before a defense or live demo, run the one-command readiness check:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldDemoReadiness.ps1
```

It verifies Git awareness, Docker services, PostgreSQL, RabbitMQ, MongoDB, demo users, Web, EventConsumer, the defense scenario, Docker lifecycle replay, Falco replay, Runtime Sensor Health, and evidence export. The generated evidence defaults to `artifacts/local/demo-readiness-evidence.md`, which must stay uncommitted.

For a broader offline integration audit that does not require Web/API, live Docker execution, live Trivy DB/network, real Fedora/Falco, external internet, real certificates, private keys, signing keys, or real secrets, run:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldFullValidation.ps1
```

The full validation checklist is documented in [`docs/CONSHIELD_FULL_VALIDATION_CHECKLIST.md`](docs/CONSHIELD_FULL_VALIDATION_CHECKLIST.md).

### Reset local demo data

Use this before a clean defense/demo run:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Reset-ConShieldLocalDemoData.ps1 -WhatIf

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Reset-ConShieldLocalDemoData.ps1 -ConfirmReset
```

The reset is local-only, does not print secrets, and does not remove Docker volumes by default. It resets demo-generated operational data such as Security Events, SIEM alerts, Incidents, outbox/inbox rows, and Mongo projections while keeping migrations, configuration, demo-user settings, source files, and Docker volumes intact.

### Demo walkthrough page

Open the guided demo page after starting the Web app:

```text
http://127.0.0.1:5080/Demo
```

The page is read-only. It shows the demo order, safe PowerShell commands, current counts, and links to Security Summary, Security Events, SIEM, Incidents, and Runtime Sensor Health. It does not execute scripts from the browser and does not display secrets, raw payloads, logs, or generated local artifacts.

### Operator dashboard

Open the read-only operator dashboard after starting the Web app:

```text
http://127.0.0.1:5080/Dashboard
```

The dashboard is status-first: it shows the current demo posture, status cards, latest sanitized SIEM alerts/incidents, and sensor trust/signature summaries before the command reference. It also includes a guided demo flow, grouped workflows for pre-deployment controls, runtime/lifecycle, and operations/evidence, plus grouped documentation links. Commands are collapsed local copy/paste references only; the Web UI does not execute PowerShell, Docker, Trivy, Falco, reset, evidence export, or packaging actions from the browser and does not display raw payloads, secrets, logs, environment values, connection strings, or generated local artifacts.

### Demo release packaging

Create a local demo release pack with the published CLI, safe docs, default configs, validation scripts, and a release README:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\New-ConShieldDemoReleasePack.ps1
```

The pack is generated under `artifacts/local/conshield-demo-release-pack` with an archive at `artifacts/local/conshield-demo-release-pack.zip`; both paths are ignored by Git. The packaging command excludes secrets, local overrides, generated evidence, logs, screenshots, raw payloads, and nested local artifacts. Details are documented in [`docs/RELEASE_AND_DEMO_PACKAGING.md`](docs/RELEASE_AND_DEMO_PACKAGING.md).

### Unified ConShield CLI

`ConShield.Cli` provides one local entry point for the existing safe scripts. The scripts remain available and are not replaced.

```powershell
dotnet run --project .\src\ConShield.Cli -- --help

dotnet run --project .\src\ConShield.Cli -- validate

dotnet run --project .\src\ConShield.Cli -- scan image `
  --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json `
  --no-submit

dotnet run --project .\src\ConShield.Cli -- gate image `
  --image demo/insecure-api:latest `
  --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json `
  --fail-on never `
  --report .\artifacts\local\cicd-gate-report.md `
  --no-submit

dotnet run --project .\src\ConShield.Cli -- run protected `
  --image demo/insecure-api:latest `
  --container-name conshield-demo-insecure `
  --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json `
  --no-run `
  --no-submit

dotnet run --project .\src\ConShield.Cli -- lifecycle replay `
  --from-docker-events-json .\tests\TestData\DockerEvents\container-lifecycle-events.json `
  --no-submit

dotnet run --project .\src\ConShield.Cli -- sensor replay `
  --demo-signature `
  --no-submit

dotnet run --project .\src\ConShield.Cli -- demo readiness

dotnet run --project .\src\ConShield.Cli -- demo reset --confirm

dotnet run --project .\src\ConShield.Cli -- evidence export `
  --output .\artifacts\local\defense-evidence-cli.md
```

Reset requires explicit `--confirm`. Live Docker execution remains opt-in through the existing protected-run safety rules. Deterministic fixture commands do not require real Fedora/Falco, live Docker run or event watching, live Trivy DB/network, external internet, certificates, private keys, signing keys, or real secrets. Details are documented in [`docs/CONSHIELD_CLI.md`](docs/CONSHIELD_CLI.md).

### CI/CD container gate

Run the deterministic gate without live Trivy DB/network or Docker execution:

```powershell
dotnet run --project .\src\ConShield.Cli -- gate image `
  --image demo/insecure-api:latest `
  --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json `
  --fail-on never `
  --report .\artifacts\local\cicd-gate-report.md `
  --no-submit
```

The gate evaluates scan fixtures against `config/container-policy.default.json`, prints `Allow` / `Warn` / `Block`, and returns deterministic CI exit codes: `0` passed, `1` failed by policy, `2` usage/input/config error, `3` infrastructure error. `Block` fails with `--fail-on block`; `Warn` fails only with `--fail-on warn`; `--fail-on never` reports findings without failing. Details and a GitHub Actions snippet are documented in [`docs/CICD_CONTAINER_GATE.md`](docs/CICD_CONTAINER_GATE.md).

### Image scan CLI

Run a deterministic offline image scan mapping check without live Trivy, internet, Fedora, or ingestion:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-ConShieldImageScan.ps1 `
  -FromTrivyJson .\tests\TestData\Trivy\sample-image-scan.json `
  -NoSubmit
```

After the local Web app is running and local ingestion is configured, submit the same sanitized fixture through the external ingestion path:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-ConShieldImageScan.ps1 `
  -FromTrivyJson .\tests\TestData\Trivy\sample-image-scan.json
```

The command maps Trivy-compatible results to `SourceSystem=conshield.image-scanner`, `ExternalEventType=container.image.scan.completed`, and the expected `IMG-001` path. Evidence export includes an `Image Scan Evidence` section when image scan events are available. The wrapper prints only safe summary fields and does not print raw Trivy JSON, raw event payloads, secrets, API keys, connection strings, or environment values.

### Protected container run

Validate the protected run workflow without Docker execution or live Trivy:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-ConShieldProtectedRun.ps1 `
  -Image demo/insecure-api:latest `
  -ContainerName conshield-demo-insecure `
  -FromTrivyJson .\tests\TestData\Trivy\sample-image-scan.json `
  -NoRun `
  -NoSubmit
```

Submit safe IMG/POL/LIFE events to local ingestion without starting a container:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-ConShieldProtectedRun.ps1 `
  -Image demo/insecure-api:latest `
  -ContainerName conshield-demo-insecure `
  -FromTrivyJson .\tests\TestData\Trivy\sample-image-scan.json `
  -NoRun
```

The runner enforces `Allow` / `Warn` / `Block` decisions from the container baseline policy. Without `-Execute`, no container is started. With `-NoRun`, a container is never started. `Block` never starts a container, and `Warn` requires both `-AcceptWarning` and `-Execute`. Evidence export includes `Protected Run Evidence` when matching policy or launch lifecycle events are available.

### Docker lifecycle collector

Replay deterministic Docker-compatible lifecycle events without live Docker:

```powershell
dotnet run --project .\src\ConShield.Cli -- lifecycle replay `
  --from-docker-events-json .\tests\TestData\DockerEvents\container-lifecycle-events.json `
  --no-submit
```

The collector maps sanitized fixture events to `SourceSystem=conshield.docker-lifecycle-collector` and `ExternalEventType=container.lifecycle.*` with deterministic external event IDs. Evidence export includes `Docker Lifecycle Collector Evidence` when matching events are available. Existing `LIFE-001` / `LIFE-002` behavior remains available for protected-run and sensor lifecycle paths. Details are documented in [`docs/DOCKER_LIFECYCLE_COLLECTOR.md`](docs/DOCKER_LIFECYCLE_COLLECTOR.md).

### Export defense evidence

Export a safe Markdown evidence pack to an ignored local artifact path:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Export-ConShieldDefenseEvidence.ps1 `
  -OutputMarkdownPath .\artifacts\local\defense-evidence.md
```

The exporter writes only safe aggregate and metadata fields. It summarizes health, scenario results, SIEM alerts, incidents, Security Events, Image Scan Evidence, Protected Run Evidence, Docker Lifecycle Collector Evidence, outbox/inbox state, Runtime Sensor Evidence, Runtime Sensor Health, demo navigation, and operator checklists. It intentionally excludes raw event payload JSON, raw `AdditionalDataJson`, secrets, connection strings, API keys, tokens, cookies, local logs, screenshots, and generated reports from source control.

Keep generated Markdown under `artifacts/local/` or another ignored local path.

### Operator workflow demo

The intended operator path is:

1. Open Security Summary.
2. Open a SIEM alert.
3. Acknowledge or review the alert.
4. Open the linked incident.
5. Move the incident to `InProgress`.
6. Open the linked source Security Event.
7. Close the incident with a non-empty conclusion.
8. Export defense evidence and verify the Operator Workflow section.

You can prepare data with:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Run-ConShieldDefenseScenario.ps1
```

### Falco runtime sensor replay

Replay a safe Falco-compatible runtime event without requiring a Fedora VM:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1
```

The replay path validates:

```text
Falco-compatible JSON fixture -> runtime mapping -> external event ingestion
-> Security Event -> RTE-001 SIEM alert -> Incident -> evidence export
```

Trust enforcement can be simulated locally without submitting events:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 `
  -SimulateUnknownSensor `
  -NoSubmit

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 `
  -SimulateRevokedSensor `
  -NoSubmit
```

Trusted sensors keep the normal `RTE-001` path. Unknown sources produce `SENSOR-001`; revoked or disabled sources produce `SENSOR-002`. This v1 enforcement layer flags untrusted runtime events with deterministic SIEM evidence and does not implement full mTLS.

Signed sensor events can also be simulated locally without real signing keys:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 `
  -DemoSignature `
  -NoSubmit

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 `
  -SimulateMissingSignature `
  -NoSubmit

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 `
  -SimulateInvalidSignature `
  -NoSubmit

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 `
  -SimulateStaleSignature `
  -NoSubmit
```

Valid demo signatures keep `RTE-001`. Missing signatures produce `SIGN-001`; invalid signatures produce `SIGN-002`; stale or replayed signatures produce `SIGN-003`. Full mTLS, real certificates, private keys, and production signing key management are intentionally left for a later PR. Details are documented in [`docs/SIGNED_SENSOR_EVENTS.md`](docs/SIGNED_SENSOR_EVENTS.md).

The local replay path does not install or require Fedora, Falco Operator, Kubernetes, or a real sensor node. The real Fedora/Falco deployment kit lives under `deploy/falco-linux`, but it is not required for the default local demo.

### Runtime Sensor Health

Runtime Sensor Health is available at:

```text
http://127.0.0.1:5080/RuntimeSensors
```

It derives source health from existing Security Events, `RTE-001` alerts, `SENSOR-001`/`SENSOR-002` trust alerts, `SIGN-001`/`SIGN-002`/`SIGN-003` signature alerts, and incidents. The view shows `SourceSystem`, `LastSeenUtc`, `EventCount`, latest event metadata, trust status, enforcement action, signature status, signature key id, related RTE alert count, related sensor trust alert count, related signature alert count, related incident count, and `Active` / `Stale` / `NoData` status. It does not require a new database migration or a real Fedora/Falco node for local validation.

### Sensor Trust Registry

Known runtime sensor sources are validated with [`config/sensor-registry.default.json`](config/sensor-registry.default.json). The local demo Falco sources map to trusted synthetic registry entries; sources not in the registry are shown as `Unknown` in Runtime Sensor Health and evidence. The default registry also includes safe revoked and disabled demo sources for deterministic `SENSOR-002` validation.

Validate the registry offline:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldSensorRegistry.ps1
```

The registry is a preparation layer for future certificate-bound enrollment. Trust enforcement v1 accepts trusted runtime events normally, raises `SENSOR-001` for unknown runtime sources, and raises `SENSOR-002` plus an incident for revoked or disabled runtime sources. It does not implement full mTLS and must not contain real certificates, private keys, secrets, API keys, connection strings, env values, raw runtime payloads, logs, screenshots, or generated local artifacts. Details are documented in [`docs/SENSOR_TRUST_REGISTRY.md`](docs/SENSOR_TRUST_REGISTRY.md).

### Validation

Common local checks:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldFullValidation.ps1

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\New-ConShieldDemoReleasePack.ps1

dotnet restore
dotnet build -c Release --no-restore
dotnet test -c Release --no-build

git diff --check
gitleaks git --redact --no-banner
```

For docs-only changes, proportional checks such as `git diff --check`, README link checks, and secret scanning are usually enough.

### Safety notes

- Do not commit `.env` files, `appsettings.Development.json`, logs, screenshots, generated reports, or anything under `artifacts/local/`.
- Do not paste secrets, passwords, API keys, tokens, cookies, connection strings, verifier values, raw event payload JSON, or raw `AdditionalDataJson` into issues, PRs, screenshots, logs, or chat.
- Demo authentication is intended for local portfolio use, not production identity.
- The runtime path supports safe local replay; real Fedora/Falco rollout should follow the dedicated operational docs.
- For local login diagnostics, use `scripts/Test-LocalDemoUserPassword.ps1`; it verifies a configured demo password without printing the password, password length, hashes, cookies, tokens, API keys, or connection strings.

### Documentation

- [Architecture and roadmap](docs/CONSHIELD_ARCHITECTURE_AND_ROADMAP.md)
- [System architecture](docs/ARCHITECTURE.md)
- [Architecture diagrams](docs/ARCHITECTURE_DIAGRAMS.md)
- [Data flow model](docs/DATA_FLOW_MODEL.md)
- [Deployment view](docs/DEPLOYMENT_VIEW.md)
- [Sequence flows](docs/SEQUENCE_FLOWS.md)
- [Product positioning](docs/PRODUCT_POSITIONING.md)
- [Competitive analysis](docs/COMPETITIVE_ANALYSIS.md)
- [Diploma defense narrative](docs/DIPLOMA_DEFENSE_NARRATIVE.md)
- [Roadmap to production](docs/ROADMAP_TO_PRODUCTION.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Attacker scenarios](docs/ATTACKER_SCENARIOS.md)
- [Security requirements](docs/SECURITY_REQUIREMENTS.md)
- [Requirements traceability matrix](docs/REQUIREMENTS_TRACEABILITY_MATRIX.md)
- [Residual risks](docs/RESIDUAL_RISKS.md)
- [Operations and SIEM runbook](docs/OPERATIONS_AND_SIEM_RUNBOOK.md)
- [Unified ConShield CLI](docs/CONSHIELD_CLI.md)
- [Full validation checklist](docs/CONSHIELD_FULL_VALIDATION_CHECKLIST.md)
- [Release and demo packaging](docs/RELEASE_AND_DEMO_PACKAGING.md)
- [CI/CD container gate](docs/CICD_CONTAINER_GATE.md)
- [Docker lifecycle collector](docs/DOCKER_LIFECYCLE_COLLECTOR.md)
- [Falco runtime sensor](docs/FALCO_RUNTIME_SENSOR.md)
- [Signed sensor events](docs/SIGNED_SENSOR_EVENTS.md)
- [Security event outbox](docs/SECURITY_EVENT_OUTBOX.md)
- [RabbitMQ security event pipeline](docs/RABBITMQ_SECURITY_EVENT_PIPELINE.md)
- [MongoDB raw-event projection](docs/MONGODB_RAW_EVENT_PROJECTION.md)
- [DLQ inspection and replay](docs/DLQ_INSPECTION_AND_REPLAY.md)
- [Container image scanning](docs/CONTAINER_IMAGE_SCANNING.md)
- [Container policy gate](docs/CONTAINER_POLICY_GATE.md)
- [Sensor provisioning and Fedora rollout](docs/SENSOR_PROVISIONING_AND_FEDORA_ROLLOUT.md)
- [Sensor credential lifecycle](docs/SENSOR_CREDENTIAL_LIFECYCLE.md)
- [Sensor lifecycle audit playbook](docs/SENSOR_LIFECYCLE_AUDIT_PLAYBOOK.md)
- [UI design system](docs/UI_DESIGN_SYSTEM.md)
- [Codex codemap](docs/CONSHIELD_CODEMAP.md)
- [Codex workflows](docs/CODEX_WORKFLOWS.md)

<a id="русский"></a>

## Русский

### Что такое ConShield?

ConShield — студенческий portfolio-проект по информационной безопасности: лёгкое SOC/SIEM web-приложение для мониторинга событий безопасности, управления пользовательскими исключениями, ведения инцидентов, корреляции оповещений по правилам и безопасного экспорта evidence для защиты проекта.

Проект показывает практический workflow ИБ-команды: собрать audit и external security events, превратить подозрительную активность в SIEM alerts, связать alerts с incidents, проверить runtime sensor signals и выгрузить безопасный Markdown evidence pack для защиты или portfolio review.

### Архитектура

```text
ConShield.Web              MVC UI, controllers, authentication, view models
ConShield.Application      Use cases, SIEM correlation, application services
ConShield.Data             EF Core DbContext and domain entities
ConShield.Contracts        Shared constants, enums, DTO models
ConShield.SecurityEvents   Security event writer and outbox message creation
ConShield.EventPipeline    Outbox dispatcher, JSONL/RabbitMQ sinks, retry and DeadLetter handling
ConShield.EventConsumer    RabbitMQ consumer, MongoDB projection, PostgreSQL inbox checkpoint
ConShield.MongoProjection  Immutable MongoDB raw-event projection and TTL indexes
ConShield.ImageScanner     Trivy-based container image scanner CLI
ConShield.ContainerPolicy  Container policy validation and evaluation library
ConShield.RuntimeDetection Falco-compatible parser, mapping, normalization, identity
ConShield.RuntimeCollector CLI for stdin/file/follow runtime alert ingestion
ConShield.Cli              Unified local CLI wrapper for demo/operator workflows
ConShield.SensorProvisioning Local operator-only enrolled sensor credential provisioning
tools/ConShield.DemoScenario Local synthetic demo scenario runner
scripts/                  Local automation, validation, replay, and evidence export
docs/                     Architecture, operations, SIEM, runtime sensor, and security notes
```

Основной поток:

```text
Security source -> ConShield ingestion -> PostgreSQL SecurityEvents
-> SIEM correlation -> Alert -> Incident -> Operator workflow -> Evidence export
```

Доставка событий может использовать PostgreSQL outbox, JSONL, RabbitMQ, PostgreSQL inbox receipts и опциональную MongoDB raw-event projection. Runtime events можно локально replay-ить через безопасные Falco-compatible fixtures; настоящий Fedora/Falco node для локальной демонстрации не обязателен.

### Локальные требования

- .NET 8 SDK.
- PowerShell 7.
- Docker Desktop или другой локальный PostgreSQL 16.
- GitHub CLI, если нужно публиковать PR из командной строки.
- Опционально: RabbitMQ и MongoDB через локальный Docker Compose stack.

Локальная development-конфигурация намеренно игнорируется Git. Реальные connection strings, API keys, demo passwords и env values храните только в ignored local files или user/process environment variables.

### Быстрый запуск

Подготовьте локальных demo users, запустите application stack и откройте локальный UI:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Set-LocalDemoUsers.ps1

pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit
```

Полезные локальные URL:

```text
Web: http://127.0.0.1:5080
RabbitMQ UI: http://localhost:15672
Runtime Sensor Health: http://127.0.0.1:5080/RuntimeSensors
Security Summary: http://127.0.0.1:5080/Reports/SecuritySummary
Security Events: http://127.0.0.1:5080/SecurityEvents
SIEM: http://127.0.0.1:5080/Siem
Incidents: http://127.0.0.1:5080/Incidents
```

В режиме `Development` ConShield применяет ожидающие EF Core migrations и создаёт воспроизводимые demo data в чистой локальной PostgreSQL database.

### Локальная демонстрация защиты

Запустите безопасный локальный defense scenario:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Run-ConShieldDefenseScenario.ps1
```

Default scenario не требует Fedora, Falco, Kubernetes или настоящего enrolled runtime sensor. Он использует помеченные synthetic demo data, чтобы показать image scan (`IMG-001`), policy gate (`POL-001`), Docker lifecycle collector replay, runtime (`RTE-001`), enforcement доверия сенсоров (`SENSOR-001`/`SENSOR-002`), signed sensor events (`SIGN-001`/`SIGN-002`/`SIGN-003`), lifecycle (`LIFE-001`/`LIFE-002`), SIEM alerts, incidents, outbox/inbox evidence и Security Summary report.

### Конфигурируемые правила SIEM

ConShield загружает конфигурируемые demo SIEM rules из [`config/siem-rules.default.json`](config/siem-rules.default.json). Закоммиченный default config сохраняет текущее поведение `IMG-001`, `POL-001`, `RTE-001`, `SENSOR-001`, `SENSOR-002`, `SIGN-001`, `SIGN-002`, `SIGN-003`, `LIFE-001` и `LIFE-002`. Optional local overrides можно хранить в `config/siem-rules.local.json`; этот файл игнорируется Git и не должен содержать secrets.

Проверьте правила без Docker, Fedora/Falco, live Trivy DB, network access или real credentials:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldSiemRules.ps1
```

Описание полей и safety notes находятся в [`docs/SIEM_RULES.md`](docs/SIEM_RULES.md).

### Политика контейнеров как код

Решения защищённого запуска контейнеров загружаются из [`config/container-policy.default.json`](config/container-policy.default.json). Закоммиченная политика по умолчанию сохраняет текущее поведение fixtures: критические findings дают `Block`, high findings дают `Warn`, clean fixtures дают `Allow`. Необязательные локальные переопределения можно хранить в `config/container-policy.local.json`; этот файл игнорируется Git.

Проверьте политику офлайн:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldContainerPolicy.ps1
```

Защищённый runner выводит безопасное policy decision, совпавшие policy rule IDs и источник config. Подробности описаны в [`docs/CONTAINER_POLICY.md`](docs/CONTAINER_POLICY.md).

Значения результата:

- `PASS`: обязательное demo evidence подтверждено.
- `WARN`: основной сценарий прошёл, но optional local service недоступен или degraded.
- `FAIL`: обязательное evidence подтвердить не удалось.

### Demo readiness check

Перед защитой или live demo запустите одну команду проверки готовности:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldDemoReadiness.ps1
```

Команда проверяет Git awareness, локальные Docker services, PostgreSQL, RabbitMQ, MongoDB, demo users, Web, EventConsumer, defense scenario, Docker lifecycle replay, Falco replay, Runtime Sensor Health и evidence export. Generated evidence по умолчанию сохраняется в `artifacts/local/demo-readiness-evidence.md`; этот файл нельзя коммитить.

Для более широкой offline integration audit без Web/API, live Docker execution, live Trivy DB/network, real Fedora/Falco, external internet, настоящих certificates, private keys, signing keys или real secrets запустите:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldFullValidation.ps1
```

Полный checklist описан в [`docs/CONSHIELD_FULL_VALIDATION_CHECKLIST.md`](docs/CONSHIELD_FULL_VALIDATION_CHECKLIST.md).

### Сброс локальных demo-данных

Используйте перед чистым прогоном защиты/демо:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Reset-ConShieldLocalDemoData.ps1 -WhatIf

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Reset-ConShieldLocalDemoData.ps1 -ConfirmReset
```

Сброс предназначен только для локальных demo-данных, не печатает секреты и не удаляет Docker volumes по умолчанию. Он очищает demo-generated operational data: Security Events, SIEM alerts, Incidents, outbox/inbox rows и Mongo projections, сохраняя migrations, configuration, demo-user settings, source files и Docker volumes.

### Страница демонстрационного сценария

После запуска Web откройте страницу:

```text
http://127.0.0.1:5080/Demo
```

Страница только для чтения: она показывает порядок демонстрации, безопасные PowerShell-команды, текущие счётчики и ссылки на Security Summary, Security Events, SIEM, Incidents и Runtime Sensor Health. Она не запускает scripts из браузера и не показывает secrets, raw payloads, logs или generated local artifacts.

### Operator dashboard

После запуска Web откройте read-only operator dashboard:

```text
http://127.0.0.1:5080/Dashboard
```

Dashboard теперь построен по принципу status-first: сначала текущая posture демо, status cards, последние sanitized SIEM alerts/incidents и summary доверия сенсоров/подписей, затем guided demo flow и только потом command reference. Workflows сгруппированы как pre-deployment controls, runtime/lifecycle и operations/evidence; documentation links тоже сгруппированы. Commands свернуты как local copy/paste references; Web UI не запускает PowerShell, Docker, Trivy, Falco, reset, evidence export или packaging actions из браузера и не показывает raw payloads, secrets, logs, environment values, connection strings или generated local artifacts.

### Упаковка demo release

Создайте локальный demo release pack с опубликованным CLI, безопасной документацией, default configs, validation scripts и release README:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\New-ConShieldDemoReleasePack.ps1
```

Pack создаётся в `artifacts/local/conshield-demo-release-pack`, архив — в `artifacts/local/conshield-demo-release-pack.zip`; оба пути игнорируются Git. Команда упаковки исключает secrets, local overrides, generated evidence, logs, screenshots, raw payloads и nested local artifacts. Подробности описаны в [`docs/RELEASE_AND_DEMO_PACKAGING.md`](docs/RELEASE_AND_DEMO_PACKAGING.md).

### Единый ConShield CLI

`ConShield.Cli` даёт одну локальную точку входа для существующих безопасных scripts. Сами scripts остаются доступными и не заменяются.

```powershell
dotnet run --project .\src\ConShield.Cli -- --help

dotnet run --project .\src\ConShield.Cli -- validate

dotnet run --project .\src\ConShield.Cli -- scan image `
  --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json `
  --no-submit

dotnet run --project .\src\ConShield.Cli -- gate image `
  --image demo/insecure-api:latest `
  --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json `
  --fail-on never `
  --report .\artifacts\local\cicd-gate-report.md `
  --no-submit

dotnet run --project .\src\ConShield.Cli -- run protected `
  --image demo/insecure-api:latest `
  --container-name conshield-demo-insecure `
  --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json `
  --no-run `
  --no-submit

dotnet run --project .\src\ConShield.Cli -- lifecycle replay `
  --from-docker-events-json .\tests\TestData\DockerEvents\container-lifecycle-events.json `
  --no-submit

dotnet run --project .\src\ConShield.Cli -- sensor replay `
  --demo-signature `
  --no-submit

dotnet run --project .\src\ConShield.Cli -- demo readiness

dotnet run --project .\src\ConShield.Cli -- demo reset --confirm

dotnet run --project .\src\ConShield.Cli -- evidence export `
  --output .\artifacts\local\defense-evidence-cli.md
```

Reset требует явный `--confirm`. Live Docker execution остаётся opt-in через существующие safety rules protected-run workflow. Deterministic fixture-команды не требуют real Fedora/Falco, live Docker run или event watching, live Trivy DB/network, external internet, certificates, private keys, signing keys или real secrets. Подробности описаны в [`docs/CONSHIELD_CLI.md`](docs/CONSHIELD_CLI.md).

### CI/CD container gate

Запустите deterministic gate без live Trivy DB/network или Docker execution:

```powershell
dotnet run --project .\src\ConShield.Cli -- gate image `
  --image demo/insecure-api:latest `
  --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json `
  --fail-on never `
  --report .\artifacts\local\cicd-gate-report.md `
  --no-submit
```

Gate оценивает scan fixtures через `config/container-policy.default.json`, печатает `Allow` / `Warn` / `Block` и возвращает deterministic CI exit codes: `0` passed, `1` failed by policy, `2` usage/input/config error, `3` infrastructure error. `Block` падает с `--fail-on block`; `Warn` падает только с `--fail-on warn`; `--fail-on never` показывает findings без падения. Подробности и GitHub Actions snippet описаны в [`docs/CICD_CONTAINER_GATE.md`](docs/CICD_CONTAINER_GATE.md).

### Image scan CLI

Запустите deterministic offline-проверку маппинга image scan без live Trivy, интернета, Fedora или ingestion:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-ConShieldImageScan.ps1 `
  -FromTrivyJson .\tests\TestData\Trivy\sample-image-scan.json `
  -NoSubmit
```

После запуска локального Web app и настройки local ingestion отправьте тот же sanitized fixture через внешний ingestion path:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-ConShieldImageScan.ps1 `
  -FromTrivyJson .\tests\TestData\Trivy\sample-image-scan.json
```

Команда маппит Trivy-compatible результат в `SourceSystem=conshield.image-scanner`, `ExternalEventType=container.image.scan.completed` и ожидаемый путь `IMG-001`. Evidence export включает секцию `Image Scan Evidence`, если image scan events доступны. Wrapper печатает только safe summary fields и не выводит raw Trivy JSON, raw event payloads, secrets, API keys, connection strings или environment values.

### Protected container run

Проверьте workflow защищённого запуска без Docker execution или live Trivy:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-ConShieldProtectedRun.ps1 `
  -Image demo/insecure-api:latest `
  -ContainerName conshield-demo-insecure `
  -FromTrivyJson .\tests\TestData\Trivy\sample-image-scan.json `
  -NoRun `
  -NoSubmit
```

Отправьте safe IMG/POL/LIFE events в local ingestion без запуска контейнера:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-ConShieldProtectedRun.ps1 `
  -Image demo/insecure-api:latest `
  -ContainerName conshield-demo-insecure `
  -FromTrivyJson .\tests\TestData\Trivy\sample-image-scan.json `
  -NoRun
```

Runner применяет решения `Allow` / `Warn` / `Block` из container baseline policy. Без `-Execute` контейнер не запускается. С `-NoRun` контейнер не запускается никогда. `Block` никогда не запускает контейнер, а `Warn` требует одновременно `-AcceptWarning` и `-Execute`. Evidence export включает `Protected Run Evidence`, если доступны policy или launch lifecycle events.

### Docker lifecycle collector

Replay deterministic Docker-compatible lifecycle events без live Docker:

```powershell
dotnet run --project .\src\ConShield.Cli -- lifecycle replay `
  --from-docker-events-json .\tests\TestData\DockerEvents\container-lifecycle-events.json `
  --no-submit
```

Collector маппит sanitized fixture events в `SourceSystem=conshield.docker-lifecycle-collector` и `ExternalEventType=container.lifecycle.*` с deterministic external event IDs. Evidence export включает `Docker Lifecycle Collector Evidence`, если matching events доступны. Existing `LIFE-001` / `LIFE-002` behavior остаётся доступным для protected-run и sensor lifecycle paths. Подробности описаны в [`docs/DOCKER_LIFECYCLE_COLLECTOR.md`](docs/DOCKER_LIFECYCLE_COLLECTOR.md).

### Экспорт evidence для защиты

Выгрузите безопасный Markdown evidence pack в ignored local artifact path:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Export-ConShieldDefenseEvidence.ps1 `
  -OutputMarkdownPath .\artifacts\local\defense-evidence.md
```

Exporter выводит только безопасные aggregate и metadata fields. Он включает health, scenario results, SIEM alerts, incidents, Security Events, Image Scan Evidence, Protected Run Evidence, Docker Lifecycle Collector Evidence, outbox/inbox state, Runtime Sensor Evidence, Runtime Sensor Health, demo navigation и operator checklists. Он намеренно не выводит raw event payload JSON, raw `AdditionalDataJson`, secrets, connection strings, API keys, tokens, cookies, local logs, screenshots или generated reports в source control.

Храните generated Markdown under `artifacts/local/` или в другом ignored local path.

### Демонстрация workflow оператора

Целевой путь оператора:

1. Открыть Security Summary.
2. Открыть SIEM alert.
3. Acknowledge или review alert.
4. Открыть связанный incident.
5. Перевести incident в `InProgress`.
6. Открыть связанный исходный Security Event.
7. Закрыть incident с непустым conclusion.
8. Экспортировать defense evidence и проверить секцию Operator Workflow.

Данные можно подготовить командой:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Run-ConShieldDefenseScenario.ps1
```

### Replay Falco runtime sensor

Replay безопасного Falco-compatible runtime event без Fedora VM:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1
```

Replay path проверяет:

```text
Falco-compatible JSON fixture -> runtime mapping -> external event ingestion
-> Security Event -> RTE-001 SIEM alert -> Incident -> evidence export
```

Trust enforcement можно симулировать локально без отправки событий:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 `
  -SimulateUnknownSensor `
  -NoSubmit

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 `
  -SimulateRevokedSensor `
  -NoSubmit
```

Trusted sensors сохраняют обычный путь `RTE-001`. Unknown sources создают `SENSOR-001`; revoked или disabled sources создают `SENSOR-002`. Этот v1 enforcement-слой фиксирует untrusted runtime events в deterministic SIEM evidence и не реализует full mTLS.

Signed sensor events тоже можно симулировать локально без настоящих signing keys:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 `
  -DemoSignature `
  -NoSubmit

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 `
  -SimulateMissingSignature `
  -NoSubmit

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 `
  -SimulateInvalidSignature `
  -NoSubmit

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 `
  -SimulateStaleSignature `
  -NoSubmit
```

Valid demo signatures сохраняют `RTE-001`. Missing signatures создают `SIGN-001`; invalid signatures создают `SIGN-002`; stale или replayed signatures создают `SIGN-003`. Full mTLS, настоящие certificates, private keys и production signing key management намеренно оставлены для будущего PR. Подробности описаны в [`docs/SIGNED_SENSOR_EVENTS.md`](docs/SIGNED_SENSOR_EVENTS.md).

Local replay path does not install or require Fedora, Falco Operator, Kubernetes или настоящий sensor node. Real Fedora/Falco deployment kit находится в `deploy/falco-linux`, но для default local demo он не нужен.

### Runtime Sensor Health

Runtime Sensor Health доступен здесь:

```text
http://127.0.0.1:5080/RuntimeSensors
```

Он рассчитывает health источников из существующих Security Events, `RTE-001` alerts, trust alerts `SENSOR-001`/`SENSOR-002`, signature alerts `SIGN-001`/`SIGN-002`/`SIGN-003` и incidents. View показывает `SourceSystem`, `LastSeenUtc`, `EventCount`, metadata последнего события, trust status, enforcement action, signature status, signature key id, количество связанных RTE alerts, количество связанных sensor trust alerts, количество связанных signature alerts, количество связанных incidents и статус `Active` / `Stale` / `NoData`. Для локальной проверки не нужна новая database migration или настоящий Fedora/Falco node.

### Реестр доверия сенсоров

Известные источники runtime-сенсоров проверяются через [`config/sensor-registry.default.json`](config/sensor-registry.default.json). Локальные демонстрационные источники Falco сопоставляются с trusted synthetic registry entries; источники вне реестра показываются как `Unknown` в Runtime Sensor Health и evidence. Default registry также содержит безопасные revoked и disabled demo sources для deterministic проверки `SENSOR-002`.

Проверьте registry офлайн:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldSensorRegistry.ps1
```

Реестр — подготовительный слой под будущую привязку enrollment к сертификатам. Trust enforcement v1 принимает trusted runtime events обычным путём, создаёт `SENSOR-001` для unknown runtime sources и создаёт `SENSOR-002` плюс incident для revoked или disabled runtime sources. Он не реализует full mTLS и не должен содержать настоящие сертификаты, private keys, secrets, API keys, connection strings, env values, raw runtime payloads, logs, screenshots или generated local artifacts. Подробности описаны в [`docs/SENSOR_TRUST_REGISTRY.md`](docs/SENSOR_TRUST_REGISTRY.md).

### Проверки

Обычные локальные проверки:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldFullValidation.ps1

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\New-ConShieldDemoReleasePack.ps1

dotnet restore
dotnet build -c Release --no-restore
dotnet test -c Release --no-build

git diff --check
gitleaks git --redact --no-banner
```

Для docs-only изменений обычно достаточно пропорциональных проверок: `git diff --check`, проверка README links и secret scanning.

### Заметки по безопасности

- Не коммитьте `.env` files, `appsettings.Development.json`, logs, screenshots, generated reports или содержимое `artifacts/local/`.
- Не вставляйте secrets, passwords, API keys, tokens, cookies, connection strings, verifier values, raw event payload JSON или raw `AdditionalDataJson` в issues, PRs, screenshots, logs или chat.
- Demo authentication предназначена для локального portfolio-сценария, а не для production identity.
- Runtime path поддерживает безопасный local replay; настоящий Fedora/Falco rollout нужно выполнять по отдельным operational docs.
- Для локальной диагностики входа используйте `scripts/Test-LocalDemoUserPassword.ps1`; он проверяет настроенный demo password без вывода password, password length, hashes, cookies, tokens, API keys или connection strings.

### Документация

- [Architecture and roadmap](docs/CONSHIELD_ARCHITECTURE_AND_ROADMAP.md)
- [System architecture](docs/ARCHITECTURE.md)
- [Architecture diagrams](docs/ARCHITECTURE_DIAGRAMS.md)
- [Data flow model](docs/DATA_FLOW_MODEL.md)
- [Deployment view](docs/DEPLOYMENT_VIEW.md)
- [Sequence flows](docs/SEQUENCE_FLOWS.md)
- [Позиционирование продукта](docs/PRODUCT_POSITIONING.md)
- [Конкурентный анализ](docs/COMPETITIVE_ANALYSIS.md)
- [Нарратив для защиты диплома](docs/DIPLOMA_DEFENSE_NARRATIVE.md)
- [Roadmap к production](docs/ROADMAP_TO_PRODUCTION.md)
- [Модель угроз](docs/THREAT_MODEL.md)
- [Сценарии атакующего](docs/ATTACKER_SCENARIOS.md)
- [Security requirements](docs/SECURITY_REQUIREMENTS.md)
- [Матрица трассируемости требований](docs/REQUIREMENTS_TRACEABILITY_MATRIX.md)
- [Residual risks](docs/RESIDUAL_RISKS.md)
- [Operations and SIEM runbook](docs/OPERATIONS_AND_SIEM_RUNBOOK.md)
- [Unified ConShield CLI](docs/CONSHIELD_CLI.md)
- [Full validation checklist](docs/CONSHIELD_FULL_VALIDATION_CHECKLIST.md)
- [Release and demo packaging](docs/RELEASE_AND_DEMO_PACKAGING.md)
- [CI/CD container gate](docs/CICD_CONTAINER_GATE.md)
- [Docker lifecycle collector](docs/DOCKER_LIFECYCLE_COLLECTOR.md)
- [Falco runtime sensor](docs/FALCO_RUNTIME_SENSOR.md)
- [Signed sensor events](docs/SIGNED_SENSOR_EVENTS.md)
- [Security event outbox](docs/SECURITY_EVENT_OUTBOX.md)
- [RabbitMQ security event pipeline](docs/RABBITMQ_SECURITY_EVENT_PIPELINE.md)
- [MongoDB raw-event projection](docs/MONGODB_RAW_EVENT_PROJECTION.md)
- [DLQ inspection and replay](docs/DLQ_INSPECTION_AND_REPLAY.md)
- [Container image scanning](docs/CONTAINER_IMAGE_SCANNING.md)
- [Container policy gate](docs/CONTAINER_POLICY_GATE.md)
- [Sensor provisioning and Fedora rollout](docs/SENSOR_PROVISIONING_AND_FEDORA_ROLLOUT.md)
- [Sensor credential lifecycle](docs/SENSOR_CREDENTIAL_LIFECYCLE.md)
- [Sensor lifecycle audit playbook](docs/SENSOR_LIFECYCLE_AUDIT_PLAYBOOK.md)
- [UI design system](docs/UI_DESIGN_SYSTEM.md)
- [Codex codemap](docs/CONSHIELD_CODEMAP.md)
- [Codex workflows](docs/CODEX_WORKFLOWS.md)
