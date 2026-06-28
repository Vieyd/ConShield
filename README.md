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

The default scenario does not require Fedora, Falco, Kubernetes, or a real enrolled runtime sensor. It uses marked synthetic demo data to demonstrate image scan (`IMG-001`), policy gate (`POL-001`), runtime (`RTE-001`), lifecycle (`LIFE-001`/`LIFE-002`), SIEM alerts, incidents, outbox/inbox evidence, and the Security Summary report.

Result meanings:

- `PASS`: required demo evidence was demonstrated.
- `WARN`: the core scenario ran, but an optional local service was unavailable or degraded.
- `FAIL`: required evidence could not be proven.

### Demo readiness check

Before a defense or live demo, run the one-command readiness check:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldDemoReadiness.ps1
```

It verifies Git awareness, Docker services, PostgreSQL, RabbitMQ, MongoDB, demo users, Web, EventConsumer, the defense scenario, Falco replay, Runtime Sensor Health, and evidence export. The generated evidence defaults to `artifacts/local/demo-readiness-evidence.md`, which must stay uncommitted.

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

### Export defense evidence

Export a safe Markdown evidence pack to an ignored local artifact path:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Export-ConShieldDefenseEvidence.ps1 `
  -OutputMarkdownPath .\artifacts\local\defense-evidence.md
```

The exporter writes only safe aggregate and metadata fields. It summarizes health, scenario results, SIEM alerts, incidents, Security Events, Image Scan Evidence, outbox/inbox state, Runtime Sensor Evidence, Runtime Sensor Health, demo navigation, and operator checklists. It intentionally excludes raw event payload JSON, raw `AdditionalDataJson`, secrets, connection strings, API keys, tokens, cookies, local logs, screenshots, and generated reports from source control.

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

The local replay path does not install or require Fedora, Falco Operator, Kubernetes, or a real sensor node. The real Fedora/Falco deployment kit lives under `deploy/falco-linux`, but it is not required for the default local demo.

### Runtime Sensor Health

Runtime Sensor Health is available at:

```text
http://127.0.0.1:5080/RuntimeSensors
```

It derives source health from existing Security Events, `RTE-001` alerts, and incidents. The view shows `SourceSystem`, `LastSeenUtc`, `EventCount`, latest event metadata, related RTE alert count, related incident count, and `Active` / `Stale` / `NoData` status. It does not require a new database migration or a real Fedora/Falco node for local validation.

### Validation

Common local checks:

```powershell
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
- [Operations and SIEM runbook](docs/OPERATIONS_AND_SIEM_RUNBOOK.md)
- [Falco runtime sensor](docs/FALCO_RUNTIME_SENSOR.md)
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

Default scenario не требует Fedora, Falco, Kubernetes или настоящего enrolled runtime sensor. Он использует помеченные synthetic demo data, чтобы показать image scan (`IMG-001`), policy gate (`POL-001`), runtime (`RTE-001`), lifecycle (`LIFE-001`/`LIFE-002`), SIEM alerts, incidents, outbox/inbox evidence и Security Summary report.

Значения результата:

- `PASS`: обязательное demo evidence подтверждено.
- `WARN`: основной сценарий прошёл, но optional local service недоступен или degraded.
- `FAIL`: обязательное evidence подтвердить не удалось.

### Demo readiness check

Перед защитой или live demo запустите одну команду проверки готовности:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldDemoReadiness.ps1
```

Команда проверяет Git awareness, локальные Docker services, PostgreSQL, RabbitMQ, MongoDB, demo users, Web, EventConsumer, defense scenario, Falco replay, Runtime Sensor Health и evidence export. Generated evidence по умолчанию сохраняется в `artifacts/local/demo-readiness-evidence.md`; этот файл нельзя коммитить.

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

### Экспорт evidence для защиты

Выгрузите безопасный Markdown evidence pack в ignored local artifact path:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Export-ConShieldDefenseEvidence.ps1 `
  -OutputMarkdownPath .\artifacts\local\defense-evidence.md
```

Exporter writes only safe aggregate and metadata fields. Он включает health, scenario results, SIEM alerts, incidents, Security Events, Image Scan Evidence, outbox/inbox state, Runtime Sensor Evidence, Runtime Sensor Health, demo navigation и operator checklists. Он намеренно не выводит raw event payload JSON, raw `AdditionalDataJson`, secrets, connection strings, API keys, tokens, cookies, local logs, screenshots и generated reports в source control.

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

Local replay path does not install or require Fedora, Falco Operator, Kubernetes или настоящий sensor node. Real Fedora/Falco deployment kit находится в `deploy/falco-linux`, но для default local demo он не нужен.

### Runtime Sensor Health

Runtime Sensor Health доступен здесь:

```text
http://127.0.0.1:5080/RuntimeSensors
```

Он рассчитывает health источников из существующих Security Events, `RTE-001` alerts и incidents. View показывает `SourceSystem`, `LastSeenUtc`, `EventCount`, metadata последнего события, количество связанных RTE alerts, количество связанных incidents и статус `Active` / `Stale` / `NoData`. Для локальной проверки не нужна новая database migration или настоящий Fedora/Falco node.

### Проверки

Обычные локальные проверки:

```powershell
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
- [Operations and SIEM runbook](docs/OPERATIONS_AND_SIEM_RUNBOOK.md)
- [Falco runtime sensor](docs/FALCO_RUNTIME_SENSOR.md)
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
