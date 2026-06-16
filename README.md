# ConShield

ConShield is a student cybersecurity portfolio project: a lightweight SOC/SIEM training web application for security event monitoring, user exception governance, incident tracking, and rule-based alert correlation.

The project is intentionally practical. It demonstrates how a security team can collect audit events, review suspicious activity, manage exceptions, and turn correlated signals into incidents.

## Features

- Role-based access for `AdminIB` and `Operator`.
- Security event journal with filtering and a JSON endpoint for recent events.
- User exception management with audit events for create, update, and delete operations.
- Incident registry with severity, status, source event links, and lifecycle actions.
- SIEM-style correlation rules for repeated login failures, suspicious exception changes, and repeated critical events from one source.
- Demo scenario generation for portfolio walkthroughs.
- UTC storage with GMT+3 display for the current Russian-language UI.

## Tech Stack

- .NET 8
- ASP.NET Core MVC and Razor Views
- Entity Framework Core
- PostgreSQL 16 for the current relational database
- Npgsql Entity Framework Core provider
- Cookie authentication with role-based authorization
- Docker Compose for PostgreSQL, with RabbitMQ and MongoDB kept as optional future infrastructure

## Architecture

```text
ConShield.Web              MVC UI, controllers, authentication, view models
ConShield.Application      Use cases, SIEM correlation, application services
ConShield.Data             EF Core DbContext and domain entities
ConShield.Contracts        Shared constants, enums, DTO models
ConShield.SecurityEvents   Security event writer and audit log model
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
- Local runtime JSONL audit log under `src/ConShield.Web/logs/`.

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
7. Run the application from Visual Studio or with:

```powershell
dotnet run --project src/ConShield.Web/ConShield.Web.csproj
```

In `Development`, pending EF Core migrations are applied at startup and `DbSeeder` creates reproducible demo data on a clean PostgreSQL database.

The development configuration is intentionally ignored by Git. Keep real local connection strings only in `appsettings.Development.json` or environment variables.

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

See [docs/ROADMAP.md](docs/ROADMAP.md).

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
7. Запустите проект из Visual Studio или командой:

```powershell
dotnet run --project src/ConShield.Web/ConShield.Web.csproj
```

Файл `appsettings.Development.json` не должен попадать в GitHub. При запуске в `Development` приложение применяет ожидающие PostgreSQL-миграции и создаёт воспроизводимые демо-данные через `DbSeeder`.

### Важно

Текущая авторизация является демонстрационной. Для production-подхода нужно заменить ее на полноценную систему учетных записей, хеширование паролей, rate limiting и безопасное управление секретами.
