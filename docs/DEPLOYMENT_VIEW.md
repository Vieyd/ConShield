# Deployment View

## Local demo deployment

The standard ConShield deployment for defense/demo is local. It can run Web/API, PostgreSQL, RabbitMQ, MongoDB, EventConsumer, CLI/scripts, and deterministic fixture workflows on the developer/operator machine.

## Services

| Service | Role |
|---|---|
| `ConShield.Web` | Web UI, local auth, ingestion API, reports, `/Demo`. |
| `ConShield.EventConsumer` | Optional RabbitMQ consumer and projection/checkpoint worker. |
| PostgreSQL | Primary operational database. |
| RabbitMQ | Optional event broker. |
| MongoDB | Optional projection store. |
| `ConShield.Cli` | Unified local command wrapper. |
| PowerShell scripts | Explicit local automation and validation workflows. |

## Ports

| Endpoint | Purpose |
|---|---|
| `http://127.0.0.1:5080` | Web UI and local API surface. |
| `http://localhost:15672` | RabbitMQ management UI. |
| `127.0.0.1:5432` | PostgreSQL. |
| `127.0.0.1:27017` | MongoDB. |

No passwords, API keys, connection strings, tokens, or environment values are documented here.

## Start command

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit
```

## CLI-only offline mode

CLI-only fixture validation can run without Web/API and without live Docker/Falco/Trivy network paths:

```powershell
dotnet run --project .\src\ConShield.Cli -- validate
dotnet run --project .\src\ConShield.Cli -- scan image --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json --no-submit
dotnet run --project .\src\ConShield.Cli -- gate image --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json --fail-on never --no-submit
dotnet run --project .\src\ConShield.Cli -- lifecycle replay --from-docker-events-json .\tests\TestData\DockerEvents\container-lifecycle-events.json --no-submit
dotnet run --project .\src\ConShield.Cli -- sensor replay --demo-signature --no-submit
```

## Web/API mode

Web/API mode adds local UI, ingestion API, reports, Runtime Sensor Health, SIEM, incidents, and `/Demo`. It is used for live walkthroughs and evidence export when local services are available.

## Message pipeline mode

Message pipeline mode uses PostgreSQL outbox, RabbitMQ, EventConsumer, PostgreSQL inbox/checkpoints, and optional MongoDB projection. It is useful for demonstrating delivery and projection behavior but remains optional for deterministic docs/tests.

## Optional live integrations

Optional integrations include:

- live Docker run through protected-run opt-in flags;
- live Trivy network scan;
- real Fedora/Falco runtime deployment;
- RabbitMQ/Mongo/PostgreSQL local service smoke checks.

These are not required for default CI-safe validation.

## Release pack layout

Release packaging writes ignored local output under:

```text
artifacts/local/conshield-demo-release-pack/
artifacts/local/conshield-demo-release-pack.zip
artifacts/local/conshieldctl/
```

The pack includes published CLI, selected docs, default configs, selected scripts, and release README. It excludes local overrides, generated evidence, logs, screenshots, sensitive payload bodies, and nested local artifacts.

## Production roadmap deployment view

Production hardening is roadmap work. It would require deployment profiles, stronger identity, key management, monitoring, backup/restore guidance, runtime agent lifecycle, optional Kubernetes admission integration, and enterprise integrations.

## Limitations

- The local deployment is a prototype/demo topology.
- Optional live integrations are manual and environment-dependent.
- Full mTLS/PKI and production Kubernetes admission are intentionally not implemented in the current local demo.
- Enterprise multi-cluster operations and formal compliance attestation are out of scope.
