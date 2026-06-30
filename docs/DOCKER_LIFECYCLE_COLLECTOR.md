# Docker Lifecycle Collector v1

Docker Lifecycle Collector v1 adds a deterministic local replay path for Docker-compatible lifecycle events. It maps sanitized fixture data into ConShield external security events with:

- `SourceSystem = conshield.docker-lifecycle-collector`
- `ExternalEventType = container.lifecycle.created`
- `ExternalEventType = container.lifecycle.started`
- `ExternalEventType = container.lifecycle.stopped`
- `ExternalEventType = container.lifecycle.destroyed`
- `ExternalEventType = container.lifecycle.abnormal_exit`
- `ExternalEventType = container.lifecycle.exec_started`

The v1 path is intentionally fixture-first and CI-safe. It does not require live Docker, Fedora/Falco, live Trivy DB/network, external internet, Kubernetes, mTLS, real certificates, private keys, signing keys, or secrets.

## Local replay

Run the deterministic replay without submitting to Web:

```powershell
dotnet run --project .\src\ConShield.Cli -- lifecycle replay `
  --from-docker-events-json .\tests\TestData\DockerEvents\container-lifecycle-events.json `
  --no-submit
```

Suspicious lifecycle fixture:

```powershell
dotnet run --project .\src\ConShield.Cli -- lifecycle replay `
  --from-docker-events-json .\tests\TestData\DockerEvents\container-lifecycle-suspicious-events.json `
  --no-submit
```

Both commands print compact summary fields only: parsed/mapped counts, event types, fixture name, sanitized actions, the latest container label, deterministic external event IDs, ingestion status, and `Result: PASS` or `Result: FAIL`.

## Submission path

When local Web is running and a local external event API key is configured, omit `--no-submit` to send sanitized lifecycle events through the existing external event ingestion API:

```powershell
dotnet run --project .\src\ConShield.Cli -- lifecycle replay `
  --from-docker-events-json .\tests\TestData\DockerEvents\container-lifecycle-events.json
```

The command reads local configuration only from environment variables or ignored local config. It never prints the key or connection details.

## Event mapping

| Docker-compatible action | ConShield event type | Severity |
| --- | --- | --- |
| `create` | `container.lifecycle.created` | `Info` |
| `start`, `restart` | `container.lifecycle.started` | `Info` |
| `stop` | `container.lifecycle.stopped` | `Info` |
| `destroy` | `container.lifecycle.destroyed` | `Info` |
| `die`, `kill`, `oom`, unhealthy health status | `container.lifecycle.abnormal_exit` | `Warning` |
| `exec_create`, `exec_start` | `container.lifecycle.exec_started` | `Warning` |

External event IDs are deterministic for the same source system, mapped event type, occurrence time, action, short container id, image reference, and container name.

## Evidence and readiness

- Defense evidence export includes a `Docker Lifecycle Collector Evidence` section with safe aggregate counts and recent safe descriptions.
- Demo readiness runs the deterministic fixture in `--no-submit` mode.
- The `/Demo` page lists the lifecycle replay command as a read-only checklist item.
- Existing `LIFE-001` / `LIFE-002` behavior remains available for protected-run and sensor lifecycle paths. This PR does not replace those rules or add a live Docker dependency.

## Safety boundaries

Do not commit generated reports or local artifacts. The collector and docs must not expose API keys, passwords, connection strings, environment values, Docker logs, raw Docker event JSON, raw event payload JSON, raw additional data, host-sensitive mount paths, screenshots, certificates, private keys, or signing keys.

`lifecycle watch` is intentionally not implemented in v1 because live Docker event watching would make CI and demo validation depend on machine state. Use deterministic replay fixtures for regression coverage.
