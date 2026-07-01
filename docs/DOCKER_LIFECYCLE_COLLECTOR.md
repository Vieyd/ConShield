# Docker Lifecycle Collector v1

Docker Lifecycle Collector v1 adds a deterministic local replay path for Docker-compatible lifecycle events. It maps sanitized fixture data into ConShield external security events with:

- `SourceSystem = conshield.docker-lifecycle-collector`
- `ExternalEventType = container.lifecycle.created`
- `ExternalEventType = container.lifecycle.started`
- `ExternalEventType = container.lifecycle.stopped`
- `ExternalEventType = container.lifecycle.destroyed`
- `ExternalEventType = container.lifecycle.abnormal_exit`
- `ExternalEventType = container.lifecycle.exec_started`

The default path is fixture-first and CI-safe. It does not require live Docker, Fedora/Falco, live Trivy DB/network, external internet, Kubernetes, mTLS, real certificates, private keys, signing keys, or secrets.

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

## Optional live Docker watch

Live Docker Lifecycle Watch v1 is an optional manual check for local machines where Docker Desktop or a compatible Docker daemon is already running. It is not required by CI, full validation, readiness, or the default guided demo seed.

Watch without submitting to Web:

```powershell
dotnet run --project .\src\ConShield.Cli -- lifecycle watch `
  --duration-seconds 30 `
  --no-submit
```

Optional submit mode:

```powershell
dotnet run --project .\src\ConShield.Cli -- lifecycle watch `
  --duration-seconds 30 `
  --submit
```

The watch command uses a bounded `docker events --format "{{json .}}" --filter type=container` process and stops after the configured duration or `--max-events` limit.

Options:

- `--duration-seconds <n>`: bounded watch duration, allowed range `1..300`, default `30`.
- `--max-events <n>`: maximum observed events, allowed range `1..1000`, default `100`.
- `--no-submit`: default safe mode; observes and normalizes only.
- `--submit`: submits sanitized events through existing external ingestion and requires local Web/API plus local ignored credentials.

Expected no-submit output:

```text
ConShield Docker lifecycle watch
Docker: OK
Mode: live watch
Duration: 30 seconds
Submit: false
Events observed: <n>
Events normalized: <n>
Events submitted: 0
Result: PASS
```

If Docker is unavailable in no-submit mode, the command exits safely with `Result: SKIP` and a hint to start Docker Desktop or use lifecycle replay fixture mode. If Docker is unavailable in submit mode, it returns an infrastructure error. The command does not print Docker raw JSON, Docker logs, host mount paths, environment values, API keys, passwords, connection strings, tokens, or raw event payloads.

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
- The `/Demo` page and `/Dashboard` list deterministic lifecycle replay and optional live watch as read-only copy/paste commands. The Web UI does not execute Docker commands.
- Existing `LIFE-001` / `LIFE-002` behavior remains available for protected-run and sensor lifecycle paths. This PR does not replace those rules or add a live Docker dependency.

## Safety boundaries

Do not commit generated reports or local artifacts. The collector and docs must not expose API keys, passwords, connection strings, environment values, Docker logs, raw Docker event JSON, raw event payload JSON, raw additional data, host-sensitive mount paths, screenshots, certificates, private keys, or signing keys.

Use deterministic replay fixtures for regression coverage. Keep live watch as an optional manual check only.
