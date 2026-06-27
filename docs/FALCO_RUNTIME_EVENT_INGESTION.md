# Falco-Compatible Runtime Event Ingestion

ConShield can ingest Falco-compatible JSON alerts without installing Falco or Kubernetes in this stage:

```text
Falco-compatible JSON line
-> ConShield.RuntimeCollector
-> POST /api/v1/security-events
-> PostgreSQL SecurityEvents + Outbox
-> RabbitMQ/Mongo pipeline when enabled
-> RTE-001 SIEM correlation
-> Alert + Incident
```

Falco itself is not bundled or executed by ConShield. The collector accepts official-style JSON objects from stdin, JSONL file, or file follow mode. Real Linux Falco sensor deployment remains a later stage.

## Contract

Supported normalized schema: `falco-compatible-v1`.

Required top-level fields are `time`, `rule`, and `priority`. Optional fields are `output`, `hostname`, `source`, `tags`, and `output_fields`. Unknown top-level properties are tolerated but not copied automatically. `output_fields` accepts only bounded scalar values from an allowlist; arrays and objects are ignored with validation warnings.

Falco priorities accepted case-insensitively:

```text
Emergency, Alert, Critical, Error, Warning, Notice, Informational, Debug
```

Mapping severity is authoritative for mapped rules, but Critical/Emergency/Alert inputs cannot be lowered below `High`.

## Mapping

Baseline mapping is stored in `config/runtime/falco-mapping-v1.json`. It uses `schemaVersion: 1`, exact case-sensitive rule-name matching, optional required tags, `container.runtime.*` event types, and deterministic policy SHA-256.

Mapped baseline rules:

- `Terminal shell in container` -> `container.runtime.shell_spawned`
- `Write below binary dir` -> `container.runtime.binary_path_write`
- `Write below etc` -> `container.runtime.etc_write`
- `Set Setuid or Setgid bit` / compatible casing -> `container.runtime.setuid_change`
- `Launch Suspicious Network Tool in Container` -> `container.runtime.suspicious_network_tool`
- `Privileged Container Started` -> `container.runtime.privileged_container_started`

Unknown rules become `container.runtime.unmapped` with `correlate = false`.

## Minimization

ConShield does not store raw Falco alerts, raw `output`, raw command line, environment variables, arbitrary output fields, API keys, or registry credentials. It stores bounded identifiers, selected container/process/network fields, `rawOutputSha256`, and `commandLineSha256`. `proc.cmdline` contributes only a sanitized command name, argument count, and hash. Selected string fields remove URL userinfo/query strings and redact common password, token, authorization, API-key, secret, and bearer forms before persistence.

## Identity

Falco alerts normally have no UUID. ConShield derives:

- `eventFingerprintSha256` from length-prefixed canonical fields;
- `externalEventId` as a deterministic UUID from the fingerprint.

Inputs include schema marker, UTC time, rule, source, hostname, container id, event type, process name, thread/process id, and raw output hash. Same event produces the same UUID; changed identity produces a different UUID.

## RTE-001

`RTE-001 Container runtime threat detected` triggers on mapped runtime external events from `conshield.falco-runtime-collector` when:

- `ExternalEventType` is one of the approved mapped runtime event types;
- severity is `High` or `Critical`;
- additionalData has schema version 1, provider `falco-compatible`, `correlate = true`, valid mapping metadata, non-empty container identity fallback, and non-empty Falco rule.

`container.runtime.unmapped` never triggers. Active alert dedup uses container identity, mapping key, and process name within the normal 10-minute alert window.

## Demo

Dry run:

```powershell
Get-Content .\samples\falco\runtime-demo.jsonl |
  dotnet run --project .\src\ConShield.RuntimeCollector -- `
  collect `
  --stdin `
  --mapping .\config\runtime\falco-mapping-v1.json `
  --no-submit
```

Submit to a running local Web app:

```powershell
Get-Content .\samples\falco\runtime-demo.jsonl |
  dotnet run --project .\src\ConShield.RuntimeCollector -- `
  collect `
  --stdin `
  --mapping .\config\runtime\falco-mapping-v1.json `
  --endpoint http://127.0.0.1:<port>/api/v1/security-events `
  --api-key-env CONSHIELD_RUNTIME_COLLECTOR_API_KEY
```

Local one-fixture replay without Fedora:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 -NoSubmit
```

See [FALCO_RUNTIME_SENSOR.md](FALCO_RUNTIME_SENSOR.md) for the v1 local replay, Fedora helper, and evidence export workflow.

Implemented:

- Falco-compatible JSON ingestion;
- runtime mapping baseline;
- RTE-001 alert/incident correlation;
- deterministic runtime event identity.

Not implemented:

- Kubernetes DaemonSet/Operator;
- automatic container response;
- Falcosidekick;
- runtime rule management UI.

## Real Fedora Deployment

The repository now includes `deploy/falco-linux` and a validated Fedora 44 deployment. Falco 0.44.1 uses the BTF `modern_ebpf` engine, writes one JSON object per line to a protected log, and is followed by a non-root RuntimeCollector systemd service.

RuntimeCollector accepts `CONSHIELD_ENDPOINT` for the dedicated sensor environment file and retains `CONSHIELD_BASE_URL` compatibility. Its stopgap source-specific credential is stored in `CONSHIELD_RUNTIME_COLLECTOR_API_KEY` and never appears in `ExecStart`. The general ingestion key cannot authorize the reserved runtime source.

Sensor inventory v1 supports sensor-bound runtime credentials. An enrolled collector sends public `CONSHIELD_SENSOR_ID` and `CONSHIELD_SENSOR_CREDENTIAL_ID` identifiers with its protected credential and posts a bounded heartbeat to `/api/v1/sensors/heartbeat`. The server stores only the credential SHA-256 verifier. Heartbeats update inventory timestamps only and never create security events, outbox messages, alerts, or incidents.

`ExternalEventIngestion:AllowLegacyRuntimeCollectorCredential` temporarily preserves the existing shared runtime key for requests without sensor identity headers. A request that includes either sensor header is always validated as sensor-bound and never falls back to the legacy key. After the Fedora sensor is provisioned and verified, disable the fallback and remove the old shared key from central configuration.

File input is read with a bounded line reader. Follow mode keeps its current offset, reads appended data once, and resets only after the configured `copytruncate` log rotation shrinks or rewrites the current file.

The safe demo rule `ConShield Safe Demo Shell in Container` is container-scoped and matches only the explicit harmless marker `conshield-falco-demo`. It maps to the existing `shell-in-container` baseline and RTE-001. The observed rootless Podman event included container ID, process name, event type, and user name; container name and image repository were unavailable.

See [REAL_FALCO_FEDORA_DEPLOYMENT.md](REAL_FALCO_FEDORA_DEPLOYMENT.md) for installation, rollback, verification, and limitations.
