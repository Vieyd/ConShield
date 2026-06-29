# Sensor Trust Registry

The sensor trust registry is a lightweight, config-backed inventory for known runtime sensor sources. It prepares ConShield for future certificate-bound enrollment without adding mTLS or certificate issuance in this PR.

## Config files

- Default committed config: `config/sensor-registry.default.json`
- Optional local override: `config/sensor-registry.local.json`

The local override is ignored by Git. Do not store real certificates, private keys, passwords, API keys, connection strings, tokens, environment values, raw runtime payloads, or generated artifacts in either file.

## Validation

Run the deterministic validator from the repository root:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldSensorRegistry.ps1
```

The validator checks:

- supported config version;
- required and unique `sensorId`;
- required `sourceSystem`;
- status in `Trusted`, `Unknown`, `Revoked`, or `Disabled`;
- safe display name and environment fields;
- optional expected event types are non-empty strings;
- fingerprint field does not contain certificate or private key blocks;
- unknown fields fail with safe diagnostics.

## Trust statuses

| Status | Meaning |
| --- | --- |
| `Trusted` | Known and expected runtime sensor source. |
| `Unknown` | Source is not present in the registry or explicitly marked unknown. |
| `Revoked` | Sensor identity should no longer be trusted. |
| `Disabled` | Sensor is known but intentionally disabled. |

## Runtime Sensor Health

`/RuntimeSensors` enriches existing runtime/Falco event health with registry data:

- `SensorId`
- display name
- source system
- environment
- trust status
- enforcement action
- expected event types
- last seen and event counts
- related `RTE-001` alerts and incidents
- related `SENSOR-001` / `SENSOR-002` trust enforcement alerts

Unknown runtime sources are shown as `Unknown`. The local demo Falco sources `conshield.falco-linux-sensor` and `conshield.falco-runtime-collector` map to trusted synthetic registry entries.

## Trust enforcement

Sensor Trust Enforcement v1 makes trust status affect SIEM correlation while keeping ingestion deterministic and safe:

| Status | Enforcement action | SIEM behavior |
| --- | --- | --- |
| `Trusted` | `AcceptTrusted` | Normal runtime path; approved mappings can create `RTE-001`. |
| `Unknown` | `AcceptUnknownWithAlert` | Runtime event is accepted and flagged with deterministic `SENSOR-001`; no incident is created by default. |
| `Revoked` | `FlagRevokedWithAlert` | Runtime event is flagged with deterministic `SENSOR-002`; a critical incident is created. |
| `Disabled` | `FlagDisabledWithAlert` | Runtime event is flagged with deterministic `SENSOR-002`; a critical incident is created. |

This layer is intentionally not full mTLS. Future certificate-bound enrollment can tighten transport/authentication, but this PR keeps the local demo CI-safe and does not require real certificates, private keys, Fedora/Falco, live Docker, live Trivy DB, or external internet.

Simulate enforcement modes without submitting events:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 `
  -SimulateUnknownSensor `
  -NoSubmit

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 `
  -SimulateRevokedSensor `
  -NoSubmit

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 `
  -SimulateDisabledSensor `
  -NoSubmit
```

## Local demo flow

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldSensorRegistry.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Export-ConShieldDefenseEvidence.ps1 `
  -OutputMarkdownPath .\artifacts\local\defense-evidence-sensor-trust.md
```

The replay script prints only a safe sensor identity summary: `SensorId`, trust status, source system, mapped runtime type, expected rule, and result.

## Evidence

The defense evidence exporter includes `Sensor Trust Evidence` with registry counts and sanitized sensor metadata. It also includes `Sensor Trust Enforcement Evidence` with aggregate `SENSOR-001` / `SENSOR-002` counts and incidents. It excludes raw runtime payload JSON, raw additional data, local secrets, logs, real certificate material, private keys, screenshots, and generated artifacts from source control.
