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
- expected event types
- last seen and event counts
- related `RTE-001` alerts and incidents

Unknown runtime sources are shown as `Unknown`. The local demo Falco source `conshield.falco-linux-sensor` maps to `demo-falco-linux-01` with `Trusted` status.

## Local demo flow

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldSensorRegistry.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Export-ConShieldDefenseEvidence.ps1 `
  -OutputMarkdownPath .\artifacts\local\defense-evidence-sensor-trust.md
```

The replay script prints only a safe sensor identity summary: `SensorId`, trust status, source system, mapped runtime type, expected rule, and result.

## Evidence

The defense evidence exporter includes `Sensor Trust Evidence` with registry counts and sanitized sensor metadata. It excludes raw runtime payload JSON, raw additional data, local secrets, logs, real certificate material, private keys, screenshots, and generated artifacts from source control.
