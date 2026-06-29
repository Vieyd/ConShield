# ConShield SIEM Rules

ConShield SIEM correlation rules for the local demo are configurable through:

```text
config/siem-rules.default.json
```

The default file is committed and validated in CI. A local override may be created as:

```text
config/siem-rules.local.json
```

The local override is ignored by Git and must not contain secrets, API keys, passwords, connection strings, tokens, environment values, raw event payload JSON, raw `AdditionalDataJson`, Docker logs, screenshots, or generated local artifacts.

## Validate rules

Run the offline validator:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldSiemRules.ps1
```

Expected successful output:

```text
ConShield SIEM rules validation
Config: config/siem-rules.default.json
Rules: 5
Enabled: 5
Disabled: 0
IMG-001: OK
POL-001: OK
RTE-001: OK
LIFE-001: OK
LIFE-002: OK
Result: PASS
```

The validator is deterministic and does not require PostgreSQL, RabbitMQ, MongoDB, Docker execution, Fedora/Falco, live Trivy DB, network access, or real credentials.

## Supported fields

Each rule supports these fields:

| Field | Purpose |
|---|---|
| `id` | Stable rule identifier. Configurable SIEM rules v1 supports `IMG-001`, `POL-001`, `RTE-001`, `LIFE-001`, and `LIFE-002`. |
| `name` | Safe display name used for alerts and incidents. |
| `description` | Safe operator-facing description of the rule purpose. |
| `enabled` | Optional; defaults to `true`. Disabled rules do not create alerts or incidents. |
| `sourceSystem` / `sourceSystems` | Exact source-system match. Wildcards are rejected. |
| `eventType` / `eventTypes` | Exact external event type match. Wildcards are rejected. |
| `minimumSeverity` | Minimum event severity: `Info`, `Warning`, `High`, or `Critical`. |
| `threshold` | Positive integer threshold used by the rule family. |
| `timeWindowMinutes` | Positive integer lookback window. |
| `groupingKey` | Documented grouping strategy for deterministic trigger keys. |
| `alertSeverity` | Alert severity created by the rule. Runtime rules may preserve critical source severity. |
| `incident.create` | Whether a matching alert creates an incident. |
| `incident.severity` | Incident severity when an incident is created. |

Unknown fields fail validation so rule behavior stays deterministic.

## Default rule mapping

| Rule | Source | Event type | Behavior |
|---|---|---|---|
| `IMG-001` | `conshield.image-scanner` | `container.image.scan.completed` | Creates a critical alert/incident when critical image scan findings meet the threshold. |
| `POL-001` | `conshield.container-guard` | `container.image.policy.evaluated` | Creates a critical alert/incident when the policy decision is `Block`. |
| `RTE-001` | `conshield.falco-runtime-collector`, `conshield.falco-linux-sensor` | `container.runtime.*` approved mappings listed in config | Creates a high/critical alert/incident for approved Falco-compatible runtime mappings. |
| `LIFE-001` | `conshield.sensor-lifecycle` | `sensor.revoked` | Creates a warning alert/incident when a sensor identity is revoked. |
| `LIFE-002` | `conshield.sensor-lifecycle` | `sensor.credential.rotated`, `sensor.credential.revoked` | Creates a warning alert/incident after repeated credential lifecycle changes for one sensor. |

Legacy training rules such as `BF-001`, `UE-001`, and `CR-001` remain built-in in this version.

## Runtime fallback behavior

At runtime, ConShield tries to load `config/siem-rules.local.json` first when it exists, then `config/siem-rules.default.json`. If no config is available or the config cannot be safely validated, the correlation service falls back to built-in defaults that preserve the committed demo behavior.

Use `Test-ConShieldSiemRules.ps1` before demos and PRs to catch invalid config early.

## Evidence and demo integration

The defense evidence exporter includes a `SIEM Rules Evidence` section with:

- config source;
- number of rules loaded;
- enabled and disabled counts;
- configured rule IDs;
- sanitized rule summary rows.

The demo readiness check runs the SIEM rules validator as a separate step and reports `SIEM rules validation: PASS` or a safe failed-step hint.
