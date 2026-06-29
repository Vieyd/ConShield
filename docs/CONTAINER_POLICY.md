# ConShield Container Policy-as-Code

ConShield protected container run uses a committed policy-as-code file:

```text
config/container-policy.default.json
```

The default policy keeps the current demo behavior:

- critical image findings produce `Block`;
- high findings without critical findings produce `Warn`;
- clean fixtures produce `Allow`.

Optional local overrides can use:

```text
config/container-policy.local.json
```

The local override is ignored by Git and must not contain secrets, API keys, passwords, connection strings, tokens, environment values, raw Trivy JSON, raw event payload JSON, raw `AdditionalDataJson`, Docker logs, screenshots, or generated local artifacts.

## Validate policy

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldContainerPolicy.ps1
```

The validator is deterministic and does not require live Trivy DB, network access, Docker container execution, Fedora/Falco, external internet, or real credentials.

## Decision precedence

When multiple rules match, ConShield uses this precedence:

```text
Block > Warn > Allow
```

If no rule matches, `defaultDecision` is used. The committed default is `Allow`.

## Supported rule fields

| Field | Purpose |
|---|---|
| `id` | Stable policy rule identifier. Required and unique. |
| `enabled` | Optional; defaults to enabled. Disabled rules do not affect the decision. |
| `name` | Operator-facing rule name. |
| `match` | Deterministic match conditions such as `criticalVulnerabilitiesAtLeast` or `highVulnerabilitiesAtLeast`. |
| `decision` | `Allow`, `Warn`, or `Block`. |
| `reason` | Required for `Warn` and `Block` rules. |

Thresholds are non-negative integers. A rule must contain at least one meaningful match condition.

## Protected run evidence

`Invoke-ConShieldProtectedRun.ps1` includes safe policy metadata in output and POL events:

- policy decision;
- matched policy rule IDs;
- policy config source;
- policy config hash/version;
- reason summary.

Raw Trivy JSON, raw payload JSON, raw `AdditionalDataJson`, Docker logs, secrets, and local artifacts are not printed.

## Demo commands

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldContainerPolicy.ps1

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-ConShieldProtectedRun.ps1 `
  -Image demo/insecure-api:latest `
  -ContainerName conshield-demo-insecure `
  -FromTrivyJson .\tests\TestData\Trivy\sample-image-scan.json `
  -NoRun `
  -NoSubmit
```
