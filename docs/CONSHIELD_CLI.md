# ConShield CLI / Agent v1

`ConShield.Cli` is a unified local command-line entry point for existing ConShield demo and operator workflows.

It is intentionally a thin v1 wrapper around the existing PowerShell scripts. The scripts remain supported and are not replaced. The CLI uses process argument arrays, not shell command strings, when forwarding user-supplied values.

## Commands

```powershell
dotnet run --project .\src\ConShield.Cli -- --help

dotnet run --project .\src\ConShield.Cli -- validate

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldFullValidation.ps1

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\New-ConShieldDemoReleasePack.ps1

dotnet run --project .\src\ConShield.Cli -- demo readiness

dotnet run --project .\src\ConShield.Cli -- demo seed

dotnet run --project .\src\ConShield.Cli -- demo reset --confirm

dotnet run --project .\src\ConShield.Cli -- scan image `
  --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json `
  --no-submit

dotnet run --project .\src\ConShield.Cli -- scan image `
  --image alpine:3.19 `
  --live-trivy `
  --no-submit

dotnet run --project .\src\ConShield.Cli -- gate image `
  --image demo/insecure-api:latest `
  --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json `
  --fail-on never `
  --report .\artifacts\local\cicd-gate-report.md `
  --no-submit

dotnet run --project .\src\ConShield.Cli -- gate image `
  --image alpine:3.19 `
  --live-trivy `
  --fail-on block `
  --no-submit

dotnet run --project .\src\ConShield.Cli -- run protected `
  --image demo/insecure-api:latest `
  --container-name conshield-demo-insecure `
  --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json `
  --no-run `
  --no-submit

dotnet run --project .\src\ConShield.Cli -- lifecycle replay `
  --from-docker-events-json .\tests\TestData\DockerEvents\container-lifecycle-events.json `
  --no-submit

dotnet run --project .\src\ConShield.Cli -- lifecycle watch `
  --duration-seconds 30 `
  --no-submit

dotnet run --project .\src\ConShield.Cli -- sensor replay `
  --demo-signature `
  --no-submit

dotnet run --project .\src\ConShield.Cli -- evidence export `
  --output .\artifacts\local\defense-evidence-cli.md
```

## Script mapping

| CLI command | Existing script |
| --- | --- |
| `validate` | `Test-ConShieldSiemRules.ps1`, `Test-ConShieldContainerPolicy.ps1`, `Test-ConShieldSensorRegistry.ps1` |
| `demo readiness` | `Test-ConShieldDemoReadiness.ps1` |
| `demo seed` | `Seed-ConShieldDemoData.ps1` |
| `demo reset --confirm` | `Reset-ConShieldLocalDemoData.ps1 -ConfirmReset` |
| `scan image` | `Invoke-ConShieldImageScan.ps1`; fixture-first, with optional live Trivy mode |
| `gate image` | Built-in CI/CD image gate for fixture scan result + container policy-as-code; optional live Trivy mode |
| `run protected` | `Invoke-ConShieldProtectedRun.ps1` |
| `lifecycle replay` | Built-in deterministic Docker lifecycle fixture replay through existing external ingestion |
| `lifecycle watch` | Optional bounded live Docker event watch; no-submit by default and not required for CI |
| `sensor replay` | `Replay-ConShieldFalcoRuntimeEvent.ps1` |
| `evidence export` | `Export-ConShieldDefenseEvidence.ps1` |

## Full validation wrapper

Use the full validation script before a stabilization/demo handoff:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldFullValidation.ps1
```

The default mode validates repository contracts, config files, CLI commands, scripts, deterministic fixtures, `/Demo` command coverage, evidence sections, and security guardrails. It does not require live Web/API, live Docker execution, live Trivy DB/network, real Fedora/Falco, external internet, browser login, real certificates, private keys, signing keys, or real secrets. The complete checklist is in [CONSHIELD_FULL_VALIDATION_CHECKLIST.md](CONSHIELD_FULL_VALIDATION_CHECKLIST.md).

## Demo release packaging

Create a local gitignored release pack with the published CLI, safe docs, default configs, validation scripts, and a generated release README:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\New-ConShieldDemoReleasePack.ps1
```

The output folder is `artifacts/local/conshield-demo-release-pack`, and the default archive is `artifacts/local/conshield-demo-release-pack.zip`. Packaging is script-based in v1; the CLI command surface is unchanged. Details are in [RELEASE_AND_DEMO_PACKAGING.md](RELEASE_AND_DEMO_PACKAGING.md).

## Guided demo seed

Prepare a meaningful local dashboard and evidence path with one safe command after the local Web/API stack is running:

```powershell
dotnet run --project .\src\ConShield.Cli -- demo seed
```

The command wraps `scripts/Seed-ConShieldDemoData.ps1`, which creates or reuses deterministic IMG, POL, LIFE, RTE, SENSOR, and SIGN demo data. It does not reset data by default; pass `--reset-first` only when you want an explicit confirmed reset before seeding. The walkthrough is documented in [GUIDED_DEMO_SCENARIO.md](GUIDED_DEMO_SCENARIO.md).

## Safety rules

- `demo reset` requires explicit `--confirm`.
- Protected container execution remains opt-in with `--execute`; fixture validation should use `--no-run --no-submit`.
- `Block` decisions are still enforced by the underlying protected-run script.
- CI/CD image gate uses deterministic fixture input, returns documented exit codes, and writes sanitized reports only when requested.
- Live Trivy scan/gate is optional/manual, requires local Trivy and image access, cannot be mixed with `--from-trivy-json`, and is not required by full validation.
- Docker lifecycle replay is fixture-first for CI; `lifecycle watch` is available as an optional manual command and is not required by full validation.
- Docker lifecycle watch is optional/manual, bounded by duration and max-events, and defaults to no-submit.
- CI-safe commands use fixtures and do not require real Fedora/Falco, live Docker run, live Trivy DB/network, external internet, real certificates, private keys, real signing keys, or real secrets.
- The CLI must not print API keys, passwords, connection strings, environment values, raw Trivy JSON, raw runtime payload JSON, raw `AdditionalDataJson`, Docker logs, screenshots, certificates, private keys, signing keys, or generated local artifacts.
- Generated evidence and published binaries should stay under ignored `artifacts/local/`.

## Optional publish

```powershell
dotnet publish .\src\ConShield.Cli -c Release -o .\artifacts\local\conshieldctl
```

Do not commit published binaries.
