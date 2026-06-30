# ConShield CLI / Agent v1

`ConShield.Cli` is a unified local command-line entry point for existing ConShield demo and operator workflows.

It is intentionally a thin v1 wrapper around the existing PowerShell scripts. The scripts remain supported and are not replaced. The CLI uses process argument arrays, not shell command strings, when forwarding user-supplied values.

## Commands

```powershell
dotnet run --project .\src\ConShield.Cli -- --help

dotnet run --project .\src\ConShield.Cli -- validate

dotnet run --project .\src\ConShield.Cli -- demo readiness

dotnet run --project .\src\ConShield.Cli -- demo reset --confirm

dotnet run --project .\src\ConShield.Cli -- scan image `
  --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json `
  --no-submit

dotnet run --project .\src\ConShield.Cli -- gate image `
  --image demo/insecure-api:latest `
  --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json `
  --fail-on never `
  --report .\artifacts\local\cicd-gate-report.md `
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
| `demo reset --confirm` | `Reset-ConShieldLocalDemoData.ps1 -ConfirmReset` |
| `scan image` | `Invoke-ConShieldImageScan.ps1` |
| `gate image` | Built-in CI/CD image gate for fixture scan result + container policy-as-code |
| `run protected` | `Invoke-ConShieldProtectedRun.ps1` |
| `lifecycle replay` | Built-in deterministic Docker lifecycle fixture replay through existing external ingestion |
| `sensor replay` | `Replay-ConShieldFalcoRuntimeEvent.ps1` |
| `evidence export` | `Export-ConShieldDefenseEvidence.ps1` |

## Safety rules

- `demo reset` requires explicit `--confirm`.
- Protected container execution remains opt-in with `--execute`; fixture validation should use `--no-run --no-submit`.
- `Block` decisions are still enforced by the underlying protected-run script.
- CI/CD image gate uses deterministic fixture input, returns documented exit codes, and writes sanitized reports only when requested.
- Docker lifecycle replay is fixture-first; `lifecycle watch` is intentionally skipped in v1 to avoid live Docker dependencies in CI.
- CI-safe commands use fixtures and do not require real Fedora/Falco, live Docker run, live Trivy DB/network, external internet, real certificates, private keys, real signing keys, or real secrets.
- The CLI must not print API keys, passwords, connection strings, environment values, raw Trivy JSON, raw runtime payload JSON, raw `AdditionalDataJson`, Docker logs, screenshots, certificates, private keys, signing keys, or generated local artifacts.
- Generated evidence and published binaries should stay under ignored `artifacts/local/`.

## Optional publish

```powershell
dotnet publish .\src\ConShield.Cli -c Release -o .\artifacts\local\conshieldctl
```

Do not commit published binaries.
