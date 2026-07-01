# CI/CD Container Gate v1

CI/CD Container Gate v1 turns a deterministic image scan result plus ConShield container policy-as-code into a pipeline-friendly decision.

Flow:

```text
container image / scan result
→ ConShield policy-as-code
→ Allow / Warn / Block
→ deterministic CI exit code
→ sanitized Markdown report
```

The default local path uses committed fixtures and does not require live Trivy DB/network, live Docker run, Fedora/Falco, external internet, Kubernetes, mTLS, real certificates, private keys, signing keys, or secrets.

## Command

```powershell
dotnet run --project .\src\ConShield.Cli -- gate image `
  --image demo/insecure-api:latest `
  --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json `
  --fail-on warn `
  --report .\artifacts\local\cicd-gate-report.md `
  --no-submit
```

Options:

| Option | Purpose |
| --- | --- |
| `--image <image>` | Image reference shown in safe gate output. |
| `--from-trivy-json <path>` | Deterministic Trivy-compatible fixture input. |
| `--live-trivy` | Optional manual live Trivy mode. Cannot be combined with `--from-trivy-json`. |
| `--trivy-path <path>` | Optional Trivy executable path for live mode. |
| `--timeout-seconds <n>` | Bounded live Trivy timeout. |
| `--policy-config <path>` | Optional policy config path. Defaults to `config/container-policy.default.json`. |
| `--fail-on block\|warn\|never` | Controls CI failure threshold. Defaults to `block`. |
| `--report <path>` | Optional sanitized Markdown report path. |
| `--json-report <path>` | Optional compact sanitized JSON report path. |
| `--no-submit` | Explicit fixture-only mode. This is the default CI-safe posture. |

`--submit` is intentionally not supported in v1. Use existing image scan or protected-run workflows for ingestion. The gate remains focused on deterministic CI behavior.

## Optional live Trivy gate

Fixture mode remains the CI/full-validation default. For a local manual smoke when Trivy and image access are available:

```powershell
dotnet run --project .\src\ConShield.Cli -- gate image `
  --image alpine:3.19 `
  --live-trivy `
  --fail-on block `
  --no-submit
```

If Trivy is unavailable, the gate fails safely with exit code `3`:

```text
Trivy: unavailable
Hint: install Trivy or use --from-trivy-json fixture mode.
```

The live gate parses Trivy JSON through the existing parser and evaluates the same container policy-as-code. It does not print raw Trivy JSON, Docker logs, raw payload JSON, `AdditionalDataJson`, secrets, API keys, connection strings, environment values, certificates, private keys, signing keys, screenshots, or generated local artifacts.

## Exit code contract

| Decision | `--fail-on block` | `--fail-on warn` | `--fail-on never` |
| --- | ---: | ---: | ---: |
| `Allow` | `0` | `0` | `0` |
| `Warn` | `0` | `1` | `0` |
| `Block` | `1` | `1` | `0` |

General exit codes:

| Exit code | Meaning |
| ---: | --- |
| `0` | Gate passed. |
| `1` | Gate failed due to policy decision. |
| `2` | Usage, config, or input error. |
| `3` | Infrastructure error, for example unsupported submit mode. |

## Safe examples

Clean fixture:

```powershell
dotnet run --project .\src\ConShield.Cli -- gate image `
  --image demo/clean-api:latest `
  --from-trivy-json .\tests\TestData\Trivy\clean-image-scan.json `
  --fail-on block `
  --no-submit
```

Warn fixture that does not fail unless the pipeline chooses `--fail-on warn`:

```powershell
dotnet run --project .\src\ConShield.Cli -- gate image `
  --image demo/warn-api:latest `
  --from-trivy-json .\tests\TestData\Trivy\warn-image-scan.json `
  --fail-on block `
  --no-submit
```

Block fixture for evidence/demo without failing readiness:

```powershell
dotnet run --project .\src\ConShield.Cli -- gate image `
  --image demo/insecure-api:latest `
  --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json `
  --fail-on never `
  --report .\artifacts\local\cicd-gate-report.md `
  --no-submit
```

Intentional failing gate:

```powershell
dotnet run --project .\src\ConShield.Cli -- gate image `
  --image demo/insecure-api:latest `
  --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json `
  --fail-on block `
  --no-submit
```

Expected: exit code `1`.

## GitHub Actions example

Use deterministic fixture mode in repository CI without making this repository intentionally fail:

```yaml
name: container-gate

on:
  pull_request:

jobs:
  conshield-container-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '8.0.x'
      - run: dotnet restore ConShield.sln
      - run: dotnet build ConShield.sln --configuration Release --no-restore
      - name: ConShield CI/CD image gate
        run: |
          dotnet run --project ./src/ConShield.Cli --configuration Release --no-build -- gate image \
            --image demo/clean-api:latest \
            --from-trivy-json ./tests/TestData/Trivy/clean-image-scan.json \
            --fail-on block \
            --no-submit
```

For a real project, replace the fixture path with a sanitized scan result generated earlier in the pipeline. Do not upload raw scanner JSON or generated local reports unless your retention and redaction rules allow it.

## Report safety

Markdown and JSON reports include only safe summary fields: image reference, policy decision, matched rule IDs, severity counts, policy config metadata, and report hash. They do not include raw scanner JSON, raw event payload JSON, raw additional data, secrets, environment variables, Docker logs, certificates, private keys, signing keys, screenshots, or generated local artifacts.

Keep generated reports under `artifacts/local/` for local demos. That path is ignored by Git.
