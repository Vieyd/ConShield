# ConShield Full Validation Checklist

This checklist is the stabilization pass for the integrated ConShield demo/product surface after PRs #51-#71. It is designed for diploma/demo preparation and for safe local regression checks.

Run the default deterministic validation command first:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldFullValidation.ps1
```

Expected default result:

```text
ConShield full validation
Repository: OK
Configuration: OK
CLI: OK
Scripts: OK
Fixtures: OK
Demo contract: OK
Evidence contract: OK
Security guardrails: OK
Result: PASS
```

The default command is CI-safe and does not require live Web/API, live Docker execution, live Trivy DB/network, real Fedora/Falco, external internet, browser login, real secrets, real certificates, private keys, or signing keys.

## 1. Local prerequisites

- Purpose: confirm that the checkout and local tooling can run the deterministic validation path.
- Commands:

```powershell
git status --short
dotnet --version
pwsh -NoProfile -Command '$PSVersionTable.PSVersion'
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldFullValidation.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\New-ConShieldDemoReleasePack.ps1
```

- Expected result: clean or understood git state; .NET and PowerShell are available; full validation prints `Result: PASS`; packaging creates `artifacts/local/conshield-demo-release-pack` and `artifacts/local/conshield-demo-release-pack.zip`.
- CI-safe: yes.
- Web/API required: no.
- Docker/Falco/Trivy network required: no.

## 2. Services / infrastructure

- Purpose: separate deterministic validation from optional local service smoke.
- Commands:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldDemoReadiness.ps1
```

- Expected result: local stack starts; readiness prints step-level `OK` statuses and `Result: PASS`.
- CI-safe: optional only; not required by the default full validation.
- Web/API required: yes for readiness.
- Docker/Falco/Trivy network required: Docker services are required; real Fedora/Falco and live Trivy DB/network are not required.

## 3. Configuration validation

- Purpose: validate committed SIEM rules, container policy-as-code, and sensor trust registry defaults.
- Commands:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldSiemRules.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldContainerPolicy.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldSensorRegistry.ps1
dotnet run --project .\src\ConShield.Cli -- validate
```

- Expected result: each command prints `Result: PASS`.
- CI-safe: yes.
- Web/API required: no.
- Docker/Falco/Trivy network required: no.

## 4. CLI validation

- Purpose: verify the unified CLI command surface remains coherent.
- Commands:

```powershell
dotnet run --project .\src\ConShield.Cli -- --help
dotnet run --project .\src\ConShield.Cli -- validate
```

- Expected result: help lists `validate`, `demo readiness`, `demo reset`, `scan image`, `run protected`, `sensor replay`, `lifecycle replay`, `gate image`, and `evidence export`; validate prints `Result: PASS`.
- CI-safe: yes.
- Web/API required: no.
- Docker/Falco/Trivy network required: no.

## 5. Image scanning

- Purpose: validate the deterministic image scan fixture path without live Trivy.
- Commands:

```powershell
dotnet run --project .\src\ConShield.Cli -- scan image `
  --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json `
  --no-submit
```

- Expected result: `SourceSystem: conshield.image-scanner`, expected rule `IMG-001`, `Ingestion: SKIP`, `Result: PASS`.
- CI-safe: yes.
- Web/API required: no with `--no-submit`.
- Docker/Falco/Trivy network required: no.

## 6. Protected container run

- Purpose: verify scan → policy → launch decision without starting a container.
- Commands:

```powershell
dotnet run --project .\src\ConShield.Cli -- run protected `
  --image demo/insecure-api:latest `
  --container-name conshield-demo-insecure `
  --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json `
  --no-run `
  --no-submit
```

- Expected result: policy decision is `Block`, launch is skipped, events are not submitted, `Result: PASS`.
- CI-safe: yes.
- Web/API required: no with `--no-submit`.
- Docker/Falco/Trivy network required: no.

## 7. CI/CD container gate

- Purpose: validate deterministic CI exit-code behavior for image policy decisions.
- Commands:

```powershell
dotnet run --project .\src\ConShield.Cli -- gate image `
  --image demo/clean-api:latest `
  --from-trivy-json .\tests\TestData\Trivy\clean-image-scan.json `
  --fail-on block `
  --no-submit
```

- Expected result: policy decision is `Allow`, gate is `PASS`, exit code is `0`, `Result: PASS`.
- CI-safe: yes.
- Web/API required: no.
- Docker/Falco/Trivy network required: no.

## 8. Docker lifecycle collector

- Purpose: map deterministic Docker-compatible fixture events to LIFE events without live Docker.
- Commands:

```powershell
dotnet run --project .\src\ConShield.Cli -- lifecycle replay `
  --from-docker-events-json .\tests\TestData\DockerEvents\container-lifecycle-events.json `
  --no-submit
```

- Expected result: `SourceSystem: conshield.docker-lifecycle-collector`, mapped lifecycle event types, `Ingestion: SKIP`, `Result: PASS`.
- CI-safe: yes.
- Web/API required: no with `--no-submit`.
- Docker/Falco/Trivy network required: no.

## 9. Falco/runtime replay

- Purpose: validate the Falco-compatible runtime event replay path without a Fedora VM.
- Commands:

```powershell
dotnet run --project .\src\ConShield.Cli -- sensor replay `
  --demo-signature `
  --no-submit
```

- Expected result: trusted demo sensor, valid demo signature, expected rule `RTE-001`, `Result: PASS`.
- CI-safe: yes.
- Web/API required: no with `--no-submit`.
- Docker/Falco/Trivy network required: no.

## 10. Sensor trust registry

- Purpose: validate known runtime sensor metadata and trust statuses.
- Commands:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldSensorRegistry.ps1
```

- Expected result: trusted, revoked, and disabled demo entries validate and command prints `Result: PASS`.
- CI-safe: yes.
- Web/API required: no.
- Docker/Falco/Trivy network required: no.

## 11. Sensor trust enforcement

- Purpose: verify that trust status affects deterministic signals.
- Commands:

```powershell
dotnet run --project .\src\ConShield.Cli -- sensor replay --simulate-unknown-sensor --no-submit
dotnet run --project .\src\ConShield.Cli -- sensor replay --simulate-revoked-sensor --no-submit
```

- Expected result: unknown sensor expects `SENSOR-001`; revoked sensor expects `SENSOR-002`; both print `Result: PASS`.
- CI-safe: yes.
- Web/API required: no with `--no-submit`.
- Docker/Falco/Trivy network required: no.

## 12. Signed sensor events

- Purpose: verify signature metadata modes without real signing keys.
- Commands:

```powershell
dotnet run --project .\src\ConShield.Cli -- sensor replay --demo-signature --no-submit
dotnet run --project .\src\ConShield.Cli -- sensor replay --simulate-missing-signature --no-submit
dotnet run --project .\src\ConShield.Cli -- sensor replay --simulate-invalid-signature --no-submit
dotnet run --project .\src\ConShield.Cli -- sensor replay --simulate-stale-signature --no-submit
```

- Expected result: valid signature expects `RTE-001`; missing expects `SIGN-001`; invalid expects `SIGN-002`; stale expects `SIGN-003`; each command prints `Result: PASS`.
- CI-safe: yes.
- Web/API required: no with `--no-submit`.
- Docker/Falco/Trivy network required: no.

## 13. SIEM rules and incidents

- Purpose: confirm correlation rules for IMG, POL, RTE, LIFE, SENSOR, and SIGN signals remain configured.
- Commands:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldSiemRules.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Run-ConShieldDefenseScenario.ps1
```

- Expected result: rules validation prints `Result: PASS`; the defense scenario prints `Result: PASS` when local services are available.
- CI-safe: rules validation is CI-safe; scenario is local-service smoke.
- Web/API required: not for rules validation; yes for scenario.
- Docker/Falco/Trivy network required: no real Fedora/Falco or live Trivy DB/network.

## 14. Operator workflow

- Purpose: verify the demo path from Security Summary → SIEM alert → incident → source event → closure/evidence.
- Commands:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Run-ConShieldDefenseScenario.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Export-ConShieldDefenseEvidence.ps1 `
  -OutputMarkdownPath .\artifacts\local\defense-evidence.md
```

- Expected result: scenario and evidence export print `Result: PASS`; evidence includes Operator Workflow.
- CI-safe: optional local-service smoke.
- Web/API required: yes.
- Docker/Falco/Trivy network required: no real Fedora/Falco or live Trivy DB/network.

## 15. Runtime Sensor Health

- Purpose: verify runtime source health/trust/signature fields are represented by existing events.
- Commands:

```powershell
dotnet run --project .\src\ConShield.Cli -- sensor replay --demo-signature --no-submit
```

Optional Web route:

```text
http://127.0.0.1:5080/RuntimeSensors
```

- Expected result: replay prints `Result: PASS`; Web route renders runtime source health when local services are running.
- CI-safe: replay is CI-safe; Web route is optional.
- Web/API required: no for replay; yes for route check.
- Docker/Falco/Trivy network required: no.

## 16. Evidence export

- Purpose: confirm the evidence exporter contains all current evidence sections and writes only ignored local reports.
- Commands:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Export-ConShieldDefenseEvidence.ps1 `
  -OutputMarkdownPath .\artifacts\local\defense-evidence.md
```

- Expected result: `Result: PASS` when local services are available; generated Markdown stays under `artifacts/local/`.
- CI-safe: optional local-service smoke.
- Web/API required: yes for live database evidence.
- Docker/Falco/Trivy network required: no real Fedora/Falco or live Trivy DB/network.

## 17. Demo walkthrough

- Purpose: verify `/Demo` remains a read-only map of safe commands and links.
- Commands:

```text
http://127.0.0.1:5080/Demo
```

- Expected result: page shows readiness, reset, image scan, protected run, CI/CD gate, Docker lifecycle collector, Falco/signed sensor replay, evidence export, and links to Security Summary, Security Events, SIEM, Incidents, and Runtime Sensor Health. It does not run shell scripts from the browser.
- CI-safe: route contract is covered by tests; live route is optional.
- Web/API required: yes for live page.
- Docker/Falco/Trivy network required: no.

## 18. README/docs consistency

- Purpose: keep bilingual README and docs aligned with the current command surface.
- Commands:

```powershell
dotnet test .\ConShield.sln --configuration Release --no-build --filter FullIntegrationContractTests
```

- Expected result: contract tests pass; README keeps English first and Russian second; README docs links point to existing files.
- CI-safe: yes.
- Web/API required: no.
- Docker/Falco/Trivy network required: no.

## 19. Security guardrails

- Purpose: prevent generated artifacts, secrets, raw payloads, and local logs from entering git.
- Commands:

```powershell
gitleaks git --redact --no-banner
gitleaks protect --staged --redact --no-banner
git diff --check
```

- Expected result: no leaks, no staged leaks, no whitespace errors; `.gitignore` protects `artifacts/local/`, `artifacts/local/conshield-demo-release-pack/`, `artifacts/local/conshield-demo-release-pack*.zip`, published CLI outputs, logs, env files, local appsettings, and build outputs.
- CI-safe: yes.
- Web/API required: no.
- Docker/Falco/Trivy network required: no.

## 20. Known intentionally optional checks

The following checks are intentionally outside the default full validation because they depend on external state, privileged hosts, live services, or future product scope:

- real Fedora/Falco deployment;
- live Docker run with `--execute`;
- live Trivy DB/network scan;
- Kubernetes/admission controller;
- full mTLS;
- real certificates, private keys, and signing keys;
- external internet-dependent runtime checks;
- browser login automation;
- production secret rotation.

Use the feature-specific operational docs for these checks when needed:

- [`REAL_FALCO_FEDORA_DEPLOYMENT.md`](REAL_FALCO_FEDORA_DEPLOYMENT.md)
- [`FALCO_RUNTIME_SENSOR.md`](FALCO_RUNTIME_SENSOR.md)
- [`CONTAINER_IMAGE_SCANNING.md`](CONTAINER_IMAGE_SCANNING.md)
- [`CONTAINER_POLICY.md`](CONTAINER_POLICY.md)
- [`CICD_CONTAINER_GATE.md`](CICD_CONTAINER_GATE.md)
- [`DOCKER_LIFECYCLE_COLLECTOR.md`](DOCKER_LIFECYCLE_COLLECTOR.md)

## Known follow-up work

- No blocking major integration issue is known from this stabilization pass.
- The default full validation intentionally stays offline/deterministic. Live Web/API readiness and evidence export remain covered by `Test-ConShieldDemoReadiness.ps1`, `Start-ConShield.ps1`, and optional manual smoke commands.
