# Guided Demo Scenario

This guide gives operators one safe, repeatable path to prepare meaningful local ConShield demo data before a defense or portfolio walkthrough.

The seed workflow is intentionally local-first. It uses committed deterministic fixtures and existing ConShield workflows; it does not require real Fedora/Falco, live Docker execution, live Trivy DB/network, Kubernetes, full mTLS, external internet, real certificates, private keys, signing keys, or secrets.

## What the seed creates

`scripts/Seed-ConShieldDemoData.ps1` creates or reuses deterministic demo evidence for:

- image scan alert `IMG-001`;
- protected run policy alert `POL-001`;
- Docker lifecycle alerts `LIFE-001` and `LIFE-002`;
- runtime/Falco-compatible alert `RTE-001`;
- sensor trust alerts `SENSOR-001` and `SENSOR-002`;
- signed sensor event alerts `SIGN-001`, `SIGN-002`, and `SIGN-003`;
- linked SIEM alerts, incidents, runtime sensor health, dashboard posture, and evidence-export-ready data.

The script is idempotent for local demos: reruns reuse deterministic event identifiers and tolerate already-created records through the existing ingestion and scenario paths.

## Prerequisites

Start the local stack first:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit
```

If the Web/API route is unavailable, the seed fails safe and prints this same hint instead of hiding the root cause.

## Optional clean reset

The seed does not reset data by default. To reset demo-generated operational data first, use an explicit confirmed reset:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Seed-ConShieldDemoData.ps1 -ResetFirst
```

Use the reset only for a clean rehearsal. It keeps source files, configs, Docker volumes, demo-user setup, and local secrets untouched.

## One-command guided seed

Run:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Seed-ConShieldDemoData.ps1
```

Optional CLI wrapper:

```powershell
dotnet run --project .\src\ConShield.Cli -- demo seed
```

Expected summary:

```text
ConShield demo data seed
Prerequisites: OK
Optional reset: SKIP
Runtime/Falco replay: OK
Sensor trust unknown: OK
Sensor trust revoked: OK
Signed sensor missing: OK
Signed sensor invalid: OK
Signed sensor stale: OK
Defense scenario correlation: OK
Image scan: OK
CI/CD gate finding: OK
Protected run decision: OK
Docker lifecycle replay: OK
Evidence-ready data: OK
Dashboard-ready data: OK
Result: PASS
```

The script captures child process output and prints only sanitized step-level status, failed step details, and safe hints.

## Guided walkthrough after seed

Open:

```text
http://127.0.0.1:5080/Dashboard
```

Recommended defense flow:

1. Show dashboard status cards and latest sanitized activity.
2. Open Security Summary.
3. Open SIEM and point to `IMG-001`, `POL-001`, `LIFE-001`, `LIFE-002`, `RTE-001`, `SENSOR-001`, `SENSOR-002`, `SIGN-001`, `SIGN-002`, and `SIGN-003`.
4. Open linked incidents and source Security Events.
5. Open Runtime Sensor Health to show source status, trust status, and signature state.
6. Export evidence.
7. Run readiness or full validation if you need a final confidence check.

Useful routes:

```text
http://127.0.0.1:5080/Reports/SecuritySummary
http://127.0.0.1:5080/SecurityEvents
http://127.0.0.1:5080/Siem
http://127.0.0.1:5080/Incidents
http://127.0.0.1:5080/RuntimeSensors
http://127.0.0.1:5080/Demo
```

## Evidence export

The seed can export a safe Markdown evidence pack when local services are available:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Export-ConShieldDefenseEvidence.ps1
```

Generated evidence stays under ignored local artifacts and must not be committed.

## Troubleshooting

| Symptom | Safe hint |
| --- | --- |
| Web/API unavailable | Run `pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit`. |
| A seed step reports `FAIL` | Rerun the named script from the hint after the local stack is healthy. |
| Evidence export fails | Confirm Web is running, then rerun the seed or evidence export. |
| Dashboard redirects to login | Sign in with the local demo user, then reopen `/Dashboard`. |
| Repeated seed creates duplicates warning | Deterministic ingestion may report duplicates; this is expected for reruns and keeps the scenario safe. |

## Safety guarantees

- The Web UI and `/Dashboard` only show copy/paste command references; they do not run local scripts.
- The seed does not perform reset unless `-ResetFirst` is explicitly passed.
- The seed does not require live Docker run, live Trivy DB/network, real Fedora/Falco, external internet, real certificates/private keys/signing keys, or secrets.
- The seed must not print API keys, passwords, connection strings, environment values, raw Trivy JSON, raw Docker event JSON, raw runtime payload JSON, raw `AdditionalDataJson`, Docker logs, screenshots, or generated local artifact contents.
