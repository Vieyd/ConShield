# Operations and SIEM Runbook

## Purpose

This runbook describes how an `AdminIB` operator uses ConShield operational screens and SIEM lifecycle alerts during daily checks and investigations.

For a safe diploma/demo walkthrough, use [DEMO_EVIDENCE_PACK.md](DEMO_EVIDENCE_PACK.md) together with this runbook.

## Main screens

- Состояние системы: `/Operations/Health`
- Сводка безопасности: `/Reports/SecuritySummary`
- Security Events: `/SecurityEvents`
- Сенсоры: `/Sensors`
- Alerts / Incidents: use the existing Оповещения SIEM and incident registry pages in the app

## Normal daily check

1. Open Состояние системы.
2. Check sensor heartbeat state.
3. Check Security Events freshness.
4. Check outbox/inbox health.
5. Check lifecycle audit activity.
6. Open Сводка безопасности and export the Markdown handoff if the check needs to be attached to an incident or shift note.
7. Open Security Events using lifecycle quick filters if needed.

## Lifecycle Оповещения SIEM

### LIFE-001 — Sensor identity revoked

Meaning:

- a sensor identity was revoked;
- heartbeat/runtime events for this sensor should fail after revocation.

Operator actions:

1. Check whether the revocation was planned.
2. Open Сенсоры and confirm sensor status.
3. Open Security Events filtered by `conshield.sensor-lifecycle`.
4. Check the actor/requestedBy and affected public sensorId.
5. Create or update an incident if the action was not planned.

### LIFE-002 — Repeated sensor credential lifecycle changes

Meaning:

- multiple credential rotations/revocations happened for the same sensor in a short window.

Operator actions:

1. Check whether this was an expected maintenance window.
2. Review lifecycle events for the sensor.
3. Confirm whether the RuntimeCollector is still reporting.
4. Check for related incidents.
5. Escalate if repeated changes were not expected.

## Investigation flow

1. Start from Состояние системы.
2. Open related Security Events.
3. Filter by SourceSystem = `conshield.sensor-lifecycle`.
4. Use ExternalEventType to narrow the event.
5. Check Сенсоры/details.
6. Create an incident from a relevant security event or alert when needed.
7. Document the operator conclusion.

## Local login troubleshooting

Local Web login uses configured `DemoUsers`, not database user records. If `adminib` or `operator` cannot sign in after changing a local password, restart Web so the process reloads `appsettings.Development.json` or inherited environment variables.

Save `appsettings.Development.json` as UTF-8 for Cyrillic display names. Environment variables may override file values; if diagnostics JSON shows mojibake after setting PowerShell environment variables, prefer file-based UTF-8 config and restart Web.

In Development only, open:

```text
http://127.0.0.1:5080/Account/DemoUserDiagnostics
```

The diagnostics response is secret-free and shows only environment, configured demo-user count, user name, display name, role, `HasPassword`, and warnings. It does not show password values, password length, hashes, connection strings, cookies, tokens, API keys, or verifier values.

To test the real login form safely:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-LocalDemoUserPassword.ps1 -UserName adminib
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-LocalDemoLogin.ps1 -UserName adminib
```

The password verification script calls `/Account/DemoUserDiagnostics/VerifyPassword` in `Development` only and prints `password_match=True/False` without printing password values, length, hashes, cookies, tokens, API keys, verifier values, or connection strings. The login script checks diagnostics, submits the real login form, and probes `/Operations/Health` with the same session. It tolerates missing redirect headers and still relies on the authenticated health probe.

Troubleshooting matrix:

- Diagnostics shows `adminib` + `HasPassword=True`, `password_match=False`: the running Web process has a different configured password than the one entered.
- `password_match=True`, `login_result=failed`: the password is correct, but login form/session flow needs investigation.
- `password_match=True`, `login_result=success`, browser still fails: clear cookies or use incognito.
- Diagnostics endpoint unavailable: Web is not running in `Development`, or the wrong URL/port is used.

Stable local demo-user setup:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Set-LocalDemoUsers.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StopApps
pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-LocalDemoUserPassword.ps1 -UserName adminib
```

The helper prompts for demo passwords and stores them in Windows User/current-process environment variables only. It does not write repository files and does not print password values. `Start-ConShield.ps1` then passes `DemoUsers__*`, `ASPNETCORE_ENVIRONMENT=Development`, `ASPNETCORE_URLS=http://127.0.0.1:5080`, and `ConnectionStrings__DefaultConnection` explicitly to the Web child process.

After startup, trust the reported `Web port owner PID` as the real serving process. A different `Web launcher PID` is possible when `dotnet run` creates a child process; use `-StopApps` after config changes so stale Web/EventConsumer processes cannot keep old environment values.

Temporary shell-only placeholder configuration:

```powershell
$env:DemoUsers__0__UserName = "adminib"
$env:DemoUsers__0__Password = "CHANGE_ME"
$env:DemoUsers__0__DisplayName = "Администратор ИБ"
$env:DemoUsers__0__Role = "AdminIB"
```

Persistent local-only Windows user environment variables avoid retyping demo credentials for every run. Store only your private local value; never commit it and never paste it into chat, tickets, screenshots, logs, or GitHub:

```powershell
[Environment]::SetEnvironmentVariable("DemoUsers__0__UserName", "adminib", "User")
[Environment]::SetEnvironmentVariable("DemoUsers__0__Password", "<your-local-demo-password>", "User")
[Environment]::SetEnvironmentVariable("DemoUsers__0__DisplayName", "Администратор ИБ", "User")
[Environment]::SetEnvironmentVariable("DemoUsers__0__Role", "AdminIB", "User")

[Environment]::SetEnvironmentVariable("DemoUsers__1__UserName", "operator", "User")
[Environment]::SetEnvironmentVariable("DemoUsers__1__Password", "<your-local-demo-password>", "User")
[Environment]::SetEnvironmentVariable("DemoUsers__1__DisplayName", "Оператор", "User")
[Environment]::SetEnvironmentVariable("DemoUsers__1__Role", "Operator", "User")
```

Open a new PowerShell session after setting user-level environment variables, or set `$env:DemoUsers__...` in the current session as a temporary override. Stop old Web processes before retesting because a running `ConShield.Web` process keeps its previous configuration:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StopApps
pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-LocalDemoUserPassword.ps1 -UserName adminib
```

After changing config, restart Web. Environment variables may override `appsettings.Development.json`. If diagnostics and the scripts succeed but browser login still fails, use an incognito window or clear ConShield cookies. Do not paste passwords into chat, tickets, screenshots, logs, or committed files.

## Local synthetic demo scenarios

For a safe local walkthrough, an operator/developer can seed marked synthetic records with `tools/ConShield.DemoScenario` or use the safer validation wrapper `scripts/Validate-DemoScenario.ps1`. This is not a production remediation or sensor operation path; it does not touch Fedora services and does not publish RabbitMQ messages.

For a full defense walkthrough, prefer the one-command scenario runner. It prepares only safe local evidence and does not require a real Fedora VM:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Set-LocalDemoUsers.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Run-ConShieldDefenseScenario.ps1
```

The runner checks Web, PostgreSQL, RabbitMQ/EventConsumer/Mongo projection availability, then uses synthetic image-scan, policy-gate, runtime, and lifecycle signals to demonstrate `IMG-001`, `POL-001`, `RTE-001`, `LIFE-001`, and `LIFE-002`. PASS/WARN/FAIL interpretation: `PASS` means the required local evidence was demonstrated; `WARN` means the core evidence exists but an optional local service is missing/degraded; `FAIL` means the evidence could not be produced. Optional Markdown evidence can be written with `-OutputMarkdownPath .\artifacts\local\defense-scenario.md`; do not commit generated evidence, logs, screenshots, `.env` files, or local config.

After the runner finishes, open `/Operations/Health`, `/SecurityEvents`, `/Sensors`, `/RuntimeSensors`, `/SiemAlerts`, `/Incidents`, and `/Reports/SecuritySummary`. The runner and report output intentionally avoid raw JSON, `AdditionalDataJson`, connection strings, API keys, tokens, cookies, credentials, verifier values, and Fedora protected env contents.

## Demo readiness check

Before a defense or live demo, run the safe readiness check from the repository root:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldDemoReadiness.ps1
```

The check verifies Git awareness, Docker, PostgreSQL, RabbitMQ, MongoDB, demo users, Web, EventConsumer, the local defense scenario, Falco replay, Runtime Sensor Health, and defense evidence export. It does not require a real Fedora/Falco setup and writes generated evidence to `artifacts/local/demo-readiness-evidence.md` by default.

Useful optional switches:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldDemoReadiness.ps1 -SkipStartApps
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldDemoReadiness.ps1 -SkipScenario -SkipFalcoReplay
```

The script prints compact PASS/FAIL statuses and safe hints only. Do not commit generated evidence, local logs, screenshots, `.env` files, `appsettings.Development.json`, API keys, passwords, tokens, cookies, raw `AdditionalDataJson`, raw payload JSON, or connection strings.

## Local demo data reset

Before a clean defense run, preview and then confirm a local-only operational reset:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Reset-ConShieldLocalDemoData.ps1 -WhatIf

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Reset-ConShieldLocalDemoData.ps1 -ConfirmReset
```

The reset removes local demo-generated operational state such as Security Events, SIEM alerts, Incidents, outbox/inbox receipts, Dead Letter quarantine rows, demo sensors, and Mongo raw-event projections. It does not delete EF migrations, source files, demo-user configuration, local app settings, Docker volumes, credentials, API keys, or connection strings.

Optional cleanup is intentionally narrow:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Reset-ConShieldLocalDemoData.ps1 -ConfirmReset -CleanLocalArtifacts
```

`-CleanLocalArtifacts` only targets files under `artifacts/local/`. The script fails closed unless the PostgreSQL target is provably local, and it never prints secrets, raw `AdditionalDataJson`, raw payload JSON, env values, logs, or generated artifact contents.

## Demo walkthrough page

After starting the Web app, open the read-only demo walkthrough page:

```text
http://127.0.0.1:5080/Demo
```

Use it as the live navigation guide for the local defense demo. It shows the order of operations, safe PowerShell commands, current Security Events / SIEM / Incidents / Runtime Sensor counts, and links to `/Reports/SecuritySummary`, `/SecurityEvents`, `/Siem`, `/Incidents`, and `/RuntimeSensors`.

The page does not execute shell scripts from the browser. Run commands in PowerShell from the repository root. It does not display secrets, connection strings, API keys, env values, raw event payloads, logs, screenshots, or generated files under `artifacts/local/`.

## Image scan CLI path

For a deterministic local check that does not require live Trivy, internet, Fedora, or ingestion, run:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-ConShieldImageScan.ps1 `
  -FromTrivyJson .\tests\TestData\Trivy\sample-image-scan.json `
  -NoSubmit
```

For the local demo ingestion path, start the Web app and submit the same sanitized fixture:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-ConShieldImageScan.ps1 `
  -FromTrivyJson .\tests\TestData\Trivy\sample-image-scan.json
```

The script maps a Trivy-compatible report to `conshield.image-scanner` / `container.image.scan.completed`, expects `IMG-001`, and prints only compact summary fields. The evidence exporter adds `Image Scan Evidence` when matching image scan events are present. Do not commit generated Markdown under `artifacts/local/`, raw Trivy reports, raw event payloads, local logs, secrets, API keys, connection strings, or environment values.

## Runtime Sensor Health

Runtime Sensor Health is a read-only UI/evidence view derived from ingested runtime/Falco-compatible security events. It shows SourceSystem, last seen time, event count, latest event metadata, related `RTE-001` alerts, related incidents, and `Active` / `Stale` / `NoData` status. It does not require a real Fedora VM for local validation.

Safe local validation:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Export-ConShieldDefenseEvidence.ps1 `
  -OutputMarkdownPath .\artifacts\local\defense-evidence.md
```

Then open `/RuntimeSensors` and confirm the `conshield.falco-linux-sensor` source appears as active or present. Keep generated Markdown under `artifacts/local/`; do not commit generated evidence, logs, screenshots, `.env` files, API keys, passwords, tokens, or connection strings.

## Operator workflow demo

Use this small walkthrough for a defense-friendly analyst path without exposing raw event JSON or local secrets:

1. Run local apps.
2. Run the defense scenario.
3. Open Security Summary.
4. Open a SIEM alert.
5. Acknowledge/review the alert.
6. Open the linked incident.
7. Move the incident to In Progress.
8. Open the linked source Security Event.
9. Close the incident with a non-empty conclusion.
10. Export defense evidence and confirm the Operator Workflow section.

Safe commands:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Run-ConShieldDefenseScenario.ps1

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Export-ConShieldDefenseEvidence.ps1 `
  -OutputMarkdownPath .\artifacts\local\defense-evidence.md
```

The close action requires a non-empty operator conclusion. Keep generated Markdown under `artifacts/local/` and do not commit generated evidence, screenshots, logs, `.env` files, `appsettings.Development.json`, API keys, passwords, tokens, or connection strings.

Start with wrapper dry-run mode:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Validate-DemoScenario.ps1 -Scenario full-demo -DryRun -SkipWebChecks
```

If the local Web app is running, omit `-SkipWebChecks` to check unauthenticated route behavior for `/`, `/Account/Login`, `/Operations/Health`, `/SecurityEvents`, and `/Reports/SecuritySummary`.

Apply is explicit and local/dev/demo only:

```powershell
$env:CONSHIELD_DEMO_CONNECTION_STRING = "Host=127.0.0.1;Port=5432;Database=conshield;Username=conshield;Password=<local-dev-password>"
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Validate-DemoScenario.ps1 -Scenario full-demo -Apply
```

Before cleanup, preview the marked rows and then reset only demo data:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Validate-DemoScenario.ps1 -ResetDemoData -DryRun
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Validate-DemoScenario.ps1 -ResetDemoData -Apply -Yes
```

Do not run `-Apply` against a production database, and do not print `CONSHIELD_DEMO_CONNECTION_STRING`.

## Safe handling rules

- Never paste generated credentials into GitHub, chat, screenshots, or logs.
- Never expose `VerifierSha256`.
- Never inspect or print Fedora protected env files in shared output.
- Never use audit events as a credential recovery mechanism.
- Use public sensorId/credentialId only.
- Use the Security Summary Markdown export only for aggregate counts and timestamps; it is not a source for raw event payloads or secret recovery.

## Current limitations

- Состояние системы is DB-backed and not a Prometheus/Grafana replacement.
- SIEM lifecycle alerts are deterministic prototype rules.
- No automatic remediation is performed.
- No centralized secret manager integration yet.
- mTLS binding is future work.
