# ConShield Demo and Diploma Evidence Pack

## Purpose

This pack explains how to demonstrate ConShield as a prototype complex for protecting containerized applications using image scanning, launch policy, runtime event monitoring, SIEM correlation, operator dashboards, and reporting. It is intended for a safe diploma/coursework defense: every example uses placeholders, local demo routes, and aggregate evidence rather than real credentials or protected environment data.

For a compact current-state handoff, see [CONSHIELD_FINAL_HANDOFF_SNAPSHOT.md](CONSHIELD_FINAL_HANDOFF_SNAPSHOT.md). For Russian diploma/explanatory-note draft text, see [DIPLOMA_TEXT_SECTIONS_DRAFT_RU.md](DIPLOMA_TEXT_SECTIONS_DRAFT_RU.md).

## Implemented protection chain

1. Image scanning: `ConShield.ImageScanner` wraps Trivy and can submit normalized image vulnerability findings.
2. Container policy gate: `ConShield.ContainerPolicy` evaluates Allow/Warn/Block decisions and records policy audit evidence.
3. Runtime collector / enrolled sensor: `ConShield.RuntimeCollector` submits mapped Falco-compatible events with enrolled sensor identity.
4. Protected event ingestion: `POST /api/v1/security-events` accepts validated events and protects reserved runtime sources.
5. Security event storage: PostgreSQL stores normalized `SecurityEvents` for investigation and correlation.
6. Outbox/RabbitMQ/EventConsumer: transactional outbox, RabbitMQ, inbox receipts, and optional MongoDB projection provide a durable processing path.
7. Sensor inventory and heartbeat: `/Sensors` and the heartbeat API show enrolled sensor freshness and revocation state.
8. Credential lifecycle: local provisioning, rotation, revocation, and sensor revocation workflows exist without exposing stored verifiers.
9. Lifecycle audit events: lifecycle actions write filterable audit events into Security Events.
10. SIEM rules and alerts: rules include image, policy, runtime, and lifecycle detections such as `LIFE-001` and `LIFE-002`.
11. Operations Health: `/Operations/Health` provides an AdminIB-only aggregate health view.
12. Security Summary report/export: `/Reports/SecuritySummary` and the Markdown export provide a safe read-only handoff.
13. Demo scenario runner: `tools/ConShield.DemoScenario` seeds local-only synthetic evidence for safe walkthroughs.

## Mapping to diploma goals

| Diploma task | ConShield evidence |
| --- | --- |
| Threat analysis for containerized apps | Architecture/roadmap docs plus implemented scan, policy, and runtime paths |
| Image vulnerability/secret scanning | `ConShield.ImageScanner`, Trivy flow, and security events |
| Runtime policy enforcement | `ConShield.ContainerPolicy` policy gate and `POL-001` correlation |
| Runtime event monitoring | `ConShield.RuntimeCollector`, enrolled sensor heartbeat, and `RTE-001` correlation |
| Secure ingestion | API key validation and sensor-bound runtime authentication |
| Event processing pipeline | PostgreSQL outbox, RabbitMQ, EventConsumer, inbox receipts, and optional MongoDB projection |
| SIEM detection | Correlation rules including `LIFE-001` and `LIFE-002` lifecycle alerts |
| Operator workflow | `/Operations/Health`, `/SecurityEvents`, `/Sensors`, SIEM alerts/incidents, and reports |
| Reporting | `/Reports/SecuritySummary` and safe Markdown export |
| Safe demo data | `tools/ConShield.DemoScenario` marked synthetic scenarios and marked-only reset |

## Demo scenario

1. Start local infrastructure and apps.
2. Login as AdminIB.
3. Open `/Operations/Health` and explain heartbeat, event, outbox, and inbox summaries.
4. Open `/Sensors` and show sensor status without exposing credentials.
5. Open `/SecurityEvents` and show standard filters.
6. Show lifecycle audit filters for `conshield.sensor-lifecycle`.
7. Show Alerts/Incidents if demo data or previous safe actions have produced them.
8. Open `/Reports/SecuritySummary`.
9. Download or copy the Markdown export and explain that it contains only aggregate counts and timestamps.
10. Explain safe credential handling: generated credentials are one-time handoff material and must not be shown.
11. Optional: show ImageScanner and PolicyGate command examples with placeholders only.
12. Optional: show Fedora runtime sensor service status without printing protected env files.

## Demo commands

Use placeholders and safe local examples only. Do not paste real API keys, generated credentials, connection strings, local passwords, or protected Fedora env file contents into the terminal, slides, screenshots, GitHub, or chat.

Local login troubleshooting:

ConShield Web login uses `DemoUsers` from configuration, not database users. `adminib` and `operator` are local configuration users. If login fails, restart Web after editing `appsettings.Development.json` or environment variables, then open the Development-only secret-free endpoint:

```text
http://127.0.0.1:5080/Account/DemoUserDiagnostics
```

The endpoint shows user names, roles, display names, and `HasPassword`, but never shows passwords, password length, cookies, tokens, API keys, or connection strings. To test the actual login form without printing the password:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-LocalDemoLogin.ps1 -UserName adminib
```

The script uses diagnostics plus an authenticated `/Operations/Health` probe with the same session. If diagnostics show `HasPassword=True` but the script returns `login_result=failed`, the entered password likely differs from the configured local value.

Shell-only placeholder example:

```powershell
$env:DemoUsers__0__UserName = "adminib"
$env:DemoUsers__0__Password = "CHANGE_ME"
$env:DemoUsers__0__DisplayName = "Администратор ИБ"
$env:DemoUsers__0__Role = "AdminIB"
```

Use incognito/clear cookies if diagnostics and the script succeed but browser login still fails. Do not paste passwords into chat or commit local config.

Start apps:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit
```

Run validation:

```powershell
dotnet restore
dotnet build -c Release --no-restore
dotnet test -c Release --no-build
```

Run image scanner without submitting:

```powershell
dotnet run --project src/ConShield.ImageScanner -- scan --image alpine:3.20 --no-submit
```

Run policy gate without submitting:

```powershell
dotnet run --project src/ConShield.ImageScanner -- gate --image alpine:3.20 --policy config/policies/container-baseline-v1.json --no-submit
```

Preview and seed synthetic demo data:

```powershell
$env:CONSHIELD_DEMO_CONNECTION_STRING = "Host=127.0.0.1;Port=5432;Database=conshield;Username=conshield;Password=<local-dev-password>"
dotnet run --project tools/ConShield.DemoScenario -- --scenario healthy --dry-run
dotnet run --project tools/ConShield.DemoScenario -- --scenario full-demo --yes
```

Use targeted scenarios when the walkthrough needs one screen:

```powershell
dotnet run --project tools/ConShield.DemoScenario -- --scenario lifecycle-alerts --yes
dotnet run --project tools/ConShield.DemoScenario -- --scenario runtime-incident --yes
dotnet run --project tools/ConShield.DemoScenario -- --scenario outbox-backlog --yes
```

Remove only marked synthetic demo rows:

```powershell
dotnet run --project tools/ConShield.DemoScenario -- --reset-demo-data --dry-run
dotnet run --project tools/ConShield.DemoScenario -- --reset-demo-data --yes
```

Run the validation wrapper in safe dry-run mode:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Validate-DemoScenario.ps1 -Scenario full-demo -DryRun -SkipWebChecks
```

If the local Web app is running, omit `-SkipWebChecks` to also check unauthenticated route behavior:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Validate-DemoScenario.ps1 -Scenario full-demo -DryRun
```

Only for a local development database, seed and reset through explicit apply commands:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Validate-DemoScenario.ps1 -Scenario full-demo -Apply
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Validate-DemoScenario.ps1 -ResetDemoData -DryRun
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Validate-DemoScenario.ps1 -ResetDemoData -Apply -Yes
```

`CONSHIELD_DEMO_CONNECTION_STRING` is required for write/reset-count operations but must never be printed or captured in screenshots/reports. Do not run `-Apply` against a production database.

Open report:

```text
http://127.0.0.1:5080/Reports/SecuritySummary
```

Download Markdown export:

```text
http://127.0.0.1:5080/Reports/SecuritySummaryMarkdown?range=24h
```

Optional Fedora status evidence should be limited to service state and file permissions, not secret contents.

## Evidence checklist

- [ ] Operations Health page opens for AdminIB.
- [ ] Security Summary report opens for AdminIB.
- [ ] Unauthenticated user is redirected to login.
- [ ] Security Events lifecycle filters are visible.
- [ ] Sensor Fleet shows sensor status.
- [ ] Lifecycle audit events are filterable.
- [ ] `LIFE-001` and `LIFE-002` rules are documented.
- [ ] Markdown report export contains no raw JSON/secrets.
- [ ] Test suite passes.
- [ ] GitHub Actions pass.

## What not to show

- Generated sensor credentials.
- API keys.
- `VerifierSha256`.
- `appsettings.Development.json`.
- Fedora protected env file contents.
- RabbitMQ/PostgreSQL passwords.
- Screenshots with secrets.
- Connection strings, cookies, tokens, local passwords, or generated reports from a real environment.

## Current limitations

- Prototype, not production hardening.
- No Kubernetes admission controller.
- No mTLS binding yet.
- No centralized secret manager.
- No automatic remediation.
- Operations dashboard is DB-backed, not Prometheus/Grafana.
- Reporting is aggregate/read-only.

## Suggested presentation order

1. Minute 0-1: explain the problem and show the architecture chain: Scan → Policy → Runtime Detection → Event Ingestion → Correlation → Alert/Incident → Report.
2. Minute 1-2: show `/Operations/Health` as the operator starting point.
3. Minute 2-3: show `/Sensors` and `/SecurityEvents`, including lifecycle filters.
4. Minute 3-4: explain SIEM rules and show lifecycle alert documentation for `LIFE-001`/`LIFE-002`.
5. Minute 4-5: show `/Reports/SecuritySummary` and the Markdown export.
6. Minute 5-6: show safe CLI examples for image scanning or policy gate in no-submit mode.
7. Minute 6-7: close with limitations and future work: mTLS, Kubernetes admission control, centralized secret management, observability, and configurable rules.
