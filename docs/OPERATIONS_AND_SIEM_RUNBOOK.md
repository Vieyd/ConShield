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

After changing config, restart Web. Environment variables may override `appsettings.Development.json`. If diagnostics and the scripts succeed but browser login still fails, use an incognito window or clear ConShield cookies. Do not paste passwords into chat, tickets, screenshots, logs, or committed files.

## Local synthetic demo scenarios

For a safe local walkthrough, an operator/developer can seed marked synthetic records with `tools/ConShield.DemoScenario` or use the safer validation wrapper `scripts/Validate-DemoScenario.ps1`. This is not a production remediation or sensor operation path; it does not touch Fedora services and does not publish RabbitMQ messages.

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
