# Operations and SIEM Runbook

## Purpose

This runbook describes how an `AdminIB` operator uses ConShield operational screens and SIEM lifecycle alerts during daily checks and investigations.

For a safe diploma/demo walkthrough, use [DEMO_EVIDENCE_PACK.md](DEMO_EVIDENCE_PACK.md) together with this runbook.

## Main screens

- Operations Health: `/Operations/Health`
- Security Summary Report: `/Reports/SecuritySummary`
- Security Events: `/SecurityEvents`
- Sensor Fleet: `/Sensors`
- Alerts / Incidents: use the existing SIEM alerts and incident registry pages in the app

## Normal daily check

1. Open Operations Health.
2. Check sensor heartbeat state.
3. Check Security Events freshness.
4. Check outbox/inbox health.
5. Check lifecycle audit activity.
6. Open Security Summary Report and export the Markdown handoff if the check needs to be attached to an incident or shift note.
7. Open Security Events using lifecycle quick filters if needed.

## Lifecycle SIEM alerts

### LIFE-001 — Sensor identity revoked

Meaning:

- a sensor identity was revoked;
- heartbeat/runtime events for this sensor should fail after revocation.

Operator actions:

1. Check whether the revocation was planned.
2. Open Sensor Fleet and confirm sensor status.
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

1. Start from Operations Health.
2. Open related Security Events.
3. Filter by SourceSystem = `conshield.sensor-lifecycle`.
4. Use ExternalEventType to narrow the event.
5. Check Sensor Fleet/details.
6. Create an incident from a relevant security event or alert when needed.
7. Document the operator conclusion.

## Local login troubleshooting

Local Web login uses configured `DemoUsers`, not database user records. If `adminib` or `operator` cannot sign in after changing a local password, restart Web so the process reloads `appsettings.Development.json` or inherited environment variables.

In Development only, open:

```text
http://127.0.0.1:5080/Account/DemoUserDiagnostics
```

The diagnostics response is secret-free and shows only environment, configured demo-user count, user name, display name, role, `HasPassword`, and warnings. It does not show password values, password length, hashes, connection strings, cookies, tokens, API keys, or verifier values.

To test the real login form safely:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-LocalDemoLogin.ps1 -UserName adminib
```

The script checks diagnostics, submits the real login form, and probes `/Operations/Health` with the same session. If diagnostics show `HasPassword=True` but the script returns `login_result=failed`, the entered password likely does not match the configured local password.

Temporary shell-only placeholder configuration:

```powershell
$env:DemoUsers__0__UserName = "adminib"
$env:DemoUsers__0__Password = "CHANGE_ME"
$env:DemoUsers__0__DisplayName = "Администратор ИБ"
$env:DemoUsers__0__Role = "AdminIB"
```

After changing config, restart Web. If diagnostics and the script succeed but browser login still fails, use an incognito window or clear ConShield cookies. Do not paste passwords into chat, tickets, screenshots, logs, or committed files.

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

- Operations Health is DB-backed and not a Prometheus/Grafana replacement.
- SIEM lifecycle alerts are deterministic prototype rules.
- No automatic remediation is performed.
- No centralized secret manager integration yet.
- mTLS binding is future work.
