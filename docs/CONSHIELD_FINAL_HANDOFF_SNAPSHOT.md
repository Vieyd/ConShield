# ConShield Final Handoff Snapshot

## Purpose

A compact snapshot of the current project state after the implemented scan → policy → runtime → ingestion → SIEM → operations/reporting flow. This document is intended for handoff and diploma writing, not as a production deployment claim.

## Current implemented state

- Image scanning: `ConShield.ImageScanner` wraps Trivy and can produce or submit normalized image scan findings.
- Policy gate: `ConShield.ContainerPolicy` evaluates container launch decisions and records policy evidence.
- Runtime sensor / collector: `ConShield.RuntimeCollector` ingests Falco-compatible JSONL events from an enrolled sensor flow.
- Protected ingestion: the Web API accepts validated security events and keeps reserved runtime source submission sensor-bound.
- Event storage: PostgreSQL stores security events, incidents, alerts, sensor inventory, credentials, outbox, and inbox receipts.
- Outbox/RabbitMQ/EventConsumer: the event pipeline supports durable delivery, RabbitMQ publication, idempotent consumption, and optional MongoDB projection.
- Sensor inventory and heartbeat: `/Sensors` and heartbeat APIs track sensor freshness and revocation state.
- Credential lifecycle: provisioning, rotation, credential revocation, and sensor revocation workflows exist for AdminIB operators.
- Lifecycle audit events: credential/sensor lifecycle actions produce filterable security events.
- Lifecycle SIEM rules: `LIFE-001` and `LIFE-002` detect sensor identity revocation and repeated lifecycle changes.
- Operations Health: `/Operations/Health` provides AdminIB-only aggregate health information.
- Security Summary report/export: `/Reports/SecuritySummary` and `/Reports/SecuritySummaryMarkdown?range=24h` provide secret-safe aggregate reporting.
- Demo scenario runner: `tools/ConShield.DemoScenario` can seed/reset clearly marked synthetic local demo data for walkthroughs.
- Demo/diploma evidence docs: `docs/DEMO_EVIDENCE_PACK.md` and `docs/DIPLOMA_FEATURE_MAP.md` describe the safe demo path and feature mapping.

## Main user roles

- `AdminIB`: can access administrative sensor inventory, operations health, reports, lifecycle actions, alerts/incidents, and investigation workflows. Destructive lifecycle operations are AdminIB-only and require the existing UI/API protections.
- `Operator`: can use non-administrative investigation workflows according to the app role model, but cannot perform AdminIB-only sensor lifecycle or operational administration actions.
- Unauthenticated user: can open the login page but is redirected to login for protected routes such as `/Operations/Health`, `/Sensors`, and `/Reports/SecuritySummary`.

## Main Web routes

- `/Account/Login`
- `/SecurityEvents`
- `/Sensors`
- `/Operations/Health`
- `/Reports/SecuritySummary`
- `/Reports/SecuritySummaryMarkdown?range=24h`
- `/Siem`
- `/Incidents`

## Important command-line modules

- `src/ConShield.ImageScanner`: image scanning and policy-gate CLI entry points.
- `src/ConShield.ContainerPolicy`: pure local policy evaluation library.
- `src/ConShield.RuntimeCollector`: runtime alert parser/collector for JSONL or stdin/follow mode.
- `src/ConShield.SensorProvisioning`: local operator-only enrolled sensor credential provisioning.
- `src/ConShield.EventConsumer`: RabbitMQ consumer, inbox receipt writer, and optional MongoDB projection.
- `tools/ConShield.DemoScenario`: local-only scenario runner for synthetic `healthy`, `full-demo`, `lifecycle-alerts`, `runtime-incident`, and `outbox-backlog` data.

## Security boundaries

- No credential plaintext storage is used for persisted sensor credentials.
- Credential verifier material is stored as a verifier only; do not expose `VerifierSha256` values.
- Reserved runtime source events require sensor-bound runtime authentication.
- Legacy runtime fallback remains disabled for enrolled-sensor-only operation.
- Lifecycle actions such as rotation/revocation are AdminIB-only.
- Security Summary reports and Markdown exports are aggregate/read-only and secret-safe.
- Report exports do not include raw `AdditionalDataJson`, credential plaintext, API keys, connection strings, env values, cookies, tokens, passwords, or local secrets.
- Demo scenario writes require explicit `CONSHIELD_DEMO_CONNECTION_STRING`; the runner must not print the value and reset deletes only marked demo records.

## Validation status

Normal validation commands:

```powershell
dotnet restore
dotnet build -c Release --no-restore
dotnet test -c Release --no-build
dotnet ef migrations has-pending-model-changes --project ./src/ConShield.Data --startup-project ./src/ConShield.Web
actionlint
gitleaks git --redact
git diff --check
```

Fedora deployment script validation:

```powershell
& "C:\Program Files\Git\bin\bash.exe" -lc "cd /c/Users/Admin/Documents/projects/ConShield && bash -n deploy/falco-linux/*.sh"
shellcheck deploy/falco-linux/*.sh
```

If available, run:

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Error
```

Expected result: build/tests pass, EF reports no pending model changes, actionlint/gitleaks/diff-check pass, shell syntax/ShellCheck pass, and PSScriptAnalyzer reports no errors.

## Safe demo path

Use `docs/DEMO_EVIDENCE_PACK.md` as the primary safe demo script. It includes a short presentation order, evidence checklist, safe command examples, and what not to show.

Optional local-only synthetic data setup:

```powershell
dotnet run --project tools/ConShield.DemoScenario -- --scenario full-demo --dry-run
dotnet run --project tools/ConShield.DemoScenario -- --scenario full-demo --yes
dotnet run --project tools/ConShield.DemoScenario -- --reset-demo-data --dry-run
```

## Known limitations / future work

- mTLS binding.
- Kubernetes/admission controller.
- Centralized secret manager.
- Prometheus/Grafana.
- Retention/partitioning.
- Rule DSL/configurable rules.
- Automatic remediation.
- Production hardening.

## What must not be shared

- Generated credentials.
- API keys.
- `appsettings.Development.json`.
- Fedora env files.
- PostgreSQL/RabbitMQ passwords.
- `VerifierSha256` values.
- Screenshots/logs with secrets.
- Connection strings, env values, tokens, cookies, local passwords, or generated reports from a real environment.
