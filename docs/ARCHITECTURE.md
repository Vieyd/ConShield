# ConShield Architecture

## Architecture summary

ConShield is a local-first DevSecOps/SIEM control plane for container security. It connects deterministic image scanning, policy-as-code, CI/CD gating, protected local run decisions, Docker lifecycle replay, Falco-compatible runtime events, sensor trust, signed sensor event verification, SIEM correlation, incidents, evidence export, and full validation.

The current architecture is intentionally demo-ready and reproducible. It is designed to explain and validate the workflow locally without requiring real Fedora/Falco, live Docker execution, live Trivy network access, Kubernetes, full mTLS, real certificates, private keys, signing keys, or real secrets.

## Main components

| Component | Responsibility |
|---|---|
| `ConShield.Web` | Local MVC UI, authentication, operator pages, external ingestion API, reports, Runtime Sensor Health, `/Demo` walkthrough. |
| `ConShield.Cli` | Unified local CLI wrapper for validation, guided demo seed, demo reset/readiness, image scan, protected run, lifecycle replay, sensor replay, gate, and evidence export. |
| External event ingestion API | Accepts normalized external security events and routes them into operational storage and SIEM correlation. |
| `ConShield.EventConsumer` | Consumes RabbitMQ-delivered events and writes projection/checkpoint data when the message pipeline is enabled. |
| PostgreSQL | Primary operational store for security events, alerts, incidents, sensors, outbox/inbox, and application state. |
| MongoDB projection | Optional immutable projection for raw-event style operational inspection with sanitized UI/reporting surfaces. |
| RabbitMQ | Optional broker for outbox/event-pipeline delivery and EventConsumer processing. |
| Image scanner path | Maps Trivy-compatible scan results into IMG security events without requiring live Trivy DB in fixture mode. |
| Protected runner path | Evaluates scan findings against container policy-as-code and controls whether a container run is allowed, warned, or blocked. |
| CI/CD gate | Evaluates scan results and policy decisions with deterministic exit behavior for pipeline use. |
| Docker lifecycle collector | Replays Docker-compatible lifecycle events into sanitized LIFE security events. |
| Falco/runtime replay path | Maps Falco-compatible runtime events into RTE security events. |
| Sensor trust registry | Defines trusted, unknown, revoked, and disabled runtime sensor status. |
| Sensor trust enforcement | Surfaces unknown/revoked/disabled runtime sources through deterministic SENSOR signals. |
| Signed sensor event verifier | Verifies deterministic signature envelope metadata for valid, missing, invalid, and stale sensor events. |
| SIEM correlation service | Loads configurable SIEM rules and correlates security events into alerts. |
| Incident/operator workflow | Links alerts to incidents and supports acknowledge, review, progress, close, and source-event navigation. |
| Evidence export | Produces safe Markdown evidence summaries under ignored local artifacts. |
| Guided demo seed | Orchestrates existing deterministic replay/scenario/evidence paths so the dashboard and operator story have meaningful local data. |
| Full validation and demo release packaging | Validates repository contracts and packages safe docs/config/scripts/CLI into a local ignored release bundle. |

## Runtime topology

The default topology is a local developer/operator machine:

- Web UI on `http://127.0.0.1:5080`.
- PostgreSQL on `127.0.0.1:5432`.
- RabbitMQ UI on `http://localhost:15672`.
- MongoDB on `127.0.0.1:27017`.
- CLI/scripts running from the repository root.
- Optional Docker/Falco integrations kept outside the default CI-safe path.

See [DEPLOYMENT_VIEW.md](DEPLOYMENT_VIEW.md) for the deployment view and endpoint table.

## Event pipeline

High-level event flow:

```text
scan/gate/protected run/lifecycle/runtime fixture
-> normalized security event
-> ingestion/application services
-> PostgreSQL operational state
-> optional outbox/RabbitMQ/EventConsumer/Mongo projection
-> SIEM alert
-> incident/operator workflow
-> evidence export and Web/CLI views
```

Detailed data-flow diagrams are in [DATA_FLOW_MODEL.md](DATA_FLOW_MODEL.md), and visual Mermaid diagrams are in [ARCHITECTURE_DIAGRAMS.md](ARCHITECTURE_DIAGRAMS.md).

## Configuration model

ConShield keeps key demo controls in committed default configuration:

- `config/siem-rules.default.json` for SIEM correlation rules.
- `config/container-policy.default.json` for Allow/Warn/Block container policy.
- `config/sensor-registry.default.json` for runtime sensor trust state.

Local overrides remain ignored by Git. Validation scripts verify committed defaults without requiring external services.

## Security model

The security model is documented through:

- [THREAT_MODEL.md](THREAT_MODEL.md)
- [ATTACKER_SCENARIOS.md](ATTACKER_SCENARIOS.md)
- [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md)
- [REQUIREMENTS_TRACEABILITY_MATRIX.md](REQUIREMENTS_TRACEABILITY_MATRIX.md)
- [RESIDUAL_RISKS.md](RESIDUAL_RISKS.md)

The model emphasizes deterministic local validation, safe evidence, conservative claims, explicit trust boundaries, and clear residual risk.

## Operator model

Operators can use:

- Web UI pages for Security Summary, Security Events, SIEM, Incidents, Runtime Sensor Health, Operations Health, and `/Demo`.
- `ConShield.Cli` for local commands.
- PowerShell scripts for explicit workflow commands.
- Evidence export for defense or review.

Browser pages do not execute shell commands. They provide navigation, status, and safe command references.

## Evidence model

Evidence is generated from current operational state and safe summaries. Generated reports stay under `artifacts/local/` by default and are ignored by Git. Evidence sections cover image scan, protected run, CI/CD gate, Docker lifecycle, runtime sensor health, sensor trust, signed sensor events, SIEM rules, incidents, operator workflow, outbox/inbox, and demo navigation.

## Validation model

Validation uses layered checks:

- focused unit/static tests for feature contracts;
- docs tests for links, diagrams, IDs, and conservative language;
- PowerShell syntax and ScriptAnalyzer checks;
- shell syntax and ShellCheck for Linux scripts;
- `gitleaks` for secret scanning;
- `Test-ConShieldFullValidation.ps1` for deterministic repository-level validation.

## Design constraints

- Default checks must be deterministic and CI-safe.
- Docs and reports must avoid secrets, local overrides, generated artifacts, and sensitive payload bodies.
- Local demo paths should not require external internet.
- Live Docker/Falco/Trivy paths remain optional/manual.
- The project should remain explainable during academic defense.

## What is intentionally out of scope

- Production Kubernetes admission controller.
- Full mTLS/PKI.
- Enterprise multi-cluster management.
- Full host EDR.
- Formal compliance attestation.
- Cloud CNAPP replacement.
- Production-grade distributed replay detection.

## Related documents

- [ARCHITECTURE_DIAGRAMS.md](ARCHITECTURE_DIAGRAMS.md)
- [DATA_FLOW_MODEL.md](DATA_FLOW_MODEL.md)
- [DEPLOYMENT_VIEW.md](DEPLOYMENT_VIEW.md)
- [SEQUENCE_FLOWS.md](SEQUENCE_FLOWS.md)
- [THREAT_MODEL.md](THREAT_MODEL.md)
- [REQUIREMENTS_TRACEABILITY_MATRIX.md](REQUIREMENTS_TRACEABILITY_MATRIX.md)
