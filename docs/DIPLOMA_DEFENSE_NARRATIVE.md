# Diploma Defense Narrative

## Short project explanation

ConShield is a local-first DevSecOps/SIEM control plane for container security. It demonstrates the complete operator path from image scan and policy decision to runtime/lifecycle signals, sensor trust, signed event verification, SIEM alerting, incident workflow, and safe evidence export.

In Russian:

> ConShield — это локальная DevSecOps/SIEM-платформа управления контейнерной безопасностью, которая показывает сквозной путь от проверки образа и политики допуска до runtime/lifecycle-событий, доверия к сенсорам, проверки подписи событий, SIEM-корреляции, инцидентов и доказательного отчёта.

## Research object and subject

- Research object: container security monitoring and response workflow.
- Research subject: integration of scan results, policy decisions, runtime signals, sensor identity, SIEM correlation, incident workflow, and evidence export in a reproducible local prototype.

Russian-ready wording:

> Объект исследования — процессы контроля и мониторинга безопасности контейнерных приложений. Предмет исследования — интеграция результатов сканирования, политик допуска, событий времени выполнения, доверия к сенсорам, SIEM-корреляции, инцидентов и доказательной базы в воспроизводимом локальном прототипе.

## Problem statement

Container security controls are frequently fragmented. A scan result may not be connected to a policy decision; a runtime event may not be connected to the original source event; an incident may not be connected to evidence that is safe to share. This makes demonstration, validation, and operator training harder.

## Goal

The goal is to build and validate a reproducible local workflow that connects container security signals into an operator-oriented SIEM and incident response process.

## Tasks

1. Support safe image scan fixture ingestion.
2. Apply container policy-as-code decisions.
3. Provide a CI/CD gate path with deterministic exit behavior.
4. Replay Docker lifecycle and Falco-compatible runtime events.
5. Track runtime sensor trust and signed event status.
6. Correlate SIEM alerts and create incidents.
7. Provide Web UI and CLI navigation.
8. Export safe evidence.
9. Validate the workflow without requiring external infrastructure by default.

The formal traceability artifacts are [THREAT_MODEL.md](THREAT_MODEL.md), [ATTACKER_SCENARIOS.md](ATTACKER_SCENARIOS.md), [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md), [REQUIREMENTS_TRACEABILITY_MATRIX.md](REQUIREMENTS_TRACEABILITY_MATRIX.md), and [RESIDUAL_RISKS.md](RESIDUAL_RISKS.md).

The visual architecture artifacts are [ARCHITECTURE.md](ARCHITECTURE.md), [ARCHITECTURE_DIAGRAMS.md](ARCHITECTURE_DIAGRAMS.md), [DATA_FLOW_MODEL.md](DATA_FLOW_MODEL.md), [DEPLOYMENT_VIEW.md](DEPLOYMENT_VIEW.md), and [SEQUENCE_FLOWS.md](SEQUENCE_FLOWS.md). Use them when explaining components, trust boundaries, and the event-to-evidence flow.

Russian-ready wording:

> Для защиты важно показать не только интерфейс и скрипты, но и трассируемость: угрозы → сценарии атакующего → требования безопасности → реализованные модули → правила SIEM → доказательная база → тесты.

## Novelty / difference from analogs

The contribution is not a new vulnerability scanner or a replacement runtime sensor. The difference is the integrated chain:

```text
scan -> policy gate -> runtime/lifecycle -> sensor trust/signatures -> SIEM -> incidents -> evidence
```

Russian-ready wording:

> Отличие ConShield заключается не в отдельном сканировании контейнерного образа, а в сквозной цепочке принятия решения: от результата проверки образа и политики допуска до событий времени выполнения, доверия к сенсорам, корреляции SIEM, инцидента и доказательной базы.

## Architecture narrative

The architecture separates ingestion, application services, data storage, correlation, Web UI, CLI, and local automation. External or fixture-based security signals become normalized security events. SIEM rules correlate the events into alerts. Alerts can be linked to incidents. Runtime sensor health summarizes source trust, enforcement status, and signed event status. Evidence export turns the current state into a safe Markdown report.

## Demo scenario

The defense demo can be explained as a controlled story:

1. Start the local stack.
2. Reset demo-generated data.
3. Run the guided demo data seed to create or reuse deterministic IMG/POL/LIFE/RTE/SENSOR/SIGN evidence.
4. Run the defense scenario or replay image scan, protected run, lifecycle, and runtime fixtures manually if you want to explain each source path.
5. Open Security Summary.
6. Open the read-only Operator Dashboard at `/Dashboard` to show status-first posture cards, latest sanitized activity, guided demo flow, grouped workflow references, and docs links.
7. Drill into SIEM alert, incident, and source event.
8. Show Runtime Sensor Health and trust/signature states.
9. Export evidence.
10. Run readiness or full validation checks.

The dashboard is a visual control center, not a command execution panel. Its command snippets are collapsed local copy/paste references for reproducibility. It does not run PowerShell, shell commands, reset, Docker, Trivy, Falco, evidence export, or release packaging from the browser.

## What to show first

Show Security Summary first because it gives the committee the system-level view. Then drill down into one alert and one incident. This keeps the story understandable before showing CLI commands or configuration.

## What to say if asked “why not just Trivy?”

Trivy answers an important scanner question: what findings exist in an image. ConShield answers the workflow question: how that finding becomes a policy decision, SIEM alert, incident, and evidence. In the demo, Trivy-compatible data is an input, not the whole system.

Russian-ready wording:

> Trivy важен как источник результатов проверки образа. ConShield показывает следующий уровень процесса: как результат проверки превращается в решение политики, SIEM-сигнал, инцидент и безопасный отчёт.

## What to say if asked “why not just Falco?”

Falco focuses on runtime detection. ConShield does not replace it; ConShield shows how Falco-compatible runtime events can be connected with source health, trust, signature status, SIEM correlation, incidents, and evidence.

## What to say if asked “why not Kubernetes?”

Kubernetes admission control is a logical next step, but the current project intentionally keeps the base demo local and deterministic. This allows the full workflow to be defended without requiring a cluster, external network access, or privileged runtime infrastructure.

## What to say if asked “is it production-ready?”

Use a careful answer:

> It is a local-first prototype and demo-ready control plane, not a finished enterprise product. The implemented value is the integrated workflow and deterministic validation. Production use would require hardening of deployment, identity, key management, monitoring, scaling, and operational support.

Russian-ready wording:

> Это локальный прототип и демонстрационная платформа, а не завершённый enterprise-продукт. Практическая ценность сейчас — в сквозном workflow и воспроизводимой проверке. Для промышленной эксплуатации потребуются усиление deployment, identity, key management, monitoring, scaling и operational support.

## Strong closing statement

ConShield demonstrates how container security can be explained as a complete decision chain rather than as isolated tool output. The project is intentionally scoped, reproducible, and transparent: it shows scan, policy, runtime, lifecycle, trust, signatures, SIEM, incidents, and evidence in one local workflow.

Russian-ready closing:

> Главная идея ConShield — показать безопасность контейнеров как управляемую цепочку решений, а не как набор разрозненных отчётов. Проект объединяет проверку образа, политику допуска, runtime/lifecycle-события, доверие к сенсорам, подпись событий, SIEM-корреляцию, инциденты и доказательную базу в одном воспроизводимом локальном сценарии.
