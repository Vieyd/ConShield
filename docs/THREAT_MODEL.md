# ConShield Threat Model

## Scope

This threat model covers the current local-first ConShield prototype and demo-ready workflow for container security. It focuses on threats that can be represented by deterministic local validation:

```text
image scan -> policy gate -> CI/CD gate -> protected run -> Docker lifecycle/runtime events
-> sensor trust/signatures -> SIEM rules -> incidents -> evidence -> validation/release pack
```

It does not claim enterprise production coverage. The model is threat-informed and uses ATT&CK-style reasoning: adversary behavior is grouped into initial access, execution, defense evasion, impact, and detection/response gaps, but the current artifact stays focused on implemented ConShield workflows.

## Protected assets

- Container images and normalized scan results.
- Container launch decisions.
- Container policy configuration.
- SIEM rules configuration.
- Runtime and lifecycle event stream.
- External event identity and deduplication metadata.
- Sensor registry and trust status.
- Sensor signing metadata and verification status.
- SIEM alerts, incidents, and operator workflow state.
- Evidence export and generated report summaries.
- Local operator interface and CLI commands.
- Local demo/release pack integrity.
- Documentation and validation commands used during defense/demo.

## Trust boundaries

| Boundary | Description | Main concern |
|---|---|---|
| CLI/user input | Operator commands, fixture paths, image names, report paths | Unsafe options, accidental live execution, wrong command path |
| Fixture/live scanner input | Trivy-compatible JSON or equivalent scan result | Tampered or oversized scanner input |
| External ingestion API | Security events submitted into ConShield | Spoofing, duplicate/replay, unsafe metadata |
| Message broker | Optional RabbitMQ event delivery | Duplicate delivery, delivery failure, poison messages |
| Database | PostgreSQL application state and optional Mongo projection | Integrity, deduplication, safe summaries |
| Runtime/lifecycle sensors | Falco-compatible and Docker lifecycle sources | Unknown/revoked source, missing signature, stale replay |
| Web UI | Operator-facing local screens | Raw payload disclosure, misleading status |
| Evidence export | Markdown evidence produced from current state | Secret/raw payload/log leakage |
| Release packaging boundary | Safe handoff bundle under ignored local artifacts | Accidentally packaging local overrides or generated artifacts |

## Actors

- Local operator: runs CLI/scripts, reviews UI, and exports evidence.
- Developer/security reviewer: validates configs, tests, and traceability.
- External event producer: submits scan/runtime/lifecycle/security events.
- Runtime sensor: sends runtime signals and heartbeat-like source evidence.
- Attacker or unsafe workflow: attempts to bypass policy, spoof events, replay events, or leak sensitive report material.

## Assumptions

- The default validation path is local and deterministic.
- Fixture modes are acceptable evidence for CI-safe behavior.
- Operators keep real secrets and local overrides outside the repository.
- Local services, when used, are trusted enough for demo validation.
- The project is a prototype/control plane and not a hardened production deployment.

## In-scope threats

- Vulnerable image promoted to deployment.
- Image with critical/high findings bypasses policy.
- Unsafe container launch after a policy block.
- Runtime shell spawned inside a container.
- Abnormal container lifecycle event.
- Unknown sensor submits runtime event.
- Revoked or disabled sensor submits event.
- Unsigned, missing, invalid, stale, or replay-like sensor event metadata.
- Tampered scan or runtime input.
- Duplicate/replayed external event.
- Unsafe generated evidence/report output.
- Operator uses stale docs or wrong commands.
- Misconfigured SIEM or container policy configuration weakens detection.

## Out-of-scope threats

- Kernel-level container escape prevention.
- Full host EDR.
- Enterprise multi-cluster management.
- Production Kubernetes admission controller.
- Full mTLS/PKI.
- Real-time distributed replay detection across nodes.
- Formal compliance attestation/reporting.
- Cloud CNAPP replacement.
- Public exploit prevention guarantees.

## Threat categories

| Category | Example ConShield concern | Related scenarios |
|---|---|---|
| Initial Access / Supply Chain | Vulnerable image reaches pipeline | AS-001 |
| Policy Bypass | Blocked image launch is attempted | AS-002 |
| Execution | Runtime shell inside container | AS-003 |
| Impact / Availability | Abnormal container lifecycle event | AS-004 |
| Spoofing / Trust | Unknown or revoked sensor sends event | AS-005, AS-006 |
| Integrity / Replay | Missing, invalid, stale, duplicate, or replayed event | AS-007, AS-008 |
| Disclosure | Evidence or report leaks raw material | AS-009 |
| Detection Gap | Weak SIEM/policy configuration | AS-010 |

## Data flows

```text
Trivy-compatible fixture -> image scan mapper -> IMG event -> IMG-001 alert/evidence
Container policy config -> protected run/gate -> POL/LIFE events -> POL-001/LIFE alerts/evidence
Docker lifecycle fixture -> lifecycle collector -> LIFE event -> LIFE-001/LIFE-002
Falco-compatible fixture -> runtime mapper -> RTE event -> RTE-001
Runtime source metadata -> sensor registry/signature verifier -> SENSOR/SIGN signals
Security events -> SIEM correlation -> alerts -> incidents -> operator workflow -> evidence export
Repository docs/config/scripts -> full validation/release pack -> safe handoff artifacts
```

## Security controls mapped to threats

| Threat | Control |
|---|---|
| Vulnerable image reaches CI/CD | Image scan normalization, IMG-001, CI/CD gate, evidence export |
| Policy bypass | Container policy-as-code, protected run rules, POL-001 |
| Unsafe local launch | `-NoRun` default, `-Execute` opt-in, block/warn handling |
| Runtime shell | Falco-compatible runtime replay, RTE-001 |
| Abnormal lifecycle | Docker lifecycle collector, LIFE-001/LIFE-002 |
| Unknown sensor | Sensor registry, SENSOR-001 |
| Revoked/disabled sensor | Trust enforcement, SENSOR-002 |
| Missing/invalid/stale signature | Signed sensor event verification, SIGN-001/SIGN-002/SIGN-003 |
| Duplicate/replayed external event | Deterministic external IDs and ingestion deduplication |
| Unsafe evidence | Sanitized evidence sections and docs/tests forbidding raw payload markers |
| Stale docs/wrong commands | README, `/Demo`, full validation, release pack, traceability matrix |

## Residual risk

Residual risk remains because ConShield is intentionally local-first and prototype-scoped. Live deployment hardening, distributed replay detection, production sensor identity, Kubernetes admission, and enterprise operations require future work.

## Future hardening

- Production-grade sensor identity and key management.
- Full mTLS/PKI.
- Kubernetes admission controller and cluster policy integration.
- Expanded runtime agent deployment/upgrade procedures.
- Stronger distributed replay detection.
- Enterprise integrations for tickets, SIEM, storage, and audit workflows.
