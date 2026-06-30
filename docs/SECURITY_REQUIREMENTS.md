# Security Requirements

These requirements use stable IDs for traceability. Status values are limited to `Implemented`, `Partially implemented`, or `Planned`.

## REQ-IMG-001 — Image scan results must be normalized into security events

- Rationale: scan results are only actionable when connected to the security event pipeline.
- Implemented by: `ConShield.ImageScanner`, image scan CLI/script, external event ingestion.
- Verification: `ImageScanCliScriptTests`, `ImageScannerParserTests`, `DemoWorkflowContractTests`.
- Related scenarios: AS-001.
- Status: Implemented.

## REQ-POL-001 — Critical/high-risk image findings must be evaluated by policy-as-code

- Rationale: a finding needs an explicit Allow/Warn/Block decision.
- Implemented by: `ConShield.ContainerPolicy`, `config/container-policy.default.json`, protected run workflow.
- Verification: `ContainerPolicyAsCodeTests`, `ProtectedContainerRunScriptTests`.
- Related scenarios: AS-001, AS-002, AS-010.
- Status: Implemented.

## REQ-CICD-001 — CI/CD gate must provide deterministic exit codes

- Rationale: pipelines need predictable pass/fail behavior.
- Implemented by: `ConShield.Cli gate image`, CI/CD gate docs and tests.
- Verification: `CicdContainerGateTests`.
- Related scenarios: AS-001, AS-010.
- Status: Implemented.

## REQ-RUN-001 — Protected run must prevent or flag blocked image launches

- Rationale: a blocked decision must not silently become a running container.
- Implemented by: `Invoke-ConShieldProtectedRun.ps1`, `ConShield.Cli run protected`, policy decision handling.
- Verification: `ProtectedContainerRunScriptTests`, `DemoWorkflowContractTests`.
- Related scenarios: AS-002.
- Status: Implemented.

## REQ-LIFE-001 — Docker lifecycle events must be normalized and sanitized

- Rationale: lifecycle behavior is useful security context but should not expose host-sensitive details.
- Implemented by: Docker lifecycle replay/collector workflow and LIFE event mapping.
- Verification: `DockerLifecycleCollectorTests`.
- Related scenarios: AS-004.
- Status: Implemented.

## REQ-RTE-001 — Runtime/Falco events must be mapped to SIEM rules

- Rationale: runtime behavior needs correlation, not only raw event storage.
- Implemented by: `ConShield.RuntimeDetection`, runtime collector, Falco replay script, `RTE-001`.
- Verification: `FalcoRuntimeDetectionTests`, `FalcoRuntimeSensorPathTests`.
- Related scenarios: AS-003.
- Status: Implemented.

## REQ-SENS-001 — Unknown sensors must be identified and surfaced

- Rationale: events from untrusted sources should be visible to operators.
- Implemented by: sensor registry, Runtime Sensor Health, `SENSOR-001`.
- Verification: `SensorTrustRegistryTests`, `SensorTrustEnforcementTests`.
- Related scenarios: AS-005.
- Status: Implemented.

## REQ-SENS-002 — Revoked/disabled sensors must trigger stronger handling

- Rationale: previously distrusted sources need higher operator attention than unknown sources.
- Implemented by: sensor trust enforcement, Runtime Sensor Health, `SENSOR-002`.
- Verification: `SensorTrustEnforcementTests`.
- Related scenarios: AS-006.
- Status: Implemented.

## REQ-SIGN-001 — Signed sensor event status must be verified and surfaced

- Rationale: runtime event authenticity metadata must be visible and correlated.
- Implemented by: signed sensor event verifier, replay modes, `SIGN-001`, `SIGN-002`, `SIGN-003`.
- Verification: `SignedSensorEventsTests`.
- Related scenarios: AS-007.
- Status: Implemented.

## REQ-SIEM-001 — SIEM rules must be configurable and validated

- Rationale: detection logic should be auditable and regression-protected.
- Implemented by: `config/siem-rules.default.json`, `Test-ConShieldSiemRules.ps1`, SIEM correlation service.
- Verification: `ConfigurableSiemRulesTests`, `SiemCorrelationServiceTests`.
- Related scenarios: AS-001, AS-003, AS-004, AS-005, AS-006, AS-007, AS-010.
- Status: Implemented.

## REQ-INC-001 — Incidents must be generated or linked from correlated security events

- Rationale: alerts become operationally useful when connected to incident workflow.
- Implemented by: SIEM alert-to-incident flow, operator workflow pages, linked source event navigation.
- Verification: `OperatorWorkflowTests`, `SecurityEventsUiTests`.
- Related scenarios: AS-001, AS-003, AS-004, AS-005, AS-006, AS-007.
- Status: Implemented.

## REQ-EVID-001 — Evidence and reports must exclude raw payloads, secrets, logs, and local overrides

- Rationale: defense/demo artifacts must be safe to share.
- Implemented by: evidence exporter, release pack allowlist, `.gitignore`, docs/tests guardrails.
- Verification: `DefenseEvidenceExportTests`, `ProductPackagingTests`, `DemoWorkflowContractTests`.
- Related scenarios: AS-009.
- Status: Implemented.

## REQ-VAL-001 — Demo/readiness/full-validation must be deterministic and CI-safe

- Rationale: the project needs reproducible proof without live infrastructure.
- Implemented by: `Test-ConShieldDemoReadiness.ps1`, `Test-ConShieldFullValidation.ps1`, fixture modes, CI-safe tests.
- Verification: `DemoReadinessCheckScriptTests`, `FullIntegrationContractTests`, `DemoWorkflowContractTests`.
- Related scenarios: AS-010.
- Status: Implemented.

## REQ-PACK-001 — Release packaging must exclude generated/local/secret material

- Rationale: handoff bundles should be safe and reproducible.
- Implemented by: `New-ConShieldDemoReleasePack.ps1`, packaging docs, allowlist-based copy.
- Verification: `ProductPackagingTests`.
- Related scenarios: AS-009.
- Status: Implemented.

## REQ-DOC-001 — Documentation must honestly describe limitations and out-of-scope items

- Rationale: academic and stakeholder claims must be defensible.
- Implemented by: product positioning, competitive analysis, threat model, roadmap, traceability docs.
- Verification: `ProductPositioningDocsTests`, `ThreatModelRequirementsDocsTests`.
- Related scenarios: AS-010.
- Status: Implemented.
