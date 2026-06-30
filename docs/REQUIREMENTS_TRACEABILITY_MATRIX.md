# Requirements Traceability Matrix

This matrix maps threat scenarios to requirements, implemented repository elements, commands, SIEM/config IDs, evidence, and tests.

| Requirement ID | Requirement summary | Threat/scenario IDs | Implemented by | Config/rule IDs | CLI/script command | Tests | Evidence/demo output | Status |
|---|---|---|---|---|---|---|---|---|
| REQ-IMG-001 | Image scan results must be normalized into security events | AS-001 | `ConShield.ImageScanner`, external event ingestion | `IMG-001`, `conshield.image-scanner` | `dotnet run --project .\src\ConShield.Cli -- scan image --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json --no-submit` | `ImageScanCliScriptTests`, `ImageScannerParserTests` | Image Scan Evidence, IMG SIEM alert path | Implemented |
| REQ-POL-001 | Critical/high findings must be evaluated by policy-as-code | AS-001, AS-002, AS-010 | `ConShield.ContainerPolicy`, protected run | `POL-001`, `config/container-policy.default.json` | `pwsh -File .\scripts\Test-ConShieldContainerPolicy.ps1` | `ContainerPolicyAsCodeTests`, `ContainerPolicyTests` | Container Policy Evidence, policy decision summary | Implemented |
| REQ-CICD-001 | CI/CD gate must provide deterministic exit codes | AS-001, AS-010 | `src/ConShield.Cli gate image` | `config/container-policy.default.json` | `dotnet run --project .\src\ConShield.Cli -- gate image --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json --fail-on never --no-submit` | `CicdContainerGateTests` | CI/CD gate report, PASS_WITH_FINDINGS | Implemented |
| REQ-RUN-001 | Protected run must prevent or flag blocked image launches | AS-002 | `Invoke-ConShieldProtectedRun.ps1`, `ConShield.Cli run protected` | `POL-001`, block/warn/allow policy rules | `dotnet run --project .\src\ConShield.Cli -- run protected --from-trivy-json .\tests\TestData\Trivy\sample-image-scan.json --no-run --no-submit` | `ProtectedContainerRunScriptTests` | Protected Run Evidence, launch decision event | Implemented |
| REQ-LIFE-001 | Docker lifecycle events must be normalized and sanitized | AS-004 | Docker lifecycle collector/replay | `LIFE-001`, `LIFE-002` | `dotnet run --project .\src\ConShield.Cli -- lifecycle replay --from-docker-events-json .\tests\TestData\DockerEvents\container-lifecycle-events.json --no-submit` | `DockerLifecycleCollectorTests` | Docker Lifecycle Collector Evidence | Implemented |
| REQ-RTE-001 | Runtime/Falco events must be mapped to SIEM rules | AS-003 | `ConShield.RuntimeDetection`, runtime collector, replay script | `RTE-001`, `config/siem-rules.default.json` | `pwsh -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 -NoSubmit` | `FalcoRuntimeDetectionTests`, `FalcoRuntimeSensorPathTests` | Runtime Sensor Health, RTE alert/incident | Implemented |
| REQ-SENS-001 | Unknown sensors must be identified and surfaced | AS-005 | sensor trust registry, Runtime Sensor Health | `SENSOR-001`, `config/sensor-registry.default.json` | `pwsh -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 -SimulateUnknownSensor -NoSubmit` | `SensorTrustRegistryTests`, `SensorTrustEnforcementTests` | Sensor Trust Evidence, Runtime Sensor Health | Implemented |
| REQ-SENS-002 | Revoked/disabled sensors must trigger stronger handling | AS-006 | sensor trust enforcement, Runtime Sensor Health | `SENSOR-002`, `config/sensor-registry.default.json` | `pwsh -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 -SimulateRevokedSensor -NoSubmit` | `SensorTrustEnforcementTests` | Sensor Trust Enforcement Evidence | Implemented |
| REQ-SIGN-001 | Signed sensor event status must be verified and surfaced | AS-007 | signed sensor event verifier, replay modes | `SIGN-001`, `SIGN-002`, `SIGN-003` | `pwsh -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 -SimulateInvalidSignature -NoSubmit` | `SignedSensorEventsTests` | Signed Sensor Event Evidence | Implemented |
| REQ-SIEM-001 | SIEM rules must be configurable and validated | AS-001, AS-003, AS-004, AS-005, AS-006, AS-007, AS-010 | SIEM correlation service, config loader | `config/siem-rules.default.json`, `IMG-001`, `POL-001`, `RTE-001`, `LIFE-001`, `LIFE-002`, `SENSOR-001`, `SENSOR-002`, `SIGN-001`, `SIGN-002`, `SIGN-003` | `pwsh -File .\scripts\Test-ConShieldSiemRules.ps1` | `ConfigurableSiemRulesTests`, `SiemCorrelationServiceTests` | SIEM Rules Evidence | Implemented |
| REQ-INC-001 | Incidents must be generated or linked from correlated security events | AS-001, AS-003, AS-004, AS-005, AS-006, AS-007 | SIEM alerts, incident workflow, source event link | SIEM alert/incident correlation | `pwsh -File .\scripts\Run-ConShieldDefenseScenario.ps1` | `OperatorWorkflowTests`, `SecurityEventsUiTests` | Operator Workflow, linked incidents | Implemented |
| REQ-EVID-001 | Evidence and reports must exclude raw payloads, secrets, logs, and local overrides | AS-009 | evidence exporter, report sanitization, docs guardrails | `.gitignore`, evidence section allowlist | `pwsh -File .\scripts\Export-ConShieldDefenseEvidence.ps1 -OutputMarkdownPath .\artifacts\local\defense-evidence.md` | `DefenseEvidenceExportTests`, `DemoWorkflowContractTests` | Safe Markdown evidence under `artifacts/local` | Implemented |
| REQ-VAL-001 | Demo/readiness/full-validation must be deterministic and CI-safe | AS-010 | readiness script, full validation script, fixture modes | deterministic fixtures in `tests/TestData` | `pwsh -File .\scripts\Test-ConShieldFullValidation.ps1` | `FullIntegrationContractTests`, `DemoReadinessCheckScriptTests` | Full validation PASS output | Implemented |
| REQ-PACK-001 | Release packaging must exclude generated/local/secret material | AS-009 | release packaging script and allowlist | `.gitignore`, packaging allowlist | `pwsh -File .\scripts\New-ConShieldDemoReleasePack.ps1` | `ProductPackagingTests` | Demo release pack under ignored local artifacts | Implemented |
| REQ-DOC-001 | Documentation must honestly describe limitations and out-of-scope items | AS-010 | product positioning, threat model, roadmap, traceability docs | docs guardrails | Review `docs/PRODUCT_POSITIONING.md` and `docs/THREAT_MODEL.md` | `ProductPositioningDocsTests`, `ThreatModelRequirementsDocsTests` | Defense narrative and docs links | Implemented |

## Coverage summary

- Image scan: REQ-IMG-001, AS-001.
- Protected run: REQ-RUN-001, AS-002.
- CI/CD gate: REQ-CICD-001, AS-001.
- Docker lifecycle collector: REQ-LIFE-001, AS-004.
- Runtime/Falco replay: REQ-RTE-001, AS-003.
- Sensor trust: REQ-SENS-001, REQ-SENS-002, AS-005, AS-006.
- Signed sensor events: REQ-SIGN-001, AS-007.
- SIEM rules: REQ-SIEM-001, AS-010.
- Incidents/operator workflow: REQ-INC-001.
- Evidence export: REQ-EVID-001, AS-009.
- Full validation: REQ-VAL-001.
- Release packaging: REQ-PACK-001.
- Product positioning limitations: REQ-DOC-001.
