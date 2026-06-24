# ConShield Diploma Feature Map

This map helps choose which implemented modules, screens, and documents to reference in diploma text and demo defense materials.

## Implemented features

| Feature | Evidence route/file/module | Status |
| --- | --- | --- |
| Architecture and threat-oriented pipeline | `docs/CONSHIELD_ARCHITECTURE_AND_ROADMAP.md` | demo-ready |
| Image scanning | `src/ConShield.ImageScanner`, `docs/CONTAINER_IMAGE_SCANNING.md` | implemented |
| Container policy gate | `src/ConShield.ContainerPolicy`, `docs/CONTAINER_POLICY_GATE.md` | implemented |
| Runtime collector | `src/ConShield.RuntimeCollector`, `docs/FALCO_RUNTIME_EVENT_INGESTION.md` | implemented |
| Fedora enrolled sensor rollout | `deploy/falco-linux`, `docs/REAL_FALCO_FEDORA_DEPLOYMENT.md`, `docs/SENSOR_PROVISIONING_AND_FEDORA_ROLLOUT.md` | demo-ready |
| Protected ingestion | `src/ConShield.Web/Controllers/ApiV1SecurityEventsController.cs`, `/api/v1/security-events` | implemented |
| Security event storage | `src/ConShield.Data/Entities/SecurityEventEntry.cs`, `/SecurityEvents` | implemented |
| Outbox/event pipeline | `src/ConShield.EventPipeline`, RabbitMQ, `src/ConShield.EventConsumer` | implemented |
| Inbox/projection receipts | PostgreSQL inbox receipts and optional MongoDB projection docs | implemented |
| Sensor inventory and heartbeat | `/Sensors`, sensor heartbeat API, `src/ConShield.Web/Controllers/SensorsController.cs` | demo-ready |
| Credential lifecycle | provisioning, rotation, revocation, and lifecycle audit docs | implemented |
| Lifecycle audit events | `/SecurityEvents` filtered by `conshield.sensor-lifecycle` | demo-ready |
| SIEM correlation | `src/ConShield.Application`, alerts/incidents UI | implemented |
| Lifecycle SIEM rules | `LIFE-001`, `LIFE-002`, `docs/SENSOR_LIFECYCLE_AUDIT_PLAYBOOK.md` | demo-ready |
| Operations Health | `/Operations/Health` | demo-ready |
| Security Summary report/export | `/Reports/SecuritySummary`, `/Reports/SecuritySummaryMarkdown?range=24h` | demo-ready |
| Safe demo evidence pack | `docs/DEMO_EVIDENCE_PACK.md` | demo-ready |

## Diploma task mapping

| Diploma task | Best evidence | Status |
| --- | --- | --- |
| Analyze threats to containerized applications | architecture/roadmap, image scan, policy gate, runtime detection docs | demo-ready |
| Detect vulnerable container images | ImageScanner module and no-submit demo command | implemented |
| Define launch policy controls | ContainerPolicy module and policy gate demo command | implemented |
| Monitor runtime behavior | RuntimeCollector and enrolled sensor heartbeat/status flow | demo-ready |
| Secure event ingestion | protected ingestion API and sensor-bound runtime source controls | implemented |
| Process events reliably | PostgreSQL outbox, RabbitMQ, EventConsumer, inbox receipts | implemented |
| Correlate security events | SIEM rules including image, policy, runtime, and lifecycle rules | implemented |
| Support operator investigation | Operations Health, Security Events, Sensor Fleet, Alerts/Incidents | demo-ready |
| Produce safe reporting evidence | Security Summary read-only report and Markdown export | demo-ready |

## Future-work backlog

| Future work | Why it matters | Status |
| --- | --- | --- |
| mTLS binding | Strong sensor/service identity beyond credential headers | future work |
| Kubernetes/admission control | Native cluster policy enforcement and workload admission | future work |
| Centralized secret manager | Production-grade credential storage and rotation | future work |
| Prometheus/Grafana | Metrics, dashboards, and alerting outside the relational UI | future work |
| Retention/partitioning | Long-term event storage management at larger scale | future work |
| Rule DSL/configurable rules | Operator-managed detections without recompilation | future work |
| Auto-remediation | Controlled response workflows after alerts/incidents | future work |
