# ConShield Architecture and Roadmap

## Product vision

ConShield is a DevSecOps/SIEM prototype for container security. It connects image scanning, policy gate decisions, runtime sensor events, durable event delivery, SIEM-style correlation, alerts, incidents, and operator workflows.

The goal is not to be a production SIEM on day one. The goal is to provide a complete, explainable security pipeline that can be demonstrated locally, reviewed as a portfolio project, and evolved into a larger platform.

```text
Image scan + policy gate + runtime sensor
        ↓
protected ingestion API
        ↓
PostgreSQL SecurityEvents + Sensors + Outbox
        ↓
RabbitMQ
        ↓
EventConsumer + Inbox + optional Mongo raw projection
        ↓
SIEM correlation rules → Alerts → Incidents → UI/reports
```

## Current architecture

### Sources

- `ConShield.Collector` submits generated or JSON-file security events.
- `ConShield.ImageScanner` wraps Trivy image scanning and submits normalized image scan findings.
- `ConShield.ContainerPolicy` evaluates local policy gate decisions and records policy/launch audit events.
- `ConShield.RuntimeCollector` reads Falco-compatible JSONL events from an enrolled Fedora sensor path.

### Central services

- `ConShield.Web` hosts the MVC UI, protected ingestion API, sensor heartbeat API, authentication, and operator workflows.
- PostgreSQL stores `SecurityEvents`, `Sensors`, `SensorCredentials`, outbox messages, alerts, incidents, exceptions, and DLQ quarantine records.
- The protected ingestion API accepts general security events and sensor-bound runtime events.
- The sensor heartbeat API maintains inventory freshness without creating security events.

### Event pipeline

- Security events are written atomically with PostgreSQL outbox messages.
- RabbitMQ decouples durable publication from downstream consumption.
- `ConShield.EventConsumer` consumes messages idempotently, records PostgreSQL inbox receipts, and can project raw messages into MongoDB.
- DLQ/quarantine/replay foundations allow failed messages to be captured and replayed without publishing directly from MVC requests.

## Implemented security boundaries

- The general ingestion key cannot submit reserved runtime source events.
- Runtime source events use enrolled sensor identity headers.
- Legacy runtime collector fallback is disabled for enrolled-sensor-only operation.
- Sensor credentials are stored as SHA-256 verifiers rather than plaintext secrets.
- Local provisioning prints a new sensor credential once for operator handoff.
- Fedora runtime collector environment files are root-owned and mode `0600`.
- The RuntimeCollector service runs as a non-root hardened user.
- SELinux remains Enforcing on the Fedora runtime sensor host.
- `ConShield.Web` does not launch Falco, Trivy, Docker, or privileged host commands directly.

## Current verticals

### Image scanning vertical

Trivy produces image vulnerability findings. `ConShield.ImageScanner` submits them through the ingestion API, PostgreSQL stores the resulting event, and `IMG-001` can create an alert and incident for critical container image risk.

```text
Trivy → ImageScanner → ingestion API → PostgreSQL → IMG-001 → alert/incident
```

### Policy gate vertical

Image scan summaries feed the container policy gate. The gate returns Allow, Warn, or Block decisions, records `POL-001`-compatible events, and can write optional launch audit events when execution is allowed.

```text
Image scan summary → ContainerPolicy → Allow/Warn/Block → POL-001 → optional launch audit
```

### Runtime detection vertical

The Fedora runtime sensor path reads Falco-compatible JSONL, maps supported rules into deterministic runtime events, submits them with enrolled sensor headers, and enables `RTE-001` correlation.

```text
Falco-compatible JSONL → RuntimeCollector → enrolled sensor headers → ingestion API → RTE-001 → alert/incident
```

### Event pipeline vertical

Every accepted security event can be delivered through the durable outbox pipeline. RabbitMQ and inbox receipts provide at-least-once delivery with idempotent consumers, and MongoDB can hold immutable raw event projections for investigation/search use cases.

```text
SecurityEvent → PostgreSQL Outbox → RabbitMQ → EventConsumer → Inbox → optional Mongo projection
```

## Scalability model

What scales in the current design:

- Multiple runtime sensors can be enrolled conceptually through the sensor inventory and credential model.
- Event ingestion is decoupled from downstream processing through PostgreSQL outbox, RabbitMQ, and inbox receipts.
- Consumers can be expanded for additional projections or integrations.
- MongoDB projection can support raw event search and retention separate from relational workflows.
- PostgreSQL can be optimized later with indexes, partitioning, and retention policies.

Current limits:

- Deployment is still local-development oriented.
- Authentication is demo/local only, not production identity.
- There is no multi-tenancy.
- There is no event retention or PostgreSQL partitioning strategy yet.
- PostgreSQL and RabbitMQ are not deployed in a high-availability topology.
- Sensor fleet UI is not implemented yet.
- Sensor credential rotation/revocation workflow is not implemented yet.
- mTLS is not implemented yet.

## Roadmap

### Near-term

1. Sensor fleet UI:
   - list sensors;
   - show online/offline status;
   - show last seen timestamp;
   - show source system;
   - show revoked state;
   - show credential age without exposing secrets.

2. Credential rotation/revocation:
   - rotate sensor credential;
   - revoke credential;
   - revoke sensor;
   - preserve an audit trail;
   - follow the [sensor credential lifecycle design](SENSOR_CREDENTIAL_LIFECYCLE.md).

3. Enrolled-sensor-only documentation and tests:
   - startup without legacy runtime key;
   - negative authentication tests;
   - operational guide for local and Fedora smoke checks.

4. Observability:
   - health endpoints;
   - event ingestion rate;
   - outbox pending count;
   - DLQ count;
   - heartbeat lag.

### Mid-term

1. Rule engine:
   - configurable YAML/JSON rules;
   - MITRE ATT&CK mapping;
   - severity mapping;
   - suppression and exception handling.

2. Retention and storage:
   - event retention policy;
   - PostgreSQL partitioning;
   - raw event search via MongoDB projection.

3. mTLS-ready identity:
   - sensor certificate fingerprint fields;
   - certificate binding;
   - staged migration from credential-only authentication.

4. Better investigation UI:
   - incident timeline;
   - source event graph;
   - related alerts and events;
   - analyst notes.

### Future / trend-aligned

1. AI-assisted triage:
   - explain alert context;
   - generate investigation checklist;
   - summarize related events;
   - never auto-remediate without explicit approval.

2. Kubernetes track:
   - admission controller;
   - Kubernetes audit logs;
   - Falco DaemonSet mode;
   - policy admission decisions;
   - keep this out of immediate scope until the base platform is stable.

3. Supply-chain security:
   - SBOM import;
   - signature verification;
   - provenance metadata;
   - policy exceptions.

## What ConShield is not yet

- A production SIEM.
- An EDR.
- A SOAR platform with automatic response.
- A Kubernetes-native platform.
- An mTLS PKI system.
- A centralized secret manager.

## Diploma/product positioning

ConShield demonstrates a complete security pipeline:

```text
Scan → Policy → Runtime Detection → Event Ingestion → Correlation → Alert → Incident
```

It is intentionally built as a safe, local, explainable prototype that can evolve into a larger DevSecOps security platform.

For defense/demo preparation, use [DEMO_EVIDENCE_PACK.md](DEMO_EVIDENCE_PACK.md) and [DIPLOMA_FEATURE_MAP.md](DIPLOMA_FEATURE_MAP.md) to map implemented modules, routes, and future-work boundaries to diploma goals.
