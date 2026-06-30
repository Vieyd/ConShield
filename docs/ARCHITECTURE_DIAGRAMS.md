# Architecture Diagrams

This document contains Mermaid diagrams for the current ConShield local-first architecture. Diagrams are source-controlled as Markdown, not generated binary images.

## System context diagram

### Purpose

Show the main external actors and local ConShield runtime surfaces.

### Scope

Local demo and deterministic validation topology.

### Diagram

```mermaid
flowchart LR
    Developer["Developer / CI"] --> CLI["ConShield.Cli and scripts"]
    Operator["Operator"] --> Web["ConShield.Web"]
    DockerHost["Docker host"] --> CLI
    RuntimeSensor["Runtime sensor / Falco-compatible source"] --> CLI
    TrivySource["Trivy-compatible scan source"] --> CLI

    CLI --> Backend["ConShield backend services"]
    Web --> Backend
    Backend --> Pg["PostgreSQL operational data"]
    Backend --> Rabbit["RabbitMQ message broker"]
    Rabbit --> Consumer["ConShield.EventConsumer"]
    Consumer --> Mongo["MongoDB projection"]
    Backend --> Evidence["Evidence export under artifacts/local"]
```

### How to read it

Developer/CI and operators interact with CLI/scripts or Web. Inputs are normalized by backend services and stored or projected through local datastores. Evidence export produces ignored local artifacts.

### Related implementation

`src/ConShield.Cli`, `src/ConShield.Web`, `src/ConShield.Application`, `src/ConShield.EventConsumer`, `scripts/Export-ConShieldDefenseEvidence.ps1`.

### Related requirements

REQ-IMG-001, REQ-CICD-001, REQ-RTE-001, REQ-SIEM-001, REQ-EVID-001, REQ-VAL-001.

## Component diagram

### Purpose

Show core internal modules and how they cooperate.

### Scope

Application modules, CLI/scripts, persistence, and optional message pipeline.

### Diagram

```mermaid
flowchart TB
    subgraph UI["Web/API"]
        WebMvc["MVC pages"]
        Ingestion["External event ingestion API"]
        Demo["/Demo walkthrough"]
    end

    subgraph CLI["CLI/scripts"]
        Cli["ConShield.Cli"]
        PsScripts["PowerShell workflows"]
        Validation["Full validation"]
    end

    subgraph Services["Application services"]
        ImageScanner["ImageScanner"]
        ContainerPolicy["ContainerPolicy"]
        RuntimeDetection["RuntimeDetection"]
        SensorTrust["Sensor trust"]
        SignedEvents["Signed sensor events"]
        Siem["SIEM correlation"]
        Incidents["Incident workflow"]
        Evidence["Evidence export"]
    end

    subgraph Persistence["Persistence"]
        Pg["PostgreSQL"]
        Rabbit["RabbitMQ"]
        EventConsumer["EventConsumer"]
        Mongo["MongoDB projection"]
    end

    WebMvc --> Services
    Demo --> Services
    Ingestion --> Services
    Cli --> Services
    PsScripts --> Services
    Validation --> Services
    Services --> Pg
    Services --> Rabbit
    Rabbit --> EventConsumer
    EventConsumer --> Mongo
```

### How to read it

Web/API and CLI/scripts are entry points. Application services normalize and correlate data. Persistence components retain operational data and optional projections.

### Related implementation

`src/ConShield.Application`, `src/ConShield.ImageScanner`, `src/ConShield.ContainerPolicy`, `src/ConShield.RuntimeDetection`, `src/ConShield.EventPipeline`.

### Related requirements

REQ-POL-001, REQ-LIFE-001, REQ-SENS-001, REQ-SIGN-001, REQ-INC-001.

## Trust boundary diagram

### Purpose

Show where data crosses boundaries and needs validation/sanitization.

### Scope

Local operator, CLI/scripts, ingestion, broker, database, runtime sensor, Docker host, Web UI, and release packaging boundaries.

### Diagram

```mermaid
flowchart LR
    subgraph B1["Local operator boundary"]
        Operator["Operator"]
        Browser["Browser"]
    end

    subgraph B2["CLI/scripts boundary"]
        CLI["ConShield.Cli"]
        Scripts["PowerShell scripts"]
    end

    subgraph B3["External event ingestion boundary"]
        API["Ingestion API"]
        Normalizer["Event normalization"]
    end

    subgraph B4["Runtime sensor boundary"]
        Sensor["Runtime/Falco source"]
        Signature["Signature metadata"]
    end

    subgraph B5["Docker host boundary"]
        Docker["Docker lifecycle source"]
    end

    subgraph B6["Message broker boundary"]
        Rabbit["RabbitMQ"]
    end

    subgraph B7["Database boundary"]
        Pg["PostgreSQL"]
        Mongo["MongoDB"]
    end

    subgraph B8["Web UI boundary"]
        Web["ConShield.Web views"]
    end

    subgraph B9["Release packaging boundary"]
        Pack["Release pack allowlist"]
        Artifacts["artifacts/local"]
    end

    Operator --> CLI
    Browser --> Web
    CLI --> API
    Scripts --> API
    Sensor --> Normalizer
    Signature --> Normalizer
    Docker --> Normalizer
    API --> Pg
    API --> Rabbit
    Rabbit --> Mongo
    Pg --> Web
    Pg --> Pack
    Pack --> Artifacts
```

### How to read it

Each subgraph is a trust boundary. Inputs crossing into ConShield are normalized, validated, deduplicated, or summarized before operator display and evidence export.

### Related implementation

`docs/THREAT_MODEL.md`, external ingestion controllers, replay scripts, release packaging script, evidence exporter.

### Related requirements

REQ-EVID-001, REQ-PACK-001, REQ-SENS-001, REQ-SIGN-001, REQ-DOC-001.

## End-to-end event pipeline diagram

### Purpose

Show how scan/gate/protected run/lifecycle/runtime inputs become alerts, incidents, and evidence.

### Scope

Security event processing from source to evidence.

### Diagram

```mermaid
flowchart LR
    Sources["scan / gate / protected run / lifecycle / runtime"] --> Normalized["normalized event"]
    Normalized --> Ingest["ingestion and application services"]
    Ingest --> Pg["PostgreSQL SecurityEvents"]
    Ingest --> Outbox["Outbox"]
    Outbox --> Rabbit["RabbitMQ"]
    Rabbit --> Consumer["EventConsumer"]
    Consumer --> Mongo["MongoDB projection"]
    Pg --> Siem["SIEM correlation"]
    Siem --> Alert["SIEM alert"]
    Alert --> Incident["Incident"]
    Pg --> Evidence["Evidence export"]
    Incident --> Evidence
    Evidence --> Views["Web / CLI review"]
```

### How to read it

The primary operational path is normalized event → PostgreSQL → SIEM alert → incident → evidence. The broker/projection path is optional but validated by existing pipeline contracts.

### Related implementation

`ConShield.SecurityEvents`, `ConShield.EventPipeline`, `ConShield.EventConsumer`, SIEM correlation service, incident services.

### Related requirements

REQ-IMG-001, REQ-SIEM-001, REQ-INC-001, REQ-EVID-001.

## Configuration-as-code diagram

### Purpose

Show committed default configs and how validation/runtime paths use them.

### Scope

SIEM rules, container policy, sensor registry, validation, CLI/Web/evidence.

### Diagram

```mermaid
flowchart TB
    SiemConfig["config/siem-rules.default.json"] --> SiemValidation["Test-ConShieldSiemRules.ps1"]
    PolicyConfig["config/container-policy.default.json"] --> PolicyValidation["Test-ConShieldContainerPolicy.ps1"]
    SensorConfig["config/sensor-registry.default.json"] --> SensorValidation["Test-ConShieldSensorRegistry.ps1"]

    SiemConfig --> SiemRuntime["SIEM correlation"]
    PolicyConfig --> ProtectedRun["Protected run and CI/CD gate"]
    SensorConfig --> SensorRuntime["Runtime Sensor Health and trust enforcement"]

    SiemRuntime --> Evidence["Evidence export"]
    ProtectedRun --> Evidence
    SensorRuntime --> Evidence
    SiemValidation --> FullValidation["Test-ConShieldFullValidation.ps1"]
    PolicyValidation --> FullValidation
    SensorValidation --> FullValidation
```

### How to read it

Committed default configs are validated directly and also consumed by runtime/demo workflows. Local overrides are intentionally ignored by Git.

### Related implementation

`config/*.default.json`, validation scripts, `ConShield.Cli validate`, evidence exporter.

### Related requirements

REQ-POL-001, REQ-SIEM-001, REQ-SENS-001, REQ-VAL-001.
