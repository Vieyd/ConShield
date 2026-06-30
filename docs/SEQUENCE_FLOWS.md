# Sequence Flows

This document shows key local ConShield sequences using Mermaid. The flows are deterministic by default and avoid external internet, live Docker execution, live Trivy DB/network, real Fedora/Falco, real certificates, private keys, signing keys, or real secrets.

## CI/CD gate sequence

```mermaid
sequenceDiagram
    participant CI as Developer/CI
    participant CLI as ConShield.Cli gate image
    participant Scan as Image scan parser
    participant Policy as Container policy
    participant Report as Sanitized gate report

    CI->>CLI: gate image with fixture and fail-on mode
    CLI->>Scan: parse Trivy-compatible fixture
    Scan-->>CLI: normalized findings summary
    CLI->>Policy: evaluate Allow/Warn/Block
    Policy-->>CLI: decision and matched rule IDs
    CLI->>Report: write optional sanitized Markdown report
    CLI-->>CI: deterministic exit code
```

## Protected run sequence

```mermaid
sequenceDiagram
    participant Operator
    participant CLI as Protected run wrapper
    participant Policy as Container policy
    participant Docker as Docker execution
    participant Event as Normalized events

    Operator->>CLI: run protected with fixture
    CLI->>Policy: evaluate findings
    Policy-->>CLI: Allow/Warn/Block
    alt Block
        CLI-->>Docker: no run
    else Warn without acceptance
        CLI-->>Docker: no run
    else Execute allowed and accepted
        CLI->>Docker: optional live run
    end
    CLI->>Event: IMG/POL/LIFE summaries
```

## Docker lifecycle replay sequence

```mermaid
sequenceDiagram
    participant Operator
    participant CLI as lifecycle replay
    participant Mapper as Lifecycle mapper
    participant Ingestion as Optional ingestion

    Operator->>CLI: replay Docker event fixture
    CLI->>Mapper: map lifecycle events
    Mapper-->>CLI: LIFE event summaries
    alt no-submit
        CLI-->>Operator: deterministic summary only
    else submit
        CLI->>Ingestion: submit normalized LIFE events
    end
```

## Runtime sensor signed event sequence

```mermaid
sequenceDiagram
    participant Operator
    participant Replay as Falco/runtime replay
    participant Trust as Sensor trust registry
    participant Sign as Signed sensor verifier
    participant Siem as SIEM correlation

    Operator->>Replay: replay runtime fixture
    Replay->>Trust: resolve source trust status
    Replay->>Sign: verify signature metadata
    Sign-->>Replay: Valid/Missing/Invalid/Stale
    Replay->>Siem: expected RTE/SENSOR/SIGN signal
    Siem-->>Operator: deterministic rule expectation
```

## Sensor trust enforcement sequence

```mermaid
sequenceDiagram
    participant Source as Runtime source
    participant Registry as Sensor registry
    participant Enforcement as Trust enforcement
    participant Alert as SIEM alert

    Source->>Registry: source system and sensor metadata
    Registry-->>Enforcement: Trusted/Unknown/Revoked/Disabled
    alt Trusted
        Enforcement-->>Alert: normal RTE behavior
    else Unknown
        Enforcement-->>Alert: SENSOR-001
    else Revoked or Disabled
        Enforcement-->>Alert: SENSOR-002
    end
```

## Evidence export sequence

```mermaid
sequenceDiagram
    participant Operator
    participant Export as Evidence exporter
    participant Db as PostgreSQL summaries
    participant Files as artifacts/local

    Operator->>Export: export evidence
    Export->>Db: query safe summaries
    Db-->>Export: counts, IDs, statuses, linked records
    Export->>Export: sanitize sections
    Export->>Files: write Markdown evidence
    Export-->>Operator: Result: PASS
```

## Full validation sequence

```mermaid
sequenceDiagram
    participant Operator
    participant Full as Test-ConShieldFullValidation.ps1
    participant Config as Config validation
    participant Cli as CLI fixture checks
    participant Docs as Docs/security guardrails

    Operator->>Full: run full validation
    Full->>Config: validate SIEM, policy, sensor registry
    Full->>Cli: validate deterministic commands/contracts
    Full->>Docs: verify docs, fixtures, artifacts, guardrails
    Full-->>Operator: Result: PASS
```
