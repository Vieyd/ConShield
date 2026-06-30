# ConShield Product Positioning

## One-sentence positioning

ConShield is a local-first DevSecOps/SIEM control plane for container security that connects image scanning, policy-as-code, CI/CD gating, runtime and lifecycle signals, sensor trust, signed events, incident correlation, and evidence export into one reproducible workflow.

## Problem

Container security work is often split across separate tools and separate moments:

- image scanning before a container is used;
- policy decisions in CI or a local operator workflow;
- runtime and lifecycle signals after the workload starts;
- SIEM correlation and incident handling;
- evidence collection for audit, training, or project defense.

For small teams, labs, and student projects, this can make the security story difficult to reproduce. The operator may have scan findings in one place, runtime events in another place, and evidence in a third place. ConShield focuses on making that chain visible and repeatable in a local environment.

## Target users

- Students and researchers demonstrating an end-to-end container security workflow.
- Small DevSecOps teams that need an explainable local prototype before adopting heavier platforms.
- Security engineers who want deterministic fixtures for training and CI-safe regression checks.
- Operators who need a guided flow from security signal to incident and evidence.

## Target environments

- Local development machines.
- Educational labs and diploma defense environments.
- Offline-friendly or restricted demo setups.
- Prototype deployments where transparency and reproducibility matter more than large-scale enterprise coverage.

The default demo does not require real Fedora/Falco, live Docker execution, live Trivy database/network access, Kubernetes, external internet, real certificates, private keys, signing keys, or real secrets.

## What ConShield does

- Accepts container image scan input and maps it into ConShield security events.
- Evaluates protected container run decisions through policy-as-code.
- Provides a deterministic CI/CD container gate path.
- Replays Docker lifecycle events into lifecycle security events.
- Replays Falco-compatible runtime events without requiring a live Fedora/Falco node.
- Tracks runtime sensor health, trust registry state, trust enforcement, and signed sensor event status.
- Correlates configured SIEM rules into alerts.
- Creates and links incidents for operator workflow.
- Exports safe evidence for demo, audit-style review, and academic defense.
- Provides both Web UI and a unified CLI wrapper for local workflows.

## What ConShield does not do

- It is not an enterprise CNAPP replacement.
- It is not a certified compliance platform.
- It is not a Kubernetes admission controller in the current version.
- It does not implement full mTLS yet.
- It does not provide broad enterprise multi-cluster management.
- It does not claim complete vulnerability coverage or guaranteed prevention.
- It does not replace specialist scanners, runtime sensors, policy engines, or enterprise SIEM/XDR platforms.

## Differentiators

- End-to-end container security chain, not scanner-only output.
- Local/offline-friendly demo paths with deterministic fixtures.
- Policy-as-code and SIEM-as-code configuration.
- Sensor trust registry, trust enforcement, and signed sensor event handling.
- Evidence-first reporting designed for defense and audit-style explanation.
- Unified CLI plus Web GUI over the same local workflows.
- Demo release pack and full validation command for reproducible handoff.
- Base demo works without requiring Kubernetes.
- Design favors transparent educational and small-team deployment over opaque automation.

## Why this is relevant for real tasks

Real container security decisions rarely stop at a single scan result. A team needs to decide whether an image can move forward, whether a running workload produced suspicious behavior, whether the signal came from a trusted sensor, how the alert is correlated, what incident action was taken, and what evidence remains afterward.

ConShield gives this chain a concrete, inspectable shape:

```text
scan -> policy gate -> runtime/lifecycle -> sensor trust/signatures -> SIEM -> incidents -> evidence
```

That makes it useful for demonstrating process maturity, validating regression contracts, and explaining how separate controls can become one operator workflow.

## Academic contribution

The academic contribution is the integration model rather than a claim of outperforming specialized security products. ConShield demonstrates how container scanning, policy decisions, runtime and lifecycle signals, sensor identity, signature verification, SIEM correlation, incident workflow, and evidence export can be connected in a reproducible local prototype.

## Practical contribution

The practical contribution is a safe, repeatable demo and validation surface:

- deterministic fixture modes for CI-safe checks;
- commands that avoid live Docker/Falco/Trivy dependencies by default;
- generated evidence that avoids raw payloads and secrets;
- clear operator navigation from summary to alert, incident, source event, and exported report;
- release packaging for local handoff.

## Demo story

The recommended demo story is:

1. Start the local stack.
2. Reset demo data.
3. Run the defense scenario.
4. Replay image scan, protected run, Docker lifecycle, and Falco-compatible runtime fixtures.
5. Review Security Summary, Security Events, SIEM, Incidents, and Runtime Sensor Health.
6. Show trust/signature outcomes for runtime sources.
7. Export evidence.
8. Run readiness and full validation checks.

## Limitations

- ConShield is intentionally smaller than commercial CNAPP platforms.
- The current base demo is local-first and fixture-friendly.
- Live Fedora/Falco deployment is optional and operationally separate from the default demo.
- Live Docker execution and live Trivy network scanning are optional/manual paths.
- Full mTLS is intentionally future work.
- Kubernetes admission control is intentionally future work.
- Compliance certification and enterprise-scale operations are outside the current scope.

## Roadmap

The realistic roadmap is documented in [ROADMAP_TO_PRODUCTION.md](ROADMAP_TO_PRODUCTION.md). The short version is: harden authentication and deployment, add stronger sensor identity and key management, add production-grade runtime agent packaging, add Kubernetes/admission integration, improve multi-node operations, and integrate with enterprise reporting systems while preserving deterministic local validation.
