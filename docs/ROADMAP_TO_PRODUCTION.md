# Roadmap to Production

This roadmap describes realistic hardening work that would be required beyond the current local-first prototype. It is not a promise that every phase already exists.

## Phase 1 — Current local prototype

- Local Web UI and unified CLI.
- Deterministic fixture paths for image scan, protected run, CI/CD gate, Docker lifecycle, and Falco-compatible runtime events.
- Configurable SIEM rules and container policy.
- Sensor trust registry, trust enforcement, and signed sensor event checks.
- Incidents, operator workflow, evidence export, full validation, and demo release packaging.

## Phase 2 — Hardening

- Stronger deployment profiles.
- Clear environment separation.
- Structured operational logging without secret exposure.
- More complete backup and restore guidance.
- Expanded regression checks for documentation, configuration, and generated artifacts.

## Phase 3 — Real runtime agent

- Package runtime collection as a maintained Linux service.
- Improve upgrade/rollback guidance.
- Expand host compatibility testing.
- Keep deterministic replay as the default CI path.

## Phase 4 — Kubernetes admission controller

- Add admission-style policy enforcement only after the local policy model is stable.
- Keep local protected-run and CI/CD gate behavior as simpler validation paths.
- Document cluster-specific risk and rollback procedures.

## Phase 5 — mTLS and key management

- Replace demo signing material with real key-management workflows.
- Add certificate lifecycle, rotation, revocation, and audit support.
- Preserve the current no-real-secret default for demos and tests.

## Phase 6 — Multi-node deployment

- Add node and tenant boundaries if product scope requires it.
- Improve sensor inventory, health aggregation, and failure handling.
- Add capacity planning and operations guidance.

## Phase 7 — Enterprise integrations

- Integrate with existing ticketing, SIEM, artifact storage, and reporting systems.
- Add role and approval workflows appropriate for production teams.
- Keep claims conservative: ConShield can complement enterprise platforms, but the current project is not positioned as their replacement.
