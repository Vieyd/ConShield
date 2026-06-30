# Residual Risks

## Deployment assumptions

The default ConShield path assumes a local demo or lab deployment. Production deployment would need hardened hosting, identity, operations, monitoring, backups, and environment separation.

## Operator assumptions

Operators are expected to run documented commands, keep local overrides outside Git, and review generated evidence before sharing it.

## Data assumptions

Fixture data is deterministic and safe for CI. Live scanner, runtime, and lifecycle data may be noisier and should be validated before relying on it operationally.

## Sensor assumptions

The current sensor trust and signature workflows are deterministic prototype controls. They make trust state visible but do not replace full device identity, full mTLS, or production key management.

## Trust assumptions

Local repository files, committed default configs, and fixture data are trusted inputs for CI-safe validation. Optional live integrations need additional operational controls.

## Current limitations

- No production Kubernetes admission controller.
- No full mTLS/PKI.
- No enterprise multi-cluster management.
- No formal compliance attestation/reporting.
- No real-time distributed replay detection across nodes.
- No claim of complete prevention or universal detection.

## Planned hardening

Future work should follow [ROADMAP_TO_PRODUCTION.md](ROADMAP_TO_PRODUCTION.md), especially production sensor identity, key management, deployment hardening, and Kubernetes integration.
