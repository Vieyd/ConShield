# Sensor Credential Lifecycle

## Purpose

Describe safe future lifecycle management for enrolled sensor credentials used by ConShield RuntimeCollector/Falco sensor ingestion.

This document tracks credential lifecycle design and implementation notes. Rotation currently exists through a service-layer workflow and an AdminIB-only UI action. Credential and sensor revocation exist in the service layer and are exposed through AdminIB-only UI actions.

## Current state

- Sensors are enrolled by local operator-only provisioning.
- Sensor credential plaintext is printed once during provisioning.
- PostgreSQL stores only a SHA-256 verifier.
- Sensor-bound requests use:
  - `X-ConShield-Sensor-Id`;
  - `X-ConShield-Credential-Id`;
  - `X-ConShield-Api-Key`.
- Legacy runtime collector fallback is disabled.
- Sensor Fleet UI exists for AdminIB users.
- Service-layer credential rotation exists and is exposed through an AdminIB-only UI action.
- The rotation UI displays the new credential exactly once from the POST response and does not store it in URLs, cookies, session, or TempData.
- Service-layer credential and sensor revocation exists and preserves database rows for audit history.
- AdminIB revocation UI exists for credential and sensor revocation with POST, anti-forgery, and explicit confirmation.
- No public revocation API exists.

## Security goals

- Never display credential plaintext after provisioning.
- Never store credential plaintext.
- Never display `VerifierSha256`.
- Support credential rotation without sensor identity confusion.
- Support credential revocation without deleting audit history.
- Support sensor revocation.
- Preserve incident and audit trails.
- Keep Fedora RuntimeCollector non-root and hardened.
- Keep SELinux Enforcing.
- Avoid automatic remediation.

## Non-goals

- No public enrollment endpoint.
- No automatic response/remediation.
- No mTLS/PKI implementation in the first lifecycle PR.
- No Kubernetes integration.
- No centralized secret manager yet.
- No remote command execution on Fedora.

## State model

### Sensor

- `Active`: `Sensors.RevokedAtUtc` is null.
- `Revoked`: `Sensors.RevokedAtUtc` is set. The sensor remains visible in inventory and its credentials are unusable.

### SensorCredential

- `Active`: `SensorCredentials.RotatedAtUtc` and `SensorCredentials.RevokedAtUtc` are null, and the parent sensor is active.
- `Rotated/Superseded`: `SensorCredentials.RotatedAtUtc` is set. The credential has been replaced by a newer credential for the same sensor.
- `Revoked`: `SensorCredentials.RevokedAtUtc` is set. Requests using this credential must fail authentication.

Relevant fields:

- `Sensors.RevokedAtUtc`
- `SensorCredentials.RotatedAtUtc`
- `SensorCredentials.RevokedAtUtc`

## Rotation workflow

Proposed safe operator workflow:

1. AdminIB opens Sensor Fleet UI.
2. AdminIB initiates rotation for one sensor.
3. Server creates a new credential record with:
   - new public `CredentialId`;
   - SHA-256 verifier;
   - `CreatedAtUtc`.
4. Plaintext credential is shown exactly once.
5. Old active credentials are marked rotated by the service-layer implementation.
6. Operator updates Fedora `/etc/conshield/runtime-collector.env` securely.
7. RuntimeCollector restarts.
8. Heartbeat verifies the new `CredentialId`.
9. Old credential is marked rotated/revoked after acceptance.
10. Audit event records the lifecycle action.

The first implementation should prefer a narrow service-layer workflow before adding destructive UI actions. Rotation should not silently revoke the only working credential until the replacement has been verified.

## Revocation workflow

### Credential revocation

- AdminIB revokes a specific credential.
- Requests using that credential return HTTP 401.
- Other active credentials for the same sensor may continue working.
- The credential row remains stored for audit and inventory history.

### Sensor revocation

- AdminIB revokes a sensor.
- All credentials for the sensor become unusable.
- Heartbeat and event ingestion fail with HTTP 401.
- Sensor remains visible in inventory as `Revoked`.
- No database row is deleted.

## UI boundaries

The UI separates:

- read-only inventory;
- rotate credential action;
- revoke credential action;
- revoke sensor action.

Each dangerous action:

- requires the `AdminIB` role;
- uses `POST` plus anti-forgery protection;
- shows confirmation;
- never displays verifier;
- display plaintext new credential only once for rotation;
- should write an audit event in a future audit enhancement.

The read-only inventory should remain useful without offering mutation controls to `Operator` users or unauthenticated users.

## API/service boundaries

Prefer an application service instead of direct credential mutation in MVC controllers, for example:

```csharp
public interface ISensorCredentialLifecycleService
{
    Task<SensorCredentialRotationResult> RotateCredentialAsync(
        Guid sensorId,
        string requestedBy,
        string? reason,
        CancellationToken cancellationToken);

    Task<SensorCredentialRevocationResult> RevokeCredentialAsync(
        Guid sensorId,
        Guid credentialId,
        string requestedBy,
        string? reason,
        CancellationToken cancellationToken);

    Task<SensorRevocationResult> RevokeSensorAsync(
        Guid sensorId,
        string requestedBy,
        string? reason,
        CancellationToken cancellationToken);
}
```

Controllers should orchestrate authorization, anti-forgery, confirmation screens, and redirects. They should not perform direct `DbContext` mutations for credential lifecycle state.

## Auditing

Future implementation should create `SecurityEvents` for:

- credential rotated;
- credential revoked;
- sensor revoked;
- failed rotation/revocation attempts if relevant.

Audit payloads must not include:

- credential plaintext;
- `VerifierSha256`;
- API keys;
- PostgreSQL or RabbitMQ passwords;
- Fedora environment file contents.

Suggested safe audit metadata:

- sensor public UUID;
- credential public UUID;
- action type;
- requested by;
- reason;
- UTC timestamp;
- old/new lifecycle state names.

## Tests required

Future implementation should include tests for:

- rotation creates a new credential with a 32-byte verifier only;
- plaintext is shown once by the service result and is not stored;
- old credential behavior during the overlap window;
- revoked credential is rejected;
- revoked sensor is rejected;
- general ingestion key still cannot submit reserved runtime source;
- anti-forgery and role protection for UI actions;
- audit event is created without secret material;
- inventory does not show verifier or secret values;
- EF has no pending model changes when no schema changes are intended;
- migration is required and reviewed if new fields are introduced.

## Operational rollout

Safe local/Fedora rollout should use a rollback plan, not secret backups:

1. Rotate credential in ConShield and copy the one-time plaintext credential through a protected operator channel.
2. Update Fedora `/etc/conshield/runtime-collector.env` securely without printing the file contents.
3. Keep file ownership and permissions hardened.
4. Restart `conshield-runtime-collector.service`.
5. Verify heartbeat freshness.
6. Run the Fedora verification wrapper and `verify-pipeline`.
7. Revoke or rotate the old credential only after the new credential is confirmed.
8. Keep SELinux Enforcing and do not change RuntimeCollector hardening as part of credential lifecycle work.

## Future mTLS-ready path

The existing `CertificateFingerprintSha256` field can later bind a sensor identity to a certificate fingerprint. A staged mTLS path can:

- keep credential-based auth as the initial compatibility layer;
- record certificate fingerprint presence in inventory;
- bind enrolled sensors to certificate fingerprints;
- enforce certificate checks once operational certificate distribution exists.

This document does not implement mTLS, PKI, certificate issuance, or Kubernetes deployment.

## Open decisions

Before implementation, decide:

- whether to support an overlap window during rotation;
- whether one sensor can have multiple active credentials;
- whether rotation immediately marks the old credential `RotatedAtUtc`;
- whether revocation requires a reason;
- whether new audit event types are needed;
- how to present one-time credential output in UI safely;
- whether sensor revocation should also set `RevokedAtUtc` on each active credential;
- how long rotated/revoked credentials should remain visible in inventory.
