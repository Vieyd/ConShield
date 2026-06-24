# Sensor Lifecycle Audit Playbook

## Purpose

This playbook helps operators interpret ConShield sensor lifecycle audit events in the Security Events UI. It is for investigation and safe handling only; it does not define automated response or remote remediation.

## Event source: `conshield.sensor-lifecycle`

Sensor lifecycle audit events are written as `SecurityEventType.ExternalEvent` with:

- `Severity = Info`;
- `SourceSystem = conshield.sensor-lifecycle`;
- an `ExternalEventType` that identifies the lifecycle action.

## Event types

### `sensor.credential.rotated`

A new public credential id was created for a sensor and the previous active credential was marked rotated. The plaintext credential is displayed only once by the rotation workflow and must never appear in the audit event.

### `sensor.credential.revoked`

A specific sensor credential was revoked. Requests using that credential should fail authentication, while other active credentials for the same non-revoked sensor may continue to work.

### `sensor.revoked`

The sensor was revoked. Its active credentials are revoked and heartbeat/event submissions from that sensor should fail authentication.

## Expected public fields

Lifecycle audit payloads should contain only public operational metadata, such as:

- public sensor id;
- public credential id when the action is credential-specific;
- sensor display name;
- original sensor source system;
- lifecycle source system;
- requested-by value;
- action name;
- `reasonProvided`;
- revoked credential count for sensor revocation.

## Must-never-include fields

Lifecycle audit events must never include:

- plaintext credential;
- `VerifierSha256`;
- API key;
- local env values;
- Fedora protected env file content;
- freeform reason text if it may contain secrets.

Do not paste credentials, API keys, local environment values, or protected Fedora environment file content into tickets, chat, screenshots, or investigation notes.

## How to find lifecycle events in the UI

Open Security Events and use the lifecycle quick filters:

- `Lifecycle сенсоров` for all events from `conshield.sensor-lifecycle`;
- `Ротации` for `sensor.credential.rotated`;
- `Отзыв credentials` for `sensor.credential.revoked`;
- `Отзыв сенсоров` for `sensor.revoked`.

You can also filter manually:

- SourceSystem: `conshield.sensor-lifecycle`;
- ExternalEventType: one of the lifecycle event types above.

## Investigation checklist

When a lifecycle event looks suspicious:

1. Confirm the `requestedBy` value matches an expected AdminIB/operator action.
2. Confirm the target sensor id and display name match the intended sensor.
3. Review nearby Security Events for login failures, access denied events, unusual SIEM alerts, or related incident activity.
4. Check whether the event type matches the operational change that was planned.
5. Confirm no plaintext credential, `VerifierSha256`, API key, or environment value appears in the event payload.
6. If a real Fedora RuntimeCollector stops reporting after revocation, check whether that outage is expected because the sensor or credential was revoked. Do not disable SELinux, do not print protected env files, and do not rotate/revoke another real sensor only to test the UI.
7. If the action was not expected, preserve the event id and surrounding context and escalate through the normal incident workflow.

## SIEM/reporting behavior

Lifecycle audit events also feed small deterministic SIEM rules:

- `LIFE-001` — creates a warning alert and incident when `SourceSystem = conshield.sensor-lifecycle` and `ExternalEventType = sensor.revoked`. The alert text uses public metadata only: sensor id, display name, requested-by value, revoked credential count, and source event id.
- `LIFE-002` — creates a warning alert and incident when one sensor has at least three credential lifecycle events in 15 minutes. It counts `sensor.credential.rotated` and `sensor.credential.revoked`, grouped by public sensor id.

These rules do not rotate, revoke, enroll, or remediate sensors. They do not render plaintext credentials, verifier values, API keys, connection strings, env values, or Fedora protected env file content.

## Safe handling rules

- Treat generated sensor credentials as secrets.
- Copy one-time credentials only through the approved protected operator channel.
- Do not include secrets in audit reason text.
- Do not paste secrets into GitHub, chat, screenshots, or logs.
- Keep Fedora RuntimeCollector hardening intact.
- Keep legacy runtime fallback disabled.
- Prefer read-only checks before any operational remediation.

## Current limitations

- Lifecycle SIEM rules are intentionally small and deterministic; they are not a full behavioral analytics system.
- There is no remote remediation or remote enrollment endpoint.
- There is no mTLS/PKI enforcement yet.
- The playbook does not replace incident response procedures.
- Operators must still correlate lifecycle events with change records, login activity, and runtime heartbeat health.
