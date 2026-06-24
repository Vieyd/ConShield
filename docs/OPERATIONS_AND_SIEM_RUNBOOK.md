# Operations and SIEM Runbook

## Purpose

This runbook describes how an `AdminIB` operator uses ConShield operational screens and SIEM lifecycle alerts during daily checks and investigations.

## Main screens

- Operations Health: `/Operations/Health`
- Security Summary Report: `/Reports/SecuritySummary`
- Security Events: `/SecurityEvents`
- Sensor Fleet: `/Sensors`
- Alerts / Incidents: use the existing SIEM alerts and incident registry pages in the app

## Normal daily check

1. Open Operations Health.
2. Check sensor heartbeat state.
3. Check Security Events freshness.
4. Check outbox/inbox health.
5. Check lifecycle audit activity.
6. Open Security Summary Report and export the Markdown handoff if the check needs to be attached to an incident or shift note.
7. Open Security Events using lifecycle quick filters if needed.

## Lifecycle SIEM alerts

### LIFE-001 — Sensor identity revoked

Meaning:

- a sensor identity was revoked;
- heartbeat/runtime events for this sensor should fail after revocation.

Operator actions:

1. Check whether the revocation was planned.
2. Open Sensor Fleet and confirm sensor status.
3. Open Security Events filtered by `conshield.sensor-lifecycle`.
4. Check the actor/requestedBy and affected public sensorId.
5. Create or update an incident if the action was not planned.

### LIFE-002 — Repeated sensor credential lifecycle changes

Meaning:

- multiple credential rotations/revocations happened for the same sensor in a short window.

Operator actions:

1. Check whether this was an expected maintenance window.
2. Review lifecycle events for the sensor.
3. Confirm whether the RuntimeCollector is still reporting.
4. Check for related incidents.
5. Escalate if repeated changes were not expected.

## Investigation flow

1. Start from Operations Health.
2. Open related Security Events.
3. Filter by SourceSystem = `conshield.sensor-lifecycle`.
4. Use ExternalEventType to narrow the event.
5. Check Sensor Fleet/details.
6. Create an incident from a relevant security event or alert when needed.
7. Document the operator conclusion.

## Safe handling rules

- Never paste generated credentials into GitHub, chat, screenshots, or logs.
- Never expose `VerifierSha256`.
- Never inspect or print Fedora protected env files in shared output.
- Never use audit events as a credential recovery mechanism.
- Use public sensorId/credentialId only.
- Use the Security Summary Markdown export only for aggregate counts and timestamps; it is not a source for raw event payloads or secret recovery.

## Current limitations

- Operations Health is DB-backed and not a Prometheus/Grafana replacement.
- SIEM lifecycle alerts are deterministic prototype rules.
- No automatic remediation is performed.
- No centralized secret manager integration yet.
- mTLS binding is future work.
