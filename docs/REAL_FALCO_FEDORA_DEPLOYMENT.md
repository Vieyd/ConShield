# Real Falco Fedora Deployment

## Purpose

Windows remains the primary developer workstation and central ConShield server. The Fedora VM represents a protected Linux node. Clients do not need to replace Windows desktops.

The validated flow is:

```text
Falco modern_ebpf -> protected JSONL -> RuntimeCollector
-> Windows host-only ingestion API -> PostgreSQL Outbox
-> RabbitMQ -> MongoDB + PostgreSQL Inbox
-> RTE-001 -> Alert + Incident
```

## Validated Host

| Component | Result |
| --- | --- |
| Fedora | 44 Workstation, x86_64 |
| Kernel | 6.19.x with readable `/sys/kernel/btf/vmlinux` |
| SELinux | Enforcing; no custom policy; no recent AVC during verification |
| Runtime | Existing Podman 5.8.1 |
| Falco | 0.44.1 from the official Falco RPM repository |
| Driver | `modern_ebpf` |
| Collector | Self-contained linux-x64, non-login `conshield-runtime` user |

## Security Controls

- Secure Boot and SELinux are not disabled.
- Falco's embedded webserver is disabled; webhook and gRPC output are not used.
- `/var/log/conshield/falco-events.jsonl` is `0640 root:conshield-runtime`.
- `/etc/conshield/runtime-collector.env` is `0600 root:root`.
- The source-specific runtime API key is an environment value, never a process argument.
- The systemd service uses `NoNewPrivileges`, `PrivateTmp`, `PrivateDevices`, `ProtectHome`, `ProtectSystem`, `RestrictSUIDSGID`, `LockPersonality`, and an empty capability bounding set.
- Logrotate retains seven rotations and rotates daily or earlier at 25 MB using `copytruncate`, which is compatible with file-follow mode.
- Windows Firewall admits TCP 5080 only from the Fedora host-only address on VMnet1.

## Windows Network Boundary

Bind the development Web/API only to loopback and VMnet1:

~~~text
ASPNETCORE_URLS=http://127.0.0.1:5080;http://192.168.54.1:5080
~~~

PostgreSQL 5432, RabbitMQ AMQP 5672, RabbitMQ management 15672, and MongoDB 27017 are bound to `127.0.0.1` by the tracked Compose file. From an elevated PowerShell 7 session, remove broad generated Web program rules and recreate the Fedora-only rule:

~~~powershell
Get-NetFirewallRule -DisplayName "conshield.web.exe" -ErrorAction SilentlyContinue |
  Remove-NetFirewallRule
Get-NetFirewallRule -DisplayName "ConShield API from Fedora VM" -ErrorAction SilentlyContinue |
  Remove-NetFirewallRule
New-NetFirewallRule `
  -DisplayName "ConShield API from Fedora VM" `
  -Direction Inbound `
  -Action Allow `
  -Protocol TCP `
  -LocalPort 5080 `
  -InterfaceAlias "VMware Network Adapter VMnet1" `
  -RemoteAddress 192.168.54.128
~~~

Do not disable Windows Firewall. Loopback access does not require an inbound allow rule.

## Installation And Rollback

The tracked kit is in `deploy/falco-linux`. `install-fedora.sh` uses official Fedora packages and the official Falco RPM repository, creates a timestamped Falco configuration backup, applies targeted engine/output/webserver keys, validates upstream plus local rules, and enables the services.

`uninstall-fedora.sh` stops and removes the collector and restores the original Falco configuration. It retains the Falco package and logs for review and never removes container storage or Windows Docker volumes. Credential staging must use an invoking-user-owned `0700` directory and a regular `0600` file; the installer rejects symlinks and removes the staging file on exit.

## Verification Result

- Fixture no-submit: `parsed=4`, `mapped=3`, `unmapped=1`, `failed=0`.
- Fixture submit: four accepted events.
- Safe real Podman event: exactly one custom-rule event.
- PostgreSQL event and Delivered Outbox row: present.
- RabbitMQ main queue and DLQ: empty after processing.
- MongoDB projection and PostgreSQL Inbox receipt: present.
- RTE-001 alert and linked incident: present.
- Collector restart did not duplicate the real event.

The real rootless Podman event exposed container ID, process name, event type, and user name. Container name and image repository were not populated, so downstream logic must treat those fields as optional.

## Current Limitations

- No Kubernetes.
- No automatic response.
- One Fedora sensor.
- HTTP over an isolated host-only network.
- No mTLS, public enrollment endpoint, or fleet-management UI.

## Sensor credential transition

Sensor inventory v1 adds public sensor and credential identifiers to the protected collector environment file and keeps the credential itself in `CONSHIELD_RUNTIME_COLLECTOR_API_KEY`. The central database stores only its SHA-256 verifier. Provision the sensor through a local operator-controlled path, update the Fedora environment file, reinstall or restart the collector, and verify both event ingestion and heartbeat before disabling `ExternalEventIngestion:AllowLegacyRuntimeCollectorCredential`.

If sensor identity headers are present but invalid, revoked, or mismatched, ConShield returns `401` and does not try the legacy key. Heartbeats update `LastSeenAtUtc` only; they do not enter the SIEM event pipeline. Certificate fingerprint storage is reserved for a future mTLS stage; this deployment still uses HTTP on the isolated host-only network.

Provisioning and the accepted rollout order are documented in [SENSOR_PROVISIONING_AND_FEDORA_ROLLOUT.md](SENSOR_PROVISIONING_AND_FEDORA_ROLLOUT.md). The operator-only console tool generates the credential locally and stores only its verifier. Disable the legacy fallback only after heartbeat and runtime ingestion succeed through the enrolled systemd collector.

## Next Stage

Add controlled credential rotation/revocation and audit history. Full mTLS remains a separate later stage.
