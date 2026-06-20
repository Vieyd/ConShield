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
- The API key is an environment value, never a process argument.
- The systemd service uses `NoNewPrivileges`, `PrivateTmp`, `PrivateDevices`, `ProtectHome`, `ProtectSystem`, `RestrictSUIDSGID`, `LockPersonality`, and an empty capability bounding set.
- Logrotate retains seven rotations and rotates daily or earlier at 25 MB using `copytruncate`, which is compatible with file-follow mode.
- Windows Firewall admits TCP 5080 only from the Fedora host-only address on VMnet1.

## Installation And Rollback

The tracked kit is in `deploy/falco-linux`. `install-fedora.sh` uses official Fedora packages and the official Falco RPM repository, creates a timestamped Falco configuration backup, applies targeted engine/output/webserver keys, validates upstream plus local rules, and enables the services.

`uninstall-fedora.sh` stops and removes the collector and restores the original Falco configuration. It retains the Falco package and logs for review and never removes container storage or Windows Docker volumes.

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
- No mTLS or sensor enrollment yet.

## Next Stage

Add multi-host sensor enrollment, per-source credentials, mTLS-ready identity, source inventory, and heartbeat events.
