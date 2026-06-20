#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run with sudo: sudo ./uninstall-fedora.sh" >&2
  exit 1
fi

systemctl disable --now conshield-runtime-collector.service 2>/dev/null || true
rm -f -- /etc/systemd/system/conshield-runtime-collector.service
rm -f -- /etc/logrotate.d/conshield-falco
rm -f -- /etc/conshield/runtime-collector.env
rm -f -- /etc/falco/falco_rules.local.yaml /etc/falco/conshield.yaml.fragment

latest_backup=$(find /etc/falco -maxdepth 1 -type f -name 'falco.yaml.conshield-backup.*' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n 1 | cut -d' ' -f2- || true)
if [[ -n $latest_backup ]]; then
  cp -a -- "$latest_backup" /etc/falco/falco.yaml
  echo "Restored Falco configuration backup: $latest_backup"
fi

if getent passwd conshield-runtime >/dev/null; then
  userdel conshield-runtime 2>/dev/null || true
fi
systemctl daemon-reload

echo "Collector removed. Falco package and /var/log/conshield were retained for review."
