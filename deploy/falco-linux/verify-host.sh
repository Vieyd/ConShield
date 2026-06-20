#!/usr/bin/env bash
set -euo pipefail

# shellcheck disable=SC1091
source /etc/os-release
echo "os=$NAME $VERSION_ID"
echo "kernel=$(uname -r)"
echo "arch=$(uname -m)"
[[ -r /sys/kernel/btf/vmlinux ]] && echo "btf=available" || echo "btf=missing"
echo "selinux=$(getenforce)"

if command -v podman >/dev/null; then
  echo "runtime=$(podman --version)"
elif command -v docker >/dev/null; then
  echo "runtime=$(docker --version)"
else
  echo "runtime=missing"
fi

echo "falco=$(falco --version 2>/dev/null | head -n 1)"
echo "falco_driver=$(awk '/^engine:/{seen=1;next} seen && /^  kind:/{print $2;exit}' /etc/falco/falco.yaml)"
falco_unit=$(systemctl list-units --type=service --state=active --no-legend | awk '/falco.*service/{print $1;exit}')
echo "falco_service=${falco_unit:-inactive}"
echo "collector_user=$(getent passwd conshield-runtime | cut -d: -f1,7)"
echo "collector_service=$(systemctl is-active conshield-runtime-collector.service)"

stat -c 'jsonl_mode=%a owner=%U group=%G' /var/log/conshield/falco-events.jsonl
stat -c 'env_mode=%a owner=%U group=%G' /etc/conshield/runtime-collector.env
echo "jsonl_lines=$(wc -l < /var/log/conshield/falco-events.jsonl)"
echo "endpoint_http=$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 5 http://192.168.54.1:5080/Account/Login)"
echo "recent_avc_count=$(ausearch -m AVC -ts recent 2>/dev/null | grep -c '^type=AVC' || true)"
