#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run with sudo: sudo ./verify-pipeline.sh" >&2
  exit 1
fi

collector=/opt/conshield/runtime-collector/ConShield.RuntimeCollector
fixture=/opt/conshield/runtime-collector/samples/runtime-demo.jsonl
mapping=/opt/conshield/runtime-collector/config/falco-mapping-v1.json
runtime_log=/var/log/conshield/falco-events.jsonl
environment_file=/etc/conshield/runtime-collector.env

runuser -u conshield-runtime -- "$collector" collect --file "$fixture" --mapping "$mapping" --no-submit

for variable in \
  CONSHIELD_ENDPOINT \
  CONSHIELD_SENSOR_ID \
  CONSHIELD_SENSOR_CREDENTIAL_ID \
  CONSHIELD_RUNTIME_COLLECTOR_API_KEY \
  CONSHIELD_HEARTBEAT_INTERVAL_SECONDS; do
  grep -Eq "^${variable}=[[:graph:]]+$" "$environment_file" || {
    echo "RuntimeCollector environment is incomplete." >&2
    exit 1
  }
done

systemctl is-active --quiet conshield-runtime-collector.service || {
  echo "RuntimeCollector service is not active." >&2
  exit 1
}

before_lines=$(wc -l < "$runtime_log")
cat -- "$fixture" >> "$runtime_log"
after_lines=$(wc -l < "$runtime_log")
[[ $after_lines -gt $before_lines ]] || {
  echo "Fixture was not appended to the protected runtime log." >&2
  exit 1
}

echo "Fixture appended for the enrolled systemd collector; inspect Windows heartbeat and pipeline records after the collector processes it."
