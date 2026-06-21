#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run with sudo: sudo ./verify-pipeline.sh" >&2
  exit 1
fi

collector=/opt/conshield/runtime-collector/ConShield.RuntimeCollector
fixture=/opt/conshield/runtime-collector/samples/runtime-demo.jsonl
mapping=/opt/conshield/runtime-collector/config/falco-mapping-v1.json

runuser -u conshield-runtime -- "$collector" collect --file "$fixture" --mapping "$mapping" --no-submit

endpoint=$(sed -n 's/^CONSHIELD_ENDPOINT=//p' /etc/conshield/runtime-collector.env)
runtime_key=$(sed -n 's/^CONSHIELD_RUNTIME_COLLECTOR_API_KEY=//p' /etc/conshield/runtime-collector.env)
[[ -n $endpoint && -n $runtime_key ]] || {
  echo "RuntimeCollector environment is incomplete." >&2
  exit 1
}
runuser -u conshield-runtime -- env -i \
  HOME=/nonexistent \
  PATH=/usr/bin:/bin \
  CONSHIELD_ENDPOINT="$endpoint" \
  CONSHIELD_RUNTIME_COLLECTOR_API_KEY="$runtime_key" \
  "$collector" collect --file "$fixture" --mapping "$mapping"
unset runtime_key

echo "Fixture verification completed; inspect Windows pipeline counters by deterministic externalEventId."
