#!/bin/bash
# fetch_ranges.sh — Download IPv4 prefixes for given ASNs from RIPE
#
# Usage:
#   ./fetch_ranges.sh AS24940              # Hetzner only
#   ./fetch_ranges.sh AS24940 AS16276      # Hetzner + OVH
#   ./fetch_ranges.sh                      # uses default ASN list

set -e

# Default ASNs if none provided. Curated list of cloud/hosting providers
# commonly used for VPN/proxy hosting.
DEFAULT_ASNS=(
  "AS24940"   # Hetzner (Germany)
  "AS16276"   # OVH (France)
  "AS51167"   # Contabo (Germany)
  "AS20473"   # Vultr (global)
  "AS14061"   # DigitalOcean (global)
  "AS63949"   # Linode/Akamai (global)
)

if [ $# -eq 0 ]; then
  ASNS=("${DEFAULT_ASNS[@]}")
  echo "[*] No ASN provided; using default list (${#ASNS[@]} ASNs)"
else
  ASNS=("$@")
fi

# Check dependencies
for cmd in curl jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[ERROR] Missing dependency: $cmd"
    echo "        Install with: sudo apt install $cmd"
    exit 1
  fi
done

OUTPUT="prefixes.txt"
> "$OUTPUT"  # truncate

TOTAL=0
for asn in "${ASNS[@]}"; do
  echo "[*] Fetching prefixes for $asn..."
  count=$(curl -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=$asn" \
    | jq -r '.data.prefixes[].prefix' \
    | grep -v ':' \
    | tee -a "$OUTPUT" \
    | wc -l)
  echo "    -> $count IPv4 prefixes"
  TOTAL=$((TOTAL + count))
done

echo ""
echo "[OK] Wrote $TOTAL prefixes to $OUTPUT"
echo "[*] Next step: python3 make_targets.py $OUTPUT"
