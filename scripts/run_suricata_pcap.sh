#!/usr/bin/env bash
set -e

PCAP_FILE="${1:-data/pcaps/benign_test.pcap}"
RUN_NAME="${2:-test-001}"
OUT_DIR="data/eve-runs/${RUN_NAME}"
IMAGE="jasonish/suricata:7.0"

echo "[+] PCAP file: $PCAP_FILE"
echo "[+] Output dir: $OUT_DIR"

if [ ! -f "$PCAP_FILE" ]; then
  echo "[!] PCAP file not found: $PCAP_FILE"
  exit 1
fi

if [ -d "$OUT_DIR" ]; then
  echo "[!] Output dir already exists: $OUT_DIR"
  echo "[!] Remove it first or use a new run name."
  exit 1
fi

mkdir -p "$OUT_DIR"

docker run --rm \
  -v "$PWD/data/pcaps:/pcaps:ro" \
  -v "$PWD/$OUT_DIR:/logs" \
  "$IMAGE" \
  -r "/pcaps/$(basename "$PCAP_FILE")" -l /logs -k none

sudo chown -R "$USER:$USER" "$OUT_DIR"

echo "[+] Event type summary:"
jq -r '.event_type // "unknown"' "$OUT_DIR/eve.json" | sort | uniq -c

echo "[+] Done: $OUT_DIR/eve.json"
