# Hybrid IDS Platform

This repository contains the Phase 1 work for a Hybrid IDS project.

Current scope: Suricata PCAP processing and Python-based `eve.json` event parsing.

The full system architecture also includes a backend API, storage, frontend dashboard, ML scoring, and alert management. Those parts are design targets, not completed code in this repository yet.

## What Is Included

- `scripts/run_suricata_pcap.sh` runs Suricata in Docker against a local PCAP.
- `backend/app/parse_eve.py` parses flow events.
- `backend/app/parse_dns.py` parses DNS events.
- `backend/app/parse_http.py` parses HTTP events.
- `backend/app/parse_tls.py` parses TLS events.
- `backend/app/parse_alert.py` parses alert events and marks known checksum alerts as noise.
- `samples/eve-demo.json` is a sanitized sample log for testing the parsers.

Raw PCAPs and generated logs are not committed because they can contain local network details.

## Basic Pipeline

```text
PCAP -> Suricata Docker -> eve.json -> Python parsers -> JSONL / table / summary
```

## Architecture Diagrams

- Current Phase 1 diagram: `docs/phase1-architecture.drawio`
- Planned final architecture: `docs/final-architecture.drawio`
- Notes on diagram scope: `docs/architecture.md`

## Run Suricata On A PCAP

Place a test PCAP under `data/pcaps/`, then run:

```bash
scripts/run_suricata_pcap.sh data/pcaps/benign_test.pcap test-001
```

The script writes Suricata output to:

```text
data/eve-runs/test-001/
```

## Test The Parsers

Use the included sample file:

```bash
python3 backend/app/parse_eve.py samples/eve-demo.json --summary
python3 backend/app/parse_dns.py samples/eve-demo.json --summary
python3 backend/app/parse_http.py samples/eve-demo.json --summary
python3 backend/app/parse_tls.py samples/eve-demo.json --summary
python3 backend/app/parse_alert.py samples/eve-demo.json --summary
```

Readable table output is also available:

```bash
python3 backend/app/parse_eve.py samples/eve-demo.json --pretty
python3 backend/app/parse_dns.py samples/eve-demo.json --pretty
python3 backend/app/parse_http.py samples/eve-demo.json --pretty
python3 backend/app/parse_tls.py samples/eve-demo.json --pretty
python3 backend/app/parse_alert.py samples/eve-demo.json --pretty
```

To save normalized JSONL output:

```bash
python3 backend/app/parse_eve.py samples/eve-demo.json --output data/normalized/demo-flows.jsonl
python3 backend/app/parse_dns.py samples/eve-demo.json --output data/normalized/demo-dns.jsonl
python3 backend/app/parse_http.py samples/eve-demo.json --output data/normalized/demo-http.jsonl
python3 backend/app/parse_tls.py samples/eve-demo.json --output data/normalized/demo-tls.jsonl
python3 backend/app/parse_alert.py samples/eve-demo.json --output data/normalized/demo-alerts.jsonl
```

## Notes

- The current work is limited to ingestion and normalization.
- The sample log is only for parser testing; it is not meant to represent a full network dataset.
- Checksum-related Suricata alerts are treated as parser noise for this prototype.
