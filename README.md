# Hybrid IDS Platform

## Overview

This project is a prototype hybrid intrusion detection system.

The goal is to combine Suricata rule-based detection with machine learning anomaly detection.

Right now, it can process PCAP files with Suricata and parse flow, DNS, HTTP, TLS, and alert events from eve.json.

## Current Status

The current working pipeline is:

`PCAP -> Suricata -> eve.json -> Python parsers`

The machine learning part and the rest of the platform are still future work.

## Requirements

For the Python parsers:
- Python 3.10 or newer
- No external Python packages are required

For the full PCAP pipeline:
- Bash
- Docker
- jq
- Permission to run Docker and `sudo`

Run everything from the repository root, and put PCAP files in `data/pcaps/`.

## Quick Start

The included sample `eve.json` file can be used to test the parsers without running Suricata:

```bash
python3 backend/app/parse_eve.py samples/eve-demo.json --summary
python3 backend/app/parse_dns.py samples/eve-demo.json --summary
python3 backend/app/parse_http.py samples/eve-demo.json --summary
python3 backend/app/parse_tls.py samples/eve-demo.json --summary
python3 backend/app/parse_alert.py samples/eve-demo.json --summary
```

To process a PCAP with Suricata:

```bash
scripts/run_suricata_pcap.sh data/pcaps/benign_test.pcap test-001
```

## Output and Verification

The parser commands print a summary of the matching event type.

A successful Suricata run creates a new folder under `data/eve-runs/`. The main output file is:

```text
data/eve-runs/test-001/eve.json
```

The script also prints an event type summary at the end.

If the PCAP file does not exist, the output directory already exists, or Suricata fails, the script stops with an error.


## Limitations

The project currently works with offline PCAP files and does not monitor live network traffic.

The machine learning detection, backend API, database, and dashboard are not implemented yet.

The included `eve-demo.json` is only a small test file for parser verification.

## Documentation

* `docs/baseline.md` — what was already completed before the semester
* `docs/scope.md` — planned semester work and project boundaries
* `docs/architecture.md` — current and planned system architecture
