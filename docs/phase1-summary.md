# Phase 1 Summary

## Goal

Build the first version of the traffic ingestion layer for the Hybrid IDS project.

This document only describes Phase 1. The larger architecture diagram is the planned final system, but this repository currently implements the Suricata ingestion and parser layer only.

The current flow is:

```text
PCAP -> Suricata Docker -> eve.json -> Python parsers
```

Related diagram:

```text
docs/phase1-architecture.drawio
```

## Completed

- Created a basic project structure for scripts, parsers, docs, sample data, and local runtime data.
- Added a Suricata Docker runner for analyzing local PCAP files.
- Added parsers for Flow, DNS, HTTP, TLS, and Alert events from Suricata `eve.json`.
- Added summary, pretty-table, and JSONL output modes for the parser scripts.
- Added simple noise labeling for common checksum alerts.
- Added a sanitized `samples/eve-demo.json` file so the parsers can be tested without private PCAP data.

## Files

```text
scripts/run_suricata_pcap.sh       Run Suricata against a PCAP
backend/app/parse_eve.py           Flow parser
backend/app/parse_dns.py           DNS parser
backend/app/parse_http.py          HTTP parser
backend/app/parse_tls.py           TLS parser
backend/app/parse_alert.py         Alert parser
samples/eve-demo.json              Sanitized parser sample
```

## Environment Used

```text
OS: Ubuntu Server 22.04 LTS
Container runtime: Docker
Suricata image: jasonish/suricata:7.0
Verified Suricata version: 7.0.15
```

## Quick Check

Run the parser summaries against the sample log:

```bash
python3 backend/app/parse_eve.py samples/eve-demo.json --summary
python3 backend/app/parse_dns.py samples/eve-demo.json --summary
python3 backend/app/parse_http.py samples/eve-demo.json --summary
python3 backend/app/parse_tls.py samples/eve-demo.json --summary
python3 backend/app/parse_alert.py samples/eve-demo.json --summary
```

## Data Privacy

Raw PCAP files, generated `eve.json` files, and normalized output files are excluded from Git. These files may include local IP addresses, DNS queries, and other network metadata.

## Next Work

- Decide on a shared schema for normalized events.
- Start extracting basic numeric features from flow records.
- Add an API or storage layer after the parser output format is stable.
- Connect later phases to the final architecture diagram only after each component is implemented.
