# Hybrid IDS Platform

## Overview

This project is a prototype hybrid intrusion detection system.

The goal is to combine Suricata rule-based detection with basic machine learning anomaly scoring.

The project currently processes offline PCAP files with Suricata, parses Flow, DNS, HTTP, TLS, and Alert events from `eve.json`, and converts the parser outputs into a shared normalized event structure.

## Current Status

The current working pipeline is:

`PCAP -> Suricata -> eve.json -> Event Parsers -> Unified Normalizer -> Shared Normalized Events`

Completed:

- Flow, DNS, HTTP, TLS, and Alert parsers
- Five-parser schema comparison
- Shared normalized event schema and data contract
- Unified event normalizer
- Normalization pipeline validation

Next:

`Feature Schema -> Feature Extraction -> Feature Dataset -> Dataset Validation -> Anomaly Scoring -> Hybrid Analysis`

## Requirements

For the Python parsers and normalizer:

- Python 3.10 or newer
- No external Python packages are currently required

For the full PCAP pipeline:

- Bash
- Docker
- jq
- Permission to run Docker and `sudo`

Run everything from the repository root, and put local PCAP files in `data/pcaps/`.

## Quick Start

The included sample `eve.json` file can be used to test the event-specific parsers without running Suricata:

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

## Unified Normalizer

The unified normalizer is implemented in:

```text
backend/app/normalize_event.py
```

Its main interface is:

```python
normalize_event(event_type, record)
```

`record` must be one event-specific parser record, not raw `eve.json` data and not table or summary output.

The caller must supply the parser context as `event_type`, for example:

```python
from backend.app.normalize_event import normalize_event

shared_record = normalize_event("dns", dns_record)
```

Supported event types:

```text
flow
dns
http
tls
alert
```

There is currently no separate CLI for the unified normalizer. The existing Quick Start commands run the event-specific parsers only.

## Shared Normalized Events

All supported events use the same top-level structure:

```json
{
  "event_type": "dns",
  "timestamp": "...",
  "flow_id": null,
  "src_ip": "...",
  "src_port": 51505,
  "dest_ip": "...",
  "dest_port": 53,
  "proto": "UDP",
  "app_proto": null,
  "metadata": {}
}
```

Event-specific fields are stored inside `metadata`.

The normalizer preserves values produced by the event-specific parsers and does not infer missing values.

## Output and Verification

The parser commands can print summaries for their matching event types.

A successful Suricata run creates a new folder under `data/eve-runs/`. The main output file is:

```text
data/eve-runs/test-001/eve.json
```

The Suricata runner also prints an event type summary.

The unified normalization layer has been validated against `samples/eve-demo.json` for:

- all five supported event types
- shared top-level fields
- event-specific metadata fields
- DNS answer consistency
- null/default preservation
- unsupported event type handling

## Limitations

The project currently works with offline PCAP files and does not monitor live network traffic.

Feature extraction, feature dataset generation, anomaly scoring, and hybrid analysis are not implemented yet.

The backend API, database, and dashboard are outside the current core implementation.

The included `samples/eve-demo.json` is a small sanitized sample for parser and normalization verification. It is not a machine-learning training dataset.

## Documentation

- `docs/baseline.md` — what was already completed before the semester
- `docs/scope.md` — semester work and project boundaries
- `docs/architecture.md` — current and planned system architecture
- `docs/shared-schema.md` — shared normalized event schema and data contract