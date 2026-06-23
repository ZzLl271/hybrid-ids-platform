# Phase 1 Summary: Suricata-Based Traffic Ingestion and Event Normalization

## Project

Hybrid IDS Platform

## Phase 1 Goal

The goal of Phase 1 is to build the data ingestion and normalization layer for a Hybrid Intrusion Detection System.

This phase focuses on turning raw network traffic into structured security event records.

The current pipeline is:

```text
PCAP
-> Suricata Docker
-> eve.json
-> Python event parsers
-> normalized JSONL / readable tables / summary statistics
```

## Why This Phase Matters

A Hybrid IDS cannot begin with machine learning or dashboards before the data pipeline is reliable.

This phase proves that the project can:

```text
Capture network traffic as PCAP files.
Analyze PCAP files using Suricata in Docker.
Generate Suricata eve.json logs.
Parse multiple Suricata event types.
Normalize raw IDS logs into structured records.
Prepare data for future feature extraction, machine learning, storage, and visualization.
```

## Environment

The project is developed on a homelab server.

## Environment

The project is developed on a homelab server.

```text
OS: Ubuntu Server 22.04 LTS
Container Runtime: Docker
IDS Engine: Suricata 7.0.15
Suricata Docker Image: jasonish/suricata:7.0
Project Path: ~/projects/hybrid-ids
```

The Suricata Docker image version is pinned to improve reproducibility.

## Completed Components

### 1. Project Structure

The project repository includes:

```text
backend/app/          Python parsers
scripts/              Automation scripts
docs/                 Project documentation
samples/              Sanitized sample data
data/pcaps/           Local PCAP storage, ignored by Git
data/eve-runs/        Local Suricata output, ignored by Git
data/normalized/      Local parser output, ignored by Git
```

Large runtime artifacts such as PCAP files, generated Suricata logs, and normalized JSONL outputs are excluded from Git.

### 2. Suricata PCAP Runner

Script:

```text
scripts/run_suricata_pcap.sh
```

Purpose:

This script runs Suricata against a PCAP file using Docker, writes the output to a run directory, fixes file ownership, and prints an event type summary.

Example:

```bash
scripts/run_suricata_pcap.sh data/pcaps/dns_http_test.pcap test-004
```

The runner also prevents accidental reuse of an existing output directory. This avoids polluted or duplicated eve.json results.

### 3. Flow Parser

File:

```text
backend/app/parse_eve.py
```

Purpose:

Parses Suricata flow events and normalizes network flow metadata.

Supported modes:

```bash
python3 backend/app/parse_eve.py samples/eve-demo.json --summary
python3 backend/app/parse_eve.py samples/eve-demo.json --pretty
python3 backend/app/parse_eve.py samples/eve-demo.json --output data/normalized/demo-flows.jsonl
```

Extracted fields include:

```text
timestamp
flow_id
src_ip
src_port
dest_ip
dest_port
proto
app_proto
pkts_toserver
pkts_toclient
bytes_toserver
bytes_toclient
flow_age
flow_state
flow_reason
alerted
```

### 4. DNS Parser

File:

```text
backend/app/parse_dns.py
```

Purpose:

Parses Suricata DNS events and normalizes domain query and response metadata.

Supported modes:

```bash
python3 backend/app/parse_dns.py samples/eve-demo.json --summary
python3 backend/app/parse_dns.py samples/eve-demo.json --pretty
python3 backend/app/parse_dns.py samples/eve-demo.json --output data/normalized/demo-dns.jsonl
```

Extracted fields include:

```text
timestamp
src_ip
src_port
dest_ip
dest_port
proto
dns_type
dns_id
rrname
rrtype
rcode
answers_count
answers
```

### 5. HTTP Parser

File:

```text
backend/app/parse_http.py
```

Purpose:

Parses Suricata HTTP events and normalizes HTTP request and response metadata.

Supported modes:

```bash
python3 backend/app/parse_http.py samples/eve-demo.json --summary
python3 backend/app/parse_http.py samples/eve-demo.json --pretty
python3 backend/app/parse_http.py samples/eve-demo.json --output data/normalized/demo-http.jsonl
```

Extracted fields include:

```text
timestamp
flow_id
src_ip
src_port
dest_ip
dest_port
proto
hostname
url
http_method
protocol
status
http_user_agent
http_content_type
length
```

### 6. TLS Parser

File:

```text
backend/app/parse_tls.py
```

Purpose:

Parses Suricata TLS events and normalizes TLS metadata.

Supported modes:

```bash
python3 backend/app/parse_tls.py samples/eve-demo.json --summary
python3 backend/app/parse_tls.py samples/eve-demo.json --pretty
python3 backend/app/parse_tls.py samples/eve-demo.json --output data/normalized/demo-tls.jsonl
```

Extracted fields include:

```text
timestamp
flow_id
src_ip
src_port
dest_ip
dest_port
proto
sni
tls_version
subject
issuerdn
fingerprint
ja3_hash
ja3_string
ja3s_hash
ja3s_string
```

### 7. Alert Parser and Noise Classification

File:

```text
backend/app/parse_alert.py
```

Purpose:

Parses Suricata alert events and adds basic alert noise classification.

Supported modes:

```bash
python3 backend/app/parse_alert.py samples/eve-demo.json --summary
python3 backend/app/parse_alert.py samples/eve-demo.json --pretty --limit 20
python3 backend/app/parse_alert.py samples/eve-demo.json --output data/normalized/demo-alerts.jsonl
```

Extracted fields include:

```text
timestamp
flow_id
src_ip
src_port
dest_ip
dest_port
proto
action
gid
signature_id
rev
signature
category
severity
is_noise
noise_reason
```

Known checksum alerts are classified as noise:

```text
SURICATA TCPv4 invalid checksum
SURICATA UDPv4 invalid checksum
```

This is important because IDS alerts are not always true security incidents. A real IDS platform needs alert triage and noise reduction.

## Sample Data

The repository includes a sanitized sample file:

```text
samples/eve-demo.json
```

This file contains example Flow, DNS, HTTP, TLS, and Alert events.

It allows the parser layer to be tested after cloning the repository without exposing real homelab network traffic.

## Privacy Note

Raw PCAP files, generated Suricata logs, and normalized parser outputs are intentionally excluded from Git.

These files may contain local IP addresses, DNS queries, external connection metadata, and other environment-specific information.

## Current Phase 1 Status

Completed:

```text
Project structure
Suricata Docker workflow
PCAP analysis runner
Flow parser
DNS parser
HTTP parser
TLS parser
Alert parser
Checksum alert noise classification
Sanitized sample event log
Clone-and-run parser demo
```

Phase 1 is complete as a data ingestion and event normalization milestone.

## Next Steps

The next phase will focus on feature extraction and enrichment.

Planned next steps:

1. Merge normalized events into a unified schema.
2. Extract numerical features from flow records.
3. Add alert enrichment and severity handling.
4. Prepare datasets for anomaly detection.
5. Add a lightweight API layer.
6. Later integrate storage, dashboarding, and ML scoring.

## Summary

Phase 1 establishes the foundation of the Hybrid IDS Platform.

The system can now transform raw network traffic into structured security event records, which prepares the project for future machine learning anomaly scoring and dashboard visualization.
