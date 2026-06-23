# Hybrid IDS Platform

- A hybrid intrusion detection prototype combining Suricata rule-based detection with machine learning anomaly scoring.

## Sprint 1: Suricata PCAP Analysis

1. Run Suricata against a test PCAP:

```bash
scripts/run_suricata_pcap.sh data/pcaps/benign_test.pcap test-002
```

2. Expected output includes an event type summary such as:

```text
2 flow
1 stats
```

3. This proves the basic pipeline works:

```text
PCAP -> Suricata Docker -> eve.json
```

## Sprint 1B: Eve Flow Parser

Parse Suricata `eve.json` flow events into normalized records:

```bash
python3 backend/app/parse_eve.py data/eve-runs/test-002/eve.json
```

Print a human-readable flow table:

```bash
python3 backend/app/parse_eve.py data/eve-runs/test-002/eve.json --pretty
```

Print aggregate flow statistics:

```bash
python3 backend/app/parse_eve.py data/eve-runs/test-002/eve.json --summary
```

Save normalized flow events as JSONL:

```bash
python3 backend/app/parse_eve.py data/eve-runs/test-002/eve.json --output data/normalized/test-002-flows.jsonl
```

Current parser extracts:

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

This proves the next stage of the pipeline works:

```text
eve.json -> Python parser -> normalized flow JSONL / table / summary
```

## Sprint 1C: DNS Event Parser

Parse Suricata `eve.json` DNS events into normalized records:

```bash
python3 backend/app/parse_dns.py data/eve-runs/test-004/eve.json
```

Print a human-readable DNS table:

```bash
python3 backend/app/parse_dns.py data/eve-runs/test-004/eve.json --pretty
```

Print aggregate DNS statistics:

```bash
python3 backend/app/parse_dns.py data/eve-runs/test-004/eve.json --summary
```

Save normalized DNS events as JSONL:

```bash
python3 backend/app/parse_dns.py data/eve-runs/test-004/eve.json --output data/normalized/test-004-dns.jsonl
```

Current DNS parser extracts:

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

This proves the DNS parsing stage works:

```text
eve.json -> DNS parser -> normalized DNS JSONL / table / summary
```

## Sprint 1D: HTTP, TLS, and Alert Parsers

Parse Suricata HTTP events:

```bash
python3 backend/app/parse_http.py data/eve-runs/test-004/eve.json --summary
python3 backend/app/parse_http.py data/eve-runs/test-004/eve.json --pretty
python3 backend/app/parse_http.py data/eve-runs/test-004/eve.json --output data/normalized/test-004-http.jsonl
```

Parse Suricata TLS events:

```bash
python3 backend/app/parse_tls.py data/eve-runs/test-004/eve.json --summary
python3 backend/app/parse_tls.py data/eve-runs/test-004/eve.json --pretty
python3 backend/app/parse_tls.py data/eve-runs/test-004/eve.json --output data/normalized/test-004-tls.jsonl
```

Parse Suricata alert events and classify known checksum alerts as noise:

```bash
python3 backend/app/parse_alert.py data/eve-runs/test-004/eve.json --summary
python3 backend/app/parse_alert.py data/eve-runs/test-004/eve.json --pretty --limit 20
python3 backend/app/parse_alert.py data/eve-runs/test-004/eve.json --output data/normalized/test-004-alerts.jsonl
```

Current event parsers:

```text
Flow  -> backend/app/parse_eve.py
DNS   -> backend/app/parse_dns.py
HTTP  -> backend/app/parse_http.py
TLS   -> backend/app/parse_tls.py
Alert -> backend/app/parse_alert.py
```

The current pipeline supports:

```text
PCAP
-> Suricata Docker
-> eve.json
-> normalized Flow / DNS / HTTP / TLS / Alert records
-> JSONL output / pretty tables / summary statistics
```

Known checksum alerts are currently classified as noise:

```text
SURICATA TCPv4 invalid checksum
SURICATA UDPv4 invalid checksum
```

## Clone-and-Run Parser Demo

This repository includes a sanitized Suricata `eve.json` sample for parser testing:

```text
samples/eve-demo.json
```

The sample is JSONL format, where each line is one Suricata event.

Run all parser summaries:

```bash
python3 backend/app/parse_eve.py samples/eve-demo.json --summary
python3 backend/app/parse_dns.py samples/eve-demo.json --summary
python3 backend/app/parse_http.py samples/eve-demo.json --summary
python3 backend/app/parse_tls.py samples/eve-demo.json --summary
python3 backend/app/parse_alert.py samples/eve-demo.json --summary
```

Run readable table outputs:

```bash
python3 backend/app/parse_eve.py samples/eve-demo.json --pretty
python3 backend/app/parse_dns.py samples/eve-demo.json --pretty
python3 backend/app/parse_http.py samples/eve-demo.json --pretty
python3 backend/app/parse_tls.py samples/eve-demo.json --pretty
python3 backend/app/parse_alert.py samples/eve-demo.json --pretty
```

The raw PCAP files and generated eve.json files from the homelab environment are intentionally excluded from this repository because they may contain local network metadata.

The sanitized sample allows the parser layer to be tested without exposing private network traffic.
