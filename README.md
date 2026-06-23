Hybrid IDS Platform

- A hybrid intrusion detection prototype combining Suricata rule-based detection with machine learning anomaly scoring.

## Sprint 1: Suricata PCAP Analysis

1. Run Suricata against a test PCAP:

```bash
scripts/run_suricata_pcap.sh data/pcaps/benign_test.pcap test-002
```

 2. Expected output includes an event type summary such as:
	 2 flow
	 1 stats

  3. This proves the basic pipeline works:
	  PCAP -> Suricata Docker -> eve.json

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

This proves the next stage of the pipeline works:
eve.json -> Python parser -> normalized flow JSONL / table / summary

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

This proves the DNS parsing stage works:
eve.json -> DNS parser -> normalized DNS JSONL / table / summary

## Sprint 1D: HTTP, TLS, and Alert Parsers

Parse Suricata HTTP events:

```bash
python3 backend/app/parse_http.py data/eve-runs/test-004/eve.json --summary
python3 backend/app/parse_http.py data/eve-runs/test-004/eve.json --pretty
python3 backend/app/parse_http.py data/eve-runs/test-004/eve.json --output data/normalized test-004-http.jsonl
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
	Flow  -> backend/app/parse_eve.py
	DNS   -> backend/app/parse_dns.py
	HTTP  -> backend/app/parse_http.py
	TLS   -> backend/app/parse_tls.py
	Alert -> backend/app/parse_alert.py

The current pipeline supports:
	PCAP
	-> Suricata Docker
	-> eve.json
	-> normalized Flow / DNS / HTTP / TLS / Alert records
	-> JSONL output / pretty tables / summary statistics

Known checksum alerts are currently classified as noise:
	SURICATA TCPv4 invalid checksum
	SURICATA UDPv4 invalid checksum