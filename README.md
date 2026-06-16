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