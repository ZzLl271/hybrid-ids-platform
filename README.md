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