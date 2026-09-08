## Boundary and Evidence Dates

This baseline covers work completed before the CISC 4900 course orientation on August 28, 2026.
The repository was rechecked on September 3, 2026, and the homelab environment was rechecked on September 6, 2026.
These are verification dates, not the dates when the components were originally built.

## Repository Snapshot

The pre-semester repository snapshot is identified by this commit on `main`:`35051175f35cde77f33ce53262585ab20ce1f8df`

At the September 3 verification, the repository had 23 commits dated from June 14 through June 26, 2026.
All of these commits were created before the semester boundary.

## Existing Components

Before the semester started, the project already had:

* A Suricata script for processing offline PCAP files
* Python parsers for Flow, DNS, HTTP, TLS, and Alert events
* JSON, JSONL, pretty-table, and summary output
* Basic checksum-alert noise labeling
* A sanitized sample `eve.json` file for testing

The working data path was:

```text
PCAP -> Suricata -> eve.json -> event-specific Python parsers
```
## Relevant Environment

The project was developed mainly on a repurposed HP OMEN laptop running Ubuntu Server 22.04 LTS.

The main environment used:

* Intel Core i7-7700HQ
* About 16 GB RAM
* Samsung 980 Pro 1 TB NVMe SSD
* Docker for running Suricata
* Python for the event parsers

The parser recheck on September 3 used Python 3.12.10.

## Verification Evidence and Limits

I rechecked the five Python parsers on September 3, 2026 using the sanitized sample file. All five parsers produced the expected summary output.

I also rechecked the homelab environment on September 6, 2026. Historical PCAP files, Suricata runs, and generated parser outputs were still present locally.

These checks confirm that the earlier work still existed and worked at the time of verification. They do not mean the components were built on those dates.

Real PCAP files and generated outputs are not stored in the public Git repository.

## Work Not Yet Implemented

At the start of the semester, the following parts had not been implemented:

* A shared schema and unified normalizer for all event types
* Feature extraction and a reproducible feature dataset
* Machine learning or anomaly scoring
* Hybrid Suricata and anomaly detection
* Backend API, database, and dashboard
* Automated testing and CI
