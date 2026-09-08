## Current Data Flow

The current implemented data flow is:

```text
PCAP
  ↓
Suricata in Docker
  ↓
eve.json
  ↓
Flow / DNS / HTTP / TLS / Alert parsers
  ↓
JSON / JSONL / table / summary output
```

Suricata reads an offline PCAP file and writes network events to eve.json.

The Python parsers read that file and process one event type at a time.

## Component Responsibilities

- **Suricata:** reads an offline PCAP file and generates structured network events in `eve.json`.
- **`eve.json`:** acts as the data boundary between Suricata and the Python processing layer.
- **Python parsers:** read `eve.json` and extract one supported event type: Flow, DNS, HTTP, TLS, or Alert.
- **Parser output:** can be printed as JSON, a readable table, a summary, or written as JSONL.
- **Alert parser:** also applies a small checksum-noise label to known checksum-related alerts.

## Data Boundaries and Interfaces

The main interface between Suricata and the Python layer is `eve.json`.

The parsers read newline-delimited JSON events from this file and produce either terminal output or normalized JSONL files.

Real PCAP files, generated `eve.json` logs, and normalized outputs stay on the local homelab because they may contain private network metadata.

The public repository uses the sanitized `samples/eve-demo.json` file for parser testing.

## Key Decisions and Limitations

I use Docker for Suricata so the analysis environment is easier to reproduce.

I started with offline PCAP files instead of live traffic so I could test the data pipeline in a controlled way.

The five event types currently use separate parsers because their fields are different. A shared cross-event schema has not been implemented yet.

I also chose not to start anomaly scoring before the event format and feature data are defined.

The current system is still limited to offline analysis, and the checksum-noise label is only a small prototype rule, not a general security conclusion.

## Relationship to Planned Work

The current parser layer is the starting point for the semester work.

The planned sequence is:

```text
Current event-specific parsers
  ↓
Shared event schema
  ↓
Unified normalizer
  ↓
Feature extraction
  ↓
Reproducible feature dataset
  ↓
Basic anomaly scoring
  ↓
Suricata alerts + anomaly scores + related event context
```
Only the parser layer is part of the current implemented architecture. The later components are planned semester work and should not be treated as completed until they are implemented and verified.

See [scope.md](scope.md) for the planned deliverables and completion criteria.