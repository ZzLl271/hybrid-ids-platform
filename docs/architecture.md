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
Event-specific parser records
  ↓
Unified normalizer
  ↓
Shared normalized events
```

The event-specific parsers can also print JSON, JSONL, table, or summary output for inspection and testing.

Suricata reads an offline PCAP file and writes network events to `eve.json`.

The Python parsers read that file and process one event type at a time. The unified normalizer then converts one parser record at a time into the shared normalized event structure.

## Component Responsibilities

- **Suricata:** reads an offline PCAP file and generates structured network events in `eve.json`.
- **`eve.json`:** acts as the data boundary between Suricata and the Python processing layer.
- **Python parsers:** read `eve.json`, select one supported event type, and produce event-specific normalized records.
- **Parser output modes:** parser records can be printed as JSON, a readable table, a summary, or written as JSONL.
- **Alert parser:** also applies a small checksum-noise label to known checksum-related alerts.
- **Shared event schema:** defines the common top-level structure and event-specific metadata contract.
- **Unified normalizer:** takes one event-specific parser record plus its `event_type` and restructures it into the shared normalized event format.

## Data Boundaries and Interfaces

The main interface between Suricata and the Python layer is `eve.json`.

The event-specific parsers read newline-delimited JSON events from this file and produce parser records.

The interface between the parser layer and the shared normalization layer is one event-specific parser record plus its parser context:

```python
normalize_event(event_type, record)
```

The normalizer returns one shared normalized event.

Real PCAP files, generated `eve.json` logs, and generated normalized outputs stay on the local homelab because they may contain private network metadata.

The public repository uses the sanitized `samples/eve-demo.json` file for parser and normalization testing.

## Key Decisions and Limitations

I use Docker for Suricata so the analysis environment is easier to reproduce.

I started with offline PCAP files instead of live traffic so I could test the data pipeline in a controlled way.

The five event types still use separate parsers because their source fields differ, but they now feed into a shared normalized event schema through the unified normalizer.

The normalizer restructures parser output and does not infer missing values from ports, event type, or other fields.

I also chose not to start anomaly scoring before the event format and feature data are defined.

The current system is still limited to offline analysis, and the checksum-noise label is only a small prototype rule, not a general security conclusion.

## Relationship to Planned Work

The current implemented architecture now includes:

```text
PCAP
  ↓
Suricata
  ↓
eve.json
  ↓
Event-specific parsers
  ↓
Shared normalized events
```

The next planned sequence is:

```text
Feature schema
  ↓
Feature extraction
  ↓
Reproducible feature dataset
  ↓
Dataset validation
  ↓
Basic anomaly scoring
  ↓
Suricata alerts + anomaly scores + related event context
```

The parser layer, shared event schema, unified normalizer, and normalization validation are implemented and verified.

Feature extraction and later anomaly-scoring components are still planned work and should not be treated as completed until they are implemented and verified.

See [scope.md](scope.md) for the planned deliverables and completion criteria.