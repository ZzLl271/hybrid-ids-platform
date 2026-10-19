## Current Data Flow

Suricata processes offline PCAP files and writes network events to `eve.json`.

The parsing and normalization path supports five event types:

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

The TCP v1 dataset builder reuses the Flow parser and normalizer through a separate CLI workflow:

```text
eve.json
  ↓
Flow parser
  ↓
TCP Flows involving the monitored host
  ↓
Unified normalizer
  ↓
30-second UTC windows (Suricata flow.start)
  ↓
Eight TCP v1 features
  ↓
CSV dataset
```

The event-specific parsers can also print JSON, JSONL, table, or summary output for inspection and testing. The dataset builder operates offline; it does not perform anomaly scoring.

## Component Responsibilities

- **Suricata:** reads an offline PCAP file and generates structured network events in `eve.json`.
- **`eve.json`:** acts as the data boundary between Suricata and the Python processing layer.
- **Python parsers:** read `eve.json`, select a supported event type, and produce event-specific parser records.
- **Parser output modes:** parser records can be printed as JSON, a readable table, a summary, or written as JSONL.
- **Alert parser:** also applies a small checksum-noise label to known checksum-related alerts.
- **Shared event schema:** defines the common top-level structure and event-specific metadata contract.
- **Unified normalizer:** takes an event-specific parser record plus its `event_type` and restructures it into the shared normalized event format.
- **Feature extractor:** groups normalized TCP Flow events by 30-second UTC windows and computes eight host-level features.
- **Dataset builder:** selects TCP Flows involving the specified monitored host, reuses the parser, normalizer, and feature extractor, and exports ordered CSV rows.

## Data Boundaries and Interfaces

The main interface between Suricata and the Python layer is `eve.json`, containing newline-delimited JSON events.

The interface between an event-specific parser and the shared normalizer is one parser record plus its parser context:

```python
normalize_event(event_type, record)
```

The normalizer returns a shared normalized event. For TCP Flow records, `metadata.flow_start` preserves the original Suricata `flow.start` value used by the feature extractor.

The dataset builder is run from the repository root:

```bash
python3 -m scripts.build_feature_dataset \
  --input samples/eve-demo.json \
  --monitored-ip 192.0.2.10 \
  --output data/feature-tests/eve-demo-v1.csv
```

Real PCAP files, generated `eve.json` logs, and local feature datasets stay on the homelab because they may contain private network metadata. The public repository uses the sanitized `samples/eve-demo.json` for testing.

## Key Decisions and Limitations

I use Docker for Suricata so the analysis environment is easier to reproduce.

I started with offline PCAP files instead of live traffic so I could test the data pipeline in a controlled way.

The five event types still use separate parsers because their source fields differ, but they feed into a shared normalized event schema through the unified normalizer.

The normalizer restructures parser output and does not infer missing values from ports, event type, or other fields. The TCP v1 builder filters to the specified monitored host and uses a simplified endpoint-orientation rule for inbound and outbound Flows.

The current feature dataset contains windows with observed TCP Flow starts. It does not establish complete capture coverage, add zero-traffic windows, or validate ML training suitability.

The current system is still limited to offline analysis, and the checksum-noise label is only a small prototype rule, not a general security conclusion.

## Relationship to Planned Work

The parser layer, shared schema, normalizer, eight-feature TCP extraction, and reproducible CSV builder are implemented and have passed local tests.

The next planned sequence is:

```text
Dataset validation and capture completeness
  ↓
Basic anomaly scoring
  ↓
Suricata alerts + anomaly scores + related event context
```

Anomaly scoring and hybrid analysis are not yet implemented. See [scope.md](scope.md) for planned deliverables, [feature-extract.md](feature-extract.md) for the feature design, and [dataset-generation.md](dataset-generation.md) for dataset generation.