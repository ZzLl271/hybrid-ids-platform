# Reproducible Feature Dataset

**Implementation:** `scripts/build_feature_dataset.py`

## 1. Purpose and Scope

The dataset builder provides a repeatable command for exporting the existing eight-feature TCP v1 schema to CSV. It reuses the Flow parser, shared normalizer, and feature extractor rather than duplicating their logic.

Input is a Suricata `eve.json` file in JSONL format, not a precomputed feature file. Only TCP Flows involving the specified monitored host are selected.

```text
Suricata eve.json
  ↓
Flow parser → TCP / monitored-host filter
  ↓
Unified normalizer
  ↓
30-second UTC windows → eight TCP features
  ↓
CSV dataset
```

This is an offline dataset-generation workflow, not anomaly detection or model training. Feature definitions and design decisions are in [feature-extract.md](feature-extract.md).

## 2. Generate a Dataset

**Requirements:** Python 3.10+; no third-party Python packages. Run commands from the repository root.

| Option | Meaning |
|---|---|
| `--input` | Path to a Suricata EVE JSONL file |
| `--monitored-ip` | IP address of the monitored host |
| `--output` | CSV output path; created or overwritten on success |

Sanitized demo:

```bash
python3 -m scripts.build_feature_dataset \
  --input samples/eve-demo.json \
  --monitored-ip 192.0.2.10 \
  --output data/feature-tests/eve-demo-v1.csv
```

Local Homelab example (requires the local EVE input):

```bash
python3 -m scripts.build_feature_dataset \
  --input data/eve-runs/tcp-baseline-002/eve.json \
  --monitored-ip 192.168.1.21 \
  --output data/feature-tests/tcp-baseline-002-v1.csv
```

The monitored IP must match the host in the capture; it is not hardcoded. Local EVE inputs may be produced using `scripts/run_suricata_pcap.sh`.

## 3. Output Contract

Each CSV row represents one monitored host and one non-overlapping, 30-second UTC window containing an observed TCP Flow start. Window assignment uses `metadata.flow_start`, preserved from Suricata `flow.start`. Rows are sorted by `window_start`.

The two metadata columns and eight numeric TCP v1 features appear in this order. The exporter now uses the shared `FEATURE_DATASET_FIELDS` constant in `backend/app/feature_extract.py` to fix the header order:

```text
window_start
monitored_ip
tcp_inbound_flow_count
tcp_outbound_flow_count
tcp_inbound_unique_dest_port_count
tcp_inbound_max_unique_dest_ports_per_src_ip
tcp_inbound_unique_src_ip_count
tcp_outbound_unique_dest_ip_count
tcp_outbound_unique_dest_port_count
tcp_outbound_max_unique_dest_ips_per_dest_port
```

The v1 endpoint-orientation rule treats remote source → monitored destination as inbound, and monitored source → remote destination as outbound. Other TCP Flows are excluded. This rule does not independently establish TCP connection initiation.

## 4. Reproducibility and Local Evidence

With the same input bytes, monitored IP, and implementation, repeated successful runs produce the same ordered CSV content. The sanitized demo was regenerated with identical SHA-256 hashes; an automated test also checks byte-for-byte equality.

Run the tests:

```bash
python3 -m unittest discover -s tests -v
```

During Issue #12, the local run passed **6 tests**: three feature-extraction tests and three dataset-builder tests (demo schema/content/reproducibility, missing input, and malformed JSON rejection). After Issue #13 added the dataset validator, the latest reported full suite passed **16 tests** (including ten validator tests).

Observed outputs during Issue #12:

| Input | Monitored IP | Exported feature rows |
|---|---|---:|
| `samples/eve-demo.json` | `192.0.2.10` | 1 |
| `data/eve-runs/tcp-baseline-002/eve.json` | `192.168.1.21` | 21 |
| `data/eve-runs/tcp-baseline-004/eve.json` | `192.168.1.21` | 7 |

The demo row contains `3, 3, 3, 2, 2, 3, 2, 2` for the eight features in schema order. The two Homelab EVE inputs are local experiment files, not included in the public repository; a fresh clone cannot reproduce those row counts without the same input data.

## 5. Validate the Exported CSV

Issue #13 added an independent CSV validator. Run it after a successful build:

```bash
python3 -m scripts.validate_feature_dataset \
  --input data/feature-tests/eve-demo-v1.csv
```

The validator checks exact schema order, non-negative integer features, valid monitored IPs, UTC-aligned windows, duplicate/unsorted windows, and basic cross-feature count bounds. It returns a nonzero exit code on failure and reports gaps **between observed rows** without filling them.

A validation **PASS** is a CSV structure/consistency result; it does **not** establish verified-complete captures, zero-flow windows, correct attack labels, or suitability for ML training. See [dataset-validation.md](dataset-validation.md) for validation rules and local evidence.

## 6. Storage and Limitations

- Generated CSVs belong under `data/feature-tests/`, excluded from Git by `.gitignore`. Commit source code, tests, and documentation rather than local experiment datasets.
- The builder uses strict EVE JSON parsing: malformed JSON lines and non-object JSON records cause a failed run instead of being silently skipped. Missing required TCP Flow fields can also stop generation. The separate validator provides CSV schema and basic consistency checks, not end-to-end PCAP quality validation.
- Failed runs do not establish that an existing output CSV is current; the same output path may still contain a file from an earlier successful run.
- The builder exports **observed-flow windows**; it does not add zero-traffic windows, verify capture start/end coverage, or exclude potentially partial capture-boundary windows.
- The 21 and 7 exported rows are not verified-complete ML training windows. A feature row is not an attack label or evidence of a successful TCP connection.