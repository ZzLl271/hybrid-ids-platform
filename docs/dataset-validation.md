# TCP Feature Dataset Validation

**Implementation:** `scripts/validate_feature_dataset.py`  
**Schema source:** `backend/app/feature_extract.py` (`FEATURE_DATASET_FIELDS`)

## 1. Purpose and Scope

The validator checks the structure and basic consistency of exported **TCP v1 host-window CSV datasets** before they are considered for anomaly-scoring experiments. It extends the reproducible CSV workflow described in [dataset-generation.md](dataset-generation.md) and uses the eight features defined in [feature-extract.md](feature-extract.md).

```text
Suricata eve.json
  ↓
Flow parser → TCP / monitored-host filter
  ↓
Unified normalizer
  ↓
30-second UTC windows → eight TCP features
  ↓
CSV dataset → Dataset validator → PASS / FAIL + window-gap report
```

The validator reads an existing CSV. It does not regenerate features, inspect the original PCAP, label attacks, or verify complete capture coverage. A **PASS** means the implemented CSV checks passed, not that the rows are ready for ML training.

## 2. Validate a Dataset

**Requirements:** Python 3.10+; no third-party Python packages. Run commands from the repository root.

First generate the sanitized demo CSV using the command in [dataset-generation.md](dataset-generation.md), then run:

```bash
python3 -m scripts.validate_feature_dataset \
  --input data/feature-tests/eve-demo-v1.csv
```

To validate an existing local CIC-IDS2017 experiment:

```bash
python3 -m scripts.validate_feature_dataset \
  --input data/feature-tests/cicids2017-friday-portscan-v1.csv
```

The CLI prints the dataset path, row and host counts, observed-window counts and gaps for each host, and a validation result. It returns **exit code 0** on PASS and a **nonzero exit code** on FAIL. Some early failures (such as a schema mismatch) print `FAIL:` directly rather than a final `Validation: FAIL` line.

## 3. Validation Contract

The expected header is the shared `FEATURE_DATASET_FIELDS` schema: `window_start`, `monitored_ip`, and the eight numeric TCP v1 fields in the order documented in [dataset-generation.md](dataset-generation.md).

| Check | Current rule | Failure behavior |
|---|---|---|
| CSV schema | Exact field names and order; ten columns | FAIL |
| Rows | At least one feature row | FAIL |
| Monitored IP | Must parse as an IP address | FAIL |
| Window start | UTC offset zero; aligned to a 30-second boundary | FAIL |
| Feature values | Eight non-negative ASCII decimal integers; no missing values | FAIL |
| Host-window identity | No duplicate `(monitored_ip, window_start)` | FAIL |
| Ordering | Windows sorted within each monitored host | FAIL |
| Feature relationships | Satisfy the six count bounds below | FAIL |
| Observed-window gaps | Count missing positions between existing rows | Report only |

The six implemented consistency checks are:

```text
tcp_inbound_unique_dest_port_count <= tcp_inbound_flow_count
tcp_inbound_max_unique_dest_ports_per_src_ip <= tcp_inbound_unique_dest_port_count
tcp_inbound_unique_src_ip_count <= tcp_inbound_flow_count
tcp_outbound_unique_dest_ip_count <= tcp_outbound_flow_count
tcp_outbound_unique_dest_port_count <= tcp_outbound_flow_count
tcp_outbound_max_unique_dest_ips_per_dest_port <= tcp_outbound_unique_dest_ip_count
```

These are basic numerical constraints, not an independent recalculation from EVE Flow records. The validator reports gaps **between the first and last observed Feature Rows**; it does not compare rows against the full PCAP capture interval.

## 4. Reproducibility and Local Evidence

The following results were reported during Issue #13 from local Homelab and CIC-IDS2017 CSV files. The raw PCAPs, EVE outputs, and generated CSVs remain local. A fresh repository clone cannot reproduce these counts without the corresponding inputs.

| Dataset under `data/feature-tests/` | Monitored IP | Rows | Reported gaps | Result |
|---|---|---:|---:|---|
| `tcp-baseline-002-v1.csv` | `192.168.1.21` | 21 | 0 | PASS |
| `tcp-baseline-004-v1.csv` | `192.168.1.21` | 7 | 0 | PASS |
| `tcp-baseline-005-v1.csv` | `192.168.1.21` | 61 | 0 | PASS |
| `tcp-baseline-006-v1.csv` | `192.168.1.21` | 60 | 0 | PASS |
| `cicids2017-monday-0900-0930-v1.csv` | `192.168.10.50` | 33 | 27 | PASS |
| `cicids2017-monday-host12-v1.csv` | `192.168.10.12` | 58 | 2 | PASS |
| `cicids2017-friday-portscan-v1.csv` | `192.168.10.50` | 56 | 4 | PASS |
| **Total** | — | **296** | **33** | **7/7 PASS** |

Earlier manual capture-boundary checks found **59 internal candidate windows** in each of Homelab Baselines 005 and 006. For the Monday and Friday CIC-IDS2017 captures monitoring `192.168.10.50`, **31** and **54** internal windows had Feature Rows, respectively, out of **58** full time positions. These are time-boundary candidates, **not independently verified-complete windows**.

### Port-scan feature evidence

The following values compare the same monitored host (`192.168.10.50`) in Monday benign-candidate traffic and Friday port-scan-candidate traffic. They cover *internal observed rows*, not every possible capture window.

| TCP feature | Monday median / max | Friday median / max |
|---|---:|---:|
| `tcp_inbound_flow_count` | 3 / 8 | 4 / **22,934** |
| `tcp_inbound_unique_dest_port_count` | 1 / 4 | 3 / **1,000** |
| `tcp_inbound_max_unique_dest_ports_per_src_ip` | 1 / 2 | 2 / **999** |
| `tcp_inbound_unique_src_ip_count` | 2 / 4 | 2 / 4 |

The Friday peaks are consistent with the multi-port scanning activity also observed in packet-level inspection. They demonstrate that the **feature extraction pipeline can represent this behavior**. They do not establish model detection accuracy, and not every Friday window is an attack window.

Run the complete test suite:

```bash
python3 -m unittest discover -s tests -v
```

The latest reported local run passed **16 tests**: three feature-extraction tests, three dataset-builder tests, and ten dataset-validator tests. The builder tests include byte-for-byte reproduction of a sanitized demo CSV. The validator tests cover successful input, informative gaps, and rejection of invalid schemas, values, timestamps, hosts, duplicate or unsorted rows, and inconsistent counts. The tests use temporary files; CIC-IDS2017 is not needed to run them.

## 5. Window Policy and Limitations

- **Observed-flow windows:** A row is generated only when an observed monitored-host TCP Flow has a `flow.start` assigned to that 30-second UTC window. This is not a complete time series.
- **Missing rows are not zero-flow evidence:** A manually inspected Monday window without a Feature Row still contained **24 TCP packets** involving the monitored host. Packets can belong to connections that started earlier. No automatic zero filling is performed.
- **Capture completeness is not validated:** The CSV checker does not read PCAP boundaries, capture metadata, or packet-drop statistics. A zero gap count does not establish uninterrupted or verified-complete capture coverage; partial first/last windows may still appear in CSV output.
- **Flow interpretation is limited:** Counts use Suricata Flow records, not raw SYN counts or confirmed successful TCP connections. Recorded source/destination orientation does not always identify the actual initiator, and NAT may affect source attribution.
- **Checksum artifacts remain a known uncertainty:** Homelab captures generated many invalid-checksum alerts. TX checksum offloading was observed enabled and may contribute, but its effect on TCP Flow extraction has not been fully established.
- **Dataset provenance and labels matter:** Monday and Friday represent different periods; Friday contains both lower-activity and scan-like windows. Attack labels must be checked at window level. Homelab and CIC-IDS2017 data should not be blindly combined or randomly split across environments.
- **No ML evaluation yet:** Validator PASS and high port-diversity values are not anomaly scores, measured false-positive rates, or proof of successful detection.

Generated datasets remain in `data/feature-tests/`, excluded from Git by `.gitignore`; commit implementation, tests, and documentation rather than raw experiment artifacts.

## 6. Remaining Work

The current validator provides a reproducible **CSV structure and internal-consistency gate**. Before using the rows as final anomaly-scoring input, establish a supported capture-completeness policy, decide how verified zero-Flow windows should be represented, preserve provenance, and define defensible window labels and training/test partitions.