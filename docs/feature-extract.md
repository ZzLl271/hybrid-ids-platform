**Implementation:** `backend/app/feature_extract.py`
## 1. Problem and Goal

The overall Hybrid IDS project aims to combine **Suricata rule-based alerts** with **machine-learning anomaly scoring**. Suricata processing, five event parsers, the shared normalizer, and basic TCP feature extraction are available; **ML anomaly scoring has not been implemented**.

The five event-specific parsers each extract information for their own event type. The **shared normalizer** then organizes their outputs into a common structure. That makes the records easier to work with, but a single event still cannot show how a server's network behavior changes over time. This task turns observed **Suricata TCP Flow records** into numerical summaries that can later be compared with a normal baseline.

I chose three behavior dimensions because each can be observed through Flow fields, compared with ordinary server activity, and tested in the existing Homelab:
- **Connection volume:** Does the number of TCP Flows *starting* in a short period rise noticeably?
- **Inbound port/source behavior:** Are remote sources reaching more server ports, or are more sources contacting the server?
- **Outbound destination behavior:** Is the server reaching more destination IPs or ports, especially several IPs on the same port?

These are possible signs of unusual activity, **not three confirmed attack categories**. They complement the information from Suricata alerts rather than replace rule-based detection.
## 2. How I Chose the Approach

I revisited the five normalized event types, considered what a dataset row could represent, and compared options using four criteria: relevance to the behavior being studied, fields actually available, experiments possible in my Homelab, and undergraduate MVP effort.

| Design question              | Choice and reason                                                                                                    | Alternative and trade-off                                                                                                                                 |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Which event data?            | **TCP Flow.** IPs, ports, IDs and start times can describe activity across several Flows.                            | DNS, HTTP and TLS describe application-specific activity and would require different features or correlation. Alert remains separate rule-based evidence. |
| What does one row represent? | **One monitored host + one time window.** A row describes the server's overall behavior, rather than one connection. | Per-Flow rows focus on individual connections; per-source windows improve attribution but require source-specific scoring.                                |
| What is monitored?           | **One Ubuntu Server**, in both inbound and outbound directions, using traffic visible to its capture interface.      | Monitoring the full LAN would require additional traffic visibility such as a mirror port or gateway deployment.                                          |
| How long is a window?        | **30 seconds**, UTC-aligned and non-overlapping, as a simple starting point for short-term behavior.                 | Shorter windows may be sparse; longer windows may hide brief bursts. I have not established that 30 seconds is optimal.                                   |
| Which features?              | Counts and endpoint diversity that I can calculate and check with controlled TCP traffic.                            | Payload, UDP, unsuccessful-connection indicators and multi-event correlations add complexity and are deferred.                                            |

**Why not one Flow per row?** A single access to port 22 or 80 may look ordinary, while one source visiting several server ports in a short period is easier to see after aggregation. The cost of host-level aggregation is that activity from several remote sources is mixed into one row; the underlying Flow records remain available for investigation.
## 3. Selected  Design

```text
PCAP → Suricata eve.json → Flow Parser → Unified Normalizer
     → TCP Flow grouping (30-second windows) → Eight Features → CSV
```
The extractor uses normalized `event_type == "flow"` records with `proto == "TCP"`. Each output row has `window_start`, `monitored_ip`, and eight numeric features. The monitored IP is passed in for each experiment, not hardcoded.

**Window and counting rules**
- Each Flow is assigned **once**, using `metadata.flow_start` (preserved from raw Suricata `flow.start`), to a UTC window `[start, start + 30 seconds)`. A long-lived Flow is not counted again in later windows.
- In the current implementation, **inbound** means `dest_ip == monitored_ip` and `src_ip != monitored_ip`; **outbound** means `src_ip == monitored_ip` and `dest_ip != monitored_ip`. This uses the recorded endpoint orientation and does not always prove the actual TCP initiator.
- For the two Flow-count features, count distinct `flow_id` values per window and direction. Other features count distinct valid IPs/ports or the maximum of such counts within a group.
- All counts summarize **observed Flow records whose start times fall in the window**. They are not counts of SYN packets, verified successful TCP connections, or every connection active during the window.
### Eight features

| Feature                                          | Meaning within one host-window                                                                                                  |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| `tcp_inbound_flow_count`                         | Number of distinct inbound TCP Flow IDs                                                                                         |
| `tcp_outbound_flow_count`                        | Number of distinct outbound TCP Flow IDs                                                                                        |
| `tcp_inbound_unique_dest_port_count`             | Number of different valid server destination ports reached by inbound Flows                                                     |
| `tcp_inbound_max_unique_dest_ports_per_src_ip`   | Group inbound Flows by valid source IP, count different valid server destination ports for each, and take the **largest count** |
| `tcp_inbound_unique_src_ip_count`                | Number of different valid inbound source IPs                                                                                    |
| `tcp_outbound_unique_dest_ip_count`              | Number of different valid outbound destination IPs                                                                              |
| `tcp_outbound_unique_dest_port_count`            | Number of different valid outbound destination ports                                                                            |
| `tcp_outbound_max_unique_dest_ips_per_dest_port` | Group outbound Flows by valid destination port, count different valid destination IPs for each, and take the **largest count**  |

The two `max` features are **counts, not percentages or concentration ratios**. Both return **0 when there are no qualifying groups** in a supplied window (including no relevant Flows or no valid IP/port pairs).

### Small calculation example
Suppose these six distinct TCP Flows have valid fields and start in the same window. `H` is the monitored host, `A` and `B` are inbound sources, and `X`, `Y`, `Z` are outbound destinations:
```text
A → H:22     A → H:80     B → H:443
H → X:443    H → Y:443    H → Z:22
```
The eight values, in table order, are **3, 3, 3, 2, 2, 3, 2, 2**. For example, the first `max` is **2** because A reached two ports; the second is **2** because port 443 was used to reach X and Y. If a window had no inbound Flow, the inbound `max` would be **0**.
## 4. Principles and Constraints

- **Use observed data, not assumed results.** A Flow is a Suricata summary; it cannot by itself prove an established connection or an attack.
- **Keep features understandable.** Each value should have a clear counting rule. Eight exported fields are candidates for later ML input, not eight already-proven independent detection signals.
- **Handle incomplete fields explicitly.** Missing `metadata.flow_start` prevents TCP Flow grouping. Missing `flow_id` on a relevant Flow causes an error in Flow counting. For IP/port features, invalid fields are excluded from the calculation requiring them; this does not necessarily remove the whole Flow from other counts.
- **Port rule:** v1 accepts destination ports that are integers **1–65535** (not booleans). Port **0** is excluded by this implementation's filtering policy; it is not a claim that a raw packet cannot contain port 0.
- **Distinguish empty from unobserved.** Grouping normally produces windows with observed TCP Flow starts. A zero-Flow window must be added explicitly and supported by trustworthy capture coverage; an incomplete capture is not proof of zero activity.
- **Keep scope manageable.** This is offline, TCP-only, host-scoped analysis. Full-LAN coverage, real-time detection, payload inspection and deep learning are outside this time.

The present feature functions do **not** validate every input field identically. Cross-feature consistency and capture coverage still need dedicated dataset checks.
## 5. Changes to Existing Components

Before Task #10, the project already had Suricata PCAP processing, five event-specific parsers, and a shared normalizer. To support the chosen host-window feature design, I made the following changes:

| Existing component                                   | Change                                                   | Reason                                                                                               |
| ---------------------------------------------------- | -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `backend/app/parse_eve.py` (Flow parser)             | Extracted Suricata `flow.start` as `flow_start`.         | The EVE event timestamp may differ from when the Flow began; window assignment needs the start time. |
| `backend/app/normalize_event.py` (shared normalizer) | Preserved `flow_start` under Flow `metadata.flow_start`. | The feature extractor should consume normalized events without reopening raw EVE fields.             |
| `.gitignore`                                         | Added `data/feature-tests/` to the ignored paths.        | Generated experiment CSVs should stay local rather than enter the source repository.                 |

I also **added** `backend/app/feature_extract.py` to group normalized TCP Flows into 30-second windows, calculate the eight features, and export CSV rows. This is a new processing step, not a replacement for the existing parsers.

The DNS, HTTP, TLS, and Alert parsers were kept. The shared normalized event structure remains the same apart from the additional Flow metadata field. These changes are limited to what feature extraction needs; they do not implement anomaly scoring.
## 6. Evidence and Open Questions
The results below were reported in terminal output during earlier local experiments. The PCAP and EVE paths identify **the inputs used at that time**.

| Experiment | Local source records | Previously observed result |
| --- | --- | --- |
| Normal outbound traffic (`tcp-baseline-002`) | `data/pcaps/tcp-baseline-002.pcap`, `data/eve-runs/tcp-baseline-002/eve.json` | About 10 minutes of primarily Ubuntu `curl` traffic; **19 candidate windows**. Outbound unique-port count: 1–2; max destination IPs per port: 1–2. |
| Normal SSH traffic (`tcp-baseline-004`) | `data/pcaps/tcp-baseline-004.pcap`, `data/eve-runs/tcp-baseline-004/eve.json` | Windows PowerShell SSH to Ubuntu, plus background traffic; **5 candidate windows**. Inbound unique-source count: 0–1; max outbound IPs per port: 1–3. |
| Controlled scan (`inbound-scan-001`) | `data/pcaps/inbound-scan-001.pcap`, `data/eve-runs/inbound-scan-001/eve.json` | Windows Nmap targeting **21, 22, 80, 443, 8080**; **1 short window**, 9 inbound Flow IDs, 5 distinct inbound ports, 1 source. |

A manually executed regression script previously printed `PASS` for all three runs and checked that five established feature calculations matched earlier local reference CSVs. The console output is **not** a persisted, independently repeatable test artifact. Any later `jq` inspection of EVE would only check the selected raw fields: it would not by itself validate full windows, host filtering, deduplication or all eight computations. A repeatable dataset-generation and validation test is still needed.

**Remaining work**
- **#12 — Reproducible dataset:** save a repeatable normalized-event-to-CSV command, rebuild current eight-feature CSVs, and record the input run, monitored IP, chosen windows and expected output.
- **#13 — Dataset validation:** verify capture coverage, field rules, empty-window handling and row consistency; add representative normal and controlled-anomaly experiments.
- **ML scoring:** evaluate which of the eight fields are helpful, using separate normal and controlled-anomaly data; report false positives and limitations rather than assuming feature counts imply detection accuracy.
- **Known design limitations:** 30-second windows can miss slower behavior; host-level rows mix remote sources; source/destination orientation does not always identify the initiator.

This document records the **design and its evidence**.