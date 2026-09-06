# CISC 4900 Pre-Semester Baseline

Baseline boundary: before the 2026-08-28 course orientation.

Repository verification: 2026-09-03.  
Homelab environment verification: 2026-09-06.

This document establishes the technical state of the Hybrid IDS Platform
before CISC 4900 semester work began. Its purpose is to distinguish
pre-semester implementation from new work completed during the course.

This public copy was prepared on 2026-09-06 from the student's maintained
course-workspace baseline. Repository evidence and student-confirmed homelab
checks are distinguished below. The homelab checks were performed and confirmed
by the student; they were not remotely executed by the AI assistant. The full
private record remains outside this repository. Adapter-specific interface
names are omitted from this public copy.

---

## Git Evidence

- Repository: `hybrid-ids-platform/`
- Branch: `main`
- Verified pre-semester HEAD:
  `35051175f35cde77f33ce53262585ab20ce1f8df`
- Commit count at repository verification: 23
- Commit date range: 2026-06-14 through 2026-06-26
- Working tree at verification: clean
- Local `main` and the locally recorded `origin/main` were aligned

Because every repository commit predates the 2026-08-28 course orientation,
all implementation present in Git at the time of verification belongs to the
pre-semester baseline.

Future semester progress reports must not present this implementation as new
CISC 4900 work.

---

## Verified Repository Baseline

The repository contains the following working pre-semester components:

- Docker-oriented Suricata offline-PCAP runner script.
- Flow event parser.
- DNS event parser.
- HTTP event parser.
- TLS event parser.
- Alert event parser.
- Per-parser JSON stdout output.
- JSONL-writing support.
- Human-readable pretty-table output.
- Summary output.
- Checksum-alert noise labeling.
- Sanitized sample EVE log.
- Phase 1 documentation.
- Current and planned architecture documentation.

### Parser Verification

Dynamic sample checks were performed on 2026-09-03 using Python 3.12.10.

| Parser | Summary result | Pretty mode |
|---|---|---|
| Flow | 1 flow; 360 total bytes; 0 alerted | Passed |
| DNS | 2 events: 1 query, 1 answer | Passed |
| HTTP | 1 event: HEAD, status 200 | Passed |
| TLS | 1 event: TLS 1.3 with JA3/JA3S values | Passed |
| Alert | 1 alert; classified as checksum noise | Passed |

The sanitized sample uses documentation-only IP ranges and `example.com`.

Git tracks no real PCAP files, generated `eve.json` files, or generated
normalized JSONL output. The tracked `data/` directories contain only
`.gitkeep` placeholders.

---

## Verified Homelab Baseline

The Homelab environment was directly reverified on 2026-09-06.

### Hardware and Operating System

- Hardware: OMEN by HP Laptop 15-ce0xx
- CPU: Intel Core i7-7700HQ @ 2.80 GHz
- Logical CPUs: 8
- Memory: approximately 15 GiB usable
- Swap: 4 GiB
- Primary system storage: Samsung SSD 980 PRO 1 TB NVMe SSD
- Secondary storage: HGST HTS721010A9 1 TB disk
- GPU:
  - Intel HD Graphics 630
  - NVIDIA GeForce GTX 1050 Ti Mobile
- Operating system: Ubuntu 22.04.5 LTS
- Kernel: Linux 5.15.0-185-generic
- Architecture: x86-64

### Storage Layout

The current Ubuntu root filesystem and EFI system partition are located on
the Samsung 980 PRO NVMe SSD.

```text
Samsung SSD 980 PRO 1TB
└── nvme0n1
    ├── nvme0n1p1 -> /boot/efi
    └── nvme0n1p2 -> /
```

The HGST disk also contains an existing LVM logical volume, but it is not the
currently mounted root filesystem.

### Remote Administration and Services

The following services and development environment were verified:

- SSH service: active
- VS Code Remote SSH used for project development
- Docker service: active
- Docker version: 29.5.3
- Portainer container: running
- UFW firewall: active
- UFW permits OpenSSH
- UFW permits TCP port 9443 for Portainer

### Network Interfaces

The student verified two active Ethernet interfaces and one Wi-Fi interface
that was down at verification. Adapter-specific names are omitted here.

Docker and Tailscale virtual interfaces were also present.

The current LAN IP address is not treated as a stable project configuration
value because it may change over time.

### Lid-Close Server Configuration

The laptop is configured to continue operating when the lid is closed.

Verified settings:

```text
HandleLidSwitch=ignore
HandleLidSwitchExternalPower=ignore
HandleLidSwitchDocked=ignore
```

---

## Verified Suricata Baseline

The Suricata environment was directly reverified on 2026-09-06.

- Docker image: `jasonish/suricata:7.0`
- Verified runtime version: Suricata 7.0.15 RELEASE
- Primary analysis mode: offline PCAP analysis
- Runner script: `scripts/run_suricata_pcap.sh`

The runner currently performs the following workflow:

1. Validates that the input PCAP exists.
2. Refuses to reuse an existing run directory.
3. Creates a separate output directory for each analysis run.
4. Mounts the PCAP directory read-only into the Suricata container.
5. Runs Suricata through Docker in offline PCAP mode.
6. Uses `-k none` for the current prototype PCAP workflow.
7. Corrects ownership of generated output files.
8. Reads `eve.json` and prints an `event_type` summary.
9. Reports the final `eve.json` output path.

---

## Baseline Repository Structure

At the semester boundary, the core repository structure was approximately:

```text
hybrid-ids-platform/
├── backend/
│   └── app/
│       ├── __init__.py
│       ├── parse_eve.py
│       ├── parse_dns.py
│       ├── parse_http.py
│       ├── parse_tls.py
│       └── parse_alert.py
│
├── data/
│   ├── pcaps/
│   │   └── .gitkeep
│   ├── eve-runs/
│   │   └── .gitkeep
│   └── normalized/
│       └── .gitkeep
│
├── docs/
│   ├── architecture.md
│   ├── phase1-summary.md
│   ├── suricata-setup.md
│   ├── phase1-architecture.drawio
│   └── final-architecture.drawio
│
├── logs/
├── samples/
│   └── eve-demo.json
├── scripts/
│   └── run_suricata_pcap.sh
├── README.md
├── .gitignore
└── LICENSE
```

The repository structure shown above describes the Hybrid IDS project itself,
not the separate CISC 4900 course-management workspace.

---

## Baseline Data Workflow

The working pre-semester data path was:

```text
PCAP
  ↓
Suricata Docker
  ↓
eve.json
  ↓
Flow / DNS / HTTP / TLS / Alert parsers
  ↓
Per-event normalized records
  ↓
JSON stdout / JSONL / pretty table / summary
```

At this stage, normalization existed independently inside the event-specific
parsers.

A shared cross-event schema and unified normalization layer had not yet been
implemented.

### Local Experiment Artifacts

Historical experiment artifacts were reverified on the Homelab on
2026-09-06.

The local development environment still contains:

- benign and DNS/HTTP test PCAP files;
- multiple Suricata experiment run directories;
- generated `eve.json`, `fast.log`, `stats.log`, and `suricata.log` files;
- normalized Flow, DNS, HTTP, TLS, and Alert JSONL outputs.

These network-derived artifacts remain local to the Homelab and are not
tracked by the public Git repository.

---

## Completed Pre-Semester Phases

### Phase 0 — Homelab / Project Foundation

Status: **Completed before CISC 4900**

The pre-semester foundation includes:

- Homelab server setup
- Ubuntu Server
- SSH remote administration
- VS Code Remote SSH workflow
- Docker
- Portainer
- UFW
- persistent lid-close server configuration
- Git repository
- project directory structure

### Phase 1 — Traffic Ingestion and Event Parsing

Status: **Completed before CISC 4900**

The completed Phase 1 pipeline includes:

```text
PCAP
  ↓
Suricata
  ↓
eve.json
  ↓
Flow / DNS / HTTP / TLS / Alert parsing
  ↓
Per-event normalized output
```

Additional completed work includes:

- reusable PCAP analysis runner;
- checksum-alert noise labeling;
- JSONL, pretty-table, and summary output;
- sanitized parser demo;
- privacy-safe repository handling;
- architecture documentation;
- parser workflow documentation.

---

## Not Present in the Baseline

The following components were not implemented before CISC 4900 began:

- Shared cross-event schema
- Unified event normalizer
- Feature extraction pipeline
- Reproducible feature dataset
- Anomaly or ML scoring
- Hybrid rule/anomaly fusion
- Alert context/enrichment beyond checksum-noise labeling.
- FastAPI backend
- PostgreSQL storage
- Redis
- React dashboard
- Production deployment
- Automated test suite
- CI workflow

---

## CISC 4900 Technical Starting Point

The project enters CISC 4900 after completion of the event-specific parser
layer.

The next technical sequence is:

```text
Existing event-specific parsers
  ↓
Compare parser schemas
  ↓
Define shared normalized event schema
  ↓
Unified normalization
  ↓
Feature extraction
  ↓
Reproducible feature dataset
  ↓
Basic anomaly scoring
  ↓
Hybrid Suricata + anomaly analysis
  ↓
Evaluation and final demonstration
```

The immediate technical problem at the semester boundary is:

> How should Flow, DNS, HTTP, TLS, and Alert events be represented through a
> consistent shared security-event data contract?

---

## Known Historical Mismatches

The following differences were identified between older handoff documentation
and later direct verification.

### Repository Commit Count

The 2026-08-12 handoff recorded 19 repository commits.

The repository verification on 2026-09-03 identified 23 pre-semester commits.

The older count should therefore be treated as a historical snapshot.

### CPU Model

The historical handoff recorded the Homelab CPU as an Intel Core i7-6700HQ.

Direct hardware verification on 2026-09-06 identified the installed CPU as:

```text
Intel Core i7-7700HQ @ 2.80 GHz
```

The directly verified hardware value is authoritative.

---

## Baseline Boundary

All implementation described above as completed belongs to the
pre-CISC 4900 project state.

New implementation, experimentation, testing, and project documentation
performed after the semester boundary should be tracked as CISC 4900 work
through the Git repository, GitHub Project, course Time Log, and relevant
planning documentation.
