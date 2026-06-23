# Architecture Diagrams

This project uses two architecture diagrams to separate current implementation from the planned final system.

## Current Phase 1 Architecture

Draw.io source:

```text
docs/phase1-architecture.drawio
```

This diagram shows the part currently implemented in this repository:

```text
PCAP -> Suricata Docker -> eve.json -> Python parsers -> summary / table / JSONL
```

## Planned Final Architecture

Draw.io source:

```text
docs/final-architecture.drawio
```

This diagram shows the intended full system design. It includes later components such as the backend API, storage, frontend dashboard, ML scoring, and alert management. These components are design targets and are not implemented in the current Phase 1 repository yet.
