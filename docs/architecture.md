# Architecture Diagrams

This project uses two architecture diagrams to separate current implementation from the long-term system concept.

## Current Phase 1 Architecture

Draw.io source:

```text
docs/phase1-architecture.drawio
```

This diagram shows the part currently implemented in this repository:

```text
PCAP -> Suricata Docker -> eve.json -> Python parsers -> summary / table / JSONL
```

## Core Semester Pipeline

The [semester scope](semester-scope.md) defines the planned core deliverable:

```text
Suricata EVE events
-> event parsing
-> shared normalization
-> feature extraction and reproducible dataset
-> basic anomaly scoring and alert context
-> CLI / JSONL / CSV results and documented validation
```

Only ingestion and the event-specific parser layer are implemented at the
[pre-semester baseline](semester-baseline.md). Normalization, feature
extraction, scoring, and cross-event alert enrichment remain planned work.
In this paragraph, normalization means the shared cross-event layer; each
existing parser already performs its own field extraction and normalization.

## Long-Term Architecture Concept

Draw.io source:

```text
docs/final-architecture.drawio
```

This diagram preserves the larger system concept, including a backend API,
storage services, a frontend dashboard, ML scoring, and alert management.
The service layout, live/replayed-traffic capture, and model choice shown are
future design ideas, not the current deployment or a binding semester plan.
The current workflow uses offline PCAP analysis on the student's Ubuntu host.

An older legend assigned solid blocks to the semester deliverable. That
interpretation is superseded by [semester-scope.md](semester-scope.md).
Colors and solid/dashed styling do not establish delivery commitments.
FastAPI, PostgreSQL, Redis, React, and advanced explainability remain stretch
goals or future work. Basic anomaly scoring does not require those services.

## Current Integration Limits

A source and sanitized-sample review on 2026-09-06 found the existing module
layout suitable for the Phase 1 offline prototype. It identified these limits
to address when implementing the planned next phase:

- Each parser scans the input separately and collects matching records in
  memory. The review did not benchmark large files or streaming operation.
- Outputs use event-specific fields rather than a shared contract. In
  particular, the DNS normalizer does not retain an input `flow_id`, and parser
  outputs do not retain `event_type`. Cross-event correlation must preserve
  the needed identifiers from the original EVE data and define a missing-ID
  policy; it cannot assume every existing output already contains them.
- The PCAP runner expects execution from the repository root and input files
  under `data/pcaps/`, as shown in the README. It is not a general-purpose
  runner for arbitrary input paths.
- The runner can report success after its event-summary pipeline fails.
  This reproduced reliability issue is recorded as
  [TASK-001](tasks.md#task-001--propagate-failures-from-the-runners-event-summary-pipeline)
  and remains unfixed.
- The included sample demonstrates parser behavior; it is not a feature
  dataset, an anomaly-scoring benchmark, or an end-to-end detection evaluation.
- No automated test suite or CI workflow is present at the baseline.

The review reran JSON stdout, summary, and pretty modes for all five parsers
(15 successful invocations) and reproduced the DNS identifier omission with
an in-memory input. It did not run Docker/Suricata, connect to the homelab, or
exercise JSONL file writing. Homelab verification in the baseline is the
student's separately confirmed work.
