# CISC 4900 Semester Scope

This file records the student's intended project scope. It is a project
decision summary derived primarily from the proposal, not a statement of
course-wide requirements.

Source: the student's project proposal and maintained semester-scope record.
The proposal and private course records are maintained outside this repository.
This public copy was prepared on 2026-09-06; it is self-contained for repository
reviewers. Keep future public updates aligned with the maintained project plan.

## Project Positioning

Build a minimum viable Hybrid IDS security-data pipeline in which Suricata
produces rule-based network events and Python processing prepares those events
for feature extraction and basic anomaly scoring.

The goal is a demonstrable undergraduate cybersecurity engineering prototype,
not a production IDS, automated attack-confirmation system, or complete SOC
platform.

## Pre-Semester Foundation

The repository-backed Phase 1 implementation is verified as pre-semester
baseline work.

```text
PCAP -> Suricata -> eve.json -> five event-specific parsers
```

See [`semester-baseline.md`](semester-baseline.md).

## Core Semester Scope

1. Stabilize and clearly validate the Phase 1 baseline.
2. Compare the five parser output schemas.
3. Define a shared normalized event schema and data contract.
4. Produce unified normalized records.
5. Extract security-relevant features.
6. Build a reproducible feature dataset.
7. Implement a basic, explicitly limited anomaly-scoring prototype.
8. Add basic alert context/enrichment.
9. Record input, configuration, expected output, actual output, and validation
   for each experiment.
10. Prepare final documentation, diagrams, demo evidence, slides, and video.

The project's technical milestones must be coordinated with the separate
official course calendar; proposal week numbers are planning targets, not
course deadlines.

## Stretch or Future Scope

- FastAPI endpoints.
- PostgreSQL storage.
- Redis queueing.
- React dashboard and real-time visualization.
- Model management and advanced explainability such as SHAP.
- Full alarm-management and system-monitoring capabilities.

These must not be described as implemented unless repository evidence changes.

## Validation Principle

For every experiment, preserve:

```text
Input
Configuration
Expected Output
Actual Output
Validation Method
Limitations
```

An IDS alert is not proof of compromise, and an anomaly score is not proof of
malicious behavior. Both require context, triage, and explicit limitations.
