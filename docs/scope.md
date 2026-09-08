## Objective

The goal for this semester is to extend the existing Suricata and parser pipeline into a basic hybrid IDS prototype.

The main new work is to create a shared event format, extract useful security features, build a reproducible dataset, and add basic anomaly scoring alongside Suricata alerts.

## Core Deliverables

The main deliverables for this semester are:

1. A shared event schema for Flow, DNS, HTTP, TLS, and Alert events
2. A unified normalizer that converts the five event types into that schema
3. A feature extraction pipeline for security-relevant fields
4. A reproducible feature dataset
5. A basic anomaly-scoring prototype
6. A basic hybrid analysis that presents Suricata alerts, anomaly scores, and related event context together

## Completion Criteria

A deliverable is considered complete when it produces a result that can be run and checked.

* **Shared event schema:** the five event types can be represented using one documented structure.
* **Unified normalizer:** Flow, DNS, HTTP, TLS, and Alert events can all be converted into that shared structure.
* **Feature extraction:** normalized events can be converted into a consistent set of security-related features.
* **Feature dataset:** the same input and configuration can reproduce the same dataset.
* **Anomaly scoring:** the prototype can assign an anomaly score to the prepared data and produce results that can be inspected.
* **Hybrid analysis:** Suricata alerts, anomaly scores, and related event context can be reviewed together.

## Milestones

My current planning targets are:

* **Weeks 1–3:** Recheck the baseline, compare the five parser outputs, and prepare for the shared schema.
* **Weeks 4–5:** Define the shared event schema and implement the unified normalizer.
* **Weeks 6–8:** Build feature extraction and generate a reproducible feature dataset.
* **Weeks 9–10:** Select a simple anomaly detection method and implement the first scoring prototype.
* **Weeks 11–13:** Combine anomaly scores with Suricata results, add basic context, and test the hybrid workflow.
* **Weeks 14–15:** Final testing, documentation, architecture updates, and demo preparation.

Each stage depends on the output of the previous stage. For example, feature extraction depends on normalized events, and anomaly scoring depends on the feature dataset.

These week numbers are my project planning targets from the proposal, not official course deadlines. Official deadlines should follow the CISC 4900 course calendar.

## Optional and Excluded Work

Optional work, if the core pipeline is completed early, may include:

* A small FastAPI interface
* Simple charts or a lightweight dashboard
* Limited MITRE ATT&CK mapping
* Additional anomaly detection experiments

The following are outside the intended core semester scope:

- A production-ready IDS
- Real-time enterprise monitoring
- PostgreSQL and Redis infrastructure
- A full React frontend
- Advanced model management or explainability
- A complete SOC or alert-management platform