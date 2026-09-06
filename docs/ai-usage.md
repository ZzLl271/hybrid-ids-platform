# AI Usage Disclosure

Updated: 2026-09-06.

This document describes how I have used Codex while developing and documenting
the Hybrid IDS Platform. It was drafted with Codex assistance from my account
of the work and the assistance recorded during the documentation review.

## Pre-Semester Work: Phases 0 and 1

Before CISC 4900, I used Codex to help with:

- Brainstorming the project proposal and discussing the project's goals.
- Creating the planned final architecture diagram and organizing the project
  file structure.
- Learning and clarifying Python and Suricata concepts.
- Reviewing code as I developed the project step by step.

My development process was incremental. Each step included a verification
method before I continued. I used AI explanations and review feedback as
inputs to that process, rather than treating an AI response as proof that a
component worked. This account describes the process; it does not provide a
line-by-line attribution of every historical code edit or command.

The larger architecture was an early design concept. Its presence in the
repository does not mean all of its components were implemented or promised
as semester deliverables. The current commitment is recorded in the
[semester scope](semester-scope.md).

## Assistance During the Semester

AI assistance has also included:

- Organizing project documentation and distinguishing pre-semester work from
  planned semester work.
- Comparing the baseline and scope with the proposal, source files, and Git
  history, and suggesting wording corrections.
- Reviewing the current repository architecture and identifying integration
  limits for the next phase, such as missing DNS correlation fields.
- Running local parser checks against the sanitized sample and reporting
  exactly what those checks covered.
- Preparing public baseline and scope copies, correcting obsolete architecture
  scope labels, and drafting this disclosure at my request.

These activities include AI-assisted drafting and editing of project
documentation, not only brainstorming. They are separate from implementation
of the planned shared normalizer, feature extraction, and anomaly scoring,
which remain future work at the documented baseline.

## Verification and Responsibility

I am responsible for understanding the project, deciding which suggestions to
adopt, and checking the resulting behavior. I perform the homelab development
and administration and report the results of my manual checks. Codex has also
performed local repository inspection and sample checks; those activities
should be credited accurately rather than described as exclusively manual.

Examples of the evidence kept for this project include Git history, parser
summaries, generated experiment artifacts retained on the homelab, and my
hardware and environment checks. Future experiments follow the scope's
input, configuration, expected output, actual output, validation method, and
limitations record.

On 2026-09-06, Codex reran JSON stdout, summary, and pretty modes for all five
parsers: 15 successful invocations against the sanitized sample. It also
checked an in-memory DNS event and confirmed that the current normalizer
omits `flow_id`. This review did not execute a Docker/Suricata PCAP run,
connect to the homelab, or test JSONL file writing. The homelab verification
dated 2026-09-06 in the [baseline](semester-baseline.md) was my own work.

AI-assisted review and a successful sample run do not establish production
readiness or detection accuracy. The limitations and remaining work are
documented in the [architecture notes](architecture.md) and semester scope.

## Disclosure Boundaries

This statement records actual assistance; it does not claim blanket course
approval for AI use. Course assignments can have their own restrictions,
which must be followed independently of this project disclosure.

Private course records, supervisor information, and raw homelab traffic remain
outside the public repository. Public examples use the sanitized sample.
This is a repository-publication boundary, not a claim that every historical
AI interaction has been audited for data handling.

I will update this record when the tools or kinds of assistance change,
including any future adoption of AI-generated implementation code, commands,
tests, or other project artifacts, with the relevant verification described.
