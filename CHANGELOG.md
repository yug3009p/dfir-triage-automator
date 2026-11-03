# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

Planned as 1.0.0 once the registry parsers are validated on real hives
(see [docs/lab-validation.md](docs/lab-validation.md)).

### Added
- `lab/`: VirtualBox automation that builds a Windows 11 lab VM unattended, generates harmless
  known activity, collects the artifacts, and checks dfir-triage against ground truth recorded in
  the VM (real SHA-1s and file times), optionally also against Eric Zimmerman's tools.
- `dfir-triage` command: parses an evidence folder and writes `timeline.csv`, `findings.csv` and a
  self-contained `report.html`.
- Parsers for Shimcache (Windows 10/11), Amcache (`InventoryApplicationFile`), Run/RunOnce keys,
  Services and UserAssist, alongside the EVTX parser.
- `TimelineEvent` schema with an explicit `time_meaning` for every timestamp.
- Eleven deterministic detection rules mapped to MITRE ATT&CK (DT-001 to DT-011).
- Optional LLM summary from Groq or a local Ollama model, now given the rule findings.
- Dockerfile (non-root), CI on Ubuntu and Windows, SECURITY.md, CONTRIBUTING.md.
- Attribution for the GPL-3.0 sample data in `sample_data/NOTICE.md`.

### Fixed
- `--summarize groq` failed because Groq retired `llama-3.3-70b-versatile`. The default is now
  `openai/gpt-oss-120b` (verified with a live run on the samples), `GROQ_MODEL` overrides it, and a
  retired model is now recognised from Groq's `model_not_found` error and explained.

### Changed
- Code moved into the `dfir_triage` package with a `pyproject.toml`.
- The EVTX parser now reads `UserData` fields (needed for event 1102), extracts user and image
  path, and logs skipped records instead of silently dropping them.
- The LLM prompt treats evidence as untrusted data.

### Removed
- An illustrative README example that did not match the real sample data.

## [0.1.0] - 2026-06-09

Not tagged; refers to the first commits on `main`.

### Added
- First version: EVTX parser, Groq-based incident summary and Streamlit UI.
