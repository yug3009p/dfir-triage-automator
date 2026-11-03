# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Development setup

```bash
git clone https://github.com/yug3009p/dfir-triage-automator.git
cd dfir-triage-automator
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Before opening a pull request:

```bash
ruff check .
ruff format .
pytest
```

CI runs the same checks on Ubuntu and Windows, plus a Docker build.

## Adding a detection rule

1. Add a match function and a `Rule(...)` entry in `src/dfir_triage/rules.py`, with an ATT&CK
   technique, a severity, and a note on common benign causes.
2. Add a case to `CASES` in `tests/test_rules.py`: one event that must match and a similar one that
   must not. The suite fails if a rule has no case.
3. Add a row to the rule table in `README.md`. The suite fails if it is missing.

## Adding a parser

1. Write it in `src/dfir_triage/parsers/` so it returns a list of `TimelineEvent`, with the right
   `time_meaning` for the artifact's timestamps.
2. For registry artifacts, use the helpers in `hive.py` so it can be tested with the fake keys in
   `tests/fakes.py`.
3. Register the file name in `classify()` and `parse_artifact()` in `timeline.py`.
4. Document what the timestamp means and what the artifact does and does not prove.

## Test data

Never commit real case evidence, client data, credentials or personal data. Use public datasets
(with their license noted in a `NOTICE.md`) or artifacts generated in your own lab VM.
