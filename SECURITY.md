# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately through GitHub's
**Report a vulnerability** button on the repository's Security tab, or by email to
yug3009p@gmail.com. Include the version (`dfir-triage --version`), steps to reproduce and, if
possible, a minimal artifact that triggers the problem. Do not send real evidence from a live case.

You can expect an acknowledgement within 7 days. This is a personal open-source project, so fixes
are best-effort.

## Supported versions

Only the latest release receives fixes.

## How the tool treats evidence

Forensic artifacts come from systems that may be compromised, so every field in them is treated as
attacker-controlled:

- **Parsing:** a malformed record or hive is skipped and reported; it should never crash the run or
  execute anything. A crash or hang on crafted input is a bug worth reporting.
- **HTML report:** rendered with autoescaping, so text such as `<script>` inside a log field is shown
  as text. A test enforces this.
- **LLM summary (optional):** the evidence may contain text written to manipulate a language model.
  The prompt tells the model not to follow instructions in the evidence, but that is not a
  guarantee, so the summary is labelled advisory and the deterministic findings stay the source of
  truth. `--summarize groq` sends evidence to a hosted API; use `--summarize ollama` or no summary
  for evidence that must not leave the machine.
- **Docker:** the image runs as an unprivileged user.

## Scope

In scope: this repository's code. Out of scope: vulnerabilities in dependencies (report those
upstream) and the bundled third-party sample data.
