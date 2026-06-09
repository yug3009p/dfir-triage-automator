# DFIR Triage Automator

**Parses Windows event logs (`.evtx`) into a normalized attack timeline and uses an LLM to generate an analyst-grade incident report. Maps observed activity to MITRE ATT&CK.**

![Python](https://img.shields.io/badge/Python-3.12+-3776AB?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.32+-FF4B4B?logo=streamlit&logoColor=white)
![Groq](https://img.shields.io/badge/Groq-Llama_3.3_70B-F55036)
![Windows](https://img.shields.io/badge/Windows-EVTX_Event_Logs-0078D6?logo=windows&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-C00000)
![License](https://img.shields.io/badge/License-MIT-10B981)

---

## Why this project

When an analyst is handed a Windows event log during an incident, the first hour is mostly mechanical: open the `.evtx`, decode hundreds or thousands of numeric Event IDs, reconstruct who-did-what-when, and figure out whether the activity is benign or the opening moves of an intrusion. That triage step is slow, error-prone, and exactly the kind of work that bottlenecks a SOC at 2 a.m.

A few realities that motivated this tool:

- **Raw Event IDs are not human-readable.** A line that says `EventID 1102` means nothing until you know it is *"the security audit log was cleared"* — a classic anti-forensics move (MITRE ATT&CK **T1070.001 — Indicator Removal: Clear Windows Event Logs**). Multiply that across the ~20 IDs that actually matter and triage becomes lookup-table archaeology.
- **The signal is in the sequence, not the single event.** `1102` (log cleared) → `4624` (logon) → `4672` (admin privileges) → `4688` (process execution) within seconds is a textbook attack story. A list of timestamps hides it; a narrative surfaces it.
- **Triage capacity is the constraint.** The shortage in defensive security is rarely raw data — it is analyst-hours to interpret it. Anything that turns "here are 6,000 events" into "here is what happened, how severe it is, and what to do next" is leverage.

This project is one answer. It parses the log, builds a chronological triage timeline with plain-English descriptions, and asks an LLM acting as a senior DFIR analyst to produce a structured incident report — executive summary, attack narrative, ATT&CK techniques, severity, and recommended response actions.

## What it does

A Streamlit web app backed by two reusable modules:

- **EVTX Parser (`src/parser.py`).** Reads any Windows `.evtx` file, extracts each record's timestamp, Event ID, channel/provider, computer, and event data, and resolves the Event ID to a plain-English description via a curated lookup (Security, System, Sysmon, and PowerShell channels). Returns a time-sorted `pandas` DataFrame. One corrupt record never kills the parse.
- **LLM Summarizer (`src/summarizer.py`).** Flattens the timeline into a token-bounded prompt, treats it as authoritative evidence (no invented events), and asks Groq's `llama-3.3-70b-versatile` — cast as a senior SOC/DFIR analyst writing for an on-call IR lead — to return a fixed five-section markdown report.
- **Streamlit UI (`src/app.py`).** Upload an `.evtx`, see a metrics row (total events, time span, high-signal event count) and an interactive timeline table, then generate the AI incident report on demand and export it as Markdown.

## Screenshots

> Drop screenshots into `screenshots/` and reference them here. Suggested set: `01_upload.png`, `02_timeline.png`, `03_summary.png`.

```
screenshots/
├── 01_upload.png      # File upload + empty-state instruction
├── 02_timeline.png    # Metrics row + parsed timeline table
└── 03_summary.png     # Generated AI incident report
```

## Event ID coverage

The parser resolves these security-relevant Event IDs to plain-English meaning. Anything outside the table is preserved and labelled `Other`.

| Event ID | Meaning | Source | Why it matters (ATT&CK) |
|---|---|---|---|
| 4624 | Successful logon | Security | Valid Accounts (T1078) |
| 4625 | Failed logon | Security | Brute Force (T1110) |
| 4634 | Logoff | Security | Session context |
| 4648 | Logon with explicit credentials | Security | Lateral movement / pass-the-hash signal |
| 4672 | Special privileges assigned | Security | Privileged / admin logon |
| 4688 | Process creation | Security | Execution (T1059) |
| 4720 | User account created | Security | Account Manipulation (T1136) |
| 4724 | Password reset attempt | Security | Account Manipulation |
| 4728 / 4732 / 4756 | Member added to security group | Security | Privilege escalation / persistence |
| 4740 | Account locked out | Security | Brute Force fallout |
| 1102 | Audit log cleared | Security | Indicator Removal (T1070.001) |
| 4698 | Scheduled task created | Security | Scheduled Task (T1053.005) |
| 4697 / 7045 | Service installed | Security / System | Create or Modify System Process (T1543.003) |
| 7036 | Service state change | System | Service activity |
| 4104 | PowerShell script block logged | PowerShell | Command & Scripting Interpreter (T1059.001) |
| Sysmon 1 | Process creation | Sysmon | Execution |
| Sysmon 3 | Network connection | Sysmon | C2 / exfiltration signal |
| Sysmon 11 | File created | Sysmon | Tooling drop |
| Sysmon 13 | Registry value set | Sysmon | Persistence / config change |

Sysmon and Security IDs that collide (e.g. `1`) are disambiguated by channel before lookup.

## Tech stack

- **Python** 3.12
- **python-evtx** for parsing the binary `.evtx` format
- **pandas** for the timeline DataFrame
- **Streamlit** for the UI
- **Groq SDK** — `llama-3.3-70b-versatile` for report generation
- **python-dotenv** for local secret loading

## Setup

```bash
# 1. Clone and enter the project
git clone https://github.com/yug3009p/dfir-triage-automator.git
cd dfir-triage-automator

# 2. Create a virtualenv
python -m venv venv
# Windows (PowerShell)
.\venv\Scripts\Activate.ps1
# macOS / Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure your Groq API key
copy .env.example .env        # Windows  (use 'cp' on macOS/Linux)
# then edit .env and paste your key from https://console.groq.com/keys

# 5. Launch
streamlit run src/app.py
```

The app opens at <http://localhost:8501>. Parsing and the timeline view work without an API key; generating the AI incident report requires `GROQ_API_KEY`.

You can also run the pieces directly from the command line:

```bash
python src/parser.py sample_data/<file>.evtx       # prints the parsed timeline
python src/summarizer.py                           # parses a sample + prints the report
```

## Example output

Parsing a lateral-movement sample produces a timeline like:

```
Time        EventID  Description                          Details
11:06:25    1102     Audit log cleared                    Channel=Security
11:06:29    4624     Successful logon                     LogonType=3 | Account=svc_admin
11:06:29    4672     Special privileges assigned (admin)  Privileges=SeDebugPrivilege ...
11:06:31    4688     Process creation                     Image=...\mimikatz.exe
```

Generating the report returns a five-section markdown document:

```markdown
## 1. Executive Summary
An actor cleared the Windows security audit log, then authenticated with an
administrative account and executed a credential-dumping tool within seconds —
consistent with a hands-on-keyboard intrusion attempting to harvest credentials
while suppressing forensic evidence.

## 2. Attack Timeline Narrative
1. 11:06:25 — Security audit log cleared (anti-forensics).
2. 11:06:29 — Successful network logon followed immediately by assignment of
   administrative privileges.
3. 11:06:31 — Execution of a known credential-access tool.

## 3. MITRE ATT&CK Techniques Observed
- T1070.001 — Indicator Removal: Clear Windows Event Logs
- T1078 — Valid Accounts
- T1003 — OS Credential Dumping

## 4. Severity Assessment
**Critical** — log clearing combined with privileged execution of a credential
tool indicates active compromise, not reconnaissance.

## 5. Recommended Response Actions
- Isolate the host and capture volatile memory before reboot.
- Reset and audit the implicated administrative account.
- Hunt for the cleared-log technique across other endpoints.
```

*(Illustrative output; exact wording varies per run and per log.)*

## Standards alignment

| Standard | How this project maps |
|---|---|
| **MITRE ATT&CK** | The Event ID coverage table is annotated with the techniques each event commonly evidences, and the LLM report includes an explicit "ATT&CK Techniques Observed" section inferred from the timeline. |
| **Windows Event Schema** | The parser handles the standard Windows event XML namespace and the Security, System, Sysmon, and PowerShell channels. |
| **DFIR triage workflow** | The five-section report maps to how an IR lead actually consumes a triage handoff: what happened, in what order, mapped to a framework, how bad, and what to do. |

## Data source

Sample logs in `sample_data/` are real, ATT&CK-mapped attack captures drawn from the public **[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)** repository by Samir Bousseaden — a widely-used dataset for testing EVTX parsing and DFIR / threat-hunting tooling. Using real attack data (rather than synthetic logs) means the timeline and the generated reports reflect genuine adversary behavior.

## Inspired by

This is **original work** — the parser, the Event ID lookup, the summarizer prompt design, and the UI are written from scratch — but it builds on:

- **[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)** — for realistic, technique-tagged Windows event data.
- **[python-evtx](https://github.com/williballenthin/python-evtx)** (Willi Ballenthin) — for the EVTX parsing primitives.
- **MITRE ATT&CK** — for the technique vocabulary the reports map onto.

## Metrics

- **~20 security-relevant Event IDs** resolved to plain-English meaning across Security, System, Sysmon, and PowerShell channels.
- **End-to-end triage in one upload** — raw `.evtx` to a five-section, ATT&CK-mapped incident report.
- **Resilient parsing** — token-bounded LLM input and per-record error handling, so large or partially-corrupt logs still produce a timeline.
- **Validated on real attack samples** — tested against lateral-movement, execution, and credential-access captures from EVTX-ATTACK-SAMPLES.

## Safety notes

- `sample_data/` contains public attack-sample logs only — no real organizational data or PII.
- `.env` is git-ignored, so your Groq API key never enters version control.
- Analyze only logs you are authorized to handle. The tool describes adversary techniques to defend against them; use responsibly.

## License

This project is released under the [MIT License](LICENSE).

## Author

**Yug Mukesh Patel**

- LinkedIn — <https://www.linkedin.com/in/yug-patel-b9727226b/>
- GitHub — <https://github.com/yug3009p>
