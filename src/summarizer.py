import os
import sys
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv
from groq import Groq

MODEL = "llama-3.3-70b-versatile"
MAX_ROWS = 200

SYSTEM_PROMPT = """You are a senior SOC analyst and DFIR investigator with deep experience triaging Windows incidents from event-log evidence. You write tight, evidence-driven reports for an on-call IR lead who needs to act in the next 15 minutes.

You will be given a chronological timeline of parsed Windows event-log records (timestamp, event ID, plain-English description, raw EventData details). Treat it as the authoritative evidence. Do not invent events that aren't in the data. If something is ambiguous, say so.

Return your response as GitHub-flavored markdown with EXACTLY these five sections and headings, in order:

## 1. Executive Summary
Two to three plain-English sentences. What appears to have happened and why it matters. No jargon.

## 2. Attack Timeline Narrative
A short prose narrative (not a bulleted re-listing of the table) of what happened in order. Reference event IDs and timestamps inline.

## 3. MITRE ATT&CK Techniques Observed
A bulleted list. Each bullet: `TXXXX[.YYY] — Technique Name — one-line justification tied to specific event IDs you saw.` Only include techniques the evidence actually supports.

## 4. Severity Assessment
One of: **Critical**, **High**, **Medium**, **Low**. Followed by a single sentence of justification.

## 5. Recommended Response Actions
A bulleted action list ordered by urgency. Each bullet is a concrete, operator-actionable step (isolate host X, reset account Y, hunt for Z), not generic advice.
"""


def _format_timeline(df: pd.DataFrame) -> str:
    total = len(df)
    rows = df.head(MAX_ROWS)
    lines = []
    for _, r in rows.iterrows():
        ts = r.get("timestamp")
        ts_str = ts.isoformat(sep=" ", timespec="seconds") if pd.notna(ts) else "unknown"
        eid = r.get("event_id")
        eid_str = str(int(eid)) if pd.notna(eid) else "?"
        desc = r.get("description") or "Other"
        details = (r.get("details") or "").replace("\n", " ").strip()
        if len(details) > 400:
            details = details[:400] + "…"
        lines.append(f"{ts_str} | EID {eid_str} | {desc} | {details}")
    if total > MAX_ROWS:
        lines.append(f"... (truncated, {total} total events)")
    return "\n".join(lines)


def _is_decommissioned_error(err: Exception) -> bool:
    msg = str(err).lower()
    return "decommission" in msg or "model_decommissioned" in msg


def summarize_timeline(df: pd.DataFrame) -> str:
    load_dotenv()
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return "ERROR: GROQ_API_KEY not set. Add it to .env (see .env.example)."

    if df is None or df.empty:
        return "ERROR: Timeline DataFrame is empty — nothing to summarize."

    timeline_text = _format_timeline(df)
    user_prompt = (
        f"Here is the parsed event-log timeline ({len(df)} total events). "
        f"Produce the five-section DFIR report.\n\n"
        f"```\n{timeline_text}\n```"
    )

    try:
        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
        )
        return response.choices[0].message.content
    except Exception as e:
        if _is_decommissioned_error(e):
            return (
                f"STOP: Groq model '{MODEL}' has been decommissioned. "
                f"Pick a current model from https://console.groq.com/docs/models "
                f"and update the MODEL constant in src/summarizer.py.\n\n"
                f"Raw error: {e}"
            )
        return f"ERROR: Groq API call failed: {type(e).__name__}: {e}"


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from parser import parse_evtx

    sample = (
        Path(__file__).resolve().parent.parent
        / "sample_data"
        / "LateralMovement_LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx"
    )
    print(f"Parsing: {sample}")
    df = parse_evtx(str(sample))
    print(f"Parsed {len(df)} records. Calling Groq...\n")
    print(summarize_timeline(df))
