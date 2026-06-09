import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))
from parser import parse_evtx
from summarizer import summarize_timeline

HIGH_SIGNAL_IDS = {1102, 4625, 4672, 4688, 7045, 4720}

st.set_page_config(
    page_title="DFIR Triage Automator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
    .stApp {
        background-color: #0b0f14;
        color: #d6e1e8;
    }
    h1, h2, h3, h4 {
        color: #e6f1ff;
        font-family: 'JetBrains Mono', 'Consolas', monospace;
        letter-spacing: 0.02em;
    }
    .stMarkdown, .stText, p, span, label {
        font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
    }
    code, pre, .stCode, .stDataFrame, [data-testid="stMetricValue"], [data-testid="stMetricLabel"] {
        font-family: 'JetBrains Mono', 'Consolas', monospace !important;
    }
    [data-testid="stMetric"] {
        background: #11171f;
        border: 1px solid #1f2a36;
        border-left: 3px solid #00ff9c;
        border-radius: 6px;
        padding: 14px 18px;
    }
    [data-testid="stMetricValue"] {
        color: #00ff9c !important;
        font-size: 1.6rem !important;
    }
    [data-testid="stMetricLabel"] {
        color: #7d92a3 !important;
        text-transform: uppercase;
        font-size: 0.72rem !important;
        letter-spacing: 0.12em;
    }
    .stButton > button, .stDownloadButton > button {
        background-color: #11171f;
        color: #00ff9c;
        border: 1px solid #00ff9c;
        border-radius: 4px;
        font-family: 'JetBrains Mono', 'Consolas', monospace;
        font-weight: 600;
        letter-spacing: 0.05em;
    }
    .stButton > button:hover, .stDownloadButton > button:hover {
        background-color: #00ff9c;
        color: #0b0f14;
    }
    [data-testid="stFileUploader"] {
        background: #11171f;
        border: 1px dashed #1f2a36;
        border-radius: 6px;
        padding: 8px;
    }
    .tag {
        display: inline-block;
        padding: 2px 8px;
        border: 1px solid #1f2a36;
        border-radius: 3px;
        color: #7d92a3;
        font-family: 'JetBrains Mono', 'Consolas', monospace;
        font-size: 0.75rem;
        margin-right: 6px;
    }
    .tag-accent { color: #00ff9c; border-color: #00ff9c; }
    hr { border-color: #1f2a36; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown("# 🛡️ DFIR Triage Automator")
st.markdown(
    "<span class='tag tag-accent'>EVTX</span>"
    "<span class='tag'>TIMELINE</span>"
    "<span class='tag'>GROQ · LLAMA 3.3 70B</span>"
    "<br><br>"
    "<span style='color:#7d92a3'>Upload a Windows .evtx event log. The parser builds a chronological triage timeline; "
    "the LLM writes the incident report.</span>",
    unsafe_allow_html=True,
)
st.markdown("---")


@st.cache_data(show_spinner=False)
def _parse_cached(file_bytes: bytes, filename: str) -> pd.DataFrame:
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".evtx") as tmp:
            tmp.write(file_bytes)
            tmp_path = tmp.name
        return parse_evtx(tmp_path)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _format_timespan(df: pd.DataFrame) -> str:
    if df.empty or df["timestamp"].dropna().empty:
        return "—"
    ts = df["timestamp"].dropna()
    first, last = ts.min(), ts.max()
    delta = last - first
    total_sec = int(delta.total_seconds())
    if total_sec < 60:
        span = f"{total_sec}s"
    elif total_sec < 3600:
        span = f"{total_sec // 60}m {total_sec % 60}s"
    elif total_sec < 86400:
        span = f"{total_sec // 3600}h {(total_sec % 3600) // 60}m"
    else:
        span = f"{total_sec // 86400}d {(total_sec % 86400) // 3600}h"
    return f"{span}\n{first:%Y-%m-%d %H:%M:%S} → {last:%Y-%m-%d %H:%M:%S}"


uploaded = st.file_uploader(
    "Drop a Windows event log (.evtx)",
    type=["evtx"],
    help="Try one of the samples in sample_data/ — they're real attack traces from EVTX-ATTACK-SAMPLES.",
)

if uploaded is None:
    st.info(
        "⬆️  Upload a `.evtx` file to begin. "
        "No data leaves your machine until you click **Generate AI Incident Summary**."
    )
    st.stop()

file_bytes = uploaded.getvalue()

try:
    with st.spinner(f"Parsing {uploaded.name}…"):
        df = _parse_cached(file_bytes, uploaded.name)
except Exception as e:
    st.error(f"Failed to parse {uploaded.name}: {type(e).__name__}: {e}")
    st.stop()

if df.empty:
    st.warning("Parser returned 0 records. The file may be empty or unreadable.")
    st.stop()

st.session_state.setdefault("summaries", {})
file_key = f"{uploaded.name}:{len(file_bytes)}"

total_events = len(df)
high_signal_count = int(df["event_id"].isin(HIGH_SIGNAL_IDS).sum())
timespan_str = _format_timespan(df)

c1, c2, c3 = st.columns(3)
c1.metric("Total Events", f"{total_events:,}")
c2.metric("Time Span", timespan_str.split("\n")[0], help=timespan_str.split("\n")[-1])
c3.metric("High-Signal Events", f"{high_signal_count:,}", help=f"IDs: {sorted(HIGH_SIGNAL_IDS)}")

st.markdown("### 📋 Triage Timeline")
display_df = df.copy()
if "timestamp" in display_df.columns:
    display_df["timestamp"] = pd.to_datetime(display_df["timestamp"], errors="coerce")
st.dataframe(
    display_df,
    use_container_width=True,
    hide_index=True,
    height=420,
)

st.markdown("---")
st.markdown("### 🤖 AI Incident Report")

col_btn, col_status = st.columns([1, 3])
generate = col_btn.button("🔍 Generate AI Incident Summary", use_container_width=True)

if generate:
    try:
        with st.spinner("Querying Groq (Llama 3.3 70B)…"):
            summary = summarize_timeline(df)
        st.session_state["summaries"][file_key] = summary
    except Exception as e:
        st.error(f"Summarizer crashed: {type(e).__name__}: {e}")

summary = st.session_state["summaries"].get(file_key)

if summary:
    if summary.startswith(("ERROR:", "STOP:")):
        st.error(summary)
    else:
        st.markdown(summary)
        report_name = (
            f"dfir_report_{Path(uploaded.name).stem}_"
            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        )
        report_body = (
            f"# DFIR Incident Report\n\n"
            f"- **Source log:** `{uploaded.name}`\n"
            f"- **Events parsed:** {total_events}\n"
            f"- **Time span:** {timespan_str.replace(chr(10), ' · ')}\n"
            f"- **Generated:** {datetime.now().isoformat(timespec='seconds')}\n\n"
            f"---\n\n{summary}\n"
        )
        st.download_button(
            "💾 Download Report (.md)",
            data=report_body.encode("utf-8"),
            file_name=report_name,
            mime="text/markdown",
        )
else:
    col_status.markdown(
        "<span style='color:#7d92a3'>Click the button to send the timeline to Groq. "
        "This is the only step that makes an external network call.</span>",
        unsafe_allow_html=True,
    )
