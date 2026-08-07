import streamlit as st
from langchain_ollama import OllamaEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from langchain_core.prompts import PromptTemplate
from models import check_if_model_is_available
from document_loader import load_documents
import argparse
import os
import time
import re
from datetime import datetime
import ollama
from typing import Dict, Generator
from collections import Counter


TEXT_SPLITTER = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
DEFAULT_MODEL = "llama3:latest"
DEFAULT_EMBEDDING_MODEL = "nomic-embed-text"
DEFAULT_PATH = "reports"
PERSIST_DIR = "db"

EMBEDDING_KEYWORDS = ("embed", "minilm", "bge-", "e5-")

KILL_CHAIN_KEYWORDS = [
    "kill chain", "kill-chain", "attack chain", "attack steps",
    "how does", "how do", "describe the", "explain the steps",
    "phases of", "stages of", "procedure", "workflow"
]

# ── Prompt (MITRE fix: one technique per line) ────────────────────────────────
PROMPT_TEMPLATE = """## ROLE
You are ThreatLens, a Cyber Threat Intelligence (CTI) analyst. You answer ONLY from the retrieved evidence below. You do not use background knowledge.

## STRICT RULES
1. Use ONLY information explicitly present in the EVIDENCE section.
2. If the evidence is insufficient, respond exactly with:
   "⚠ INSUFFICIENT EVIDENCE: The loaded documents do not contain information about [topic]. Add relevant reports to the knowledge base."
3. Never invent TTPs, malware names, CVEs, IOCs, or attribution that are not in the evidence.
4. Cite each claim inline as [SOURCE: <filename>].
5. MITRE ATT&CK: write EACH technique on its OWN separate line. Never put two techniques on the same line.

## EVIDENCE
{context}

## QUERY
{question}

## RESPONSE
Structure your answer exactly as follows (skip sections with no evidence):

**ANALYSIS**
[Evidence-grounded answer with inline [SOURCE: filename] citations. Write numbered steps if describing a process.]

**MITRE ATT&CK TECHNIQUES** *(only if techniques are in the evidence)*
IMPORTANT — one technique per line, exactly this format:
• T[ID] – Technique Name (Tactic) — brief description [SOURCE: filename]
• T[ID] – Technique Name (Tactic) — brief description [SOURCE: filename]

**INDICATORS OF COMPROMISE** *(if applicable)*
[IOCs explicitly mentioned in evidence — IPs, domains, hashes, file names]

**DETECTION & INVESTIGATION**
[All detection tips, event IDs, log sources, hunting queries from the evidence. Do NOT write "Not covered" if detection content exists in the evidence.]

**SOURCES**
[List every source document used, one per line]
"""

PROMPT = PromptTemplate(
    template=PROMPT_TEMPLATE, input_variables=["context", "question"]
)


# ── Helper functions ──────────────────────────────────────────────────────────

def format_context_with_sources(docs) -> str:
    parts = []
    for i, doc in enumerate(docs):
        src = os.path.basename(doc.metadata.get("source", "unknown"))
        parts.append(f"[DOC {i+1} | SOURCE: {src}]\n{doc.page_content.strip()}")
    return "\n\n---\n\n".join(parts)


# ── IOC regex patterns ────────────────────────────────────────────────────────
_RE_IP     = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_RE_DOMAIN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|co|gov|mil|de|onion|xyz)\b', re.I)
_RE_MD5    = re.compile(r'\b[a-fA-F0-9]{32}\b')
_RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
_RE_URL    = re.compile(r'https?://[^\s<>"\']{8,}')
_RE_MITRE  = re.compile(r'(T\d{4}(?:\.\d{3})?)\s*[–\-]\s*([^(\[\n]{3,45}?)\s*\(([^)\n]{3,30})\)', re.MULTILINE)


# ── Known threat database for instant summary cards ──────────────────────────
THREAT_DB = {
    "lockbit":          ("LockBit 3.0",              "Ransomware-as-a-Service",  "🔴 Critical", "Windows Enterprise"),
    "apt29":            ("APT29 / Cozy Bear",         "Nation-State APT",         "🔴 Critical", "Windows / Cloud"),
    "cozy bear":        ("APT29 / Cozy Bear",         "Nation-State APT",         "🔴 Critical", "Windows / Cloud"),
    "nobelium":         ("NOBELIUM (APT29)",          "Nation-State APT",         "🔴 Critical", "Windows / Cloud"),
    "sunburst":         ("SUNBURST Backdoor",         "Supply-Chain Malware",     "🔴 Critical", "Windows / Network"),
    "lazarus":          ("Lazarus Group",             "Nation-State APT (DPRK)",  "🔴 Critical", "Multi-platform"),
    "wannacry":         ("WannaCry",                  "Ransomware Worm",          "🔴 Critical", "Windows"),
    "phishing":         ("Phishing Campaign",         "Social Engineering",       "🟠 High",     "Email / Web"),
    "aitm":             ("AiTM Phishing",             "Adversary-in-the-Middle",  "🟠 High",     "Web / Email"),
    "evilproxy":        ("EvilProxy",                 "AiTM Framework (MaaS)",    "🟠 High",     "Web"),
    "evilginx":         ("Evilginx2",                "AiTM Framework",           "🟠 High",     "Web"),
    "pass-the-hash":    ("Pass-the-Hash Attack",      "Credential Abuse",         "🟠 High",     "Windows AD"),
    "pass the hash":    ("Pass-the-Hash Attack",      "Credential Abuse",         "🟠 High",     "Windows AD"),
    "kerberoasting":    ("Kerberoasting",             "Credential Theft",         "🟠 High",     "Windows AD"),
    "golden ticket":    ("Golden Ticket Attack",      "Kerberos Forgery",         "🔴 Critical", "Windows AD"),
    "silver ticket":    ("Silver Ticket Attack",      "Kerberos Forgery",         "🟠 High",     "Windows AD"),
    "lateral movement": ("Lateral Movement",          "Post-Exploitation",        "🟠 High",     "Windows"),
    "ransomware":       ("Ransomware Attack",         "Malware",                  "🔴 Critical", "Windows"),
    "bec":              ("Business Email Compromise", "Financial Fraud",          "🟠 High",     "Email / Cloud"),
    "smishing":         ("Smishing Campaign",         "SMS Phishing",             "🟡 Medium",   "Mobile"),
    "quishing":         ("QR Code Phishing",          "Social Engineering",       "🟡 Medium",   "Email / Physical"),
    "mimikatz":         ("Mimikatz Credential Dump",  "Credential Access Tool",   "🟠 High",     "Windows"),
    "cobalt strike":    ("Cobalt Strike",             "C2 Framework",             "🔴 Critical", "Windows / Linux"),
    "psexec":           ("PsExec Lateral Movement",   "Remote Execution",         "🟠 High",     "Windows"),
}

_SEV_COLORS = {"🔴": "#ef5350", "🟠": "#ff8f00", "🟡": "#ffca28"}


def extract_threat_info(query: str, docs) -> dict:
    """Return threat summary dict from query keywords or doc content."""
    q = query.lower()
    for keyword, (name, t_type, severity, target) in THREAT_DB.items():
        if keyword in q:
            return {"name": name, "type": t_type, "severity": severity, "target": target}
    # Infer from retrieved content
    combined = " ".join(d.page_content.lower() for d in docs[:3])
    if "ransomware" in combined and ("encrypt" in combined or "ransom" in combined):
        return {"name": "Ransomware Attack", "type": "Malware", "severity": "🔴 Critical", "target": "Windows"}
    if "apt" in combined or "nation-state" in combined or "espionage" in combined:
        return {"name": "Advanced Persistent Threat", "type": "Nation-State APT", "severity": "🔴 Critical", "target": "Multi-platform"}
    if "phishing" in combined or "social engineering" in combined:
        return {"name": "Phishing Campaign", "type": "Social Engineering", "severity": "🟠 High", "target": "Email / Web"}
    return {}


def extract_iocs(docs) -> dict:
    """Regex-based IOC extraction from retrieved document chunks."""
    text = "\n".join(doc.page_content for doc in docs)
    return {
        "IP Addresses":   sorted(set(_RE_IP.findall(text))),
        "Domains":        sorted(set(_RE_DOMAIN.findall(text))),
        "URLs":           sorted(set(_RE_URL.findall(text)))[:10],
        "MD5 Hashes":     sorted(set(_RE_MD5.findall(text))),
        "SHA-256 Hashes": sorted(set(_RE_SHA256.findall(text))),
    }


def parse_mitre_from_response(response_text: str) -> list:
    """Extract (T-code, technique name, tactic) tuples from LLM response."""
    seen, results = set(), []
    for m in _RE_MITRE.finditer(response_text):
        tid    = m.group(1)
        name   = m.group(2).strip().rstrip("–-—").strip()
        tactic = m.group(3).strip()
        if tid not in seen and len(name) > 2:
            seen.add(tid)
            results.append((tid, name, tactic))
    return results


def get_db_stats(db, path: str):
    """Count source files and indexed chunks in ChromaDB."""
    try:
        n_files = len([
            f for f in os.listdir(path)
            if os.path.isfile(os.path.join(path, f))
        ])
    except Exception:
        n_files = 0
    try:
        col = db.get()
        n_chunks = len(col.get("ids", []))
        sources = set()
        for meta in col.get("metadatas", []):
            if meta and "source" in meta:
                sources.add(os.path.basename(meta["source"]))
        n_sources = len(sources)
    except Exception:
        n_chunks = 0
        n_sources = 0
    return n_files, n_chunks, n_sources


def extract_kill_chain_steps(response_text: str, query: str) -> list:
    """
    If the query is about a kill chain / attack process and the response has 3+ numbered
    steps, return those steps as a list. Otherwise return [].
    """
    query_lower = query.lower()
    if not any(kw in query_lower for kw in KILL_CHAIN_KEYWORDS):
        return []
    steps = re.findall(r'^\s*\d+\.\s+(.+)', response_text, re.MULTILINE)
    # Strip [SOURCE: ...] citations inline
    steps = [re.sub(r'\[SOURCE:[^\]]*\]', '', s).strip() for s in steps]
    steps = [s for s in steps if len(s) > 10]
    return steps[:7]


def generate_html_export(messages: list, query_history: list) -> bytes:
    """Generate a styled, printable HTML CTI report from the conversation."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    query_rows = ""
    for h in query_history:
        conf_color = "#00e676" if "🟢" in h["confidence"] else "#ffca28" if "🟡" in h["confidence"] else "#ef5350"
        srcs = ", ".join(h.get("sources", []))
        s_time = f'{h.get("search_time", 0):.2f}s'
        g_time = f'{h.get("gen_time", 0):.1f}s'
        q_short = h["query"][:70] + ("…" if len(h["query"]) > 70 else "")
        query_rows += f"""
        <tr>
            <td style="color:#546e7a;">{h["time"]}</td>
            <td>{q_short}</td>
            <td style="color:{conf_color};">{h["confidence"]}</td>
            <td style="color:#546e7a;">{srcs}</td>
            <td style="color:#546e7a;">{s_time} / {g_time}</td>
        </tr>"""

    msg_html = ""
    for msg in messages:
        role = msg["role"]
        raw = msg["content"]
        if role == "user":
            msg_html += f"""
            <div style="margin:20px 0;background:#0d1b12;border-left:3px solid #00e676;
                border-radius:4px;padding:14px 18px;">
                <div style="font-size:0.6rem;letter-spacing:2px;color:#00e676;margin-bottom:8px;">
                    ▶ QUERY INPUT</div>
                <div style="color:#69f0ae;font-family:monospace;font-size:0.9rem;">{raw}</div>
            </div>"""
        else:
            # Convert basic markdown: **bold**, then newlines
            html_content = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', raw)
            html_content = html_content.replace('\n', '<br>')
            msg_html += f"""
            <div style="margin:20px 0;background:#070d1a;border-left:3px solid #00b8d4;
                border-radius:4px;padding:14px 18px;">
                <div style="font-size:0.6rem;letter-spacing:2px;color:#00b8d4;margin-bottom:8px;">
                    ⬡ THREAT ANALYSIS</div>
                <div style="color:#b0bec5;font-size:0.88rem;line-height:1.75;">{html_content}</div>
            </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatLens CTI Report — {now}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: #07090f; color: #c8d6e5;
    font-family: 'Segoe UI', sans-serif;
    max-width: 960px; margin: 40px auto; padding: 24px;
  }}
  h1 {{ color: #00e5ff; font-size: 1.9rem; padding-bottom: 10px;
        border-bottom: 1px solid #1a2a3a; margin-bottom: 8px; }}
  h2 {{ color: #00b8d4; font-size: 1.1rem; margin: 28px 0 12px; letter-spacing: 1px; }}
  .meta {{ color: #546e7a; font-size: 0.82rem; margin-bottom: 28px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.82rem; }}
  th {{ background: #0b0f1a; color: #00b8d4; padding: 8px 10px; text-align: left;
        letter-spacing: 1px; border-bottom: 1px solid #1a2a3a; }}
  td {{ padding: 7px 10px; border-bottom: 1px solid #111a25; color: #90a4ae; }}
  strong {{ color: #00e5ff; }}
  .print-note {{ color: #546e7a; font-size: 0.75rem; margin-top: 24px;
                 border-top: 1px solid #1a2a3a; padding-top: 12px; }}
  @media print {{
    body {{ background: white; color: black; }}
    h1, h2 {{ color: #003366; }}
  }}
</style>
</head>
<body>
<h1>🔍 ThreatLens — CTI Analysis Report</h1>
<div class="meta">
  Generated: {now} &nbsp;|&nbsp;
  Total queries: {len(query_history)} &nbsp;|&nbsp;
  Model: local LLM via Ollama
</div>

<h2>📋 Query Log</h2>
<table>
  <tr>
    <th>Time</th><th>Query</th><th>Confidence</th><th>Sources</th><th>Search / Gen</th>
  </tr>
  {query_rows if query_rows else '<tr><td colspan="5" style="color:#546e7a;">No queries yet.</td></tr>'}
</table>

<h2>💬 Full Analysis</h2>
{msg_html if msg_html else '<p style="color:#546e7a;">No conversation recorded.</p>'}

<div class="print-note">
  💡 To export as PDF: press <strong>Ctrl+P</strong> (or ⌘P on Mac) → <strong>Save as PDF</strong>
</div>
</body>
</html>"""
    return html.encode("utf-8")


def load_documents_into_database(model_name: str, documents_path: str) -> Chroma:
    print("Loading documents")
    raw_documents = load_documents(documents_path)
    if not raw_documents:
        if os.path.exists(PERSIST_DIR):
            db = Chroma(
                persist_directory=PERSIST_DIR,
                embedding_function=OllamaEmbeddings(model=model_name)
            )
            return db
        else:
            raise FileNotFoundError("No documents found in the specified directory")

    documents = TEXT_SPLITTER.split_documents(raw_documents)
    print("Creating embeddings and loading documents into Chroma")
    start = time.time()
    db = Chroma.from_documents(
        documents,
        OllamaEmbeddings(model=model_name),
        persist_directory=PERSIST_DIR,
    )
    print(f"Time to load documents into Chroma: {time.time() - start:.2f} seconds")
    return db


@st.cache_resource(show_spinner="⏳ Loading documents into vector database…")
def load_db_cached(embedding_model_name: str, documents_path: str) -> Chroma:
    return load_documents_into_database(embedding_model_name, documents_path)


def ollama_generator(model_name: str, messages: Dict) -> Generator:
    stream = ollama.chat(model=model_name, messages=messages, stream=True)
    for chunk in stream:
        if hasattr(chunk, "message"):
            yield chunk.message.content
        else:
            yield chunk["message"]["content"]


def get_available_models():
    try:
        result = ollama.list()
        if hasattr(result, "models"):
            names = [getattr(m, "model", None) for m in result.models]
        else:
            names = [m.get("name") for m in result.get("models", [])]
        chat_models = [
            n for n in names
            if n and not any(kw in n.lower() for kw in EMBEDDING_KEYWORDS)
        ]
        return chat_models or [DEFAULT_MODEL]
    except Exception:
        return [DEFAULT_MODEL]


def _find_model_idx(models: list, target: str) -> int:
    for i, m in enumerate(models):
        if m == target or m.split(":")[0] == target.split(":")[0]:
            return i
    return 0


# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ThreatLens — Cyber Threat Intelligence",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

    .stApp {
        background-color: #07090f;
        background-image:
            linear-gradient(to right,
                #07090f 0%, #07090f 42%,
                rgba(7,9,15,0.88) 58%, rgba(7,9,15,0.45) 78%, rgba(7,9,15,0.15) 100%
            ),
            url('https://images.unsplash.com/photo-1562813733-b31f71025d54?w=1920&q=80');
        background-size: cover;
        background-position: right center;
        background-attachment: fixed;
        color: #c8d6e5;
        font-family: 'Rajdhani', sans-serif;
    }

    [data-testid="stSidebar"] {
        background-color: #0b0f1a !important;
        border-right: 1px solid #1a2a3a;
        box-shadow: 4px 0 20px rgba(0,0,0,0.5);
    }
    [data-testid="stSidebar"] * { font-family: 'Rajdhani', sans-serif; }

    h1 {
        font-family: 'Share Tech Mono', monospace !important;
        color: #00e5ff !important;
        text-shadow: 0 0 20px rgba(0,229,255,0.6), 0 0 40px rgba(0,229,255,0.2);
        letter-spacing: 3px;
    }
    h2, h3 { color: #00bcd4 !important; font-family: 'Rajdhani', sans-serif !important; letter-spacing: 1px; }

    [data-testid="stCaptionContainer"] p {
        font-family: 'Share Tech Mono', monospace;
        color: #546e7a !important;
        letter-spacing: 2px;
        font-size: 0.75rem;
    }

    /* User message */
    [data-testid="stChatMessage"]:has([data-testid="chatAvatarIcon-user"]) {
        background: linear-gradient(135deg, #0d1b12 0%, #0a1a10 100%);
        border: 1px solid #1b4332;
        border-left: 3px solid #00e676;
        border-radius: 4px;
        padding: 14px 18px;
        position: relative;
        font-family: 'Share Tech Mono', monospace;
        box-shadow: 0 0 15px rgba(0,230,118,0.08), inset 0 0 30px rgba(0,230,118,0.03);
    }
    [data-testid="stChatMessage"]:has([data-testid="chatAvatarIcon-user"])::before {
        content: "▶  QUERY INPUT";
        position: absolute;
        top: -10px; left: 12px;
        font-size: 0.6rem;
        font-family: 'Share Tech Mono', monospace;
        color: #00e676;
        background: #0d1b12;
        padding: 0 6px;
        letter-spacing: 2px;
    }
    [data-testid="stChatMessage"]:has([data-testid="chatAvatarIcon-user"]) p {
        color: #69f0ae !important;
        font-family: 'Share Tech Mono', monospace !important;
    }

    /* Assistant message */
    [data-testid="stChatMessage"]:has([data-testid="chatAvatarIcon-assistant"]) {
        background: linear-gradient(135deg, #070d1a 0%, #0a1022 100%);
        border: 1px solid #1a2a4a;
        border-left: 3px solid #00b8d4;
        border-radius: 4px;
        padding: 14px 18px;
        position: relative;
        box-shadow: 0 0 20px rgba(0,184,212,0.07), inset 0 0 30px rgba(0,184,212,0.03);
    }
    [data-testid="stChatMessage"]:has([data-testid="chatAvatarIcon-assistant"])::before {
        content: "⬡  THREAT ANALYSIS";
        position: absolute;
        top: -10px; left: 12px;
        font-size: 0.6rem;
        font-family: 'Share Tech Mono', monospace;
        color: #00b8d4;
        background: #070d1a;
        padding: 0 6px;
        letter-spacing: 2px;
    }
    [data-testid="stChatMessage"]:has([data-testid="chatAvatarIcon-assistant"]) p,
    [data-testid="stChatMessage"]:has([data-testid="chatAvatarIcon-assistant"]) li {
        color: #b0bec5 !important;
        line-height: 1.8;
    }

    /* Chat input */
    [data-testid="stChatInput"] {
        background-color: #0b0f1a !important;
        border: 1px solid #1a2a3a !important;
        border-top: 2px solid #00b8d4 !important;
    }
    [data-testid="stChatInput"] textarea {
        background-color: #0b0f1a !important;
        color: #00e676 !important;
        font-family: 'Share Tech Mono', monospace !important;
        caret-color: #00e676;
    }
    [data-testid="stChatInput"] textarea::placeholder { color: #2e4a3a !important; }

    /* Expander */
    [data-testid="stExpander"] {
        background-color: #0b0f1a;
        border: 1px solid #1a2a3a;
        border-left: 3px solid #ff6f00;
        border-radius: 4px;
        box-shadow: 0 0 10px rgba(255,111,0,0.06);
    }
    [data-testid="stExpander"] summary {
        color: #ff8f00 !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-size: 0.82rem;
        letter-spacing: 1px;
    }

    /* Stat cards */
    .stat-card {
        background: linear-gradient(135deg, #0b0f1a, #0d1520);
        border: 1px solid #1a2a3a;
        border-top: 2px solid #00b8d4;
        border-radius: 4px;
        padding: 10px 6px;
        text-align: center;
        margin-bottom: 8px;
        box-shadow: 0 4px 15px rgba(0,184,212,0.07);
    }
    .stat-value {
        font-size: 1.6rem;
        font-weight: 700;
        color: #00e5ff;
        font-family: 'Share Tech Mono', monospace;
        text-shadow: 0 0 10px rgba(0,229,255,0.4);
    }
    .stat-label {
        font-size: 0.62rem;
        color: #546e7a;
        font-family: 'Share Tech Mono', monospace;
        letter-spacing: 2px;
        text-transform: uppercase;
    }
    .stat-card-green { border-top-color: #00e676 !important; }
    .stat-card-green .stat-value { color: #00e676 !important; text-shadow: 0 0 10px rgba(0,230,118,0.4) !important; }
    .stat-card-orange { border-top-color: #ff8f00 !important; }
    .stat-card-orange .stat-value { color: #ff8f00 !important; text-shadow: 0 0 10px rgba(255,143,0,0.4) !important; }

    /* History item */
    .hist-item {
        background: #0b0f1a;
        border: 1px solid #1a2a3a;
        border-left: 2px solid #546e7a;
        border-radius: 3px;
        padding: 6px 10px;
        margin-bottom: 6px;
        font-size: 0.72rem;
        font-family: 'Share Tech Mono', monospace;
        color: #546e7a;
    }
    .hist-query { color: #90a4ae; margin-top: 2px; font-size: 0.75rem; }

    hr { border-color: #1a2a3a !important; }
    [data-testid="stSelectbox"] label { color: #546e7a !important; font-size: 0.75rem; letter-spacing: 1px; }
    [data-testid="stSlider"] label { color: #546e7a !important; font-size: 0.75rem; letter-spacing: 1px; }

    .stButton button {
        background: transparent !important;
        border: 1px solid #c62828 !important;
        color: #ef5350 !important;
        font-family: 'Share Tech Mono', monospace !important;
        letter-spacing: 1px;
        border-radius: 4px !important;
        transition: all 0.2s;
    }
    .stButton button:hover {
        background: rgba(198,40,40,0.15) !important;
        box-shadow: 0 0 12px rgba(239,83,80,0.3) !important;
    }

    /* Download button override */
    [data-testid="stDownloadButton"] button {
        background: transparent !important;
        border: 1px solid #00b8d4 !important;
        color: #00e5ff !important;
        font-family: 'Share Tech Mono', monospace !important;
        letter-spacing: 1px;
        border-radius: 4px !important;
    }
    [data-testid="stDownloadButton"] button:hover {
        background: rgba(0,184,212,0.12) !important;
        box-shadow: 0 0 12px rgba(0,229,255,0.25) !important;
    }

    ::-webkit-scrollbar { width: 4px; height: 4px; }
    ::-webkit-scrollbar-track { background: #07090f; }
    ::-webkit-scrollbar-thumb { background: #1a2a3a; border-radius: 2px; }
    ::-webkit-scrollbar-thumb:hover { background: #00b8d4; }

    code {
        background: #0d1520 !important;
        color: #ff8f00 !important;
        font-family: 'Share Tech Mono', monospace !important;
        border: 1px solid #2a1a00 !important;
        padding: 1px 5px !important;
        border-radius: 3px !important;
    }
</style>
""", unsafe_allow_html=True)


# ── Main ──────────────────────────────────────────────────────────────────────

def main(llm_model_name: str, embedding_model_name: str, documents_path: str, nb_docs: int) -> None:

    try:
        db = load_db_cached(embedding_model_name, documents_path)
    except FileNotFoundError as e:
        st.error(f"❌ {e}\n\nPlace documents in the `{documents_path}` folder and restart.")
        st.stop()
    except Exception as e:
        st.error(f"❌ Failed to load database: {e}")
        st.stop()

    # ── Session state ─────────────────────────────────────────────────────────
    defaults = {
        "selected_model": llm_model_name,
        "messages": [],
        "rag_messages": [],
        "nb_docs": nb_docs,
        "total_queries": 0,
        "query_history": [],
        "show_context": False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

    # ── Sidebar ───────────────────────────────────────────────────────────────
    with st.sidebar:
        if os.path.exists("images/logo.webp"):
            st.image("images/logo.webp", use_container_width=True)
        st.markdown("---")

        # ── Settings ──────────────────────────────────────────────────────────
        st.markdown("### ⚙️ Settings")
        available_models = get_available_models()
        default_idx = _find_model_idx(available_models, st.session_state.selected_model)
        st.session_state.selected_model = st.selectbox(
            "🤖 LLM Model", available_models, index=default_idx
        )
        st.session_state.nb_docs = st.slider(
            "📄 Documents retrieved", min_value=1, max_value=20,
            value=st.session_state.nb_docs, step=1
        )
        st.markdown("---")

        # ── Knowledge Base Stats ───────────────────────────────────────────────
        st.markdown("### 🗄️ Knowledge Base")
        n_files, n_chunks, n_sources_db = get_db_stats(db, documents_path)
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown(
                f'<div class="stat-card stat-card-green">'
                f'<div class="stat-value">{n_files}</div>'
                f'<div class="stat-label">Files</div></div>',
                unsafe_allow_html=True
            )
        with c2:
            st.markdown(
                f'<div class="stat-card stat-card-orange">'
                f'<div class="stat-value">{n_chunks}</div>'
                f'<div class="stat-label">Chunks</div></div>',
                unsafe_allow_html=True
            )
        with c3:
            st.markdown(
                f'<div class="stat-card">'
                f'<div class="stat-value">{n_sources_db}</div>'
                f'<div class="stat-label">Sources</div></div>',
                unsafe_allow_html=True
            )
        st.markdown("---")

        # ── Session Stats ─────────────────────────────────────────────────────
        st.markdown("### 📊 Session Stats")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(
                f'<div class="stat-card"><div class="stat-value">'
                f'{st.session_state.total_queries}</div>'
                f'<div class="stat-label">Queries</div></div>',
                unsafe_allow_html=True
            )
        with col2:
            st.markdown(
                f'<div class="stat-card"><div class="stat-value">'
                f'{len(st.session_state.messages) // 2}</div>'
                f'<div class="stat-label">Exchanges</div></div>',
                unsafe_allow_html=True
            )
        st.markdown("---")

        # ── Query History ─────────────────────────────────────────────────────
        if st.session_state.query_history:
            st.markdown("### 🕐 Query History")
            with st.expander(f"{len(st.session_state.query_history)} queries this session", expanded=False):
                for h in reversed(st.session_state.query_history):
                    q_short = h["query"][:45] + ("…" if len(h["query"]) > 45 else "")
                    st.markdown(
                        f'<div class="hist-item">'
                        f'{h["time"]} &nbsp;{h["confidence"]}'
                        f'<div class="hist-query">{q_short}</div>'
                        f'</div>',
                        unsafe_allow_html=True
                    )
            st.markdown("---")

        # ── Debug ─────────────────────────────────────────────────────────────
        st.markdown("### 🔬 Debug")
        st.session_state.show_context = st.toggle("Show retrieved context", value=st.session_state.show_context)
        st.markdown("---")

        # ── Supported formats ─────────────────────────────────────────────────
        st.markdown("### ℹ️ Supported formats")
        st.markdown("📄 PDF &nbsp;|&nbsp; 📝 TXT &nbsp;|&nbsp; 📃 DOCX &nbsp;|&nbsp; 🌐 HTML")
        st.markdown("---")

        # ── Export ────────────────────────────────────────────────────────────
        if st.session_state.messages:
            export_bytes = generate_html_export(
                st.session_state.messages,
                st.session_state.query_history
            )
            fname = f"threatlens_report_{datetime.now().strftime('%Y%m%d_%H%M')}.html"
            st.download_button(
                "⬇️ Export Report (HTML/PDF)",
                data=export_bytes,
                file_name=fname,
                mime="text/html",
                use_container_width=True
            )
            st.markdown("---")

        # ── Clear ─────────────────────────────────────────────────────────────
        if st.button("🗑️ Clear conversation", use_container_width=True):
            st.session_state.messages = []
            st.session_state.rag_messages = []
            st.session_state.total_queries = 0
            st.session_state.query_history = []
            st.rerun()

    # ── Main area ─────────────────────────────────────────────────────────────
    st.title("ThreatLens")
    st.caption("Cyber Threat Intelligence · local LLMs + RAG")
    st.markdown("---")

    # Replay chat history
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # ── Chat input ────────────────────────────────────────────────────────────
    if prompt := st.chat_input("Ask a cyber threat intelligence question…"):
        st.session_state.total_queries += 1

        # Timed vector search with similarity scores
        t_search = time.time()
        docs_with_scores = db.similarity_search_with_score(prompt, k=st.session_state.nb_docs)
        search_time = time.time() - t_search
        docs   = [d for d, _ in docs_with_scores]
        scores = [s for _, s in docs_with_scores]
        avg_score = sum(scores) / len(scores) if scores else 1.0
        confidence_pct = max(10, min(99, int(1 / (1 + avg_score) * 100)))

        # Debug context expander
        if st.session_state.show_context:
            with st.expander("◈  RETRIEVED CONTEXT", expanded=False):
                unique_sources_dbg = set()
                for i, (doc, score) in enumerate(docs_with_scores):
                    src = os.path.basename(doc.metadata.get("source", "Unknown"))
                    unique_sources_dbg.add(src)
                    sim_pct = max(0, min(100, int(1 / (1 + score) * 100)))
                    sim_col = "#00e676" if sim_pct >= 70 else "#ffca28" if sim_pct >= 50 else "#ef5350"
                    st.markdown(
                        f"**[{i+1}]** `{src}` &nbsp; "
                        f"<span style='color:{sim_col};font-size:0.8rem;'>"
                        f"Similarity: {sim_pct}%</span>",
                        unsafe_allow_html=True
                    )
                    st.markdown(doc.page_content[:400] + ("…" if len(doc.page_content) > 400 else ""))
                    st.markdown("---")
                st.caption(
                    f"Evidence from **{len(unique_sources_dbg)}** source(s): "
                    f"{', '.join(unique_sources_dbg)} · "
                    f"⚡ Search: {search_time:.2f}s · Avg confidence: {confidence_pct}%"
                )

        # Build grounded context
        grounded_context = format_context_with_sources(docs)
        formatted_prompt = PROMPT_TEMPLATE.format(context=grounded_context, question=prompt)

        st.session_state.rag_messages.append({"role": "user", "content": formatted_prompt})
        st.session_state.messages.append({"role": "user", "content": prompt})

        with st.chat_message("user"):
            st.markdown(prompt)

        # Unique sources for evidence bar
        unique_sources = sorted(set(
            os.path.basename(doc.metadata.get("source", "Unknown")) for doc in docs
        ))
        n_sources = len(unique_sources)

        with st.chat_message("assistant"):
            # ── Threat Summary Card (instant, before LLM generates) ───────────
            threat_info = extract_threat_info(prompt, docs)
            if threat_info:
                _sev_icon  = threat_info["severity"].split()[0]
                _sev_color = _SEV_COLORS.get(_sev_icon, "#546e7a")
                _rows_html = "".join(
                    f"<tr><td style='padding:4px 10px;color:#546e7a;"
                    f"font-family:Share Tech Mono,monospace;font-size:0.6rem;"
                    f"letter-spacing:1px;white-space:nowrap;'>{lbl}</td>"
                    f"<td style='padding:4px 10px;color:{col};font-size:0.8rem;'>{val}</td></tr>"
                    for lbl, val, col in [
                        ("THREAT NAME",  threat_info["name"],     "#e0e0e0"),
                        ("THREAT TYPE",  threat_info["type"],     "#b0bec5"),
                        ("SEVERITY",     threat_info["severity"], _sev_color),
                        ("TARGET",       threat_info["target"],   "#b0bec5"),
                        ("CONFIDENCE",   f"{confidence_pct}%  "
                                         f"<span style='color:#37474f;font-size:0.72rem;'>"
                                         f"({len(docs)} chunks · {n_sources} "
                                         f"source{'s' if n_sources>1 else ''})</span>",
                                         "#00e5ff"),
                    ]
                )
                st.markdown(
                    f"<div style='margin-bottom:14px;padding:10px 0;background:#070d1a;"
                    f"border:1px solid {_sev_color}33;border-left:3px solid {_sev_color};"
                    f"border-radius:4px;overflow:hidden;'>"
                    f"<div style='font-family:Share Tech Mono,monospace;color:{_sev_color};"
                    f"font-size:0.62rem;letter-spacing:2px;margin:8px 12px 10px;'>◈ THREAT SUMMARY</div>"
                    f"<table style='width:100%;border-collapse:collapse;'>{_rows_html}</table>"
                    f"</div>",
                    unsafe_allow_html=True
                )

            # Timed generation
            t_gen = time.time()
            response = st.write_stream(
                ollama_generator(st.session_state.selected_model, st.session_state.rag_messages)
            )
            gen_time = time.time() - t_gen

            # Evidence + timing bar
            conf_color = "#00e676" if confidence_pct >= 70 else "#ffca28" if confidence_pct >= 50 else "#ef5350"
            conf_icon  = "🟢" if confidence_pct >= 70 else "🟡" if confidence_pct >= 50 else "🔴"
            src_chunks = Counter(os.path.basename(d.metadata.get("source","?")) for d in docs)
            sources_md = " &nbsp;|&nbsp; ".join(
                f"`{s}` <span style='color:#37474f;font-size:0.68rem;'>×{n}</span>"
                for s, n in src_chunks.most_common()
            )
            st.markdown(
                f"<div style='margin-top:12px;padding:8px 14px;background:#0b0f1a;"
                f"border-left:3px solid #ff8f00;border-radius:4px;font-size:0.75rem;"
                f"font-family:Share Tech Mono,monospace;color:#78909c;'>"
                f"📂 <b style='color:#ff8f00'>EVIDENCE</b> &nbsp;·&nbsp; "
                f"Confidence: <b style='color:{conf_color}'>{conf_icon} {confidence_pct}%</b>"
                f" &nbsp;·&nbsp; Sources: {sources_md}"
                f"&nbsp;&nbsp;|&nbsp;&nbsp;"
                f"⚡ Search: <b style='color:#546e7a'>{search_time:.2f}s</b> &nbsp; "
                f"Gen: <b style='color:#546e7a'>{gen_time:.1f}s</b>"
                f"</div>",
                unsafe_allow_html=True
            )

            # Kill chain timeline (auto-detect, native Streamlit columns)
            kc_steps = extract_kill_chain_steps(response, prompt)
            if kc_steps:
                _PHASE_COLORS = ["#00e5ff","#00b8d4","#26a69a","#66bb6a","#ff8f00","#ef5350","#ab47bc"]
                st.markdown(
                    "<p style='margin-top:14px;margin-bottom:6px;"
                    "font-family:Share Tech Mono,monospace;color:#00e5ff;"
                    "font-size:0.7rem;letter-spacing:2px;'>⬡ KILL CHAIN TIMELINE</p>",
                    unsafe_allow_html=True
                )
                kc_cols = st.columns(len(kc_steps))
                for _i, (_col, _step) in enumerate(zip(kc_cols, kc_steps)):
                    _color = _PHASE_COLORS[_i % len(_PHASE_COLORS)]
                    _short = (_step[:70] + "…") if len(_step) > 70 else _step
                    with _col:
                        st.markdown(
                            f"<div style='background:#0b1520;border:1px solid #1a2a3a;"
                            f"border-top:3px solid {_color};border-radius:4px;"
                            f"padding:10px 6px;text-align:center;min-height:80px;'>"
                            f"<div style='color:{_color};font-size:0.6rem;"
                            f"font-family:Share Tech Mono,monospace;margin-bottom:5px;"
                            f"letter-spacing:1px;'>PHASE {_i+1}</div>"
                            f"<div style='color:#b0bec5;font-size:0.7rem;"
                            f"line-height:1.4;'>{_short}</div></div>",
                            unsafe_allow_html=True
                        )

            # ── Auto-extracted IOCs ───────────────────────────────────────────
            iocs = extract_iocs(docs)
            active_iocs = {k: v for k, v in iocs.items() if v}
            if active_iocs:
                total_iocs = sum(len(v) for v in active_iocs.values())
                with st.expander(f"⚡ AUTO-EXTRACTED IOCs — {total_iocs} artifacts found", expanded=False):
                    for ioc_type, ioc_list in active_iocs.items():
                        if ioc_list:
                            badges = " ".join(
                                f"<code style='background:#0d1520;color:#ff8f00;"
                                f"border:1px solid #2a1a00;padding:2px 7px;"
                                f"border-radius:3px;font-size:0.78rem;"
                                f"display:inline-block;margin:2px;'>{ioc}</code>"
                                for ioc in ioc_list[:8]
                            )
                            st.markdown(
                                f"<div style='margin-bottom:10px;'>"
                                f"<span style='color:#546e7a;font-family:Share Tech Mono,monospace;"
                                f"font-size:0.65rem;letter-spacing:1px;'>"
                                f"{ioc_type.upper()} ({len(ioc_list)})</span><br>"
                                f"<div style='margin-top:4px;'>{badges}</div></div>",
                                unsafe_allow_html=True
                            )

            # ── MITRE ATT&CK mini-table ───────────────────────────────────────
            mitre_techs = parse_mitre_from_response(response)
            if mitre_techs:
                with st.expander(f"⬡ MITRE ATT&CK TABLE — {len(mitre_techs)} techniques detected", expanded=False):
                    rows = "".join(
                        f"<tr style='border-bottom:1px solid #0f1a28;'>"
                        f"<td style='padding:7px 12px;color:#00e5ff;"
                        f"font-family:Share Tech Mono,monospace;white-space:nowrap;'>"
                        f"<b>{tid}</b></td>"
                        f"<td style='padding:7px 12px;color:#b0bec5;'>{name}</td>"
                        f"<td style='padding:7px 12px;color:#ff8f00;"
                        f"font-size:0.78rem;white-space:nowrap;'>{tactic}</td>"
                        f"</tr>"
                        for tid, name, tactic in mitre_techs
                    )
                    st.markdown(
                        f"<table style='width:100%;border-collapse:collapse;"
                        f"font-size:0.82rem;background:#070d1a;border-radius:4px;'>"
                        f"<tr style='background:#0b0f1a;'>"
                        f"<th style='padding:7px 12px;color:#546e7a;text-align:left;"
                        f"font-family:Share Tech Mono,monospace;font-size:0.65rem;"
                        f"letter-spacing:1px;border-bottom:1px solid #1a2a3a;'>T-CODE</th>"
                        f"<th style='padding:7px 12px;color:#546e7a;text-align:left;"
                        f"font-family:Share Tech Mono,monospace;font-size:0.65rem;"
                        f"letter-spacing:1px;border-bottom:1px solid #1a2a3a;'>TECHNIQUE</th>"
                        f"<th style='padding:7px 12px;color:#546e7a;text-align:left;"
                        f"font-family:Share Tech Mono,monospace;font-size:0.65rem;"
                        f"letter-spacing:1px;border-bottom:1px solid #1a2a3a;'>TACTIC</th>"
                        f"</tr>{rows}</table>",
                        unsafe_allow_html=True
                    )
                    # Tactic distribution bar chart
                    if len(mitre_techs) > 1:
                        tactic_counts = Counter(t for _, _, t in mitre_techs)
                        max_c = max(tactic_counts.values())
                        bars_html = "".join(
                            f"<div style='display:flex;align-items:center;gap:8px;margin-bottom:5px;'>"
                            f"<div style='width:130px;color:#546e7a;"
                            f"font-family:Share Tech Mono,monospace;font-size:0.6rem;"
                            f"text-align:right;overflow:hidden;white-space:nowrap;"
                            f"text-overflow:ellipsis;'>{tactic}</div>"
                            f"<div style='flex:1;background:#0b0f1a;border-radius:2px;height:14px;'>"
                            f"<div style='width:{int(cnt/max_c*100)}%;"
                            f"background:linear-gradient(90deg,#00b8d4,#00e5ff);"
                            f"height:100%;border-radius:2px;'></div></div>"
                            f"<div style='color:#00e5ff;font-family:Share Tech Mono,monospace;"
                            f"font-size:0.65rem;min-width:14px;'>{cnt}</div></div>"
                            for tactic, cnt in tactic_counts.most_common()
                        )
                        st.markdown(
                            f"<div style='margin-top:14px;padding-top:10px;"
                            f"border-top:1px solid #1a2a3a;'>"
                            f"<div style='font-family:Share Tech Mono,monospace;color:#546e7a;"
                            f"font-size:0.6rem;letter-spacing:1px;margin-bottom:8px;'>"
                            f"TACTIC DISTRIBUTION</div>{bars_html}</div>",
                            unsafe_allow_html=True
                        )

        # Store in history
        st.session_state.query_history.append({
            "query": prompt,
            "time": datetime.now().strftime("%H:%M:%S"),
            "confidence": f"{conf_icon} {confidence_pct}%",
            "sources": unique_sources,
            "search_time": search_time,
            "gen_time": gen_time,
        })

        full_response = response + f"\n\n📂 Sources: {', '.join(unique_sources)}"
        st.session_state.rag_messages.append({"role": "assistant", "content": full_response})
        st.session_state.messages.append({"role": "assistant", "content": full_response})


# ── CLI args ──────────────────────────────────────────────────────────────────

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ThreatLens — Cyber Threat Intelligence with local LLMs.")
    parser.add_argument("-m", "--model", default=DEFAULT_MODEL)
    parser.add_argument("-e", "--embedding_model", default=DEFAULT_EMBEDDING_MODEL)
    parser.add_argument("-p", "--path", default=DEFAULT_PATH)
    parser.add_argument("--nb-docs", type=int, default=8)
    args, _ = parser.parse_known_args()
    return args


if __name__ == "__main__":
    args = parse_arguments()
    main(args.model, args.embedding_model, args.path, args.nb_docs)
