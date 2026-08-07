# 🔍 ThreatLens

**ThreatLens** is an open-source Cyber Threat Intelligence (CTI) platform that runs entirely on your local machine. It uses Retrieval-Augmented Generation (RAG) to deliver accurate, evidence-grounded answers about cyber threats — with zero data sent to external servers.

> Built as part of an academic journey in Information Security.

---

## How it works

1. You load threat reports (PDF, DOCX, TXT, HTML) into the `reports/` folder
2. ThreatLens indexes them into a local vector database (ChromaDB)
3. You ask a question — the system retrieves the most relevant document chunks
4. A local LLM (via Ollama) generates a structured, cited answer grounded in those documents

---

## Key features

- **100% local** — powered by Ollama + ChromaDB, no cloud required
- **Anti-hallucination** — every claim cited with `[SOURCE: filename]`; responds "INSUFFICIENT EVIDENCE" when information is not in loaded documents
- **Multi-format ingestion** — PDF, DOCX, TXT, HTML
- **MITRE ATT&CK formatting** — techniques displayed as `T[ID] – Name (Tactic)`
- **Source attribution** — confidence indicator (HIGH / MEDIUM / LOW) based on supporting sources
- **Structured responses** — ANALYSIS / MITRE ATT&CK / IOCs / DETECTION / SOURCES
- **Dark cybersecurity UI** — terminal-style interface
- **Fully open source** — MIT license

---

## Requirements

- Python 3.10+
- [Ollama](https://ollama.ai/) installed and running

### Models needed

```bash
ollama pull llama3
ollama pull nomic-embed-text
```

---

## Setup

```bash
git clone https://github.com/aziz-benihya/ThreatLens.git
cd ThreatLens
pip install -r requirements.txt
```

---

## Running

```bash
python -m streamlit run app.py
```

> On Windows, use `python -m streamlit run app.py` to avoid Device Guard issues.

---

## Adding documents

Place your files in the `reports/` folder:

| Format | Extension |
|--------|-----------|
| PDF | `.pdf` |
| Plain text | `.txt` |
| Word document | `.docx` |
| Web page | `.html` |

To re-index after adding new files:

```bash
rmdir /s /q db          # Windows
python -m streamlit run app.py
```

---

## Example queries

- *What MITRE ATT&CK techniques does LockBit ransomware use?*
- *How does APT29 perform lateral movement?*
- *What are the indicators of compromise for Lazarus Group?*
- *How do attackers use Pass-the-Hash?*
- *What AiTM phishing tools bypass MFA?*

---

## Stack

| Component | Technology |
|-----------|------------|
| LLM runtime | [Ollama](https://ollama.ai/) |
| LLM orchestration | [LangChain 0.3.x](https://github.com/langchain-ai/langchain) |
| Vector database | [ChromaDB](https://docs.trychroma.com/) |
| PDF parsing | [pypdf](https://pypi.org/project/pypdf/) |
| DOCX parsing | [docx2txt](https://pypi.org/project/docx2txt/) |
| HTML parsing | [BeautifulSoup4](https://pypi.org/project/beautifulsoup4/) |
| Web UI | [Streamlit](https://streamlit.io/) |

---

## License

MIT — see [LICENSE](LICENSE)

## Author

**Abdelaaziz AIT BENIHYA** · Information Security Student  
[@aziz-benihya](https://github.com/aziz-benihya)
