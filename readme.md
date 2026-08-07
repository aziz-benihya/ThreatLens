# ThreatLens

<p align="center">
    <img src="images/logo.webp" width="400">
</p>

**ThreatLens** is a cyber threat intelligence tool that uses local large language models (LLMs) and a vector database to answer your questions about cyber threats. It's built on top of Langchain, Ollama, Chroma, and PyPDF.

> This project is a fork of [CTrag](https://github.com/search?q=CTrag), enhanced with a new dark-themed UI, multi-format document support (PDF, TXT, DOCX, HTML), and an interactive sidebar.

## Credits

The original project was adapted from [local-LLM-with-RAG](https://github.com/amscotti/local-LLM-with-RAG) by amscotti, then specialized for cyber threat intelligence as CTrag. ThreatLens extends this work with UI improvements and broader document support.

## Requirements

- [Ollama](https://ollama.ai/) version 0.1.26 or higher.
  - Default model: `llama3`. You can pull others with `ollama pull [MODEL_NAME]`.

## Setup

1. Clone this repository:
   ```bash
   git clone https://github.com/YOUR-USERNAME/ThreatLens.git
   cd ThreatLens
   ```
2. Create a Python virtual environment:
   ```bash
   python3 -m venv env
   ```
3. Activate it:
   - Unix/macOS: `source env/bin/activate`
   - Windows: `.\env\Scripts\activate`
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Running the project

> **Note:** The first run will download the required Ollama models. This is a one-time process.

```bash
streamlit run app.py
```

## Adding documents to the knowledge base

Place your files in the `reports/` folder. ThreatLens supports:

| Format | Extension |
|--------|-----------|
| PDF | `.pdf` |
| Plain text | `.txt` |
| Word document | `.docx` |
| Web page | `.html` |

The tool will automatically process and index them on the next run.

## Available commands

```
streamlit run app.py [-m MODEL] [-e EMBEDDING_MODEL] [-p PATH] [--nb-docs NB_DOCS]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `-m MODEL` | `llama3` | LLM model to use |
| `-e EMBEDDING_MODEL` | `nomic-embed-text` | Embedding model |
| `-p PATH` | `reports` | Path to documents directory |
| `--nb-docs NB_DOCS` | `8` | Number of documents retrieved per query |

Example:
```bash
streamlit run app.py -m "llama3" -e "nomic-embed-text" -p "./reports" --nb-docs 10
```

## Data sources for the pre-built vector database

- [VX-Underground archives](https://vx-underground.org/)

## Technologies Used

- [Langchain](https://github.com/langchain/langchain) — LLM orchestration
- [Ollama](https://ollama.ai/) — local LLM runtime
- [Chroma](https://docs.trychroma.com/) — vector database
- [PyPDF](https://pypi.org/project/PyPDF2/) — PDF parsing
- [docx2txt](https://pypi.org/project/docx2txt/) — Word document parsing
- [Unstructured](https://pypi.org/project/unstructured/) — HTML parsing
- [Streamlit](https://streamlit.io/) — web UI

## License

This project is licensed under the terms of the MIT license.
