import streamlit as st
from langchain_ollama import OllamaEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from langchain_core.prompts import PromptTemplate
from models import check_if_model_is_available
from document_loader import load_documents
import argparse
import sys
import os
import time
import ollama
from typing import Dict, Generator


TEXT_SPLITTER = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
DEFAULT_MODEL = "llama3"
DEFAULT_EMBEDDING_MODEL = "nomic-embed-text"
DEFAULT_PATH = "reports"
PERSIST_DIR = "db"

PROMPT_TEMPLATE = """
## Instruction:
Act as a cyber threat intelligence expert. Answer the question based solely on the provided context.
Do not use knowledge outside the given context. Be concise, precise, and structured in your response.
If the context does not contain enough information to answer, say so clearly.

## Context:
{context}

## Question:
{question}

## Answer:
"""

PROMPT = PromptTemplate(
    template=PROMPT_TEMPLATE, input_variables=["context", "question"]
)

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ThreatLens — Cyber Threat Intelligence",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    /* Main background */
    .stApp { background-color: #0d1117; color: #c9d1d9; }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #161b22;
        border-right: 1px solid #30363d;
    }

    /* Chat input */
    [data-testid="stChatInput"] textarea {
        background-color: #161b22 !important;
        color: #c9d1d9 !important;
        border: 1px solid #30363d !important;
    }

    /* User message bubble */
    [data-testid="stChatMessage"]:has([data-testid="chatAvatarIcon-user"]) {
        background-color: #1f2937;
        border-radius: 10px;
        padding: 10px;
    }

    /* Assistant message bubble */
    [data-testid="stChatMessage"]:has([data-testid="chatAvatarIcon-assistant"]) {
        background-color: #0d2137;
        border-radius: 10px;
        padding: 10px;
    }

    /* Title */
    h1 { color: #58a6ff !important; }
    h3 { color: #79c0ff !important; }

    /* Stat cards */
    .stat-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 12px 16px;
        text-align: center;
        margin-bottom: 8px;
    }
    .stat-value { font-size: 1.6rem; font-weight: bold; color: #58a6ff; }
    .stat-label { font-size: 0.8rem; color: #8b949e; }

    /* Expander */
    [data-testid="stExpander"] {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
    }

    /* Selectbox */
    [data-testid="stSelectbox"] select {
        background-color: #161b22 !important;
        color: #c9d1d9 !important;
    }

    /* Divider */
    hr { border-color: #30363d; }
</style>
""", unsafe_allow_html=True)


# ── Helper functions ──────────────────────────────────────────────────────────

def load_documents_into_database(model_name: str, documents_path: str) -> Chroma:
    """
    Loads documents from the specified directory into the Chroma database
    after splitting the text into chunks.
    """
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
    end_time = time.time() - start
    print(f"Time to load documents into Chroma: {end_time:.2f} seconds")
    # chromadb >= 0.5 auto-persists — no explicit .persist() needed
    return db


def ollama_generator(model_name: str, messages: Dict) -> Generator:
    stream = ollama.chat(model=model_name, messages=messages, stream=True)
    for chunk in stream:
        # Support both old dict API (< 0.2) and new object API (>= 0.2)
        if hasattr(chunk, "message"):
            yield chunk.message.content
        else:
            yield chunk["message"]["content"]


def get_available_models():
    try:
        result = ollama.list()
        # New object API (ollama >= 0.2.0)
        if hasattr(result, "models"):
            names = [getattr(m, "model", None) for m in result.models]
        else:
            names = [m.get("name") for m in result.get("models", [])]
        return [n for n in names if n] or [DEFAULT_MODEL]
    except Exception:
        return [DEFAULT_MODEL]


# ── Main app ──────────────────────────────────────────────────────────────────

def main(llm_model_name: str, embedding_model_name: str, documents_path: str, nb_docs: int) -> None:
    # ── Check models ──────────────────────────────────────────────────────────
    try:
        check_if_model_is_available(llm_model_name)
        check_if_model_is_available(embedding_model_name)
    except Exception as e:
        print(e)
        sys.exit()

    try:
        db = load_documents_into_database(embedding_model_name, documents_path)
    except FileNotFoundError as e:
        print(e)
        sys.exit()

    # ── Session state init ────────────────────────────────────────────────────
    if "selected_model" not in st.session_state:
        st.session_state.selected_model = llm_model_name
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "rag_messages" not in st.session_state:
        st.session_state.rag_messages = []
    if "nb_docs" not in st.session_state:
        st.session_state.nb_docs = nb_docs
    if "total_queries" not in st.session_state:
        st.session_state.total_queries = 0

    # ── Sidebar ───────────────────────────────────────────────────────────────
    with st.sidebar:
        st.image("images/logo.webp", use_container_width=True)
        st.markdown("---")

        st.markdown("### ⚙️ Settings")
        available_models = get_available_models()
        default_idx = available_models.index(st.session_state.selected_model) \
            if st.session_state.selected_model in available_models else 0
        st.session_state.selected_model = st.selectbox(
            "🤖 LLM Model", available_models, index=default_idx
        )
        st.session_state.nb_docs = st.slider(
            "📄 Documents retrieved", min_value=1, max_value=20,
            value=st.session_state.nb_docs, step=1
        )

        st.markdown("---")
        st.markdown("### 📊 Session stats")

        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-value">{st.session_state.total_queries}</div>
                <div class="stat-label">Queries</div>
            </div>""", unsafe_allow_html=True)
        with col2:
            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-value">{len(st.session_state.messages) // 2}</div>
                <div class="stat-label">Exchanges</div>
            </div>""", unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("### ℹ️ Supported formats")
        st.markdown("📄 PDF &nbsp;|&nbsp; 📝 TXT &nbsp;|&nbsp; 📃 DOCX &nbsp;|&nbsp; 🌐 HTML")

        st.markdown("---")
        if st.button("🗑️ Clear conversation", use_container_width=True):
            st.session_state.messages = []
            st.session_state.rag_messages = []
            st.session_state.total_queries = 0
            st.rerun()

    # ── Main area ─────────────────────────────────────────────────────────────
    st.title("🔍 ThreatLens")
    st.caption("Cyber Threat Intelligence powered by local LLMs + RAG")
    st.markdown("---")

    # Chat history
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Chat input
    if prompt := st.chat_input("Ask a cyber threat intelligence question…"):
        st.session_state.total_queries += 1
        docs = db.similarity_search(prompt, k=st.session_state.nb_docs)

        with st.expander("📚 View retrieved context", expanded=False):
            for i, doc in enumerate(docs):
                source = doc.metadata.get("source", "Unknown")
                st.markdown(f"**[{i+1}] Source:** `{source}`")
                st.markdown(doc.page_content[:500] + ("…" if len(doc.page_content) > 500 else ""))
                st.markdown("---")

        formatted_prompt = PROMPT_TEMPLATE.format(context=docs, question=prompt)
        st.session_state.rag_messages.append({"role": "user", "content": formatted_prompt})
        st.session_state.messages.append({"role": "user", "content": prompt})

        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("assistant"):
            response = st.write_stream(
                ollama_generator(st.session_state.selected_model, st.session_state.rag_messages)
            )

        st.session_state.rag_messages.append({"role": "assistant", "content": response})
        st.session_state.messages.append({"role": "assistant", "content": response})


# ── CLI args ──────────────────────────────────────────────────────────────────

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ThreatLens — Cyber Threat Intelligence with local LLMs.")
    parser.add_argument("-m", "--model", default=DEFAULT_MODEL,
                        help=f"LLM model to use. Default: {DEFAULT_MODEL}.")
    parser.add_argument("-e", "--embedding_model", default=DEFAULT_EMBEDDING_MODEL,
                        help=f"Embedding model. Default: {DEFAULT_EMBEDDING_MODEL}.")
    parser.add_argument("-p", "--path", default=DEFAULT_PATH,
                        help=f"Path to documents directory. Default: {DEFAULT_PATH}.")
    parser.add_argument("--nb-docs", type=int, default=8,
                        help="Number of documents to retrieve. Default: 8.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    main(args.model, args.embedding_model, args.path, args.nb_docs)
