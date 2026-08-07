from langchain_community.document_loaders import (
    DirectoryLoader,
    PyPDFLoader,
    TextLoader,
    UnstructuredHTMLLoader,
    Docx2txtLoader,
)
import os
from typing import List
from langchain_core.documents import Document


def load_documents(path: str) -> List[Document]:
    """
    Loads documents from the specified directory path.

    Supports: PDF (.pdf), plain text (.txt), Word (.docx), and HTML (.html) files.

    Args:
        path (str): The path to the directory containing documents to load.

    Returns:
        List[Document]: A list of loaded documents.

    Raises:
        FileNotFoundError: If the specified path does not exist.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"The specified path does not exist: {path}")

    loaders = {
        ".pdf": DirectoryLoader(
            path,
            glob="**/*.pdf",
            loader_cls=PyPDFLoader,
            show_progress=True,
            use_multithreading=True,
        ),
        ".txt": DirectoryLoader(
            path,
            glob="**/*.txt",
            loader_cls=TextLoader,
            show_progress=True,
            loader_kwargs={"encoding": "utf-8", "autodetect_encoding": True},
        ),
        ".docx": DirectoryLoader(
            path,
            glob="**/*.docx",
            loader_cls=Docx2txtLoader,
            show_progress=True,
        ),
        ".html": DirectoryLoader(
            path,
            glob="**/*.html",
            loader_cls=UnstructuredHTMLLoader,
            show_progress=True,
        ),
    }

    docs = []
    for file_type, loader in loaders.items():
        print(f"Loading {file_type} files")
        try:
            loaded = loader.load()
            if loaded:
                print(f"  -> {len(loaded)} {file_type} file(s) loaded")
            docs.extend(loaded)
        except Exception as e:
            print(f"  -> Warning: could not load {file_type} files: {e}")
    return docs
