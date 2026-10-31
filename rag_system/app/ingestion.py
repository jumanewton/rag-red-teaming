"""
Document ingestion pipeline.
Loads documents from the data/ directory, chunks them, embeds them,
and persists them into ChromaDB.

Usage:
    python -m rag_system.app.ingestion --source ./rag_system/data/clean
    python -m rag_system.app.ingestion --source ./rag_system/data/poisoned --poisoned
"""
import argparse
import hashlib
import logging
from pathlib import Path
from typing import List

from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter

# Document loaders — fallback to community if standalone not available
try:
    from langchain_community.document_loaders import (
        DirectoryLoader,
        PyPDFLoader,
        TextLoader,
        UnstructuredMarkdownLoader,
    )
except ImportError:
    from langchain.document_loaders import (  # type: ignore
        DirectoryLoader,
        PyPDFLoader,
        TextLoader,
        UnstructuredMarkdownLoader,
    )

# Embeddings — prefer standalone HuggingFace package
try:
    from langchain_huggingface import HuggingFaceEmbeddings as SentenceTransformerEmbeddings
except ImportError:
    from langchain_community.embeddings import SentenceTransformerEmbeddings  # type: ignore

from langchain_chroma import Chroma

from .config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def get_embeddings():
    """Return embedding model — tries HuggingFace standalone, falls back to community."""
    try:
        from langchain_huggingface import HuggingFaceEmbeddings
        return HuggingFaceEmbeddings(model_name=settings.embedding_model)
    except ImportError:
        pass
    try:
        from langchain_community.embeddings import SentenceTransformerEmbeddings
        return SentenceTransformerEmbeddings(model_name=settings.embedding_model)
    except ImportError:
        raise RuntimeError(
            "No embedding backend found. Run: pip install langchain-huggingface sentence-transformers"
        )


def get_vectorstore() -> Chroma:
    """Returns the persistent ChromaDB vectorstore."""
    return Chroma(
        collection_name=settings.chroma_collection,
        embedding_function=get_embeddings(),
        persist_directory=settings.chroma_persist_dir,
    )


def load_documents(source_dir: str) -> List[Document]:
    """Load documents from a directory. Supports PDF, TXT, MD, HTML."""
    source_path = Path(source_dir)
    docs: List[Document] = []

    loaders = {
        "**/*.pdf":  PyPDFLoader,
        "**/*.txt":  TextLoader,
        "**/*.md":   UnstructuredMarkdownLoader,
    }

    for glob_pattern, loader_cls in loaders.items():
        try:
            loader = DirectoryLoader(
                str(source_path),
                glob=glob_pattern,
                loader_cls=loader_cls,
                use_multithreading=True,
                show_progress=True,
                silent_errors=True,
            )
            batch = loader.load()
            logger.info(f"Loaded {len(batch)} docs via {glob_pattern}")
            docs.extend(batch)
        except Exception as e:
            logger.warning(f"Loader failed for {glob_pattern}: {e}")

    return docs


def chunk_documents(docs: List[Document], poisoned: bool = False) -> List[Document]:
    """
    Splits documents into overlapping chunks.
    Tags each chunk with metadata including a content hash and poison flag.
    """
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=settings.chunk_size,
        chunk_overlap=settings.chunk_overlap,
        separators=["\n\n", "\n", ".", " ", ""],
        length_function=len,
    )
    chunks = splitter.split_documents(docs)

    for chunk in chunks:
        # Stable deterministic ID for deduplication
        content_hash = hashlib.sha256(chunk.page_content.encode()).hexdigest()[:16]
        chunk.metadata["chunk_id"] = content_hash
        chunk.metadata["poisoned"] = poisoned          # red team marker
        chunk.metadata["access_level"] = chunk.metadata.get("access_level", "public")

    logger.info(f"Created {len(chunks)} chunks (poisoned={poisoned})")
    return chunks


def ingest(source_dir: str, poisoned: bool = False) -> int:
    """Full ingestion pipeline. Returns number of chunks added."""
    logger.info(f"Ingesting from: {source_dir} (poisoned={poisoned})")
    docs = load_documents(source_dir)
    if not docs:
        logger.warning("No documents found.")
        return 0

    chunks = chunk_documents(docs, poisoned=poisoned)
    vectorstore = get_vectorstore()

    # Deduplicate by chunk_id before adding
    existing_ids = set()
    try:
        existing = vectorstore._collection.get(include=[])
        existing_ids = set(existing.get("ids", []))
    except Exception:
        pass

    new_chunks = [c for c in chunks if c.metadata["chunk_id"] not in existing_ids]
    if not new_chunks:
        logger.info("All chunks already indexed. Nothing to add.")
        return 0

    vectorstore.add_documents(new_chunks, ids=[c.metadata["chunk_id"] for c in new_chunks])
    logger.info(f"✅ Added {len(new_chunks)} new chunks to ChromaDB.")
    return len(new_chunks)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--poisoned", action="store_true")
    args = parser.parse_args()
    ingest(args.source, args.poisoned)
