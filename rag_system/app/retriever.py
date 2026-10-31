"""
Retrieval layer with MMR reranking.
Pulls the most relevant + diverse chunks from ChromaDB for a given query.
"""
import logging
from typing import List, Optional

from langchain_chroma import Chroma
from langchain_core.documents import Document

from .config import settings
from .ingestion import get_embeddings, get_vectorstore

logger = logging.getLogger(__name__)


def retrieve(
    query: str,
    top_k: int | None = None,
    access_level: str = "public",
    user_id: Optional[str] = None,
) -> List[Document]:
    """
    Retrieves relevant documents using Maximal Marginal Relevance (MMR).

    MMR balances relevance with diversity to avoid redundant chunks.

    Security filter: only returns chunks matching the caller's access_level.
    This is one of the RBAC controls that red teamers will try to bypass.
    """
    k = top_k or settings.retrieval_top_k
    vectorstore = get_vectorstore()

    # ── RBAC filter (intentionally simple for red team testing) ───────────────
    # access levels: "public" < "internal" < "confidential" < "secret"
    level_hierarchy = {"public": 0, "internal": 1, "confidential": 2, "secret": 3}
    caller_level = level_hierarchy.get(access_level, 0)
    allowed_levels = [lvl for lvl, rank in level_hierarchy.items() if rank <= caller_level]

    where_filter = {"access_level": {"$in": allowed_levels}}

    try:
        docs = vectorstore.max_marginal_relevance_search(
            query=query,
            k=k,
            fetch_k=settings.retrieval_mmr_fetch_k,
            lambda_mult=0.7,          # 0=max diversity, 1=max relevance
            filter=where_filter,
        )
        logger.debug(f"Retrieved {len(docs)} chunks for query (user={user_id})")
        return docs
    except Exception as e:
        logger.error(f"Retrieval failed: {e}")
        return []


def format_context(docs: List[Document]) -> tuple[str, List[dict]]:
    """
    Formats retrieved docs into a context string + citation list.
    Returns (context_text, citations).
    """
    context_parts = []
    citations = []

    for i, doc in enumerate(docs, 1):
        source = doc.metadata.get("source", "Unknown")
        chunk_id = doc.metadata.get("chunk_id", "?")
        page = doc.metadata.get("page", "")
        page_str = f", page {page}" if page else ""

        context_parts.append(
            f"[{i}] Source: {source}{page_str}\n{doc.page_content}"
        )
        citations.append({
            "index": i,
            "source": source,
            "chunk_id": chunk_id,
            "page": page,
            "snippet": doc.page_content[:200],
        })

    return "\n\n---\n\n".join(context_parts), citations
