"""
LLM abstraction layer — swaps between Ollama (local) and Gemini API.
Supports streaming and standard calls.
"""
import os

from langchain_core.language_models import BaseChatModel
from .config import settings


def _ollama_base_url() -> str:
    """ChatOllama appends /api/chat; strip a trailing /api from cloud URLs."""
    base_url = settings.ollama_base_url.rstrip("/")
    if base_url.endswith("/api"):
        base_url = base_url[: -len("/api")]
    return base_url


def get_llm(streaming: bool = False) -> BaseChatModel:
    """
    Returns the configured LLM backend.
    Falls back gracefully if the selected backend isn't available.
    """
    if settings.llm_backend == "ollama":
        from langchain_ollama import ChatOllama
        kwargs = dict(
            base_url=_ollama_base_url(),
            model=settings.ollama_model,
            temperature=0.0,       # deterministic for security testing
            streaming=streaming,
            num_ctx=4096,
        )
        if settings.ollama_api_key:
            # ollama-python also reads this; pydantic-settings does not export .env into os.environ
            os.environ.setdefault("OLLAMA_API_KEY", settings.ollama_api_key)
            kwargs["client_kwargs"] = {
                "headers": {"Authorization": f"Bearer {settings.ollama_api_key}"},
            }
        return ChatOllama(**kwargs)
    elif settings.llm_backend == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(
            model=settings.gemini_model,
            google_api_key=settings.gemini_api_key,
            temperature=0.0,
            streaming=streaming,
        )
    else:
        raise ValueError(f"Unknown LLM backend: {settings.llm_backend}")
