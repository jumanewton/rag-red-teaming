"""
LLM abstraction layer — swaps between Ollama (local) and Gemini API.
Supports streaming and standard calls.
"""
from langchain_core.language_models import BaseChatModel
from .config import settings


def get_llm(streaming: bool = False) -> BaseChatModel:
    """
    Returns the configured LLM backend.
    Falls back gracefully if the selected backend isn't available.
    """
    if settings.llm_backend == "ollama":
        from langchain_ollama import ChatOllama
        return ChatOllama(
            base_url=settings.ollama_base_url,
            model=settings.ollama_model,
            temperature=0.0,       # deterministic for security testing
            streaming=streaming,
            num_ctx=4096,
        )
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
