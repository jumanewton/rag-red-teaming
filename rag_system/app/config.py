"""
Configuration management using pydantic-settings.
All settings are loaded from environment variables / .env file.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Literal


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── LLM ──────────────────────────────────────────────────────────────────
    llm_backend: Literal["ollama", "gemini"] = "ollama"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"
    gemini_api_key: str = ""
    gemini_model: str = "gemini-3.8-flash"

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379"
    redis_cache_ttl: int = 3600

    # ── ChromaDB ──────────────────────────────────────────────────────────────
    chroma_persist_dir: str = "./chroma_db"
    chroma_collection: str = "rag_knowledge_base"

    # ── Embeddings ────────────────────────────────────────────────────────────
    embedding_model: str = "all-MiniLM-L6-v2"

    # ── RAG Retrieval ─────────────────────────────────────────────────────────
    retrieval_top_k: int = 6
    retrieval_mmr_fetch_k: int = 20
    chunk_size: int = 512
    chunk_overlap: int = 64

    # ── Security ──────────────────────────────────────────────────────────────
    api_key: str = "redteam-secret-key-change-in-prod"
    rate_limit_requests: int = 60
    rate_limit_window: int = 60

    # ── Observability ─────────────────────────────────────────────────────────
    phoenix_enabled: bool = True
    phoenix_port: int = 6006

    # ── Red Team ──────────────────────────────────────────────────────────────
    rag_service_url: str = "http://localhost:8000"
    red_team_api_key: str = "redteam-secret-key-change-in-prod"
    reports_dir: str = "./red_team/reports"


settings = Settings()
