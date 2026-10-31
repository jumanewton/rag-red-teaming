import sys, warnings
warnings.filterwarnings("ignore")
sys.path.insert(0, ".")

print("Testing lightweight imports...")

from rag_system.app.config import settings
print(f"  [OK] config — LLM backend: {settings.llm_backend}")

from rag_system.app.security import hash_query, verify_api_key
h = hash_query("test")
print(f"  [OK] security — hash_query: {h}")

from red_team.attacks._client import query_rag, AttackResult, console
print("  [OK] red_team._client loaded")

from rag_system.app.llm import get_llm
print("  [OK] llm module loaded")

import fastapi, uvicorn, pydantic, pydantic_settings
print(f"  [OK] fastapi={fastapi.__version__}, uvicorn={uvicorn.__version__}, pydantic={pydantic.__version__}")

import langchain, redis, httpx, rich
print(f"  [OK] langchain={langchain.__version__}, redis={redis.__version__}, httpx={httpx.__version__}")

print()
print("=== Core imports: ALL OK ===")
print(f"LLM_BACKEND     = {settings.llm_backend}")
print(f"OLLAMA_MODEL    = {settings.ollama_model}")
print(f"CHROMA_DIR      = {settings.chroma_persist_dir}")
print(f"REDIS_URL       = {settings.redis_url}")
