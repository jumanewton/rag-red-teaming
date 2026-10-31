"""
Redis-backed conversation memory.
Provides per-session chat history persistence.
"""
import json
import logging
from typing import List, Optional

import redis.asyncio as aioredis
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage

from .config import settings

logger = logging.getLogger(__name__)

# ── Async Redis client (module-level singleton) ────────────────────────────────
_redis_client: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=3,
        )
    return _redis_client


async def get_history(session_id: str, max_turns: int = 10) -> List[BaseMessage]:
    """Load the last N turns of chat history for a session."""
    try:
        client = await get_redis()
        key = f"chat_history:{session_id}"
        raw = await client.lrange(key, -max_turns * 2, -1)
        messages: List[BaseMessage] = []
        for item in raw:
            data = json.loads(item)
            if data["role"] == "human":
                messages.append(HumanMessage(content=data["content"]))
            else:
                messages.append(AIMessage(content=data["content"]))
        return messages
    except Exception as e:
        logger.warning(f"Failed to load history for {session_id}: {e}")
        return []


async def save_turn(session_id: str, human_msg: str, ai_msg: str) -> None:
    """Persist one conversation turn to Redis."""
    try:
        client = await get_redis()
        key = f"chat_history:{session_id}"
        pipe = client.pipeline()
        pipe.rpush(key, json.dumps({"role": "human", "content": human_msg}))
        pipe.rpush(key, json.dumps({"role": "ai", "content": ai_msg}))
        pipe.expire(key, 86400)  # 24 hours TTL
        await pipe.execute()
    except Exception as e:
        logger.warning(f"Failed to save history for {session_id}: {e}")


async def clear_history(session_id: str) -> None:
    """Delete session history (e.g., on logout)."""
    try:
        client = await get_redis()
        await client.delete(f"chat_history:{session_id}")
    except Exception as e:
        logger.warning(f"Failed to clear history for {session_id}: {e}")


async def cache_get(key: str) -> Optional[str]:
    """Query response cache."""
    try:
        client = await get_redis()
        return await client.get(f"cache:{key}")
    except Exception:
        return None


async def cache_set(key: str, value: str, ttl: int | None = None) -> None:
    """Store query response in cache."""
    try:
        client = await get_redis()
        await client.setex(f"cache:{key}", ttl or settings.redis_cache_ttl, value)
    except Exception as e:
        logger.warning(f"Cache write failed: {e}")
