"""
TwinSanity Recon V2 - LLM Response Caching

This module provides intelligent caching for LLM responses:
- Semantic caching with prompt hashing
- TTL-based expiration
- Cache statistics and management
- Optional persistent storage
"""

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Callable, Awaitable, Any

logger = logging.getLogger("LLMCache")


@dataclass
class CacheEntry:
    """A single cache entry with metadata."""
    response: str
    provider: str
    model: str
    created_at: float
    expires_at: float
    hit_count: int = 0
    prompt_hash: str = ""
    
    def is_expired(self) -> bool:
        """Check if this entry has expired."""
        return time.time() > self.expires_at
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "response": self.response,
            "provider": self.provider,
            "model": self.model,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "hit_count": self.hit_count,
            "prompt_hash": self.prompt_hash
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "CacheEntry":
        """Create from dictionary."""
        return cls(**data)


class LLMCache:
    """
    Intelligent caching layer for LLM responses.
    
    Features:
    - Hash-based cache keys from prompt + model
    - Configurable TTL (time-to-live)
    - Optional persistent storage to disk
    - Cache statistics and hit rate tracking
    - Automatic cleanup of expired entries
    """
    
    def __init__(
        self,
        ttl_hours: int = 6,
        max_entries: int = 500,
        persist_path: Optional[Path] = None
    ):
        """
        Initialize the cache.
        
        Args:
            ttl_hours: Hours before cache entries expire
            max_entries: Maximum number of entries to store
            persist_path: Optional path for persistent cache file
        """
        self.ttl = timedelta(hours=ttl_hours)
        self.max_entries = max_entries
        self.persist_path = persist_path
        
        self.cache: Dict[str, CacheEntry] = {}
        self.stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0
        }
        
        # Load persisted cache if available
        if persist_path and persist_path.exists():
            self._load_from_disk()
        
        logger.info(f"LLMCache initialized: TTL={ttl_hours}h, max={max_entries} entries")
    
    def _hash_prompt(self, prompt: str, model: str) -> str:
        """
        Create a unique cache key from prompt and model.
        
        Uses SHA-256 for consistent hashing.
        """
        content = f"{model}:{prompt}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:24]
    
    def _normalize_prompt(self, prompt: str) -> str:
        """
        Normalize prompt for better cache hits.
        
        Removes extra whitespace, lowercases for comparison.
        """
        # Remove excessive whitespace
        normalized = " ".join(prompt.split())
        return normalized
    
    def get(self, prompt: str, model: str) -> Optional[str]:
        """
        Get cached response if available and not expired.
        
        Args:
            prompt: The original prompt
            model: The model name
        
        Returns:
            Cached response string or None
        """
        normalized = self._normalize_prompt(prompt)
        key = self._hash_prompt(normalized, model)
        
        if key in self.cache:
            entry = self.cache[key]
            
            if entry.is_expired():
                # Remove expired entry
                del self.cache[key]
                self.stats["misses"] += 1
                logger.debug(f"Cache EXPIRED for {key[:8]}...")
                return None
            
            # Cache hit!
            entry.hit_count += 1
            self.stats["hits"] += 1
            logger.info(f"Cache HIT for {key[:8]}... (hits: {entry.hit_count})")
            return entry.response
        
        self.stats["misses"] += 1
        return None
    
    def put(self, prompt: str, model: str, response: str, provider: str):
        """
        Store a response in the cache.
        
        Args:
            prompt: The original prompt
            model: The model name
            response: The LLM response to cache
            provider: The provider that generated this response
        """
        # Cleanup if at capacity
        if len(self.cache) >= self.max_entries:
            self._evict_oldest()
        
        normalized = self._normalize_prompt(prompt)
        key = self._hash_prompt(normalized, model)
        
        now = time.time()
        entry = CacheEntry(
            response=response,
            provider=provider,
            model=model,
            created_at=now,
            expires_at=now + self.ttl.total_seconds(),
            prompt_hash=key
        )
        
        self.cache[key] = entry
        logger.debug(f"Cache PUT for {key[:8]}... (provider: {provider})")
        
        # Persist if configured
        if self.persist_path:
            self._save_to_disk()
    
    async def get_or_call(
        self,
        prompt: str,
        model: str,
        call_func: Callable[[str, str], Awaitable[str]],
        provider: str = "unknown"
    ) -> tuple[str, bool]:
        """
        Get from cache or call LLM function.
        
        Args:
            prompt: The prompt to send
            model: The model to use
            call_func: Async function to call if cache miss
            provider: Provider name for cache metadata
        
        Returns:
            Tuple of (response, was_cached)
        """
        # Try cache first
        cached = self.get(prompt, model)
        if cached:
            return cached, True
        
        # Cache miss - call the LLM
        response = await call_func(prompt, model)
        
        # Store in cache
        self.put(prompt, model, response, provider)
        
        return response, False
    
    def _evict_oldest(self):
        """Evict the oldest or least-used entries."""
        if not self.cache:
            return
        
        # First, remove any expired entries
        expired_keys = [k for k, v in self.cache.items() if v.is_expired()]
        for key in expired_keys:
            del self.cache[key]
            self.stats["evictions"] += 1
        
        # If still at capacity, remove least recently used
        if len(self.cache) >= self.max_entries:
            # Sort by created_at (oldest first)
            sorted_keys = sorted(
                self.cache.keys(),
                key=lambda k: self.cache[k].created_at
            )
            
            # Remove oldest 10%
            to_remove = max(1, len(sorted_keys) // 10)
            for key in sorted_keys[:to_remove]:
                del self.cache[key]
                self.stats["evictions"] += 1
        
        logger.debug(f"Cache eviction: {len(expired_keys)} expired, total {self.stats['evictions']}")
    
    def invalidate(self, prompt: str = None, model: str = None):
        """
        Invalidate cache entries.
        
        Args:
            prompt: Specific prompt to invalidate (with model)
            model: Model name (required if prompt specified)
        
        If no arguments, clears entire cache.
        """
        if prompt and model:
            key = self._hash_prompt(self._normalize_prompt(prompt), model)
            if key in self.cache:
                del self.cache[key]
                logger.info(f"Cache invalidated: {key[:8]}...")
        else:
            self.cache.clear()
            logger.info("Cache cleared entirely")
    
    def cleanup_expired(self):
        """Remove all expired entries."""
        expired_keys = [k for k, v in self.cache.items() if v.is_expired()]
        for key in expired_keys:
            del self.cache[key]
        
        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self.stats["hits"] + self.stats["misses"]
        hit_rate = self.stats["hits"] / total_requests if total_requests > 0 else 0
        
        return {
            "entries": len(self.cache),
            "max_entries": self.max_entries,
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "hit_rate": round(hit_rate * 100, 1),
            "evictions": self.stats["evictions"],
            "ttl_hours": self.ttl.total_seconds() / 3600
        }
    
    def _save_to_disk(self):
        """Persist cache to disk."""
        if not self.persist_path:
            return
        
        try:
            data = {
                "cache": {k: v.to_dict() for k, v in self.cache.items()},
                "stats": self.stats,
                "saved_at": time.time()
            }
            
            with open(self.persist_path, "w") as f:
                json.dump(data, f)
            
        except Exception as e:
            logger.warning(f"Failed to persist cache: {e}")
    
    def _load_from_disk(self):
        """Load cache from disk."""
        if not self.persist_path or not self.persist_path.exists():
            return
        
        try:
            with open(self.persist_path, "r") as f:
                data = json.load(f)
            
            for key, entry_data in data.get("cache", {}).items():
                entry = CacheEntry.from_dict(entry_data)
                if not entry.is_expired():
                    self.cache[key] = entry
            
            self.stats = data.get("stats", self.stats)
            logger.info(f"Loaded {len(self.cache)} cache entries from disk")
            
        except Exception as e:
            logger.warning(f"Failed to load cache from disk: {e}")


# Global cache instance
_llm_cache: Optional[LLMCache] = None


def get_llm_cache(
    ttl_hours: int = 6,
    max_entries: int = 500,
    persist_path: Optional[Path] = None
) -> LLMCache:
    """Get or create the global LLM cache instance."""
    global _llm_cache
    if _llm_cache is None:
        _llm_cache = LLMCache(
            ttl_hours=ttl_hours,
            max_entries=max_entries,
            persist_path=persist_path
        )
    return _llm_cache
