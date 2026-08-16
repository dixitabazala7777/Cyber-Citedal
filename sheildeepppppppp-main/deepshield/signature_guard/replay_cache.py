"""
DEEPSHIELD Enterprise — Signature Replay Detection Cache

Redis-backed nonce & signature payload digest cache with configurable TTL.
Prevents replay attacks by rejecting previously-seen (nonce, sig_hash) pairs.

Falls back to in-memory cache when Redis is unavailable (fail-closed: rejects
if cache state is unknown).
"""

import hashlib
import logging
import time
from typing import Optional, Tuple

logger = logging.getLogger("DeepShield.SignatureGuard.ReplayCache")

# In-memory fallback cache (used when Redis is unavailable)
_memory_cache: dict[str, float] = {}
_CACHE_TTL_SEC = 3600  # 1 hour default


def _sig_hash(payload_b64: str, signature_b64: str) -> str:
    """Compute a unique digest for a (payload, signature) pair."""
    combined = f"{payload_b64}:{signature_b64}"
    return hashlib.sha256(combined.encode()).hexdigest()


async def check_replay_async(
    key_id: str,
    payload_b64: str,
    signature_b64: str,
    nonce: Optional[str] = None,
    redis_client=None,
    ttl_sec: int = 3600,
) -> Tuple[bool, str]:
    """
    Check if this signature has been seen before.

    Returns:
        (is_replay, message)
    """
    sig_digest = _sig_hash(payload_b64, signature_b64)
    cache_key_sig = f"deepshield:sig_replay:{key_id}:{sig_digest}"

    # Nonce check
    if nonce:
        cache_key_nonce = f"deepshield:nonce:{key_id}:{nonce}"

        if redis_client:
            try:
                existing_nonce = await redis_client.get(cache_key_nonce)
                if existing_nonce:
                    return True, f"REPLAY: Nonce '{nonce}' already used for key '{key_id}'"
                # Store nonce with TTL
                await redis_client.setex(cache_key_nonce, ttl_sec, "1")
            except Exception as e:
                logger.error(f"Redis nonce check failed: {e}. Fail-closed: treating as replay.")
                return True, f"REPLAY_CHECK_FAILED: Redis unavailable for nonce verification (fail-closed)"
        else:
            # In-memory fallback
            if cache_key_nonce in _memory_cache:
                if time.time() - _memory_cache[cache_key_nonce] < ttl_sec:
                    return True, f"REPLAY: Nonce '{nonce}' already used (in-memory cache)"
            _memory_cache[cache_key_nonce] = time.time()

    # Signature digest check
    if redis_client:
        try:
            existing_sig = await redis_client.get(cache_key_sig)
            if existing_sig:
                return True, f"REPLAY: Signature digest already recorded for key '{key_id}'"
            await redis_client.setex(cache_key_sig, ttl_sec, "1")
            return False, "No replay detected"
        except Exception as e:
            logger.error(f"Redis sig check failed: {e}. Fail-closed: treating as replay.")
            return True, f"REPLAY_CHECK_FAILED: Redis unavailable for signature verification (fail-closed)"
    else:
        # In-memory fallback
        if cache_key_sig in _memory_cache:
            if time.time() - _memory_cache[cache_key_sig] < ttl_sec:
                return True, f"REPLAY: Signature digest already seen (in-memory cache)"
        _memory_cache[cache_key_sig] = time.time()
        return False, "No replay detected (in-memory cache)"


def check_replay_sync(
    key_id: str,
    payload_b64: str,
    signature_b64: str,
    nonce: Optional[str] = None,
    ttl_sec: int = 3600,
) -> Tuple[bool, str]:
    """
    Synchronous version for environments without async Redis.
    Uses in-memory cache only.
    """
    sig_digest = _sig_hash(payload_b64, signature_b64)
    cache_key_sig = f"deepshield:sig_replay:{key_id}:{sig_digest}"

    # Clean expired entries periodically
    now = time.time()
    expired = [k for k, v in _memory_cache.items() if now - v > ttl_sec]
    for k in expired:
        del _memory_cache[k]

    # Nonce check
    if nonce:
        cache_key_nonce = f"deepshield:nonce:{key_id}:{nonce}"
        if cache_key_nonce in _memory_cache:
            return True, f"REPLAY: Nonce '{nonce}' already used for key '{key_id}'"
        _memory_cache[cache_key_nonce] = now

    # Sig digest check
    if cache_key_sig in _memory_cache:
        return True, f"REPLAY: Signature digest already recorded for key '{key_id}'"
    _memory_cache[cache_key_sig] = now
    return False, "No replay detected"


async def evict_key_cache(key_id: str, redis_client=None) -> int:
    """
    Evict all cached nonces and signature digests for a key (used during revocation).
    Returns number of keys evicted.
    """
    evicted = 0
    pattern_nonce = f"deepshield:nonce:{key_id}:*"
    pattern_sig = f"deepshield:sig_replay:{key_id}:*"

    if redis_client:
        try:
            for pattern in [pattern_nonce, pattern_sig]:
                async for k in redis_client.scan_iter(match=pattern, count=100):
                    await redis_client.delete(k)
                    evicted += 1
        except Exception as e:
            logger.error(f"Redis cache eviction failed for key {key_id}: {e}")

    # Also clean in-memory
    prefix_nonce = f"deepshield:nonce:{key_id}:"
    prefix_sig = f"deepshield:sig_replay:{key_id}:"
    to_delete = [k for k in _memory_cache if k.startswith(prefix_nonce) or k.startswith(prefix_sig)]
    for k in to_delete:
        del _memory_cache[k]
        evicted += 1

    logger.info(f"Evicted {evicted} cached entries for key {key_id}")
    return evicted
