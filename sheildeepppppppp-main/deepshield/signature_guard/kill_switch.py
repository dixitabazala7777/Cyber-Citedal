"""
DEEPSHIELD Enterprise — Compromised Key Kill Switch

Immediate revocation workflow:
1. Mark key as REVOKED in the key store
2. Evict all cached nonces/digests for the key from Redis
3. Generate a Merkle audit ledger entry for tamper-proof revocation proof
4. Optionally generate a replacement key and rotate provenance bindings
"""

import time
import uuid
import logging
from typing import Optional, Tuple

from .models import (
    SigningKey, KeyStatus, KeyAlgorithm, ProvenanceBinding,
    RevocationRecord, TimelineEvent,
)
from .verifier import generate_test_keypair
from .replay_cache import evict_key_cache

logger = logging.getLogger("DeepShield.SignatureGuard.KillSwitch")

# ─── In-Memory Key Store (Production → PostgreSQL/Supabase) ────────────────
_key_store: dict[str, SigningKey] = {}
_revocation_log: list[RevocationRecord] = []
_timeline_log: dict[str, list[TimelineEvent]] = {}


def register_key(key: SigningKey) -> str:
    """Register a signing key in the store. Returns key_id."""
    _key_store[key.key_id] = key
    _record_timeline(key.key_id, "REGISTER", "KEY_REGISTERED",
                     details=f"Algorithm: {key.algorithm.value}, Owner: {key.provenance.owner_identity}")
    logger.info(f"Registered key {key.key_id} ({key.algorithm.value}) for {key.provenance.owner_identity}")
    return key.key_id


def get_key(key_id: str) -> Optional[SigningKey]:
    """Retrieve a signing key by ID."""
    return _key_store.get(key_id)


def list_keys() -> list[SigningKey]:
    """List all registered signing keys."""
    return list(_key_store.values())


async def revoke_key(
    key_id: str,
    reason: str,
    actor: str = "system",
    redis_client=None,
) -> Tuple[bool, RevocationRecord | None, str]:
    """
    Execute the kill switch for a compromised key.

    1. Mark key as REVOKED
    2. Evict all cached entries
    3. Log revocation record
    4. Record timeline event

    Returns (success, revocation_record, message).
    """
    key = _key_store.get(key_id)
    if not key:
        return False, None, f"Key '{key_id}' not found"

    if key.status == KeyStatus.REVOKED:
        return False, None, f"Key '{key_id}' is already revoked"

    # 1. Mark as revoked
    key.status = KeyStatus.REVOKED
    key.revoked_at = time.time()
    key.revocation_reason = reason

    # 2. Evict all cached entries
    evicted = await evict_key_cache(key_id, redis_client)

    # 3. Create revocation record
    record = RevocationRecord(
        key_id=key_id,
        reason=reason,
        actor=actor,
    )
    _revocation_log.append(record)

    # 4. Record timeline
    _record_timeline(
        key_id, "REVOKE", "KEY_REVOKED",
        details=f"Reason: {reason} | Actor: {actor} | Cache entries evicted: {evicted}",
        risk_score=100.0,
    )

    logger.warning(
        f"KILL SWITCH ACTIVATED: Key {key_id} revoked. Reason: {reason}. "
        f"Actor: {actor}. Evicted {evicted} cache entries."
    )

    return True, record, f"Key {key_id} revoked successfully. {evicted} cache entries evicted."


async def rotate_key(
    old_key_id: str,
    reason: str = "Scheduled rotation",
    actor: str = "system",
    redis_client=None,
) -> Tuple[bool, Optional[SigningKey], str]:
    """
    Rotate a key: revoke the old one and generate a replacement with the same provenance.

    Returns (success, new_key | None, message).
    """
    old_key = _key_store.get(old_key_id)
    if not old_key:
        return False, None, f"Key '{old_key_id}' not found"

    # Generate new key pair
    priv_pem, pub_pem = generate_test_keypair(old_key.algorithm)

    # Create new key with same provenance
    new_key = SigningKey(
        algorithm=old_key.algorithm,
        public_key_pem=pub_pem,
        provenance=old_key.provenance,
        rotated_from=old_key_id,
    )

    # Revoke old key
    success, rev_record, msg = await revoke_key(
        old_key_id,
        reason=f"Rotated: {reason}",
        actor=actor,
        redis_client=redis_client,
    )

    if not success:
        return False, None, f"Failed to revoke old key: {msg}"

    # Mark old key as rotated (not just revoked)
    old_key.status = KeyStatus.ROTATED

    # Update revocation record with replacement
    if rev_record:
        rev_record.replacement_key_id = new_key.key_id

    # Register new key
    register_key(new_key)

    _record_timeline(
        new_key.key_id, "ROTATE_IN", "KEY_ROTATED_IN",
        details=f"Replacement for {old_key_id}. Reason: {reason}",
    )

    logger.info(
        f"Key rotation complete: {old_key_id} → {new_key.key_id} "
        f"({old_key.algorithm.value})"
    )

    return True, new_key, f"Rotation complete: {old_key_id} → {new_key.key_id}"


def get_timeline(key_id: str) -> list[TimelineEvent]:
    """Get forensic timeline for a key."""
    return _timeline_log.get(key_id, [])


def get_all_timelines() -> dict[str, list[TimelineEvent]]:
    """Get all forensic timelines."""
    return dict(_timeline_log)


def get_revocation_log() -> list[RevocationRecord]:
    """Get all revocation records."""
    return list(_revocation_log)


def _record_timeline(
    key_id: str,
    event_type: str,
    outcome: str,
    source_ip: Optional[str] = None,
    geo_lat: Optional[float] = None,
    geo_lon: Optional[float] = None,
    risk_score: float = 0.0,
    details: str = "",
):
    """Record an event in the forensic timeline."""
    event = TimelineEvent(
        key_id=key_id,
        event_type=event_type,
        outcome=outcome,
        source_ip=source_ip,
        geo_lat=geo_lat,
        geo_lon=geo_lon,
        risk_score=risk_score,
        details=details,
    )
    if key_id not in _timeline_log:
        _timeline_log[key_id] = []
    _timeline_log[key_id].append(event)


def record_verify_event(
    key_id: str,
    outcome: str,
    source_ip: Optional[str] = None,
    geo_lat: Optional[float] = None,
    geo_lon: Optional[float] = None,
    risk_score: float = 0.0,
    details: str = "",
):
    """Public interface to record a verification event in the timeline."""
    _record_timeline(
        key_id, "VERIFY", outcome,
        source_ip=source_ip,
        geo_lat=geo_lat,
        geo_lon=geo_lon,
        risk_score=risk_score,
        details=details,
    )
