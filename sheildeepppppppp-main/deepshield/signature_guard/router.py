"""
DEEPSHIELD Enterprise — Signature Guard FastAPI Router

Endpoints:
  POST /api/v1/signature-guard/verify    — Verify a signature through the full pipeline
  GET  /api/v1/signature-guard/keys      — List all registered keys
  POST /api/v1/signature-guard/keys      — Register a new signing key
  POST /api/v1/signature-guard/revoke    — Revoke a compromised key (kill switch)
  POST /api/v1/signature-guard/rotate    — Rotate a key (revoke + generate replacement)
  GET  /api/v1/signature-guard/timeline/{key_id} — Forensic timeline for a key
  POST /api/v1/signature-guard/simulate  — Run a simulation with test keypair
"""

import time
import base64
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .models import (
    SigningKey, KeyAlgorithm, KeyStatus, ProvenanceBinding,
    SignatureVerifyRequest, SignatureVerifyResponse, VerifyOutcome,
    AnomalyResult,
)
from .verifier import verify_signature, generate_test_keypair, sign_payload
from .provenance import check_provenance
from .replay_cache import check_replay_sync
from .anomaly_detector import analyze_anomaly
from .kill_switch import (
    register_key, get_key, list_keys, revoke_key, rotate_key,
    get_timeline, get_revocation_log, record_verify_event,
)

logger = logging.getLogger("DeepShield.SignatureGuard.Router")

router = APIRouter(prefix="/api/v1/signature-guard", tags=["Signature Guard"])

# ─── Request / Response Models ─────────────────────────────────────────────

class RegisterKeyRequest(BaseModel):
    algorithm: str = Field(..., description="Key algorithm: RSA-PSS, RSA-PKCS1v1.5, ECDSA-P256, ECDSA-P384, Ed25519")
    public_key_pem: str
    owner_identity: str
    allowed_ip_cidrs: list[str] = []
    allowed_asns: list[int] = []
    device_fingerprint_hash: Optional[str] = None
    service_context: Optional[str] = None
    max_signing_rate_per_minute: int = 60

class RevokeRequest(BaseModel):
    key_id: str
    reason: str
    actor: str = "dashboard_user"

class RotateRequest(BaseModel):
    key_id: str
    reason: str = "Manual rotation"
    actor: str = "dashboard_user"

class SimulateRequest(BaseModel):
    algorithm: str = "Ed25519"
    payload_text: str = "Hello, DEEPSHIELD!"
    scenario: str = "valid"  # valid, tampered, replay, stolen_key, impossible_travel
    source_ip: Optional[str] = "10.0.1.42"
    geo_lat: Optional[float] = 28.6139
    geo_lon: Optional[float] = 77.2090

# ─── Endpoints ─────────────────────────────────────────────────────────────

@router.get("/keys")
async def api_list_keys():
    """List all registered signing keys."""
    keys = list_keys()
    return {
        "keys": [k.model_dump() for k in keys],
        "total": len(keys),
    }


@router.post("/keys")
async def api_register_key(req: RegisterKeyRequest):
    """Register a new signing key with provenance binding."""
    try:
        algo = KeyAlgorithm(req.algorithm)
    except ValueError:
        raise HTTPException(400, f"Invalid algorithm: {req.algorithm}. Supported: {[a.value for a in KeyAlgorithm]}")

    provenance = ProvenanceBinding(
        owner_identity=req.owner_identity,
        allowed_ip_cidrs=req.allowed_ip_cidrs,
        allowed_asns=req.allowed_asns,
        device_fingerprint_hash=req.device_fingerprint_hash,
        service_context=req.service_context,
        max_signing_rate_per_minute=req.max_signing_rate_per_minute,
    )

    key = SigningKey(
        algorithm=algo,
        public_key_pem=req.public_key_pem,
        provenance=provenance,
    )

    key_id = register_key(key)
    return {"key_id": key_id, "status": "ACTIVE", "algorithm": algo.value}


@router.post("/verify")
async def api_verify_signature(req: SignatureVerifyRequest):
    """
    Full 4-stage verification pipeline:
    1. Cryptographic verification
    2. Replay detection
    3. Provenance binding check
    4. Behavioral anomaly scoring
    """
    start_time = time.time()

    # Look up key
    key = get_key(req.key_id)
    if not key:
        return SignatureVerifyResponse(
            key_id=req.key_id,
            outcome=VerifyOutcome.KEY_NOT_FOUND,
            message=f"Signing key '{req.key_id}' not found in registry",
        ).model_dump()

    # Check if key is revoked
    if key.status in (KeyStatus.REVOKED, KeyStatus.ROTATED):
        record_verify_event(req.key_id, "REJECTED_REVOKED", req.source_ip, req.geo_lat, req.geo_lon, 100.0)
        return SignatureVerifyResponse(
            key_id=req.key_id,
            outcome=VerifyOutcome.KEY_REVOKED,
            message=f"Key '{req.key_id}' has been revoked: {key.revocation_reason or 'No reason given'}",
        ).model_dump()

    # ── Stage 1: Cryptographic Verification ───────────────────────────────
    crypto_valid, crypto_msg = verify_signature(
        key.algorithm, key.public_key_pem, req.payload_b64, req.signature_b64
    )

    if not crypto_valid:
        record_verify_event(req.key_id, "INVALID_SIGNATURE", req.source_ip, req.geo_lat, req.geo_lon, 80.0, crypto_msg)
        return SignatureVerifyResponse(
            key_id=req.key_id,
            outcome=VerifyOutcome.INVALID_SIGNATURE,
            cryptographic_valid=False,
            message=crypto_msg,
            processing_time_ms=(time.time() - start_time) * 1000,
        ).model_dump()

    # ── Stage 2: Replay Detection ─────────────────────────────────────────
    is_replay, replay_msg = check_replay_sync(
        req.key_id, req.payload_b64, req.signature_b64, req.nonce
    )

    if is_replay:
        record_verify_event(req.key_id, "REPLAY_DETECTED", req.source_ip, req.geo_lat, req.geo_lon, 90.0, replay_msg)
        return SignatureVerifyResponse(
            key_id=req.key_id,
            outcome=VerifyOutcome.REPLAY_DETECTED,
            cryptographic_valid=True,
            replay_check_passed=False,
            message=replay_msg,
            processing_time_ms=(time.time() - start_time) * 1000,
        ).model_dump()

    # ── Stage 3: Provenance Binding Check ─────────────────────────────────
    prov_passed, prov_violations = check_provenance(key.provenance, req)

    if not prov_passed:
        record_verify_event(req.key_id, "PROVENANCE_MISMATCH", req.source_ip, req.geo_lat, req.geo_lon, 70.0,
                           "; ".join(prov_violations))
        return SignatureVerifyResponse(
            key_id=req.key_id,
            outcome=VerifyOutcome.PROVENANCE_MISMATCH,
            cryptographic_valid=True,
            replay_check_passed=True,
            provenance_check_passed=False,
            message=f"Provenance violations: {'; '.join(prov_violations)}",
            processing_time_ms=(time.time() - start_time) * 1000,
        ).model_dump()

    # ── Stage 4: Behavioral Anomaly Scoring ───────────────────────────────
    anomaly = analyze_anomaly(req.key_id, req, key.provenance)

    # Update key stats
    key.last_used_at = time.time()
    key.total_signatures += 1
    key.risk_score = anomaly.risk_score

    # Determine outcome based on anomaly risk
    if anomaly.risk_score >= 70.0:
        outcome = VerifyOutcome.ANOMALY_DETECTED
        msg = f"High anomaly risk ({anomaly.risk_score:.0f}%): {anomaly.details}"
    else:
        outcome = VerifyOutcome.VALID
        msg = f"Signature verified. Risk: {anomaly.risk_score:.0f}%"

    record_verify_event(
        req.key_id, outcome.value, req.source_ip, req.geo_lat, req.geo_lon,
        anomaly.risk_score, msg
    )

    return SignatureVerifyResponse(
        key_id=req.key_id,
        outcome=outcome,
        cryptographic_valid=True,
        replay_check_passed=True,
        provenance_check_passed=True,
        anomaly=anomaly,
        message=msg,
        processing_time_ms=(time.time() - start_time) * 1000,
    ).model_dump()


@router.post("/revoke")
async def api_revoke_key(req: RevokeRequest):
    """Execute the kill switch — immediately revoke a compromised key."""
    success, record, msg = await revoke_key(
        req.key_id, req.reason, req.actor
    )
    if not success:
        raise HTTPException(400, msg)
    return {
        "success": True,
        "message": msg,
        "revocation_record": record.model_dump() if record else None,
    }


@router.post("/rotate")
async def api_rotate_key(req: RotateRequest):
    """Rotate a key: revoke + generate replacement with same provenance."""
    success, new_key, msg = await rotate_key(
        req.key_id, req.reason, req.actor
    )
    if not success:
        raise HTTPException(400, msg)
    return {
        "success": True,
        "message": msg,
        "new_key": new_key.model_dump() if new_key else None,
    }


@router.get("/timeline/{key_id}")
async def api_get_timeline(key_id: str):
    """Get forensic timeline for a signing key."""
    events = get_timeline(key_id)
    return {
        "key_id": key_id,
        "events": [e.model_dump() for e in events],
        "total": len(events),
    }


@router.get("/revocation-log")
async def api_get_revocation_log():
    """Get all revocation records."""
    records = get_revocation_log()
    return {
        "records": [r.model_dump() for r in records],
        "total": len(records),
    }


@router.post("/simulate")
async def api_simulate(req: SimulateRequest):
    """
    Run a full simulation with auto-generated test keypair.
    Scenarios: valid, tampered, replay, stolen_key, impossible_travel
    """
    try:
        algo = KeyAlgorithm(req.algorithm)
    except ValueError:
        algo = KeyAlgorithm.ED25519

    # Generate test keypair
    priv_pem, pub_pem = generate_test_keypair(algo)
    payload_b64 = base64.b64encode(req.payload_text.encode()).decode()

    # Sign the payload
    sig_b64 = sign_payload(algo, priv_pem, payload_b64)

    # Register key with provenance
    provenance = ProvenanceBinding(
        owner_identity="simulation-user",
        allowed_ip_cidrs=["10.0.0.0/8"],
        allowed_asns=[13335],
        service_context="simulation",
    )

    key = SigningKey(
        algorithm=algo,
        public_key_pem=pub_pem,
        provenance=provenance,
    )
    key_id = register_key(key)

    # Build verification request based on scenario
    verify_req = SignatureVerifyRequest(
        key_id=key_id,
        payload_b64=payload_b64,
        signature_b64=sig_b64,
        nonce=f"sim-nonce-{time.time()}",
        source_ip=req.source_ip or "10.0.1.42",
        source_asn=13335,
        geo_lat=req.geo_lat,
        geo_lon=req.geo_lon,
    )

    if req.scenario == "tampered":
        # Tamper with the signature
        verify_req.signature_b64 = base64.b64encode(b"TAMPERED_SIGNATURE_DATA").decode()
    elif req.scenario == "replay":
        # First verify (should pass), then verify again (should detect replay)
        first_result = await api_verify_signature(verify_req)
        # Same request again
        verify_req.nonce = verify_req.nonce  # Same nonce
        second_result = await api_verify_signature(verify_req)
        return {
            "scenario": "replay",
            "first_verification": first_result,
            "replay_attempt": second_result,
            "key_id": key_id,
        }
    elif req.scenario == "stolen_key":
        # Change source IP to outside allowed range
        verify_req.source_ip = "203.0.113.1"
        verify_req.source_asn = 99999
    elif req.scenario == "impossible_travel":
        # First verify from one location
        first_result = await api_verify_signature(verify_req)
        # Then immediately from a very distant location
        verify_req.nonce = f"sim-nonce-travel-{time.time()}"
        verify_req.geo_lat = -33.8688  # Sydney, AU
        verify_req.geo_lon = 151.2093
        verify_req.signature_b64 = sign_payload(algo, priv_pem, payload_b64)
        second_result = await api_verify_signature(verify_req)
        return {
            "scenario": "impossible_travel",
            "first_verification": first_result,
            "travel_attempt": second_result,
            "key_id": key_id,
        }

    # Default: single verification
    result = await api_verify_signature(verify_req)
    return {
        "scenario": req.scenario,
        "verification": result,
        "key_id": key_id,
    }
