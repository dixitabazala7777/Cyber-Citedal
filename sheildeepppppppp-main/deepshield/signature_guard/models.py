"""
DEEPSHIELD Enterprise — Signature Guard Data Models

Pydantic models for signing keys, provenance bindings,
verification requests, anomaly results, and revocation records.
"""

from __future__ import annotations
import time
import uuid
from typing import Optional, List
from enum import Enum
from pydantic import BaseModel, Field


class KeyAlgorithm(str, Enum):
    RSA_PSS = "RSA-PSS"
    RSA_PKCS1 = "RSA-PKCS1v1.5"
    ECDSA_P256 = "ECDSA-P256"
    ECDSA_P384 = "ECDSA-P384"
    ECDSA_SECP256K1 = "ECDSA-secp256k1"
    ED25519 = "Ed25519"


class KeyStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    ROTATED = "ROTATED"
    SUSPENDED = "SUSPENDED"
    EXPIRED = "EXPIRED"


class ProvenanceBinding(BaseModel):
    """
    Identity + context binding for a signing key.
    Used to verify that signature usage matches expected origin.
    """
    owner_identity: str = Field(..., description="User/service identity (e.g., 'svc:api-gateway-prod')")
    device_fingerprint_hash: Optional[str] = Field(None, description="SHA-256 hash of device fingerprint")
    allowed_ip_cidrs: List[str] = Field(default_factory=list, description="Allowed source IP CIDRs (e.g., ['10.0.0.0/8', '172.16.0.0/12'])")
    allowed_asns: List[int] = Field(default_factory=list, description="Allowed Autonomous System Numbers")
    service_context: Optional[str] = Field(None, description="Service partition tag (e.g., 'prod-us-east-1')")
    max_signing_rate_per_minute: int = Field(default=60, description="Maximum signing operations per minute")
    allowed_hours_utc: Optional[tuple[int, int]] = Field(None, description="Allowed hours (start, end) in UTC. None = 24/7")


class SigningKey(BaseModel):
    """Represents a registered signing key in the system."""
    key_id: str = Field(default_factory=lambda: f"key-{uuid.uuid4().hex[:12]}")
    algorithm: KeyAlgorithm
    public_key_pem: str = Field(..., description="PEM-encoded public key")
    status: KeyStatus = KeyStatus.ACTIVE
    provenance: ProvenanceBinding
    created_at: float = Field(default_factory=time.time)
    rotated_from: Optional[str] = Field(None, description="Key ID this was rotated from")
    revoked_at: Optional[float] = None
    revocation_reason: Optional[str] = None
    last_used_at: Optional[float] = None
    total_signatures: int = 0
    risk_score: float = 0.0  # 0–100


class SignatureVerifyRequest(BaseModel):
    """Inbound request to verify a digital signature."""
    key_id: str
    payload_b64: str = Field(..., description="Base64-encoded payload that was signed")
    signature_b64: str = Field(..., description="Base64-encoded signature bytes")
    nonce: Optional[str] = Field(None, description="One-time nonce for replay prevention")
    timestamp: float = Field(default_factory=time.time)
    source_ip: Optional[str] = None
    source_asn: Optional[int] = None
    device_fingerprint: Optional[str] = None
    geo_lat: Optional[float] = None
    geo_lon: Optional[float] = None


class VerifyOutcome(str, Enum):
    VALID = "VALID"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    PROVENANCE_MISMATCH = "PROVENANCE_MISMATCH"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    KEY_REVOKED = "KEY_REVOKED"
    KEY_NOT_FOUND = "KEY_NOT_FOUND"
    VERIFICATION_ERROR = "VERIFICATION_ERROR"


class AnomalyResult(BaseModel):
    """Result of behavioral anomaly analysis on a signature event."""
    risk_score: float = 0.0
    flags: List[str] = Field(default_factory=list)
    rate_spike: bool = False
    impossible_travel: bool = False
    off_hours: bool = False
    asn_mismatch: bool = False
    ip_out_of_range: bool = False
    device_mismatch: bool = False
    details: str = ""


class SignatureVerifyResponse(BaseModel):
    """Full response from the signature verification pipeline."""
    request_id: str = Field(default_factory=lambda: f"req-{uuid.uuid4().hex[:8]}")
    key_id: str
    outcome: VerifyOutcome
    cryptographic_valid: bool = False
    replay_check_passed: bool = False
    provenance_check_passed: bool = False
    anomaly: Optional[AnomalyResult] = None
    message: str = ""
    processing_time_ms: float = 0.0
    merkle_leaf_hash: Optional[str] = None


class RevocationRecord(BaseModel):
    """Immutable record of a key revocation event."""
    record_id: str = Field(default_factory=lambda: f"rev-{uuid.uuid4().hex[:8]}")
    key_id: str
    revoked_at: float = Field(default_factory=time.time)
    reason: str
    actor: str = "system"
    replacement_key_id: Optional[str] = None
    merkle_leaf_hash: Optional[str] = None


class TimelineEvent(BaseModel):
    """A single event in the forensic timeline for a signing key."""
    event_id: str = Field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:8]}")
    key_id: str
    timestamp: float = Field(default_factory=time.time)
    event_type: str  # e.g., "VERIFY", "ANOMALY", "REVOKE", "ROTATE", "REGISTER"
    outcome: str
    source_ip: Optional[str] = None
    geo_lat: Optional[float] = None
    geo_lon: Optional[float] = None
    risk_score: float = 0.0
    details: str = ""
