"""
DEEPSHIELD Enterprise — Key Provenance & Binding Checker

Verifies that the source context (IP, ASN, device fingerprint, service partition)
of a signing event matches the registered provenance bindings for the key.
"""

import hashlib
import ipaddress
import logging
from typing import Tuple, List

from .models import ProvenanceBinding, SignatureVerifyRequest

logger = logging.getLogger("DeepShield.SignatureGuard.Provenance")


def _ip_in_cidrs(ip_str: str, cidrs: List[str]) -> bool:
    """Check if an IP address is within any of the allowed CIDRs."""
    if not ip_str or not cidrs:
        return True  # No binding = no restriction (but provenance is optional)
    try:
        ip = ipaddress.ip_address(ip_str)
        for cidr in cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                if ip in network:
                    return True
            except ValueError:
                continue
        return False
    except ValueError:
        return False


def _check_device_fingerprint(request_fp: str | None, bound_fp_hash: str | None) -> bool:
    """Compare device fingerprint hash."""
    if not bound_fp_hash:
        return True  # No fingerprint binding
    if not request_fp:
        return False  # Binding exists but no fingerprint provided → fail closed
    computed_hash = hashlib.sha256(request_fp.encode()).hexdigest()
    return computed_hash == bound_fp_hash


def _check_asn(source_asn: int | None, allowed_asns: List[int]) -> bool:
    """Check if source ASN is in the allowed list."""
    if not allowed_asns:
        return True  # No ASN binding
    if source_asn is None:
        return False  # Binding exists but no ASN → fail closed
    return source_asn in allowed_asns


def _check_hours(binding: ProvenanceBinding) -> bool:
    """Check if current UTC hour is within allowed operational hours."""
    import datetime
    if binding.allowed_hours_utc is None:
        return True  # No time restriction
    now_hour = datetime.datetime.utcnow().hour
    start, end = binding.allowed_hours_utc
    if start <= end:
        return start <= now_hour < end
    else:
        # Wraps around midnight (e.g., 22–06)
        return now_hour >= start or now_hour < end


def check_provenance(
    binding: ProvenanceBinding,
    request: SignatureVerifyRequest,
) -> Tuple[bool, List[str]]:
    """
    Verify that the signature request's context matches the key's provenance binding.

    Returns:
        (passed, list_of_violation_flags)
    """
    violations: List[str] = []

    # 1. IP CIDR check
    if binding.allowed_ip_cidrs and request.source_ip:
        if not _ip_in_cidrs(request.source_ip, binding.allowed_ip_cidrs):
            violations.append(f"IP_OUT_OF_RANGE: {request.source_ip} not in {binding.allowed_ip_cidrs}")

    # 2. ASN check
    if not _check_asn(request.source_asn, binding.allowed_asns):
        violations.append(f"ASN_MISMATCH: source ASN {request.source_asn} not in {binding.allowed_asns}")

    # 3. Device fingerprint check
    if not _check_device_fingerprint(request.device_fingerprint, binding.device_fingerprint_hash):
        violations.append("DEVICE_MISMATCH: device fingerprint does not match registered binding")

    # 4. Operational hours check
    if not _check_hours(binding):
        violations.append("OFF_HOURS: signing attempt outside allowed operational hours")

    passed = len(violations) == 0

    if not passed:
        logger.warning(
            f"Provenance check FAILED for key owner '{binding.owner_identity}': "
            f"{len(violations)} violation(s) — {', '.join(violations)}"
        )

    return passed, violations
