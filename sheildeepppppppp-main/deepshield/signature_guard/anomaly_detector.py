"""
DEEPSHIELD Enterprise — Behavioral & Anomaly Scoring for Signature Usage

Detects abnormal signing patterns:
- Rate spikes: Signing frequency exceeds baseline by > 3 standard deviations
- Impossible travel: Geo-location change faster than 900 km/h
- Off-hours usage: Signing outside allowed operational window
- ASN/IP deviation: Source context doesn't match historical baseline
- Device fingerprint mismatch: New device fingerprint not seen before
"""

import math
import time
import logging
from typing import List, Optional, Tuple
from collections import defaultdict

from .models import AnomalyResult, SignatureVerifyRequest, ProvenanceBinding, TimelineEvent

logger = logging.getLogger("DeepShield.SignatureGuard.AnomalyDetector")

# ─── In-Memory Usage History ───────────────────────────────────────────────
# In production, this would be backed by Redis time-series or PostgreSQL.
_usage_history: dict[str, List[dict]] = defaultdict(list)
_MAX_HISTORY_PER_KEY = 1000

IMPOSSIBLE_TRAVEL_SPEED_KMH = 900  # Max plausible travel speed
RATE_SPIKE_STD_DEVS = 3.0  # Number of std devs above mean for spike detection
RATE_WINDOW_SEC = 60  # Window for rate calculation


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate great-circle distance between two points on Earth using Haversine formula.
    Returns distance in kilometers.
    """
    R = 6371.0  # Earth radius in km
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = math.sin(delta_phi / 2) ** 2 + \
        math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    return R * c


def _record_usage(key_id: str, request: SignatureVerifyRequest):
    """Record a signing event for historical analysis."""
    entry = {
        "timestamp": request.timestamp,
        "source_ip": request.source_ip,
        "source_asn": request.source_asn,
        "device_fingerprint": request.device_fingerprint,
        "geo_lat": request.geo_lat,
        "geo_lon": request.geo_lon,
    }
    history = _usage_history[key_id]
    history.append(entry)
    # Trim to max history
    if len(history) > _MAX_HISTORY_PER_KEY:
        _usage_history[key_id] = history[-_MAX_HISTORY_PER_KEY:]


def _check_rate_spike(key_id: str, current_time: float) -> Tuple[bool, float]:
    """
    Check if current signing rate significantly exceeds historical baseline.
    Returns (is_spike, current_rate_per_minute).
    """
    history = _usage_history.get(key_id, [])
    if len(history) < 5:
        return False, 0.0  # Not enough data for baseline

    # Count events in the last RATE_WINDOW_SEC
    window_start = current_time - RATE_WINDOW_SEC
    recent_count = sum(1 for e in history if e["timestamp"] >= window_start)
    current_rate = recent_count  # events per minute (window = 60s)

    # Compute historical baseline (events per minute over all windows)
    if len(history) < 2:
        return False, current_rate

    total_span = history[-1]["timestamp"] - history[0]["timestamp"]
    if total_span <= 0:
        return False, current_rate

    avg_rate = len(history) / (total_span / RATE_WINDOW_SEC)

    # Simple variance calculation
    window_counts: List[float] = []
    t = history[0]["timestamp"]
    while t < history[-1]["timestamp"]:
        count = sum(1 for e in history if t <= e["timestamp"] < t + RATE_WINDOW_SEC)
        window_counts.append(count)
        t += RATE_WINDOW_SEC

    if len(window_counts) < 2:
        return False, current_rate

    mean = sum(window_counts) / len(window_counts)
    variance = sum((x - mean) ** 2 for x in window_counts) / len(window_counts)
    std_dev = math.sqrt(variance) if variance > 0 else 1.0

    threshold = mean + RATE_SPIKE_STD_DEVS * std_dev
    is_spike = current_rate > threshold and current_rate > 5  # Minimum absolute threshold

    return is_spike, current_rate


def _check_impossible_travel(
    key_id: str,
    current_lat: Optional[float],
    current_lon: Optional[float],
    current_time: float,
) -> Tuple[bool, float, float]:
    """
    Check if geo-location changed faster than physically possible.
    Returns (is_impossible, distance_km, speed_kmh).
    """
    if current_lat is None or current_lon is None:
        return False, 0.0, 0.0

    history = _usage_history.get(key_id, [])

    # Find the most recent event with geo data
    for entry in reversed(history):
        if entry.get("geo_lat") is not None and entry.get("geo_lon") is not None:
            prev_lat = entry["geo_lat"]
            prev_lon = entry["geo_lon"]
            prev_time = entry["timestamp"]

            time_diff_hours = (current_time - prev_time) / 3600.0
            if time_diff_hours <= 0:
                continue

            distance_km = _haversine_km(prev_lat, prev_lon, current_lat, current_lon)
            speed_kmh = distance_km / time_diff_hours

            if speed_kmh > IMPOSSIBLE_TRAVEL_SPEED_KMH and distance_km > 50:
                return True, distance_km, speed_kmh

            return False, distance_km, speed_kmh

    return False, 0.0, 0.0


def analyze_anomaly(
    key_id: str,
    request: SignatureVerifyRequest,
    provenance: ProvenanceBinding,
) -> AnomalyResult:
    """
    Run full behavioral anomaly analysis on a signature verification request.
    Returns an AnomalyResult with risk score and detailed flags.
    """
    result = AnomalyResult()
    risk_components: List[float] = []
    details_parts: List[str] = []

    # 1. Rate spike detection
    is_spike, current_rate = _check_rate_spike(key_id, request.timestamp)
    if is_spike:
        result.rate_spike = True
        result.flags.append("RATE_SPIKE")
        risk_components.append(25.0)
        details_parts.append(f"Rate spike detected: {current_rate:.1f} ops/min (threshold exceeded)")

    # 2. Impossible travel detection
    is_travel, distance, speed = _check_impossible_travel(
        key_id, request.geo_lat, request.geo_lon, request.timestamp
    )
    if is_travel:
        result.impossible_travel = True
        result.flags.append("IMPOSSIBLE_TRAVEL")
        risk_components.append(40.0)
        details_parts.append(
            f"Impossible travel: {distance:.0f} km in {speed:.0f} km/h "
            f"(threshold: {IMPOSSIBLE_TRAVEL_SPEED_KMH} km/h)"
        )

    # 3. Off-hours check
    import datetime
    if provenance.allowed_hours_utc:
        now_hour = datetime.datetime.utcnow().hour
        start, end = provenance.allowed_hours_utc
        in_window = (start <= now_hour < end) if start <= end else (now_hour >= start or now_hour < end)
        if not in_window:
            result.off_hours = True
            result.flags.append("OFF_HOURS")
            risk_components.append(15.0)
            details_parts.append(f"Off-hours signing at UTC {now_hour}:00 (allowed: {start}:00–{end}:00)")

    # 4. ASN mismatch vs historical
    if request.source_asn and provenance.allowed_asns:
        if request.source_asn not in provenance.allowed_asns:
            result.asn_mismatch = True
            result.flags.append("ASN_MISMATCH")
            risk_components.append(20.0)
            details_parts.append(f"ASN mismatch: AS{request.source_asn} not in allowed list")

    # 5. Device fingerprint mismatch
    if request.device_fingerprint and provenance.device_fingerprint_hash:
        import hashlib
        computed = hashlib.sha256(request.device_fingerprint.encode()).hexdigest()
        if computed != provenance.device_fingerprint_hash:
            result.device_mismatch = True
            result.flags.append("DEVICE_MISMATCH")
            risk_components.append(20.0)
            details_parts.append("Device fingerprint does not match registered binding")

    # Compute aggregate risk score (capped at 100)
    result.risk_score = min(100.0, sum(risk_components))
    result.details = " | ".join(details_parts) if details_parts else "No anomalies detected"

    # Record this usage event for future baseline comparison
    _record_usage(key_id, request)

    if result.flags:
        logger.warning(
            f"Anomaly detected for key {key_id}: risk={result.risk_score:.0f}%, "
            f"flags={result.flags}"
        )

    return result
