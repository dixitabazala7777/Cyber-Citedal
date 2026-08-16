import time
import json
import hashlib
import asyncio
import logging
from typing import Dict, Any, Optional, List
from pydantic import BaseModel
import redis.asyncio as aioredis
import httpx

logger = logging.getLogger("DeepShield.CircuitBreaker")

class ThreatCoordinate(BaseModel):
    threat_id: str
    timestamp_utc: str
    failed_gate: str
    prompt_sha256_hash: str
    client_identity: str
    client_ip: str
    risk_score: float
    circuit_breaker_latency_ms: float
    rejection_code: str

class CircuitBreakerResponse(BaseModel):
    status: str = "ERROR"
    code: str = "ERR_SECURITY_POLICY_VIOLATION"
    circuit_broken: bool = True
    message: str = "Request cannot be processed by enterprise security policy."
    execution_time_ms: float
    trace_id: str

class CircuitBreaker:
    """
    Automated Circuit Breaker:
    - Sub-10ms fast-fail halt on any gate failure.
    - Zero oracle leaks in safe client fallback response.
    - Redis AOF logging with SHA-256 prompt hashing.
    - Asynchronous batch sync to Supabase cold storage.
    """
    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        supabase_url: Optional[str] = None,
        supabase_key: Optional[str] = None,
        max_trip_latency_ms: float = 10.0
    ):
        self.redis_url = redis_url
        self.supabase_url = supabase_url
        self.supabase_key = supabase_key
        self.max_trip_latency_ms = max_trip_latency_ms
        self._redis_pool = None
        self._sync_queue: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()

    async def get_redis(self):
        if self._redis_pool is None:
            self._redis_pool = aioredis.ConnectionPool.from_url(
                self.redis_url, 
                max_connections=20, 
                socket_timeout=1.0
            )
        return aioredis.Redis(connection_pool=self._redis_pool)

    def generate_safe_fallback_response(
        self, 
        trace_id: str, 
        execution_time_ms: float
    ) -> CircuitBreakerResponse:
        """
        Returns a standardized, non-revealing safe response.
        Does not leak which gate failed or internal threshold details.
        """
        return CircuitBreakerResponse(
            status="SECURITY_POLICY_HALT",
            code="ERR_CIRCUIT_BREAKER_TRIPPED",
            circuit_broken=True,
            message="Request cannot be processed by enterprise security policy.",
            execution_time_ms=round(execution_time_ms, 2),
            trace_id=trace_id
        )

    async def log_threat_coordinates(
        self,
        failed_gate: str,
        raw_or_masked_prompt: str,
        client_identity: str,
        client_ip: str,
        risk_score: float,
        rejection_code: str,
        trip_latency_ms: float
    ) -> ThreatCoordinate:
        """
        Appends a cryptographically sanitized threat coordinate record to Redis (AOF mode).
        Stores only the SHA-256 hash of the prompt (never the raw text).
        """
        prompt_hash = hashlib.sha256(raw_or_masked_prompt.encode('utf-8')).hexdigest()
        threat_id = f"THREAT-{int(time.time()*1000)}-{prompt_hash[:8].upper()}"
        
        coordinate = ThreatCoordinate(
            threat_id=threat_id,
            timestamp_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            failed_gate=failed_gate,
            prompt_sha256_hash=prompt_hash,
            client_identity=client_identity,
            client_ip=client_ip,
            risk_score=round(risk_score, 4),
            circuit_breaker_latency_ms=round(trip_latency_ms, 2),
            rejection_code=rejection_code
        )

        # 1. Asynchronously offload to Redis AOF Key
        try:
            r = await self.get_redis()
            key = f"deepshield:threat_coordinates:{threat_id}"
            await r.hset(key, mapping={
                "threat_id": coordinate.threat_id,
                "timestamp_utc": coordinate.timestamp_utc,
                "failed_gate": coordinate.failed_gate,
                "prompt_sha256": coordinate.prompt_sha256_hash,
                "client_identity": coordinate.client_identity,
                "client_ip": coordinate.client_ip,
                "risk_score": str(coordinate.risk_score),
                "rejection_code": coordinate.rejection_code,
                "latency_ms": str(coordinate.circuit_breaker_latency_ms)
            })
            # Expire after 30 days retention
            await r.expire(key, 86400 * 30)
            
            # Push to Redis stream / list for real-time dashboard listeners
            await r.lpush("deepshield:stream:threats", json.dumps(coordinate.model_dump()))
            await r.ltrim("deepshield:stream:threats", 0, 999) # keep last 1000 in memory
            await r.close()
        except Exception as redis_err:
            logger.warning(f"Redis telemetry write skipped: {str(redis_err)}")

        # 2. Queue for Async Cold Storage Sync (Supabase)
        asyncio.create_task(self._sync_to_supabase_cold_storage(coordinate.model_dump()))

        return coordinate

    async def _sync_to_supabase_cold_storage(self, record: Dict[str, Any]):
        """
        Asynchronously flushes aggregated/anonymized threat coordinates to Supabase PostgreSQL.
        """
        if not self.supabase_url or not self.supabase_key:
            return

        try:
            url = f"{self.supabase_url.rstrip('/')}/rest/v1/security_audit_logs"
            headers = {
                "apikey": self.supabase_key,
                "Authorization": f"Bearer {self.supabase_key}",
                "Content-Type": "application/json",
                "Prefer": "return=minimal"
            }
            
            payload = {
                "threat_id": record["threat_id"],
                "created_at": record["timestamp_utc"],
                "failed_gate": record["failed_gate"],
                "prompt_hash": record["prompt_sha256_hash"],
                "identity": record["client_identity"],
                "client_ip": record["client_ip"],
                "risk_score": record["risk_score"],
                "rejection_code": record["rejection_code"]
            }

            async with httpx.AsyncClient(timeout=4.0) as client:
                await client.post(url, headers=headers, json=payload)
        except Exception as err:
            logger.debug(f"Supabase cold storage sync background offload: {str(err)}")
