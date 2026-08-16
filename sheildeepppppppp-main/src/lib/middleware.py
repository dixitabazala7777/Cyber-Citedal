# DeepShield-Core Layer 1 Identity & Device Verification Gate
# Complete and production-ready FastAPI middleware implementing zero-trust verification.

import time
import logging
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

# Cryptographically secure JWT decoding via python-jose
from jose import jwt, JWTError

# Async non-blocking connection to Redis cluster
import redis.asyncio as aioredis

# Configured telemetry and gateway logs (isolated inside the air-gap)
logger = logging.getLogger("DeepShieldCoreGate")

# Identity claims schema
class IdentityClaims(BaseModel):
    sub: str = Field(..., description="Unique client hardware UUID or certificate identity")
    tenant_id: str = Field(..., description="Organization tenant boundaries")
    scopes: List[str] = Field(default_factory=list, description="OAuth2 assigned scopes")
    vector_partition: str = Field(..., description="Authorized vector database partition identifier")
    exp: int = Field(..., description="Unix expiration timestamp")

class IdentityCheckMiddleware(BaseHTTPMiddleware):
    def __init__(
        self, 
        app: FastAPI, 
        redis_url: str = "redis://localhost:6379/0",
        trusted_fingerprints: Optional[List[str]] = None,
        jwt_public_key: str = "deepshield_ca_secops_public_key_2026",
        jwt_algorithm: str = "HS256"
    ):
        super().__init__(app)
        self.redis_pool = aioredis.ConnectionPool.from_url(redis_url, max_connections=50)
        self.jwt_public_key = jwt_public_key
        self.jwt_algorithm = jwt_algorithm
        self.trusted_fingerprints = trusted_fingerprints or [
            "f8b31a89c36290356cbb015fa4d38c691307b22ee015a9e334bc6ad734fe0ce2"
        ]

    async def _write_telemetry(self, ip: str, identity: str, status_code: int, action_taken: str):
        """
        Asynchronously streams edge telemetry into Redis caches without blocking the ASGI event loop.
        """
        try:
            client = aioredis.Redis(connection_pool=self.redis_pool)
            telemetry_key = f"telemetry:gateway:audit:{int(time.time())}:{ip}"
            mapping = {
                "timestamp": str(time.time()),
                "client_ip": ip,
                "identity": identity,
                "http_status": str(status_code),
                "action": action_taken
            }
            await client.hset(telemetry_key, mapping=mapping)
            await client.expire(telemetry_key, 86400) # Auto-pruning after 24 hours
            await client.close()
        except Exception as e:
            logger.error(f"Async telemetry buffer overflow: {str(e)}")

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start_time = time.perf_counter()
        client_ip = request.client.host if request.client else "127.0.0.1"

        # --- 1. Payload Size Pre-Inspection (Early Exit Circuit Breaker <1ms) ---
        content_length_header = request.headers.get("Content-Length")
        if content_length_header:
            try:
                content_length = int(content_length_header)
                if content_length > 51200: # Max 50KB payload
                    await self._write_telemetry(client_ip, "BLOCKED_PAYLOAD", 413, "REJECT_OVERSIZED_PAYLOAD")
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={"error": "Payload Too Large", "code": "GATEWAY_PAYLOAD_LIMIT_BREACHED"}
                    )
            except ValueError:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"error": "Invalid Content-Length Header", "code": "GATEWAY_MALFORMED_HEADERS"}
                )

        # --- 2. mTLS Fingerprint Verification (Early Exit Circuit Breaker <2ms) ---
        client_verify = request.headers.get("X-Client-Verify")
        client_cert_sha = request.headers.get("X-Client-Cert-SHA256")

        if not client_verify or client_verify != "SUCCESS" or not client_cert_sha:
            await self._write_telemetry(client_ip, "ANONYMOUS_MTLS", 403, "REJECT_MTLS_FAILED")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Access Denied", "code": "GATEWAY_MTLS_FAILED"}
            )

        if client_cert_sha not in self.trusted_fingerprints:
            await self._write_telemetry(client_ip, f"UNTRUSTED_DEVICE_{client_cert_sha[:8]}", 403, "REJECT_MTLS_UNTRUSTED")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Access Denied", "code": "GATEWAY_DEVICE_UNTRUSTED"}
            )

        # --- 3. OAuth2 Bearer JWT Scope Validation (Early Exit Circuit Breaker <5ms) ---
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            await self._write_telemetry(client_ip, "UNAUTHORIZED_JWT", 403, "REJECT_JWT_MISSING")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Access Denied", "code": "GATEWAY_UNAUTHORIZED"}
            )

        token = auth_header.split(" ")[1]

        try:
            # Jose automatically decodes and verifies 'exp' expiration properties securely
            payload = jwt.decode(token, self.jwt_public_key, algorithms=[self.jwt_algorithm])
            claims = IdentityClaims(**payload)
        except JWTError as jwt_err:
            await self._write_telemetry(client_ip, "INVALID_JWT", 403, f"REJECT_JWT_INVALID: {str(jwt_err)}")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Access Denied", "code": "GATEWAY_CREDENTIALS_INVALID"}
            )

        # --- 4. Context-Aware Scope & Vector Database Claims Verification ---
        # AI models mandate write protection pipelines
        required_scopes = {"crimegpt:write", "defense:execute"}
        token_scopes = set(claims.scopes)
        if not required_scopes.intersection(token_scopes):
            await self._write_telemetry(client_ip, claims.sub, 403, "REJECT_SCOPES_INSUFFICIENT")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Access Denied", "code": "GATEWAY_SCOPES_INSUFFICIENT"}
            )

        # Validate partition boundaries mapping directly to tenant permissions
        requested_partition = request.headers.get("X-Target-Partition")
        if requested_partition and claims.vector_partition != requested_partition:
            await self._write_telemetry(client_ip, claims.sub, 403, "REJECT_PARTITION_VIOLATION")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Access Denied", "code": "GATEWAY_PARTITION_VIOLATION"}
            )

        # Bind validated context state for application routes
        request.state.identity = claims

        response = await call_next(request)

        # Non-blocking telemetry output logging
        latency_ms = (time.perf_counter() - start_time) * 1000
        await self._write_telemetry(client_ip, claims.sub, response.status_code, f"ALLOW_INFERENCE ({latency_ms:.2f}ms)")

        return response
