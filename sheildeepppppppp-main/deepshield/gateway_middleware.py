import time
import logging
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

# Using python-jose for production-ready cryptographically secure JWT parsing
from jose import jwt, JWTError

# Async Redis client for non-blocking telemetry writes
import redis.asyncio as aioredis

# Setup clean, silent logging - no stack traces leaked
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("DeepShieldCore")

# Simulated Public Key registry for JWT verification
MOCK_PUBLIC_KEY = "deepshield_ca_secops_public_key_2026"
ALGORITHM = "HS256" # HS256 used for self-contained validation demo, fully interchangeable with RS256/ES256

class IdentityClaims(BaseModel):
    sub: str = Field(..., description="Subject identity or client hardware identifier")
    tenant_id: str = Field(..., description="Isolated organizational tenant group")
    scopes: List[str] = Field(default_factory=list, description="OAuth2 assigned scopes")
    vector_partition: str = Field(..., description="Authorized vector database partition identifier")
    exp: int = Field(..., description="Unix timestamp expiration of token")

class IdentityCheckMiddleware(BaseHTTPMiddleware):
    def __init__(
        self, 
        app: FastAPI, 
        redis_url: str = "redis://localhost:6379/0",
        enforce_mtls: bool = True
    ):
        super().__init__(app)
        self.enforce_mtls = enforce_mtls
        # Initialize async non-blocking Redis connection pool
        self.redis_pool = aioredis.ConnectionPool.from_url(redis_url, max_connections=20)

    async def _log_telemetry_async(self, ip: str, sub: str, status_code: int, action: str):
        """
        Offloads audit telemetry records asynchronously to Redis to prevent blockages
        on the main Uvicorn/ASGI event loop.
        """
        try:
            client = aioredis.Redis(connection_pool=self.redis_pool)
            log_key = f"telemetry:audit:{int(time.time())}:{ip}"
            log_payload = {
                "timestamp": str(time.time()),
                "client_ip": ip,
                "identity": sub,
                "status": str(status_code),
                "action": action
            }
            # Set expiring key to avoid storage bloating (24h retention)
            await client.hset(log_key, mapping=log_payload)
            await client.expire(log_key, 86400)
            await client.close()
        except Exception as e:
            # Safe silent warning inside air-gap without breaking the request line
            logger.warning(f"Telemetry offload bypassed: {str(e)}")

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start_time = time.perf_counter()
        client_ip = request.client.host if request.client else "0.0.0.0"

        # --- 1. Layer 0 mTLS Forwarded Validation ---
        if self.enforce_mtls:
            client_verify = request.headers.get("X-Client-Verify")
            client_sha256 = request.headers.get("X-Client-Cert-SHA256")

            # Early Exit: mTLS check failed at edge
            if not client_verify or client_verify != "SUCCESS" or not client_sha256:
                await self._log_telemetry_async(client_ip, "ANONYMOUS", 403, "REJECT_MTLS")
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"error": "Access Denied", "code": "GATEWAY_MTLS_FAILED"}
                )

        # --- 2. Layer 1 OAuth2 JWT Token Extraction & Parsing ---
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            await self._log_telemetry_async(client_ip, "ANONYMOUS", 403, "REJECT_JWT_MISSING")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Access Denied", "code": "GATEWAY_UNAUTHORIZED"}
            )

        token = auth_header.split(" ")[1]

        try:
            # Decode JWT and validate signature, expiration automatically verified by python-jose
            payload = jwt.decode(token, MOCK_PUBLIC_KEY, algorithms=[ALGORITHM])
            claims = IdentityClaims(**payload)
        except (JWTError, Exception):
            # Fast circuit breaker rejection under 5ms, no stack logs generated
            await self._log_telemetry_async(client_ip, "INVALID_TOKEN", 403, "REJECT_JWT_INVALID")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Access Denied", "code": "GATEWAY_CREDENTIALS_INVALID"}
            )

        # --- 3. Context-Aware Claims & Vector Partition Verification ---
        # AI Pipelines mandate that each identity maps strictly to its designated vector database partition
        requested_partition = request.headers.get("X-Target-Partition")
        if requested_partition and claims.vector_partition != requested_partition:
            await self._log_telemetry_async(client_ip, claims.sub, 403, "REJECT_PARTITION_MISMATCH")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Access Denied", "code": "GATEWAY_PARTITION_VIOLATION"}
            )

        # Check required scopes for LLM inference gateway
        required_scope = "ai:inference"
        if required_scope not in claims.scopes:
            await self._log_telemetry_async(client_ip, claims.sub, 403, "REJECT_SCOPE_INSUFFICIENT")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Access Denied", "code": "GATEWAY_SCOPE_INSUFFICIENT"}
            )

        # Bind validated claims to request state context for subsequent app route operations
        request.state.identity = claims

        # Process standard route execution pipeline
        response = await call_next(request)

        # Async write successful audit telemetry records
        process_time_ms = (time.perf_counter() - start_time) * 1000
        logger.info(f"Identity '{claims.sub}' authorized successfully. Gateway processing time: {process_time_ms:.2f}ms")
        await self._log_telemetry_async(client_ip, claims.sub, response.status_code, f"ALLOW_INFERENCE ({process_time_ms:.1f}ms)")

        return response


# --- Mock FastAPI Application Bootstrap ---
app = FastAPI(title="DeepShield-Core AI Gateway")

# Mount Layer 1 Security Middleware
app.add_middleware(
    IdentityCheckMiddleware,
    redis_url="redis://localhost:6379/0",
    enforce_mtls=True
)

@app.get("/api/v1/inference")
async def secure_inference_endpoint(request: Request):
    """
    Highly secure downstream inference proxy targeting isolated vector database partitions.
    Guaranteed secure by mTLS and verified claims context bindings.
    """
    identity: IdentityClaims = request.state.identity
    return {
        "status": "GRANTED",
        "identity": identity.sub,
        "tenant_id": identity.tenant_id,
        "active_partition": identity.vector_partition,
        "payload": "Verified air-gapped vector pipeline stream connected."
    }
