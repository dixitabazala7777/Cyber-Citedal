// DeepShield-Core Layer 1 Identity Check Middleware
// This file provides both the TypeScript representation of the gateway enforcer
// and exports the raw Python FastAPI executable code for integration.

/**
 * TypeScript Representation of DeepShield-Core Identity Claims
 */
export interface IdentityClaims {
  sub: string;
  tenantId: string;
  scopes: string[];
  vectorPartition: string;
  exp: number;
}

/**
 * Asynchronous mTLS Header and OAuth2 JWT verification circuit breaker simulator.
 * Processes requests in <10ms to verify hardware certs and tenant mapping.
 */
export async function verifyGatewaySecurity(headers: {
  'x-client-verify'?: string;
  'x-client-cert-sha256'?: string;
  'x-target-partition'?: string;
  'authorization'?: string;
  'content-length'?: string;
}): Promise<{
  allowed: boolean;
  status: number;
  code: string;
  message: string;
  identity?: IdentityClaims;
  latencyMs: number;
}> {
  const startTime = performance.now();

  // 1. Layer 0 Connection Limits & Request Body Payload Size Check (50KB Max)
  const contentLength = headers['content-length'] ? parseInt(headers['content-length'], 10) : 0;
  if (contentLength > 51200) { // 50 KB in bytes (50 * 1024 = 51200)
    return {
      allowed: false,
      status: 413,
      code: "GATEWAY_PAYLOAD_TOO_LARGE",
      message: "Perimeter error: client_max_body_size cap breached. Request discarded.",
      latencyMs: Number((performance.now() - startTime).toFixed(2))
    };
  }

  // 2. Layer 1 mTLS Verification Check
  const clientVerify = headers['x-client-verify'];
  const clientSha256 = headers['x-client-cert-sha256'];

  if (!clientVerify || clientVerify !== 'SUCCESS' || !clientSha256) {
    return {
      allowed: false,
      status: 403,
      code: "GATEWAY_MTLS_FAILED",
      message: "Access Denied: Client hardware certificate signature verification failed.",
      latencyMs: Number((performance.now() - startTime).toFixed(2))
    };
  }

  // 3. Layer 1 OAuth2 JWT verification
  const authHeader = headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return {
      allowed: false,
      status: 403,
      code: "GATEWAY_UNAUTHORIZED",
      message: "Access Denied: Authorization header empty or malformed bearer token.",
      latencyMs: Number((performance.now() - startTime).toFixed(2))
    };
  }

  const token = authHeader.split(' ')[1];

  // Decode mock JWT payload simulation
  // Standard token validation logic checking signatures and claims
  try {
    if (token === 'expired_token') {
      return {
        allowed: false,
        status: 403,
        code: "GATEWAY_CREDENTIALS_EXPIRED",
        message: "JWT token validation error: Claims expiration check failed (exp parameter).",
        latencyMs: Number((performance.now() - startTime).toFixed(2))
      };
    }

    if (token === 'invalid_signature') {
      return {
        allowed: false,
        status: 403,
        code: "GATEWAY_CREDENTIALS_INVALID",
        message: "Cryptographic rejection: Signature verification failed against gateway CA trust ring.",
        latencyMs: Number((performance.now() - startTime).toFixed(2))
      };
    }

    // Default validated token payload mapping
    const claims: IdentityClaims = {
      sub: "pipeline-agent-77",
      tenantId: "tenant_alpha",
      scopes: ["ai:inference"],
      vectorPartition: "partition_alpha",
      exp: Math.floor(Date.now() / 1000) + 3600
    };

    // 4. Scope verification
    if (!claims.scopes.includes("ai:inference")) {
      return {
        allowed: false,
        status: 403,
        code: "GATEWAY_SCOPE_INSUFFICIENT",
        message: "Rejection: Security context lacks required 'ai:inference' permission context.",
        latencyMs: Number((performance.now() - startTime).toFixed(2))
      };
    }

    // 5. Context-aware Partition check
    const requestedPartition = headers['x-target-partition'] || 'partition_alpha';
    if (claims.vectorPartition !== requestedPartition) {
      return {
        allowed: false,
        status: 403,
        code: "GATEWAY_PARTITION_VIOLATION",
        message: `Critical Violation: Access token tenant '${claims.tenantId}' is prohibited from routing queries to external partition: '${requestedPartition}'.`,
        latencyMs: Number((performance.now() - startTime).toFixed(2))
      };
    }

    return {
      allowed: true,
      status: 200,
      code: "SUCCESS",
      message: "Verified air-gapped vector pipeline stream connected.",
      identity: claims,
      latencyMs: Number((performance.now() - startTime).toFixed(2))
    };

  } catch {
    return {
      allowed: false,
      status: 403,
      code: "GATEWAY_CREDENTIALS_INVALID",
      message: "Access Denied: Credentials verification error.",
      latencyMs: Number((performance.now() - startTime).toFixed(2))
    };
  }
}

/**
 * Raw Executable Python FastAPI Middleware Code Implementation
 */
export const PYTHON_FASTAPI_MIDDLEWARE = `
import time
import logging
from typing import Optional, List
from pydantic import BaseModel, Field
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from jose import jwt, JWTError
import redis.asyncio as aioredis

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("DeepShieldCore")

MOCK_PUBLIC_KEY = "deepshield_ca_secops_public_key_2026"
ALGORITHM = "HS256"

class IdentityClaims(BaseModel):
    sub: str = Field(..., description="Subject identity or client hardware identifier")
    tenant_id: str = Field(..., description="Isolated organizational tenant group")
    scopes: List[str] = Field(default_factory=list, description="OAuth2 assigned scopes")
    vector_partition: str = Field(..., description="Authorized vector database partition identifier")
    exp: int = Field(..., description="Unix timestamp expiration of token")

class IdentityCheckMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI, redis_url: str = "redis://localhost:6379/0", enforce_mtls: bool = True):
        super().__init__(app)
        self.enforce_mtls = enforce_mtls
        self.redis_pool = aioredis.ConnectionPool.from_url(redis_url, max_connections=20)

    async def _log_telemetry_async(self, ip: str, sub: str, status_code: int, action: str):
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
            await client.hset(log_key, mapping=log_payload)
            await client.expire(log_key, 86400)
            await client.close()
        except Exception as e:
            logger.warning(f"Telemetry offload bypassed: {str(e)}")

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start_time = time.perf_counter()
        client_ip = request.client.host if request.client else "0.0.0.0"

        # 1. mTLS Hardware Cert validation
        if self.enforce_mtls:
            client_verify = request.headers.get("X-Client-Verify")
            client_sha256 = request.headers.get("X-Client-Cert-SHA256")
            if not client_verify or client_verify != "SUCCESS" or not client_sha256:
                await self._log_telemetry_async(client_ip, "ANONYMOUS", 403, "REJECT_MTLS")
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"error": "Access Denied", "code": "GATEWAY_MTLS_FAILED"}
                )

        # 2. OAuth2 JWT parsing and validation
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            await self._log_telemetry_async(client_ip, "ANONYMOUS", 403, "REJECT_JWT_MISSING")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Access Denied", "code": "GATEWAY_UNAUTHORIZED"}
            )

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, MOCK_PUBLIC_KEY, algorithms=[ALGORITHM])
            claims = IdentityClaims(**payload)
        except (JWTError, Exception):
            await self._log_telemetry_async(client_ip, "INVALID_TOKEN", 403, "REJECT_JWT_INVALID")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Access Denied", "code": "GATEWAY_CREDENTIALS_INVALID"}
            )

        # 3. Context-Aware partition checking
        requested_partition = request.headers.get("X-Target-Partition")
        if requested_partition and claims.vector_partition != requested_partition:
            await self._log_telemetry_async(client_ip, claims.sub, 403, "REJECT_PARTITION_MISMATCH")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Access Denied", "code": "GATEWAY_PARTITION_VIOLATION"}
            )

        # 4. Scope enforcer
        if "ai:inference" not in claims.scopes:
            await self._log_telemetry_async(client_ip, claims.sub, 403, "REJECT_SCOPE_INSUFFICIENT")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Access Denied", "code": "GATEWAY_SCOPE_INSUFFICIENT"}
            )

        request.state.identity = claims
        response = await call_next(request)

        process_time_ms = (time.perf_counter() - start_time) * 1000
        await self._log_telemetry_async(client_ip, claims.sub, response.status_code, f"ALLOW_INFERENCE ({process_time_ms:.1f}ms)")
        return response
`;
