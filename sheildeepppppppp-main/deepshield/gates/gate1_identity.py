import time
import logging
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field
import jwt

logger = logging.getLogger("DeepShield.Gate1")

class IdentityClaims(BaseModel):
    sub: str = Field(..., description="Subject identity or client hardware identifier")
    tenant_id: str = Field(..., description="Isolated organizational tenant group")
    scopes: List[str] = Field(default_factory=list, description="OAuth2 assigned scopes")
    vector_partition: str = Field(default="partition_default", description="Authorized vector database partition identifier")
    exp: int = Field(..., description="Unix timestamp expiration of token")

class Gate1Result(BaseModel):
    passed: bool
    status: str
    identity: str = "ANONYMOUS"
    tenant_id: str = "UNKNOWN"
    vector_partition: str = "partition_default"
    latency_ms: float
    error: Optional[str] = None
    detail: Optional[str] = None

class Gate1IdentityAccess:
    def __init__(self, jwt_secret: str, jwt_algorithm: str = "HS256", enforce_mtls: bool = True):
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm
        self.enforce_mtls = enforce_mtls

    def validate_request_headers(
        self, 
        headers: Dict[str, str],
        client_ip: str = "127.0.0.1"
    ) -> Gate1Result:
        """
        Gate 1: Literal first check ahead of body parsing.
        Validates mTLS transport cert validation and OAuth2 Bearer JWT.
        Fails closed on any missing or invalid parameters.
        """
        start_time = time.perf_counter()
        
        # Normalize header keys to lowercase
        norm_headers = {k.lower(): v for k, v in headers.items()}
        
        # 1. Transport Layer mTLS Validation
        if self.enforce_mtls:
            client_verify = norm_headers.get("x-client-verify", "")
            client_cert_sha256 = norm_headers.get("x-client-cert-sha256", "")
            
            if client_verify != "SUCCESS" or not client_cert_sha256:
                latency_ms = (time.perf_counter() - start_time) * 1000
                logger.warning(f"Gate 1 Rejected: mTLS validation failed for IP {client_ip} (Verify: '{client_verify}')")
                return Gate1Result(
                    passed=False,
                    status="REJECT_MTLS_FAILED",
                    latency_ms=round(latency_ms, 3),
                    error="Transport Layer mTLS Validation Failed",
                    detail="Valid client certificate required by enterprise perimeter gateway."
                )

        # 2. OAuth2 Bearer Authorization Token Validation
        auth_header = norm_headers.get("authorization", "")
        if not auth_header or not auth_header.startswith("Bearer "):
            latency_ms = (time.perf_counter() - start_time) * 1000
            logger.warning(f"Gate 1 Rejected: Missing Bearer Token from IP {client_ip}")
            return Gate1Result(
                passed=False,
                status="REJECT_BEARER_MISSING",
                latency_ms=round(latency_ms, 3),
                error="OAuth2 Bearer Token Missing",
                detail="Request authorization header must contain a valid Bearer token."
            )

        token = auth_header.split(" ", 1)[1].strip()
        if not token:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return Gate1Result(
                passed=False,
                status="REJECT_TOKEN_EMPTY",
                latency_ms=round(latency_ms, 3),
                error="Empty Authorization Token",
                detail="Bearer token contains no credential payload."
            )

        # 3. Cryptographic JWT Signature & Claims Validation
        try:
            payload = jwt.decode(
                token, 
                self.jwt_secret, 
                algorithms=[self.jwt_algorithm],
                options={"require": ["exp", "sub"]}
            )
            claims = IdentityClaims(**payload)
            
            # Check required scopes for LLM inference gateway
            if "ai:inference" not in claims.scopes:
                latency_ms = (time.perf_counter() - start_time) * 1000
                logger.warning(f"Gate 1 Rejected: Insufficient scopes for subject '{claims.sub}' (Scopes: {claims.scopes})")
                return Gate1Result(
                    passed=False,
                    status="REJECT_SCOPE_INSUFFICIENT",
                    identity=claims.sub,
                    tenant_id=claims.tenant_id,
                    latency_ms=round(latency_ms, 3),
                    error="Insufficient Scopes",
                    detail="Credential lacks mandatory 'ai:inference' operational scope."
                )

            # Check vector partition access
            target_partition = norm_headers.get("x-target-partition")
            if target_partition and claims.vector_partition != target_partition:
                latency_ms = (time.perf_counter() - start_time) * 1000
                logger.warning(f"Gate 1 Rejected: Partition violation for subject '{claims.sub}' (Assigned: {claims.vector_partition}, Requested: {target_partition})")
                return Gate1Result(
                    passed=False,
                    status="REJECT_PARTITION_VIOLATION",
                    identity=claims.sub,
                    tenant_id=claims.tenant_id,
                    latency_ms=round(latency_ms, 3),
                    error="Vector Partition Violation",
                    detail=f"Identity '{claims.sub}' is restricted to partition '{claims.vector_partition}'."
                )

            latency_ms = (time.perf_counter() - start_time) * 1000
            return Gate1Result(
                passed=True,
                status="PASS",
                identity=claims.sub,
                tenant_id=claims.tenant_id,
                vector_partition=claims.vector_partition,
                latency_ms=round(latency_ms, 3),
                detail=f"Identity '{claims.sub}' verified with mTLS and OAuth2 claims."
            )

        except jwt.ExpiredSignatureError:
            latency_ms = (time.perf_counter() - start_time) * 1000
            logger.warning(f"Gate 1 Rejected: Expired token from IP {client_ip}")
            return Gate1Result(
                passed=False,
                status="REJECT_TOKEN_EXPIRED",
                latency_ms=round(latency_ms, 3),
                error="OAuth2 Token Expired",
                detail="Bearer credential expiration timestamp (exp) has elapsed."
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            logger.warning(f"Gate 1 Rejected: Invalid JWT signature from IP {client_ip} ({type(e).__name__})")
            return Gate1Result(
                passed=False,
                status="REJECT_SIGNATURE_INVALID",
                latency_ms=round(latency_ms, 3),
                error="Invalid Authentication Credentials",
                detail="Bearer token cryptographic signature verification failed."
            )
