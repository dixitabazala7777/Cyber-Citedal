import os
import time
import uuid
import logging
import asyncio
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, Request, Response, status, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from deepshield.config import config
from deepshield.gates.gate1_identity import Gate1IdentityAccess, Gate1Result
from deepshield.gates.gate2_quantum import Gate2QuantumLock, Gate2Result
from deepshield.gates.gate3_privacy import Gate3PrivacyMask, Gate3Result
from deepshield.gates.gate4_math_wall import Gate4MathWall, Gate4Result
from deepshield.gates.gate5_ai_judge import Gate5AiJudge, Gate5Result
from deepshield.circuit_breaker import CircuitBreaker, CircuitBreakerResponse

# Setup enterprise logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [DEEPSHEILD] %(message)s")
logger = logging.getLogger("DeepShield.Gateway")

class ShieldInboundPayload(BaseModel):
    prompt: Optional[str] = None
    encrypted_payload: Optional[str] = None
    session_id: Optional[str] = None

class HandshakePayload(BaseModel):
    public_key_hex: str
    session_id: Optional[str] = None

class GateTelemetryCounters:
    def __init__(self):
        self.lock = asyncio.Lock()
        self.gate1_pass = 0
        self.gate1_fail = 0
        self.gate2_pass = 0
        self.gate2_fail = 0
        self.gate3_pass = 0
        self.gate3_fail = 0
        self.gate4_pass = 0
        self.gate4_fail = 0
        self.gate5_pass = 0
        self.gate5_fail = 0
        self.circuit_breaker_trips = 0
        self.total_processed = 0
        self.recent_latencies: List[Dict[str, float]] = []

    async def record_gate(self, gate_num: int, passed: bool, latency: float):
        async with self.lock:
            if gate_num == 1:
                if passed: self.gate1_pass += 1
                else: self.gate1_fail += 1
            elif gate_num == 2:
                if passed: self.gate2_pass += 1
                else: self.gate2_fail += 1
            elif gate_num == 3:
                if passed: self.gate3_pass += 1
                else: self.gate3_fail += 1
            elif gate_num == 4:
                if passed: self.gate4_pass += 1
                else: self.gate4_fail += 1
            elif gate_num == 5:
                if passed: self.gate5_pass += 1
                else: self.gate5_fail += 1
            
            if not passed:
                self.circuit_breaker_trips += 1
            self.total_processed += 1

class PromptSecurityGateway:
    """
    PromptSecurityGateway:
    Single orchestration service executing the 5-gate security pipeline in strict sequence.
    Every gate fails closed. No gate is skippable or bypassable.
    """
    def __init__(self):
        logger.info("Initializing DEEPSHEILD Enterprise PromptSecurityGateway...")
        self.gate1 = Gate1IdentityAccess(
            jwt_secret=config.JWT_SECRET_KEY,
            jwt_algorithm=config.JWT_ALGORITHM,
            enforce_mtls=config.ENFORCE_MTLS
        )
        self.gate2 = Gate2QuantumLock(
            rotation_interval_sec=config.PQC_KEY_ROTATION_INTERVAL_SEC
        )
        self.gate3 = Gate3PrivacyMask(
            entities=config.PRESIDIO_ENTITIES,
            ttl_sec=config.PII_MAPPING_TTL_SEC
        )
        self.gate4 = Gate4MathWall(
            similarity_threshold=config.SIMILARITY_THRESHOLD,
            perplexity_max=config.PERPLEXITY_MAX_THRESHOLD,
            perplexity_min=config.PERPLEXITY_MIN_THRESHOLD,
            weight_sim=config.MATH_WALL_WEIGHT_SIMILARITY,
            weight_perp=config.MATH_WALL_WEIGHT_PERPLEXITY,
            embedding_model=config.EMBEDDING_MODEL_NAME,
            perplexity_model=config.PERPLEXITY_MODEL_NAME
        )
        self.gate5 = Gate5AiJudge(
            ollama_host=config.OLLAMA_HOST,
            model_name=config.OLLAMA_MODEL,
            timeout_sec=config.OLLAMA_TIMEOUT_SEC
        )
        self.circuit_breaker = CircuitBreaker(
            redis_url=config.REDIS_URL,
            supabase_url=config.SUPABASE_URL,
            supabase_key=config.SUPABASE_KEY,
            max_trip_latency_ms=config.CIRCUIT_BREAKER_MAX_LATENCY_MS
        )
        self.telemetry = GateTelemetryCounters()
        logger.info("DEEPSHEILD PromptSecurityGateway 5-Gate pipeline active & armed.")

    async def process_pipeline(
        self, 
        headers: Dict[str, str], 
        payload: ShieldInboundPayload,
        client_ip: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """
        Executes the 5 sequential fail-closed security gates:
        Gate 1 (Identity) -> Gate 2 (Quantum) -> Gate 3 (Privacy) -> Gate 4 (Math Wall) -> Gate 5 (AI Judge)
        """
        trace_id = f"TRC-{int(time.time()*1000)}-{uuid.uuid4().hex[:6].upper()}"
        pipeline_start = time.perf_counter()
        session_id = payload.session_id or f"sess_{trace_id}"
        
        gate_latencies: Dict[str, float] = {}

        # =========================================================================
        # GATE 1: Identity & Access (Literal First Check)
        # =========================================================================
        g1_res: Gate1Result = self.gate1.validate_request_headers(headers, client_ip=client_ip)
        gate_latencies["gate1_identity_ms"] = g1_res.latency_ms
        await self.telemetry.record_gate(1, g1_res.passed, g1_res.latency_ms)

        if not g1_res.passed:
            cb_start = time.perf_counter()
            total_elapsed = (time.perf_counter() - pipeline_start) * 1000
            cb_latency = (time.perf_counter() - cb_start) * 1000
            
            await self.circuit_breaker.log_threat_coordinates(
                failed_gate="GATE_1_IDENTITY_ACCESS",
                raw_or_masked_prompt="[HEADER_REJECTION_NO_BODY]",
                client_identity=g1_res.identity,
                client_ip=client_ip,
                risk_score=1.0,
                rejection_code=g1_res.status,
                trip_latency_ms=cb_latency
            )
            
            return {
                "status": "CIRCUIT_BREAKER_TRIPPED",
                "code": g1_res.status,
                "circuit_broken": True,
                "failed_gate": "Gate 1: Identity & Access",
                "error": g1_res.error,
                "message": config.SAFE_FALLBACK_MESSAGE,
                "execution_time_ms": round(total_elapsed, 2),
                "gate_latencies": gate_latencies,
                "gate_results": {
                    "gate1": {"status": "FAIL", "detail": g1_res.detail, "latency_ms": g1_res.latency_ms},
                    "gate2": {"status": "BLOCKED", "detail": "Halted by Gate 1"},
                    "gate3": {"status": "BLOCKED", "detail": "Halted by Gate 1"},
                    "gate4": {"status": "BLOCKED", "detail": "Halted by Gate 1"},
                    "gate5": {"status": "BLOCKED", "detail": "Halted by Gate 1"}
                },
                "trace_id": trace_id
            }

        raw_prompt = payload.prompt or ""
        encrypted_hex = payload.encrypted_payload

        if not raw_prompt and not encrypted_hex:
            total_elapsed = (time.perf_counter() - pipeline_start) * 1000
            return {
                "status": "BAD_REQUEST",
                "code": "ERR_EMPTY_PROMPT",
                "circuit_broken": True,
                "failed_gate": "Gate 1: Validation",
                "message": "Prompt text or encrypted payload is required.",
                "execution_time_ms": round(total_elapsed, 2),
                "trace_id": trace_id
            }

        # =========================================================================
        # GATE 2: Quantum Lock (Crystals-Kyber-1024 & AES-256-GCM)
        # =========================================================================
        g2_res: Gate2Result = self.gate2.process_gate(raw_prompt, session_id, encrypted_hex)
        gate_latencies["gate2_quantum_ms"] = g2_res.latency_ms
        await self.telemetry.record_gate(2, g2_res.passed, g2_res.latency_ms)

        if not g2_res.passed or not g2_res.decrypted_prompt:
            cb_start = time.perf_counter()
            total_elapsed = (time.perf_counter() - pipeline_start) * 1000
            cb_latency = (time.perf_counter() - cb_start) * 1000

            await self.circuit_breaker.log_threat_coordinates(
                failed_gate="GATE_2_QUANTUM_LOCK",
                raw_or_masked_prompt=raw_prompt or "[ENCRYPTED_PAYLOAD_CORRUPT]",
                client_identity=g1_res.identity,
                client_ip=client_ip,
                risk_score=0.95,
                rejection_code=g2_res.status,
                trip_latency_ms=cb_latency
            )

            return {
                "status": "CIRCUIT_BREAKER_TRIPPED",
                "code": g2_res.status,
                "circuit_broken": True,
                "failed_gate": "Gate 2: Quantum Lock",
                "error": g2_res.error,
                "message": config.SAFE_FALLBACK_MESSAGE,
                "execution_time_ms": round(total_elapsed, 2),
                "gate_latencies": gate_latencies,
                "gate_results": {
                    "gate1": {"status": "PASS", "detail": g1_res.detail, "latency_ms": g1_res.latency_ms},
                    "gate2": {"status": "FAIL", "detail": g2_res.detail, "latency_ms": g2_res.latency_ms},
                    "gate3": {"status": "BLOCKED", "detail": "Halted by Gate 2"},
                    "gate4": {"status": "BLOCKED", "detail": "Halted by Gate 2"},
                    "gate5": {"status": "BLOCKED", "detail": "Halted by Gate 2"}
                },
                "trace_id": trace_id
            }

        verified_prompt = g2_res.decrypted_prompt

        # =========================================================================
        # GATE 3: Privacy Mask (Microsoft Presidio Analyzer + Anonymizer)
        # =========================================================================
        g3_res: Gate3Result = self.gate3.process_gate(verified_prompt, session_id)
        gate_latencies["gate3_privacy_ms"] = g3_res.latency_ms
        await self.telemetry.record_gate(3, g3_res.passed, g3_res.latency_ms)

        if not g3_res.passed:
            cb_start = time.perf_counter()
            total_elapsed = (time.perf_counter() - pipeline_start) * 1000
            cb_latency = (time.perf_counter() - cb_start) * 1000

            await self.circuit_breaker.log_threat_coordinates(
                failed_gate="GATE_3_PRIVACY_MASK",
                raw_or_masked_prompt=verified_prompt,
                client_identity=g1_res.identity,
                client_ip=client_ip,
                risk_score=0.90,
                rejection_code=g3_res.status,
                trip_latency_ms=cb_latency
            )

            return {
                "status": "CIRCUIT_BREAKER_TRIPPED",
                "code": g3_res.status,
                "circuit_broken": True,
                "failed_gate": "Gate 3: Privacy Mask",
                "error": g3_res.error,
                "message": config.SAFE_FALLBACK_MESSAGE,
                "execution_time_ms": round(total_elapsed, 2),
                "gate_latencies": gate_latencies,
                "gate_results": {
                    "gate1": {"status": "PASS", "detail": g1_res.detail, "latency_ms": g1_res.latency_ms},
                    "gate2": {"status": "PASS", "detail": g2_res.detail, "latency_ms": g2_res.latency_ms},
                    "gate3": {"status": "FAIL", "detail": g3_res.detail, "latency_ms": g3_res.latency_ms},
                    "gate4": {"status": "BLOCKED", "detail": "Halted by Gate 3"},
                    "gate5": {"status": "BLOCKED", "detail": "Halted by Gate 3"}
                },
                "trace_id": trace_id
            }

        masked_prompt = g3_res.anonymized_prompt

        # =========================================================================
        # GATE 4: Math Wall (Sentence-Transformers + Sliding Window Perplexity)
        # =========================================================================
        g4_res: Gate4Result = self.gate4.process_gate(masked_prompt)
        gate_latencies["gate4_math_wall_ms"] = g4_res.latency_ms
        await self.telemetry.record_gate(4, g4_res.passed, g4_res.latency_ms)

        if not g4_res.passed or g4_res.is_circuit_broken:
            cb_start = time.perf_counter()
            total_elapsed = (time.perf_counter() - pipeline_start) * 1000
            cb_latency = (time.perf_counter() - cb_start) * 1000

            await self.circuit_breaker.log_threat_coordinates(
                failed_gate="GATE_4_MATH_WALL",
                raw_or_masked_prompt=masked_prompt,
                client_identity=g1_res.identity,
                client_ip=client_ip,
                risk_score=g4_res.combined_risk_score,
                rejection_code=g4_res.status,
                trip_latency_ms=cb_latency
            )

            return {
                "status": "CIRCUIT_BREAKER_TRIPPED",
                "code": g4_res.status,
                "circuit_broken": True,
                "failed_gate": "Gate 4: Math Wall",
                "error": g4_res.error,
                "message": config.SAFE_FALLBACK_MESSAGE,
                "execution_time_ms": round(total_elapsed, 2),
                "gate_latencies": gate_latencies,
                "gate_results": {
                    "gate1": {"status": "PASS", "detail": g1_res.detail, "latency_ms": g1_res.latency_ms},
                    "gate2": {"status": "PASS", "detail": g2_res.detail, "latency_ms": g2_res.latency_ms},
                    "gate3": {"status": "PASS", "detail": g3_res.detail, "latency_ms": g3_res.latency_ms},
                    "gate4": {"status": "FAIL", "detail": g4_res.detail, "latency_ms": g4_res.latency_ms, "score": g4_res.cosine_similarity, "perplexity": g4_res.sliding_window_perplexity},
                    "gate5": {"status": "BLOCKED", "detail": "Halted by Gate 4"}
                },
                "trace_id": trace_id
            }

        # =========================================================================
        # GATE 5: AI Judge (Offline Local Llama-Guard-3-1B)
        # =========================================================================
        g5_res: Gate5Result = await self.gate5.process_gate(masked_prompt)
        gate_latencies["gate5_ai_judge_ms"] = g5_res.latency_ms
        await self.telemetry.record_gate(5, g5_res.passed, g5_res.latency_ms)

        if not g5_res.passed or g5_res.safety_verdict != "SAFE":
            cb_start = time.perf_counter()
            total_elapsed = (time.perf_counter() - pipeline_start) * 1000
            cb_latency = (time.perf_counter() - cb_start) * 1000

            await self.circuit_breaker.log_threat_coordinates(
                failed_gate="GATE_5_AI_JUDGE",
                raw_or_masked_prompt=masked_prompt,
                client_identity=g1_res.identity,
                client_ip=client_ip,
                risk_score=0.98,
                rejection_code=g5_res.status,
                trip_latency_ms=cb_latency
            )

            return {
                "status": "CIRCUIT_BREAKER_TRIPPED",
                "code": g5_res.status,
                "circuit_broken": True,
                "failed_gate": "Gate 5: AI Judge",
                "error": g5_res.error,
                "message": config.SAFE_FALLBACK_MESSAGE,
                "execution_time_ms": round(total_elapsed, 2),
                "gate_latencies": gate_latencies,
                "gate_results": {
                    "gate1": {"status": "PASS", "detail": g1_res.detail, "latency_ms": g1_res.latency_ms},
                    "gate2": {"status": "PASS", "detail": g2_res.detail, "latency_ms": g2_res.latency_ms},
                    "gate3": {"status": "PASS", "detail": g3_res.detail, "latency_ms": g3_res.latency_ms},
                    "gate4": {"status": "PASS", "detail": g4_res.detail, "latency_ms": g4_res.latency_ms},
                    "gate5": {"status": "FAIL", "detail": g5_res.detail, "latency_ms": g5_res.latency_ms, "categories": g5_res.flagged_categories}
                },
                "trace_id": trace_id
            }

        # =========================================================================
        # PASSED ALL 5 GATES — Forward Sanitized Prompt to Target LLM
        # =========================================================================
        total_elapsed = (time.perf_counter() - pipeline_start) * 1000
        
        # Simulated sanitized model response
        llm_response = f"DEEPSHEILD Enterprise Model: Verified and processed sanitized input for '{masked_prompt}'."

        return {
            "status": "PASSED_ALL_GATES",
            "code": "PIPELINE_VERIFIED_SAFE",
            "circuit_broken": False,
            "sanitized_prompt": masked_prompt,
            "execution_time_ms": round(total_elapsed, 2),
            "gate_latencies": gate_latencies,
            "pii_detected": g3_res.pii_detected,
            "gdpr_dpdpa_compliant": True,
            "quantum_session": {
                "algorithm": g2_res.algorithm,
                "key_fingerprint": g2_res.key_fingerprint
            },
            "gate_results": {
                "gate1": {"status": "PASS", "detail": g1_res.detail, "latency_ms": g1_res.latency_ms},
                "gate2": {"status": "PASS", "detail": g2_res.detail, "latency_ms": g2_res.latency_ms},
                "gate3": {"status": "PASS", "detail": g3_res.detail, "latency_ms": g3_res.latency_ms},
                "gate4": {"status": "PASS", "detail": g4_res.detail, "latency_ms": g4_res.latency_ms, "score": g4_res.cosine_similarity},
                "gate5": {"status": "PASS", "detail": g5_res.detail, "latency_ms": g5_res.latency_ms}
            },
            "model_response": llm_response,
            "trace_id": trace_id
        }

# Instantiate Singleton Gateway Orchestrator
gateway_core = PromptSecurityGateway()

# =============================================================================
# FastAPI Application & ASGI Routes
# =============================================================================
app = FastAPI(
    title=config.GATEWAY_NAME,
    version=config.VERSION,
    description="Sequential 5-Gate Fail-Closed Pre-LLM Security Gateway"
)

# CORS Policy
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/healthz")
async def health_check():
    return {
        "status": "HEALTHY",
        "service": config.GATEWAY_NAME,
        "version": config.VERSION,
        "pqc_algorithm": config.PQC_ALGORITHM,
        "strict_offline_mode": config.STRICT_OFFLINE_MODE
    }

@app.post("/api/v1/pqc/handshake")
async def pqc_handshake(payload: HandshakePayload):
    """
    Gate 2: Post-Quantum Crystals-Kyber-1024 Handshake
    """
    session_id = payload.session_id or f"sess_{uuid.uuid4().hex[:12]}"
    ciphertext_hex, fingerprint = gateway_core.gate2.establish_session(
        session_id=session_id,
        client_public_key_hex=payload.public_key_hex
    )
    return {
        "status": "Quantum Session Established",
        "code": "PQC_HANDSHAKE_SUCCESS",
        "algorithm": config.PQC_ALGORITHM,
        "session_id": session_id,
        "ciphertext_hex": ciphertext_hex,
        "key_fingerprint": fingerprint
    }

@app.post("/api/v1/shield/process")
async def process_prompt_security_pipeline(request: Request, payload: ShieldInboundPayload):
    """
    Main Pre-LLM Security Gateway Pipeline
    """
    headers_dict = dict(request.headers)
    client_ip = request.client.host if request.client else "127.0.0.1"
    
    result = await gateway_core.process_pipeline(
        headers=headers_dict,
        payload=payload,
        client_ip=client_ip
    )
    
    status_code = status.HTTP_200_OK
    if result.get("circuit_broken"):
        status_code = status.HTTP_403_FORBIDDEN
        
    return JSONResponse(status_code=status_code, content=result)

@app.get("/api/v1/shield/telemetry")
async def get_gateway_telemetry():
    """
    Provides real-time pass/fail metrics per gate for dashboard visualization.
    """
    t = gateway_core.telemetry
    return {
        "total_processed": t.total_processed,
        "circuit_breaker_trips": t.circuit_breaker_trips,
        "gates": {
            "gate1": {"name": "Identity & Access", "pass": t.gate1_pass, "fail": t.gate1_fail},
            "gate2": {"name": "Quantum Lock", "pass": t.gate2_pass, "fail": t.gate2_fail},
            "gate3": {"name": "Privacy Mask", "pass": t.gate3_pass, "fail": t.gate3_fail},
            "gate4": {"name": "Math Wall", "pass": t.gate4_pass, "fail": t.gate4_fail},
            "gate5": {"name": "AI Judge", "pass": t.gate5_pass, "fail": t.gate5_fail},
        }
    }
