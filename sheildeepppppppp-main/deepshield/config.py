import os
from typing import List, Dict, Any
from pydantic import BaseModel

class GatewayConfig(BaseModel):
    # Gateway Identity & Core
    GATEWAY_NAME: str = "DEEPSHIELD Enterprise PromptSecurityGateway"
    VERSION: str = "2026.08.16-ENTERPRISE"
    DEBUG: bool = False
    
    # Gate 1: Identity & Access Configuration
    JWT_SECRET_KEY: str = os.getenv("DEEPSHIELD_JWT_SECRET", "deepshield_ca_secops_public_key_2026")
    JWT_ALGORITHM: str = "HS256"
    ENFORCE_MTLS: bool = os.getenv("ENFORCE_MTLS", "true").lower() == "true"
    REQUIRED_SCOPES: List[str] = ["ai:inference"]
    RATE_LIMIT_MAX_REQUESTS: int = 120
    RATE_LIMIT_WINDOW_SEC: float = 60.0
    
    # Gate 2: Quantum Lock (Crystals-Kyber-1024 / ML-KEM)
    PQC_ALGORITHM: str = "Crystals-Kyber-1024"
    PQC_KEY_ROTATION_INTERVAL_SEC: int = int(os.getenv("PQC_KEY_ROTATION_INTERVAL_SEC", "3600")) # 1 hour
    SESSION_ENCRYPTION_CIPHER: str = "AES-256-GCM"
    
    # Gate 3: Privacy Mask (Microsoft Presidio)
    PRESIDIO_ENTITIES: List[str] = [
        "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "LOCATION", 
        "IP_ADDRESS", "CREDIT_CARD", "CRYPTO", "US_SSN", "IBAN_CODE", "MEDICAL_LICENSE"
    ]
    PII_MAPPING_TTL_SEC: int = 300 # 5 minutes ephemeral cache
    TAG_GDPR_AUDIT: bool = True
    
    # Gate 4: Math Wall (Sentence-Transformers & Perplexity)
    EMBEDDING_MODEL_NAME: str = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
    SIMILARITY_THRESHOLD: float = float(os.getenv("MATH_WALL_SIMILARITY_THRESHOLD", "0.78"))
    PERPLEXITY_MODEL_NAME: str = os.getenv("PERPLEXITY_MODEL", "distilgpt2")
    PERPLEXITY_WINDOW_SIZE: int = 32
    PERPLEXITY_WINDOW_STRIDE: int = 16
    PERPLEXITY_MAX_THRESHOLD: float = float(os.getenv("PERPLEXITY_MAX_THRESHOLD", "380.0"))
    PERPLEXITY_MIN_THRESHOLD: float = float(os.getenv("PERPLEXITY_MIN_THRESHOLD", "2.0"))
    MATH_WALL_WEIGHT_SIMILARITY: float = 0.65
    MATH_WALL_WEIGHT_PERPLEXITY: float = 0.35
    
    # Gate 5: AI Judge (Offline Local Llama-Guard-3-1B)
    OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama-guard3:1b")
    OLLAMA_TIMEOUT_SEC: float = 3.5
    STRICT_OFFLINE_MODE: bool = True
    
    # Automated Circuit Breaker
    CIRCUIT_BREAKER_MAX_LATENCY_MS: float = 10.0
    SAFE_FALLBACK_MESSAGE: str = "Request cannot be processed by enterprise security policy."
    
    # Storage & Audit Telemetry
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    REDIS_AOF_MODE: bool = True
    SUPABASE_URL: str = os.getenv("VITE_SUPABASE_URL", "")
    SUPABASE_KEY: str = os.getenv("VITE_SUPABASE_ANON_KEY", "")
    SUPABASE_COLD_STORAGE_TABLE: str = "security_audit_logs"

config = GatewayConfig()
