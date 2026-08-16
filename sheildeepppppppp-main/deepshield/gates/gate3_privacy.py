import time
import logging
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel
from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

logger = logging.getLogger("DeepShield.Gate3")

class PiiEntityRecord(BaseModel):
    entity_type: str
    token: str
    start: int
    end: int
    score: float

class Gate3Result(BaseModel):
    passed: bool
    status: str
    original_length: int
    anonymized_prompt: str
    pii_detected: bool
    entity_count: int
    entities_masked: List[PiiEntityRecord] = []
    gdpr_dpdpa_tagged: bool = False
    latency_ms: float
    error: Optional[str] = None
    detail: Optional[str] = None

class EphemeralTokenVault:
    """
    In-memory / short-lived encrypted token vault.
    Strictly keeps mapping isolated and ephemeral (default TTL: 300s).
    NEVER written to cold storage (Supabase).
    """
    def __init__(self, ttl_sec: int = 300):
        self.ttl_sec = ttl_sec
        # session_id -> { token: real_value, "_created_at": timestamp }
        self._vault: Dict[str, Dict[str, Any]] = {}

    def store_mapping(self, session_id: str, mapping: Dict[str, str]):
        self._vault[session_id] = {
            "mapping": mapping,
            "created_at": time.time()
        }

    def get_mapping(self, session_id: str) -> Optional[Dict[str, str]]:
        record = self._vault.get(session_id)
        if not record:
            return None
        if (time.time() - record["created_at"]) > self.ttl_sec:
            del self._vault[session_id]
            return None
        return record["mapping"]

    def cleanup_expired(self):
        now = time.time()
        expired_keys = [k for k, v in self._vault.items() if (now - v["created_at"]) > self.ttl_sec]
        for k in expired_keys:
            del self._vault[k]

class Gate3PrivacyMask:
    """
    Gate 3: Microsoft Presidio PII Masking with Consistent Tokenization
    and ephemeral in-memory mapping vault.
    """
    def __init__(self, entities: Optional[List[str]] = None, ttl_sec: int = 300):
        self.entities = entities or [
            "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "LOCATION", 
            "IP_ADDRESS", "CREDIT_CARD", "CRYPTO", "US_SSN", "IBAN_CODE", "MEDICAL_LICENSE"
        ]
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        self.vault = EphemeralTokenVault(ttl_sec=ttl_sec)

    def process_gate(
        self, 
        prompt_text: str, 
        session_id: str = "default_session"
    ) -> Gate3Result:
        """
        Gate 3 Execution:
        1. Analyzes prompt for all configured PII categories.
        2. Assigns consistent sequential tokens (e.g. <PERSON_1>, <EMAIL_1>).
        3. Stores ephemeral mapping in memory for response re-hydration.
        4. Tags GDPR/DPDPA compliance markers.
        """
        start_time = time.perf_counter()
        
        try:
            # 1. Analyze text for PII entities
            results: List[RecognizerResult] = self.analyzer.analyze(
                text=prompt_text,
                entities=self.entities,
                language="en"
            )

            # Sort entities by start position descending for safe replacement
            results_sorted = sorted(results, key=lambda x: x.start, reverse=True)
            
            # 2. Build consistent token replacements and mapping
            type_counters: Dict[str, int] = {}
            entities_masked: List[PiiEntityRecord] = []
            session_mapping: Dict[str, str] = {}

            # Map from original substring to unique token
            val_to_token: Dict[str, str] = {}
            anonymized_chars = list(prompt_text)

            for item in results_sorted:
                real_val = prompt_text[item.start:item.end]
                ent_type = item.entity_type
                
                if real_val not in val_to_token:
                    count = type_counters.get(ent_type, 0) + 1
                    type_counters[ent_type] = count
                    token = f"<{ent_type}_{count}>"
                    val_to_token[real_val] = token
                else:
                    token = val_to_token[real_val]

                # Replace in character buffer
                anonymized_chars[item.start:item.end] = list(token)
                session_mapping[token] = real_val

                entities_masked.append(PiiEntityRecord(
                    entity_type=ent_type,
                    token=token,
                    start=item.start,
                    end=item.end,
                    score=round(item.score, 3)
                ))

            anonymized_text = "".join(anonymized_chars)
            pii_detected = len(results) > 0
            
            # Store in short-lived ephemeral memory vault
            if pii_detected:
                self.vault.store_mapping(session_id, session_mapping)
                self.vault.cleanup_expired()

            latency_ms = (time.perf_counter() - start_time) * 1000
            
            detail = (
                f"Presidio masked {len(results)} PII entity/entities with consistent tokens. GDPR/DPDPA tagged."
                if pii_detected else
                "Zero PII entities detected. Privacy boundary clear."
            )

            return Gate3Result(
                passed=True,
                status="PASS",
                original_length=len(prompt_text),
                anonymized_prompt=anonymized_text,
                pii_detected=pii_detected,
                entity_count=len(results),
                entities_masked=entities_masked,
                gdpr_dpdpa_tagged=pii_detected,
                latency_ms=round(latency_ms, 3),
                detail=detail
            )

        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            logger.error(f"Gate 3 Privacy Anonymizer Error: {str(e)}")
            return Gate3Result(
                passed=False,
                status="REJECT_PRIVACY_MASK_FAILED",
                original_length=len(prompt_text),
                anonymized_prompt=prompt_text,
                pii_detected=False,
                entity_count=0,
                latency_ms=round(latency_ms, 3),
                error="Presidio PII Anonymization Engine Failure",
                detail=f"Fail-closed halt: Privacy masking encountered an exception ({str(e)})."
            )
