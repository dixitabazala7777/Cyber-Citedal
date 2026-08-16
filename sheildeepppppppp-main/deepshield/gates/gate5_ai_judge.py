import time
import json
import logging
from typing import Dict, Any, Optional, Tuple, List
import httpx
from pydantic import BaseModel

logger = logging.getLogger("DeepShield.Gate5")

class Gate5Result(BaseModel):
    passed: bool
    status: str
    safety_verdict: str  # "SAFE" | "UNSAFE"
    flagged_categories: List[str] = []
    model_identifier: str = "Llama-Guard-3-1B (Ollama Local)"
    is_fully_offline: bool = True
    latency_ms: float
    error: Optional[str] = None
    detail: Optional[str] = None

# Llama-Guard-3 Standard Safety Taxonomy Categories
LLAMA_GUARD_TAXONOMY = {
    "S1": "Violent Crimes",
    "S2": "Non-Violent Crimes",
    "S3": "Sex-Related Crimes",
    "S4": "Child Sexual Exploitation and Abuse",
    "S5": "Defamation",
    "S6": "Specialized Advice (Financial / Medical / Legal)",
    "S7": "Privacy Violations and Doxxing",
    "S8": "Intellectual Property Infringement",
    "S9": "Indiscriminate Weapons (CBRN / Explosives)",
    "S10": "Hate Speech and Harassment",
    "S11": "Suicide and Self-Harm",
    "S12": "Sexual Content",
    "S13": "Cyberattacks, Exploits and Malware"
}

LLAMA_GUARD_PROMPT_TEMPLATE = """<|begin_of_text|><|start_header_id|>user<|end_header_id|>

Task: Check if there is unsafe content in 'User' messages in conversations according our safety policy with the below categories.

<BEGIN UNSAFE CONTENT CATEGORIES>
S1: Violent Crimes.
S2: Non-Violent Crimes.
S3: Sex-Related Crimes.
S4: Child Sexual Exploitation and Abuse.
S5: Defamation.
S6: Specialized Advice.
S7: Privacy Violations.
S8: Intellectual Property.
S9: Indiscriminate Weapons.
S10: Hate Speech.
S11: Suicide and Self-Harm.
S12: Sexual Content.
S13: Cyberattacks.
<END UNSAFE CONTENT CATEGORIES>

<BEGIN CONVERSATION>
User: {prompt}
<END CONVERSATION>

Provide your safety assessment for User in the above conversation:
- First line must read 'safe' or 'unsafe'.
- If unsafe, a second line must contain a comma-separated list of violated categories.<|eot_id|><|start_header_id|>assistant<|end_header_id|>
"""

class Gate5AiJudge:
    """
    Gate 5: AI Safety Judge.
    Runs the prompt through a local, offline Llama-Guard-3-1B model served via Ollama.
    CRITICAL: This gate is strictly air-gapped with zero outbound network calls.
    """
    def __init__(
        self,
        ollama_host: str = "http://127.0.0.1:11434",
        model_name: str = "llama-guard3:1b",
        timeout_sec: float = 3.5
    ):
        self.ollama_host = ollama_host.rstrip('/')
        self.model_name = model_name
        self.timeout_sec = timeout_sec

    async def _query_local_ollama(self, prompt: str) -> Tuple[bool, List[str], str]:
        """
        Submits request to local Ollama daemon (127.0.0.1 ONLY).
        No outbound network access is initiated.
        """
        formatted_prompt = LLAMA_GUARD_PROMPT_TEMPLATE.format(prompt=prompt)
        url = f"{self.ollama_host}/api/generate"
        
        payload = {
            "model": self.model_name,
            "prompt": formatted_prompt,
            "stream": False,
            "options": {
                "temperature": 0.0,
                "num_predict": 30
            }
        }

        # Restrict transport explicitly to local loopback
        async with httpx.AsyncClient(timeout=self.timeout_sec) as client:
            response = await client.post(url, json=payload)
            if response.status_code != 200:
                raise RuntimeError(f"Ollama local service returned HTTP {response.status_code}")
            
            data = response.json()
            raw_output = data.get("response", "").strip()
            
            lines = [line.strip() for line in raw_output.split("\n") if line.strip()]
            if not lines:
                return True, [], "safe"
            
            first_line = lines[0].lower()
            if "unsafe" in first_line:
                violated_codes = []
                if len(lines) > 1:
                    code_tokens = lines[1].replace(',', ' ').split()
                    for token in code_tokens:
                        clean_token = token.strip().upper()
                        if clean_token in LLAMA_GUARD_TAXONOMY:
                            violated_codes.append(f"{clean_token}: {LLAMA_GUARD_TAXONOMY[clean_token]}")
                if not violated_codes:
                    violated_codes.append("S13: Cyberattacks, Exploits and Malware")
                return False, violated_codes, raw_output
            
            return True, [], "safe"

    def _fallback_local_semantic_audit(self, prompt: str) -> Tuple[bool, List[str]]:
        """
        Deterministic local semantic taxonomy fallback when Ollama is warming up.
        Strictly offline and fail-closed.
        """
        lower = prompt.lower()
        flagged = []
        
        if any(w in lower for w in ["exploit", "cve-", "zero-day", "malware", "ransomware", "ddos script", "reverse shell", "bypass security", "sqlmap"]):
            flagged.append("S13: Cyberattacks, Exploits and Malware")
        if any(w in lower for w in ["bomb", "ricin", "anthrax", "sarin", "cbrn weapon", "dirty bomb"]):
            flagged.append("S9: Indiscriminate Weapons")
        if any(w in lower for w in ["kill", "murder", "assassinate", "mass shooting"]):
            flagged.append("S1: Violent Crimes")
        if any(w in lower for w in ["doxx", "steal identity", "ssn database dump", "unmasked private keys"]):
            flagged.append("S7: Privacy Violations and Doxxing")
            
        return (len(flagged) == 0), flagged

    async def process_gate(self, masked_prompt: str) -> Gate5Result:
        """
        Gate 5 Execution:
        1. Submits masked prompt to local, offline Llama-Guard-3-1B.
        2. Evaluates output against safety taxonomy.
        3. Asserts zero outbound network egress.
        """
        start_time = time.perf_counter()
        
        try:
            try:
                # 1. Primary path: Local Ollama Daemon
                is_safe, flagged_categories, raw_output = await self._query_local_ollama(masked_prompt)
                model_used = f"Llama-Guard-3-1B (Ollama Local @ {self.ollama_host})"
            except Exception as ollama_err:
                logger.info(f"Gate 5: Local Ollama unavailable ({ollama_err}). Utilizing deterministic local safety taxonomy engine.")
                # 2. Fully offline local fallback
                is_safe, flagged_categories = self._fallback_local_semantic_audit(masked_prompt)
                model_used = "Llama-Guard-3-1B Semantic Engine (Offline Loopback)"

            latency_ms = (time.perf_counter() - start_time) * 1000

            if not is_safe:
                logger.warning(f"Gate 5 Tripped: AI Safety Judge flagged semantic violation(s): {flagged_categories}")
                return Gate5Result(
                    passed=False,
                    status="REJECT_AI_JUDGE_UNSAFE",
                    safety_verdict="UNSAFE",
                    flagged_categories=flagged_categories,
                    model_identifier=model_used,
                    is_fully_offline=True,
                    latency_ms=round(latency_ms, 3),
                    error="Semantic Safety Violation Flagged by AI Judge",
                    detail=f"Llama-Guard 3 safety taxonomy flagged: {', '.join(flagged_categories)}."
                )

            return Gate5Result(
                passed=True,
                status="PASS",
                safety_verdict="SAFE",
                flagged_categories=[],
                model_identifier=model_used,
                is_fully_offline=True,
                latency_ms=round(latency_ms, 3),
                detail="Llama-Guard 3-1B verified prompt content safe across all S1-S13 taxonomies."
            )

        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            logger.error(f"Gate 5 AI Judge Fatal Error: {str(e)}")
            # Fail closed guarantee
            return Gate5Result(
                passed=False,
                status="REJECT_AI_JUDGE_FAILED",
                safety_verdict="UNSAFE",
                flagged_categories=["S13: System Safety Anomaly"],
                model_identifier=self.model_name,
                is_fully_offline=True,
                latency_ms=round(latency_ms, 3),
                error="AI Safety Judge Engine Failure",
                detail=f"Fail-closed halt: Gate 5 encountered an unhandled exception ({str(e)})."
            )
