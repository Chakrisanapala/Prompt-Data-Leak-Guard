"""
Prompt Rewriter Engine.
Generates privacy-safe, task-preserving prompt rewrites using Local Ollama LLM or Deterministic Safe Fallback.
Follows strict Privacy-by-Design: Spans are masked BEFORE sending to any LLM.
"""

import time
import logging
import requests
from typing import List, Dict, Any, Tuple, Optional
from core.models import DetectedSpan
from core.anonymizer import Anonymizer
from config import DEFAULT_OLLAMA_HOST, DEFAULT_OLLAMA_MODEL

logger = logging.getLogger(__name__)


class PromptRewriter:
    """Orchestrates safe prompt rewriting via local Ollama LLM with zero-dependency fallback."""

    def __init__(self, host: str = DEFAULT_OLLAMA_HOST, default_model: str = DEFAULT_OLLAMA_MODEL):
        self.host = host.rstrip("/")
        self.default_model = default_model
        self.anonymizer = Anonymizer()

    def check_ollama_status(self) -> Dict[str, Any]:
        """Check if local Ollama daemon is responsive and list available models."""
        try:
            resp = requests.get(f"{self.host}/api/tags", timeout=1.5)
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                return {
                    "available": True,
                    "models": models,
                    "host": self.host,
                    "status_message": f"Connected to Ollama ({len(models)} local models found)",
                }
        except Exception as e:
            logger.debug(f"Ollama not reachable at {self.host}: {e}")

        return {
            "available": False,
            "models": [],
            "host": self.host,
            "status_message": "Ollama daemon offline. Instant Fallback Rewriter active.",
        }

    def rewrite(
        self,
        text: str,
        spans: List[DetectedSpan],
        model: Optional[str] = None,
        prefer_ollama: bool = True,
        timeout_seconds: float = 12.0,
    ) -> Tuple[str, str, float]:
        """
        Rewrite the prompt safely.
        Returns:
            (rewritten_prompt, backend_used, latency_ms)
        """
        if not spans:
            # If no sensitive data was detected, prompt is already clean
            return text, "none_needed", 0.0

        t0 = time.perf_counter()

        # Step 1: Pre-anonymize locally with typed placeholders before passing to any LLM (Privacy-by-Design)
        placeholder_prompt = self.anonymizer.mask_with_placeholders(text, spans)

        if not prefer_ollama:
            latency_ms = (time.perf_counter() - t0) * 1000.0
            return placeholder_prompt, "deterministic_fallback", latency_ms

        # Step 2: Try local Ollama LLM
        target_model = model or self.default_model
        ollama_status = self.check_ollama_status()

        if ollama_status["available"]:
            try:
                system_prompt = (
                    "You are a Privacy Guard prompt sanitizer assistant.\n"
                    "Your goal: Rewrite the user's prompt by preserving their exact technical request, logic, code structure, and question, "
                    "while keeping all typed placeholders like <AWS_ACCESS_KEY_ID>, <PERSON_NAME>, <EMAIL_ADDRESS>, <PASSWORD>, <INTERNAL_IP> intact.\n"
                    "Rules:\n"
                    "1. Do NOT add conversational preamble (do not say 'Here is the rewritten prompt:').\n"
                    "2. Return ONLY the sanitized prompt text.\n"
                    "3. Keep all formatting, markdown, code blocks, and typed placeholders intact.\n"
                    "4. NEVER invent or hallucinate realistic person names, fake emails, phone numbers, or credentials."
                )

                user_content = (
                    f"Please refine and polish this safe version of a prompt while keeping its original problem and instructions intact:\n\n"
                    f"{placeholder_prompt}"
                )

                payload = {
                    "model": target_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_content},
                    ],
                    "stream": False,
                    "options": {
                        "temperature": 0.2,
                        "num_predict": 1024,
                    },
                }

                resp = requests.post(f"{self.host}/api/chat", json=payload, timeout=timeout_seconds)
                if resp.status_code == 200:
                    res_json = resp.json()
                    rewritten = res_json.get("message", {}).get("content", "").strip()
                    if rewritten and len(rewritten) > 10:
                        # Step 3: Enforce deterministic placeholder safety on LLM output
                        safe_rewritten = self.anonymizer.enforce_placeholder_safety(rewritten, spans)
                        latency_ms = (time.perf_counter() - t0) * 1000.0
                        return safe_rewritten, f"ollama ({target_model})", latency_ms
            except Exception as e:
                logger.warning(f"Ollama generation failed or timed out: {e}. Using deterministic fallback.")

        # Step 4: Reliable deterministic fallback
        latency_ms = (time.perf_counter() - t0) * 1000.0
        return placeholder_prompt, "deterministic_fallback", latency_ms
