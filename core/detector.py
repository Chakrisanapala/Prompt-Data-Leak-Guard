"""
Guard Detector Orchestrator.
Combines Regex secrets detection, Presidio PII analysis, conflict resolution, risk scoring, and safe prompt rewriting.
"""

import time
from typing import List, Optional
from core.models import ScanResult, DetectedSpan, SeverityLevel
from core.regex_detector import RegexDetector
from core.presidio_detector import PresidioDetector
from core.span_utils import merge_and_resolve_spans
from core.risk_explainer import RiskExplainer
from core.anonymizer import Anonymizer
from core.rewriter import PromptRewriter


class GuardDetector:
    """Main entrypoint orchestrating data leak detection and prompt sanitization."""

    def __init__(self, ollama_host: Optional[str] = None):
        self.regex_detector = RegexDetector()
        self.presidio_detector = PresidioDetector()
        self.risk_explainer = RiskExplainer()
        self.anonymizer = Anonymizer()
        self.rewriter = PromptRewriter(host=ollama_host) if ollama_host else PromptRewriter()

    def scan(self, prompt: str, min_confidence: float = 0.4) -> List[DetectedSpan]:
        """Run all detectors and return merged, non-overlapping detected spans."""
        if not prompt or not prompt.strip():
            return []

        # 1. Regex Secrets scan
        regex_spans = self.regex_detector.scan(prompt)

        # 2. Presidio PII scan
        presidio_spans = self.presidio_detector.scan(prompt, min_confidence=min_confidence)

        # 3. Merge & resolve conflicts
        all_spans = regex_spans + presidio_spans
        resolved = merge_and_resolve_spans(all_spans)

        # 4. AWS Credential Pair Analysis on resolved spans
        has_aws_access = any(s.entity_type == "AWS_ACCESS_KEY" for s in resolved)
        has_aws_secret = any(s.entity_type in ("AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY") for s in resolved)
        if has_aws_access and has_aws_secret:
            for s in resolved:
                if s.entity_type in ("AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY"):
                    s.severity = SeverityLevel.CRITICAL
                    s.risk_explanation = (
                        "Exposes a complete AWS credential pair (Access Key ID + Secret Access Key). "
                        "This combination represents highly sensitive cloud credentials that grant full unauthorized access "
                        "to AWS cloud infrastructure (S3, EC2, IAM) and creates an immediate account takeover risk."
                    )

        return resolved

    def analyze_and_rewrite(
        self,
        prompt: str,
        prefer_ollama: bool = True,
        ollama_model: Optional[str] = None,
        min_confidence: float = 0.4,
    ) -> ScanResult:
        """Complete pipeline: scan, assess risk, mask, rewrite, and measure performance metrics."""
        t_start = time.perf_counter()

        # Step 1: Scan for sensitive entities
        spans = self.scan(prompt, min_confidence=min_confidence)
        t_scanned = time.perf_counter()
        scan_latency_ms = (t_scanned - t_start) * 1000.0

        # Step 2: Risk Assessment
        risk_summary = self.risk_explainer.assess_risk(spans)

        # Step 3: Masking & Safe Rewriting
        masked_prompt = self.anonymizer.mask_with_placeholders(prompt, spans)

        rewritten_prompt, backend_used, rewrite_latency_ms = self.rewriter.rewrite(
            text=prompt,
            spans=spans,
            model=ollama_model,
            prefer_ollama=prefer_ollama,
        )

        # Step 3b: FINAL SECURITY VALIDATION & SANITIZATION LAYER (Requirement 9)
        # 1. Enforce strict replacement of all detected original spans
        rewritten_prompt = self.anonymizer.enforce_placeholder_safety(rewritten_prompt, spans)

        # 2. Rescan the generated Safe Prompt with the detection engine to guarantee zero lingering leaks
        rescan_spans = self.scan(rewritten_prompt, min_confidence=0.3)
        if rescan_spans:
            rewritten_prompt = self.anonymizer.mask_with_placeholders(rewritten_prompt, rescan_spans)

        # 3. Final verification: ensure no raw sensitive string from original spans survives
        for span in spans:
            if span.text in rewritten_prompt:
                placeholder = span.suggested_placeholder or f"<{span.entity_type}>"
                rewritten_prompt = rewritten_prompt.replace(span.text, placeholder)

        total_latency_ms = (time.perf_counter() - t_start) * 1000.0

        # Step 4: Calculate Task Preservation Score (Lexical Jaccard & Structure preservation)
        preservation_score = self._compute_preservation_score(prompt, rewritten_prompt, spans)

        return ScanResult(
            original_prompt=prompt,
            spans=spans,
            risk_summary=risk_summary,
            safe_masked_prompt=masked_prompt,
            safe_rewritten_prompt=rewritten_prompt,
            scan_latency_ms=round(scan_latency_ms, 2),
            rewrite_latency_ms=round(rewrite_latency_ms, 2),
            total_latency_ms=round(total_latency_ms, 2),
            rewriter_backend=backend_used,
            task_preservation_score=round(preservation_score, 3),
        )

    def _compute_preservation_score(self, original: str, rewritten: str, spans: List[DetectedSpan]) -> float:
        """
        Estimate task & intent preservation score (0.0 to 1.0)
        by comparing non-sensitive token overlap between original and rewritten prompts.
        """
        if not original.strip():
            return 1.0
        if not spans:
            return 1.0

        # Extract non-sensitive words from original
        orig_clean = original
        for span in spans:
            orig_clean = orig_clean.replace(span.text, " ")

        orig_words = set(w.lower() for w in orig_clean.split() if len(w) > 2)
        rewritten_words = set(w.lower() for w in rewritten.split() if len(w) > 2)

        if not orig_words:
            return 1.0

        overlap = orig_words.intersection(rewritten_words)
        jaccard = len(overlap) / len(orig_words)

        # Base preservation minimum if core structure is kept
        return min(1.0, max(0.5, jaccard * 1.15))
