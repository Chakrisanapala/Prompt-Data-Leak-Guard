"""
Risk Assessment and Explainability Engine.
Quantifies threat levels, detects regulatory compliance exposures, and generates actionable risk rationales.
"""

from typing import List, Dict, Any, Tuple
from core.models import DetectedSpan, SeverityLevel, CategoryType, RiskSummary


class RiskExplainer:
    """Computes risk scores, compliance implications, and human-readable risk summaries."""

    SEVERITY_WEIGHTS = {
        SeverityLevel.CRITICAL: 35,
        SeverityLevel.HIGH: 20,
        SeverityLevel.MEDIUM: 10,
        SeverityLevel.LOW: 3,
    }

    def assess_risk(self, spans: List[DetectedSpan]) -> RiskSummary:
        """Analyze detected spans and construct a RiskSummary."""
        if not spans:
            return RiskSummary(
                total_detected=0,
                max_severity=None,
                risk_score=0,
                severity_counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                category_counts={"SECRET": 0, "PII": 0, "INTERNAL_DATA": 0, "INTERNAL_INFRASTRUCTURE": 0},
                compliance_risks=[],
                overview_message="✅ No sensitive data detected. This prompt is safe for public LLMs.",
            )

        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        cat_counts = {"SECRET": 0, "PII": 0, "INTERNAL_DATA": 0, "INTERNAL_INFRASTRUCTURE": 0}
        compliance_set = set()

        raw_score = 0
        max_sev = SeverityLevel.LOW

        for span in spans:
            # Count severity
            sev_counts[span.severity.value] += 1
            cat_counts[span.category.value] += 1

            # Accumulate raw weighted score
            raw_score += self.SEVERITY_WEIGHTS.get(span.severity, 5)

            # Track max severity
            if span.severity == SeverityLevel.CRITICAL:
                max_sev = SeverityLevel.CRITICAL
            elif span.severity == SeverityLevel.HIGH and max_sev != SeverityLevel.CRITICAL:
                max_sev = SeverityLevel.HIGH
            elif span.severity == SeverityLevel.MEDIUM and max_sev not in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
                max_sev = SeverityLevel.MEDIUM

            # Compliance detection logic
            if span.entity_type == "CREDIT_CARD":
                compliance_set.add("PCI-DSS (Payment Card Industry Data Security Standard)")
            if span.entity_type in ("US_SSN", "EMAIL_ADDRESS", "PERSON", "PHONE_NUMBER", "LOCATION"):
                compliance_set.add("GDPR (General Data Protection Regulation)")
                compliance_set.add("CCPA (California Consumer Privacy Act)")
            if span.category == CategoryType.SECRET:
                compliance_set.add("SOC 2 (Trust Services Criteria - Security)")
                compliance_set.add("ISO/IEC 27001 (Information Security Management)")

        # Cap score between 0 and 100
        # If any CRITICAL secret is present, base score is at least 80
        if sev_counts["CRITICAL"] > 0:
            risk_score = min(100, max(80, raw_score))
        elif sev_counts["HIGH"] > 0:
            risk_score = min(79, max(50, raw_score))
        elif sev_counts["MEDIUM"] > 0:
            risk_score = min(49, max(25, raw_score))
        else:
            risk_score = min(24, max(5, raw_score))

        # Generate overview message
        if max_sev == SeverityLevel.CRITICAL:
            overview = f"🚨 CRITICAL RISK: Prompt contains {len(spans)} sensitive items including credentials or high-value personal data! Do NOT send to a public LLM."
        elif max_sev == SeverityLevel.HIGH:
            overview = f"⚠️ HIGH RISK: Prompt contains {len(spans)} sensitive tokens or identifiers. Redaction required."
        elif max_sev == SeverityLevel.MEDIUM:
            overview = f"⚡ MEDIUM RISK: Prompt contains {len(spans)} personal or corporate data elements. Anonymization recommended."
        else:
            overview = f"ℹ️ LOW RISK: Prompt contains {len(spans)} minor metadata or IP elements."

        return RiskSummary(
            total_detected=len(spans),
            max_severity=max_sev,
            risk_score=risk_score,
            severity_counts=sev_counts,
            category_counts=cat_counts,
            compliance_risks=sorted(list(compliance_set)),
            overview_message=overview,
        )
