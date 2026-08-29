"""
Data models and typed schemas for Prompt Data-Leak Guard.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class CategoryType(str, Enum):
    SECRET = "SECRET"
    PII = "PII"
    INTERNAL_DATA = "INTERNAL_DATA"
    INTERNAL_INFRASTRUCTURE = "INTERNAL_INFRASTRUCTURE"


class DetectedSpan(BaseModel):
    text: str = Field(description="The exact text snippet that was detected")
    start: int = Field(description="Starting character offset in the prompt")
    end: int = Field(description="Ending character offset in the prompt")
    entity_type: str = Field(description="Entity type identifier (e.g. AWS_ACCESS_KEY, EMAIL_ADDRESS, PERSON)")
    category: CategoryType = Field(default=CategoryType.PII, description="Category of the detected item")
    severity: SeverityLevel = Field(default=SeverityLevel.MEDIUM, description="Assessed severity level")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0")
    risk_explanation: str = Field(default="", description="Educational risk explanation")
    suggested_placeholder: str = Field(default="", description="Sanitized placeholder for replacement")
    detector_source: str = Field(default="regex", description="Source detector: regex, presidio, custom")


class RiskSummary(BaseModel):
    total_detected: int = 0
    max_severity: Optional[SeverityLevel] = None
    risk_score: int = Field(default=0, ge=0, le=100, description="0 to 100 overall leak risk score")
    severity_counts: Dict[str, int] = Field(default_factory=lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})
    category_counts: Dict[str, int] = Field(default_factory=lambda: {"SECRET": 0, "PII": 0, "INTERNAL_DATA": 0, "INTERNAL_INFRASTRUCTURE": 0})
    compliance_risks: List[str] = Field(default_factory=list, description="Applicable regulations e.g. GDPR, PCI-DSS, SOC2, HIPAA")
    overview_message: str = ""


class ScanResult(BaseModel):
    original_prompt: str
    spans: List[DetectedSpan] = Field(default_factory=list)
    risk_summary: RiskSummary = Field(default_factory=RiskSummary)
    safe_masked_prompt: str = ""
    safe_rewritten_prompt: str = ""
    scan_latency_ms: float = 0.0
    rewrite_latency_ms: float = 0.0
    total_latency_ms: float = 0.0
    rewriter_backend: str = "fallback"  # 'ollama' or 'fallback'
    task_preservation_score: float = 1.0  # 0.0 to 1.0


class BenchmarkCase(BaseModel):
    id: str
    title: str
    category: str
    prompt: str
    expected_entities: List[str]
    expected_min_count: int


class BenchmarkCaseResult(BaseModel):
    case_id: str
    title: str
    category: str
    expected_count: int
    detected_count: int
    expected_entities: List[str] = Field(default_factory=list)
    detected_entities: List[str] = Field(default_factory=list)
    matched_entities: List[str] = Field(default_factory=list)
    missed_entities: List[str] = Field(default_factory=list)
    false_positives: List[str] = Field(default_factory=list)
    precision: float
    recall: float
    f1: float
    task_preservation_score: float
    scan_latency_ms: float
    rewrite_latency_ms: float
    passed: bool
