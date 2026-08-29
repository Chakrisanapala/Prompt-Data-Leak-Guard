"""
Microsoft Presidio PII & NER Detector wrapper with custom recognizers, false positive filtering, and graceful fallback.
Detects personal names, email addresses, phone numbers, locations, and custom enterprise identifiers.
"""

import re
import ipaddress
import logging
from typing import List, Optional, Set
from core.models import DetectedSpan, CategoryType, SeverityLevel

logger = logging.getLogger(__name__)


def is_private_ipv4(ip_str: str) -> bool:
    """Check if string is a valid private RFC1918 IPv4 address."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return ip_obj.version == 4 and ip_obj.is_private
    except ValueError:
        return False

# Common programming, technical, and benign words that spaCy NER commonly misclassifies as PERSON/LOCATION
TECH_BENIGN_WHITELIST: Set[str] = {
    "python", "java", "javascript", "typescript", "c++", "c#", "rust", "golang", "go",
    "docker", "kubernetes", "k8s", "aws", "azure", "gcp", "sql", "mysql", "postgres",
    "postgresql", "mongodb", "redis", "react", "vue", "angular", "node", "nodejs",
    "s3", "ec2", "lambda", "iam", "api", "rest", "graphql", "http", "https", "url",
    "git", "github", "gitlab", "bitbucket", "linux", "ubuntu", "debian", "windows",
    "macos", "html", "css", "json", "yaml", "xml", "csv", "jwt", "oauth", "ssh",
    "boto3", "psycopg2", "pandas", "numpy", "django", "flask", "fastapi", "express",
    "spring", "springfield", "quicksort", "mergesort", "fibonacci", "big-o", "crud",
    "modal", "dialog", "component", "modules", "esc", "focus", "trapping", "closure",
    "keyboard", "props", "state", "redux", "nextjs", "vite", "webpack", "tailwind",
}

# Supported entity types to inspect (ignores unneeded noise like DATE_TIME, MONEY, CARDINAL)
SUPPORTED_ENTITIES = [
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "US_SSN",
    "CREDIT_CARD",
    "IP_ADDRESS",
    "US_BANK_NUMBER",
    "IBAN_CODE",
    "LOCATION",
    "EMPLOYEE_ID",
    "TICKET_ID",
    "INTERNAL_HOST",
]

# Entity Severity Mapping for PII items
PII_SEVERITY_MAP = {
    "EMAIL_ADDRESS": (SeverityLevel.MEDIUM, "<EMAIL_ADDRESS>", "Exposes personal or corporate email address, risking spam, targeted phishing, or GDPR violation."),
    "PHONE_NUMBER": (SeverityLevel.MEDIUM, "<PHONE_NUMBER>", "Exposes telephone number, exposing individuals to vishing, SIM swapping, and unsolicited contact."),
    "PERSON": (SeverityLevel.MEDIUM, "<PERSON_NAME>", "Discloses individual names. In sensitive contexts (e.g. HR, medical, legal), this violates privacy regulations."),
    "LOCATION": (SeverityLevel.LOW, "<LOCATION>", "Discloses physical location, residential address, or geographic details."),
    "US_SSN": (SeverityLevel.CRITICAL, "<US_SSN>", "Discloses US Social Security Number, critical risk of personal identity theft."),
    "CREDIT_CARD": (SeverityLevel.CRITICAL, "<CREDIT_CARD_NUMBER>", "Discloses payment card number, subject to PCI-DSS compliance and financial fraud."),
    "IP_ADDRESS": (SeverityLevel.LOW, "<IP_ADDRESS>", "Discloses IP address which may expose internal server topology or user location."),
    "US_BANK_NUMBER": (SeverityLevel.CRITICAL, "<BANK_ACCOUNT_NUMBER>", "Exposes bank account details, posing financial fraud risk."),
    "IBAN_CODE": (SeverityLevel.CRITICAL, "<IBAN_CODE>", "Exposes International Bank Account Number."),
    "EMPLOYEE_ID": (SeverityLevel.MEDIUM, "<EMPLOYEE_ID>", "Exposes internal corporate staff identifier."),
    "TICKET_ID": (SeverityLevel.LOW, "<INTERNAL_TICKET_ID>", "Exposes internal tracking or issue ticket ID."),
    "INTERNAL_HOST": (SeverityLevel.MEDIUM, "<INTERNAL_HOSTNAME>", "Exposes internal company intranet/server hostname."),
}


_GLOBAL_ANALYZER = None


def get_presidio_analyzer():
    """Singleton getter for Presidio AnalyzerEngine."""
    global _GLOBAL_ANALYZER
    if _GLOBAL_ANALYZER is not None:
        return _GLOBAL_ANALYZER

    try:
        from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        # Explicitly configure spaCy with en_core_web_sm for fast loading
        config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        provider = NlpEngineProvider(nlp_configuration=config)
        nlp_engine = provider.create_engine()
        analyzer = AnalyzerEngine(nlp_engine=nlp_engine)

        # Custom recognizer 1: Employee ID (e.g. EMP-10492, EMP_9921)
        emp_pattern = Pattern(name="emp_id_pattern", regex=r"\bEMP[-_]\d{4,7}\b", score=0.95)
        emp_recognizer = PatternRecognizer(
            supported_entity="EMPLOYEE_ID",
            patterns=[emp_pattern],
            context=["employee", "staff", "badge", "worker", "id"],
        )
        analyzer.registry.add_recognizer(emp_recognizer)

        # Custom recognizer 2: Internal Support Ticket (e.g. TICKET-88910, INC-12903)
        ticket_pattern = Pattern(name="ticket_pattern", regex=r"\b(?:TICKET|INC|BUG|REQ)[-_]\d{4,8}\b", score=0.90)
        ticket_recognizer = PatternRecognizer(
            supported_entity="TICKET_ID",
            patterns=[ticket_pattern],
            context=["ticket", "issue", "incident", "request"],
        )
        analyzer.registry.add_recognizer(ticket_recognizer)

        # Custom recognizer 3: Internal Hostname (e.g. db.internal.corp, auth.staging.local)
        host_pattern = Pattern(name="internal_host_pattern", regex=r"\b[a-zA-Z0-9\-_.]+\.internal\.(?:corp|local|net|lan)\b", score=0.95)
        host_recognizer = PatternRecognizer(
            supported_entity="INTERNAL_HOST",
            patterns=[host_pattern],
            context=["internal", "host", "server", "intranet"],
        )
        analyzer.registry.add_recognizer(host_recognizer)

        # Custom recognizer 4: Standard Phone Numbers
        phone_pattern = Pattern(name="us_phone_pattern", regex=r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b", score=0.85)
        phone_recognizer = PatternRecognizer(
            supported_entity="PHONE_NUMBER",
            patterns=[phone_pattern],
            context=["phone", "call", "mobile", "tel", "contact"],
        )
        analyzer.registry.add_recognizer(phone_recognizer)

        _GLOBAL_ANALYZER = analyzer
        return _GLOBAL_ANALYZER
    except Exception as e:
        logger.warning(f"Presidio initialization warning ({e}). Using robust fallback PII engine.")
        return None


class PresidioDetector:
    """Wrapper around Microsoft Presidio Analyzer with custom recognizers and whitelist filtering."""

    def __init__(self):
        self.analyzer = get_presidio_analyzer()
        self._is_presidio_loaded = self.analyzer is not None

    def scan(self, text: str, min_confidence: float = 0.35) -> List[DetectedSpan]:
        """Detect PII entities in the text."""
        if self._is_presidio_loaded and self.analyzer:
            try:
                return self._scan_with_presidio(text, min_confidence)
            except Exception as e:
                logger.error(f"Presidio scan error: {e}. Falling back to rule-based PII scan.")
                return self._scan_with_fallback(text)
        else:
            return self._scan_with_fallback(text)

    def _scan_with_presidio(self, text: str, min_confidence: float) -> List[DetectedSpan]:
        results = self.analyzer.analyze(
            text=text,
            language="en",
            entities=SUPPORTED_ENTITIES,
            score_threshold=min_confidence,
        )

        spans: List[DetectedSpan] = []
        for res in results:
            span_text = text[res.start:res.end].strip()
            entity_type = res.entity_type

            # Skip any span that is already a placeholder or contains angle brackets
            if span_text.startswith("<") or span_text.endswith(">") or "<" in span_text or ">" in span_text:
                continue

            # Whitelist filter: eliminate common programming and benign words misidentified as PERSON/LOCATION
            span_tokens = set(re.findall(r"\w+", span_text.lower()))
            if span_tokens and span_tokens.intersection(TECH_BENIGN_WHITELIST):
                continue

            # Person name validation: real human names do not contain '=', '_', or technical keywords
            if entity_type == "PERSON":
                if "=" in span_text or "_" in span_text or ":" in span_text or "/" in span_text:
                    continue
                if span_text.isupper() and len(span_text) > 4:
                    continue
                lower_text = span_text.lower()
                if any(kw in lower_text for kw in ["secret", "key", "token", "auth", "bearer", "access", "config", "jwt", "api"]):
                    continue
                # Skip single-word common non-name terms with low confidence
                if (" " not in span_text) and res.score < 0.85:
                    continue

            # Skip phone number misclassifications on IP addresses
            if entity_type == "PHONE_NUMBER" and span_text.count(".") >= 2:
                continue

            sev_info = PII_SEVERITY_MAP.get(
                entity_type,
                (SeverityLevel.MEDIUM, f"<{entity_type}>", f"Detected personal identifier of type {entity_type}.")
            )
            severity, placeholder, explanation = sev_info
            category = CategoryType.PII

            if entity_type == "IP_ADDRESS":
                if is_private_ipv4(span_text):
                    entity_type = "INTERNAL_IP"
                    category = CategoryType.INTERNAL_INFRASTRUCTURE
                    severity = SeverityLevel.MEDIUM
                    placeholder = "<INTERNAL_IP>"
                    explanation = "Exposing an internal/private IP can reveal internal network topology or infrastructure information and may assist reconnaissance."
                else:
                    category = CategoryType.INTERNAL_DATA
                    severity = SeverityLevel.LOW
                    placeholder = "<IP_ADDRESS>"
                    explanation = "Exposes a public IP address which may disclose network endpoints or user geographic location."
            elif entity_type in ("INTERNAL_HOST", "TICKET_ID"):
                category = CategoryType.INTERNAL_DATA

            spans.append(
                DetectedSpan(
                    text=span_text,
                    start=res.start,
                    end=res.end,
                    entity_type=entity_type,
                    category=category,
                    severity=severity,
                    confidence=round(res.score, 2),
                    risk_explanation=explanation,
                    suggested_placeholder=placeholder,
                    detector_source="presidio",
                )
            )
        return spans

    def _scan_with_fallback(self, text: str) -> List[DetectedSpan]:
        """Lightweight regex-based fallback for PII in case spaCy/Presidio is unavailable."""
        spans: List[DetectedSpan] = []

        fallback_rules = [
            (
                "EMAIL_ADDRESS",
                re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
                SeverityLevel.MEDIUM,
                "<EMAIL_ADDRESS>",
                "Exposes an email address.",
                0.95,
            ),
            (
                "PHONE_NUMBER",
                re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
                SeverityLevel.MEDIUM,
                "<PHONE_NUMBER>",
                "Exposes a phone number.",
                0.85,
            ),
            (
                "EMPLOYEE_ID",
                re.compile(r"\bEMP[-_]\d{4,7}\b"),
                SeverityLevel.MEDIUM,
                "<EMPLOYEE_ID>",
                "Exposes an internal employee identifier.",
                0.90,
            ),
            (
                "TICKET_ID",
                re.compile(r"\b(?:TICKET|INC|BUG|REQ)[-_]\d{4,8}\b"),
                SeverityLevel.LOW,
                "<INTERNAL_TICKET_ID>",
                "Exposes an internal ticket number.",
                0.85,
            ),
            (
                "PERSON",
                re.compile(r"(?i)(?:customer|patient|employee|user|member|staff|client)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)"),
                SeverityLevel.MEDIUM,
                "<PERSON_NAME>",
                "Exposes an individual person's name in a sensitive operational context.",
                0.75,
                1,
            ),
        ]

        for item in fallback_rules:
            entity_type = item[0]
            pattern = item[1]
            sev = item[2]
            placeholder = item[3]
            expl = item[4]
            conf = item[5]
            group_idx = item[6] if len(item) > 6 else 0

            for m in pattern.finditer(text):
                try:
                    span_text = m.group(group_idx)
                    start, end = m.span(group_idx)
                except IndexError:
                    span_text = m.group(0)
                    start, end = m.span(0)

                if span_text.lower() in TECH_BENIGN_WHITELIST:
                    continue

                spans.append(
                    DetectedSpan(
                        text=span_text,
                        start=start,
                        end=end,
                        entity_type=entity_type,
                        category=CategoryType.PII,
                        severity=sev,
                        confidence=conf,
                        risk_explanation=expl,
                        suggested_placeholder=placeholder,
                        detector_source="fallback_pii",
                    )
                )

        return spans
