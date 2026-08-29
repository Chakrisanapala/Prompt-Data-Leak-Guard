"""
High-precision Regex-based Secrets, Credentials & Universal Pattern Detector.
Detects cloud API keys, tokens, passwords, database strings, private keys, corporate emails, and phone numbers.
"""

import re
import ipaddress
from typing import List, Dict, Any
from core.models import DetectedSpan, CategoryType, SeverityLevel


def is_private_ipv4(ip_str: str) -> bool:
    """Check if string is a valid private RFC1918 IPv4 address."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return ip_obj.version == 4 and ip_obj.is_private
    except ValueError:
        return False


class RegexDetector:
    """Regex pattern detector for secrets, credentials, and sensitive configurations."""

    def __init__(self):
        self.rules = self._init_rules()

    def _init_rules(self) -> List[Dict[str, Any]]:
        return [
            # 1. AWS Access Key ID
            {
                "entity_type": "AWS_ACCESS_KEY",
                "category": CategoryType.SECRET,
                "severity": SeverityLevel.HIGH,
                "pattern": re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
                "placeholder": "<AWS_ACCESS_KEY_ID>",
                "explanation": "Exposes an AWS Access Key ID. While not a complete credential on its own without the Secret Access Key, it identifies an AWS IAM user/role and should not be shared publicly.",
                "confidence": 0.99,
            },
            # 2. AWS Secret Access Key (all common forms: spaces, underscores, colons, equals)
            {
                "entity_type": "AWS_SECRET_ACCESS_KEY",
                "category": CategoryType.SECRET,
                "severity": SeverityLevel.CRITICAL,
                "pattern": re.compile(
                    r"(?i)(?:aws[_\s]+secret[_\s]+access[_\s]+key|aws[_\s]+secret[_\s]+key|aws[_\s]+secret|secret[_\s]+access[_\s]+key|secret[_\s]+key|aws[_\s]+sec[_\s]+key|aws[_\s]+key|secret[_\s]+token|api[_\s]+secret|secret)\s*(?:=|:|is|\s)\s*['\"]?([0-9a-zA-Z/+=]{40})['\"]?"
                ),
                "group": 1,
                "placeholder": "<AWS_SECRET_ACCESS_KEY>",
                "explanation": "Exposes an AWS Secret Access Key. This is a private cryptographic master key that provides programmatic access to AWS cloud services and must never be exposed.",
                "confidence": 0.99,
            },
            # 3. OpenAI API Keys (old format sk-..., project format sk-proj-...)
            {
                "entity_type": "OPENAI_API_KEY",
                "category": CategoryType.SECRET,
                "severity": SeverityLevel.CRITICAL,
                "pattern": re.compile(r"\b(sk-[a-zA-Z0-9]{20,T3BlbkFJ[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9\-_]{32,}|sk-[a-zA-Z0-9]{32,})\b"),
                "placeholder": "<OPENAI_API_KEY>",
                "explanation": "Exposes an OpenAI API key. Public LLMs or third parties could abuse this token to deplete quota or access private fine-tuned models.",
                "confidence": 0.99,
            },
            # 4. GitHub Personal Access Tokens (Classic & Fine-Grained)
            {
                "entity_type": "GITHUB_TOKEN",
                "category": CategoryType.SECRET,
                "severity": SeverityLevel.CRITICAL,
                "pattern": re.compile(r"\b(gh[pousr]_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9_]{40,})\b"),
                "placeholder": "<GITHUB_ACCESS_TOKEN>",
                "explanation": "Exposes a GitHub Personal Access Token. Can allow unauthorized read/write access to proprietary source code and CI/CD pipelines.",
                "confidence": 0.99,
            },
            # 5. Slack Bot / User Tokens
            {
                "entity_type": "SLACK_TOKEN",
                "category": CategoryType.SECRET,
                "severity": SeverityLevel.HIGH,
                "pattern": re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{8,14}-[0-9a-zA-Z]{8,14}-[a-zA-Z0-9]{20,34})\b"),
                "placeholder": "<SLACK_TOKEN>",
                "explanation": "Exposes a Slack OAuth token, risking eavesdropping on internal workplace conversations or sending unauthorized messages.",
                "confidence": 0.99,
            },
            # 6. Google Cloud / Firebase API Key
            {
                "entity_type": "GOOGLE_API_KEY",
                "category": CategoryType.SECRET,
                "severity": SeverityLevel.HIGH,
                "pattern": re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
                "placeholder": "<GOOGLE_API_KEY>",
                "explanation": "Exposes a Google Cloud or Firebase API Key, potentially granting access to Maps, Firebase DBs, or GCP services.",
                "confidence": 0.95,
            },
            # 7. HuggingFace Access Token
            {
                "entity_type": "HUGGINGFACE_TOKEN",
                "category": CategoryType.SECRET,
                "severity": SeverityLevel.HIGH,
                "pattern": re.compile(r"\b(hf_[a-zA-Z0-9]{34,})\b"),
                "placeholder": "<HUGGINGFACE_TOKEN>",
                "explanation": "Exposes a HuggingFace User Access Token. Can compromise private repositories, models, and datasets.",
                "confidence": 0.98,
            },
            # 8. Stripe API Key
            {
                "entity_type": "STRIPE_KEY",
                "category": CategoryType.SECRET,
                "severity": SeverityLevel.CRITICAL,
                "pattern": re.compile(r"\b((?:sk|pk|rk)_(?:live|test|mock|sample|dummy|test_mock)_[0-9a-zA-Z]{16,34})\b"),
                "placeholder": "<STRIPE_API_KEY>",
                "explanation": "Exposes a Stripe payment processing key. Live keys present a catastrophic risk of unauthorized financial charges or customer record leaks.",
                "confidence": 0.98,
            },
            # 9. JSON Web Token (JWT)
            {
                "entity_type": "JWT_TOKEN",
                "category": CategoryType.SECRET,
                "severity": SeverityLevel.HIGH,
                "pattern": re.compile(r"\b(eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})\b"),
                "placeholder": "<JWT_TOKEN>",
                "explanation": "Exposes an active JSON Web Token (JWT) containing user claims, session state, and cryptographic signatures.",
                "confidence": 0.96,
            },
            # 10. Private Encryption Keys
            {
                "entity_type": "PRIVATE_KEY",
                "category": CategoryType.SECRET,
                "severity": SeverityLevel.CRITICAL,
                "pattern": re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)"),
                "placeholder": "<RSA_PRIVATE_KEY_BLOCK>",
                "explanation": "Exposes a private cryptographic key. Compromises server SSH access, SSL/TLS decryption, and server authentication.",
                "confidence": 1.0,
            },
            # 11. Database Connection URIs with credentials
            {
                "entity_type": "DATABASE_URI",
                "category": CategoryType.SECRET,
                "severity": SeverityLevel.CRITICAL,
                "pattern": re.compile(r"((?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|mssql):\/\/[^\s@]+:[^\s@]+@[^\s\/]+(?:\/[^\s\?\"']*)?)"),
                "placeholder": "<DATABASE_CONNECTION_URI>",
                "explanation": "Exposes a full database connection string with plaintext username, password, and host. Highly vulnerable to direct data exfiltration.",
                "confidence": 0.99,
            },
            # 12. Password / Secret in assignment statements
            {
                "entity_type": "PASSWORD_ASSIGNMENT",
                "category": CategoryType.SECRET,
                "severity": SeverityLevel.CRITICAL,
                "pattern": re.compile(r"(?i)(?:password|passwd|pwd|db_pass|api_secret|client_secret)\s*[:=]\s*['\"]([^'\"\n]{6,})['\"]"),
                "group": 1,
                "placeholder": "<REDACTED_PASSWORD>",
                "explanation": "Exposes a hardcoded plaintext password or client secret in configuration or source code.",
                "confidence": 0.92,
            },
            # 13. Credit Card Numbers (Formatted or continuous 13-19 digits)
            {
                "entity_type": "CREDIT_CARD",
                "category": CategoryType.PII,
                "severity": SeverityLevel.CRITICAL,
                "pattern": re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"),
                "placeholder": "<CREDIT_CARD_NUMBER>",
                "explanation": "Exposes a 16-digit credit card number. Violates PCI-DSS regulations and exposes individuals to identity theft and financial fraud.",
                "confidence": 0.88,
            },
            # 14. US Social Security Number (SSN)
            {
                "entity_type": "US_SSN",
                "category": CategoryType.PII,
                "severity": SeverityLevel.CRITICAL,
                "pattern": re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
                "placeholder": "<US_SSN>",
                "explanation": "Exposes a United States Social Security Number (SSN). High risk of personal identity theft and privacy regulation violations.",
                "confidence": 0.95,
            },
            # 15. Universal Email Address (Internet + Corporate Intranet)
            {
                "entity_type": "EMAIL_ADDRESS",
                "category": CategoryType.PII,
                "severity": SeverityLevel.MEDIUM,
                "pattern": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
                "placeholder": "<EMAIL_ADDRESS>",
                "explanation": "Exposes a personal or corporate email address.",
                "confidence": 0.95,
            },
            # 16. Universal Phone Number (including 7-digit US local 555-0199 and international)
            {
                "entity_type": "PHONE_NUMBER",
                "category": CategoryType.PII,
                "severity": SeverityLevel.MEDIUM,
                "pattern": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b|\b\d{3}[-.]\d{4}\b"),
                "placeholder": "<PHONE_NUMBER>",
                "explanation": "Exposes a telephone or mobile number.",
                "confidence": 0.90,
            },
            # 17. IPv4 Addresses (dynamically evaluated as INTERNAL_IP or public IP_ADDRESS)
            {
                "entity_type": "IPV4_ADDRESS",
                "category": CategoryType.INTERNAL_DATA,
                "severity": SeverityLevel.LOW,
                "pattern": re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
                "placeholder": "<IP_ADDRESS>",
                "explanation": "Exposes an IP address.",
                "confidence": 0.96,
            },
            # 18. Internal Hostnames (e.g. db.internal.corp, auth.staging.local)
            {
                "entity_type": "INTERNAL_HOST",
                "category": CategoryType.INTERNAL_DATA,
                "severity": SeverityLevel.MEDIUM,
                "pattern": re.compile(r"\b[a-zA-Z0-9\-_.]+\.(?:internal|corp|local|lan|intranet)(?:\.[a-zA-Z0-9\-_]+)?\b"),
                "placeholder": "<INTERNAL_HOSTNAME>",
                "explanation": "Exposes an internal company server hostname or domain suffix.",
                "confidence": 0.92,
            },
        ]

    def scan(self, text: str) -> List[DetectedSpan]:
        """Scan text and return a list of DetectedSpans with AWS credential pair and IP classification."""
        spans: List[DetectedSpan] = []

        for rule in self.rules:
            pattern: re.Pattern = rule["pattern"]
            group_idx = rule.get("group", 0)

            for match in pattern.finditer(text):
                try:
                    span_text = match.group(group_idx)
                    start, end = match.span(group_idx)
                except IndexError:
                    span_text = match.group(0)
                    start, end = match.span(0)

                # Skip empty or trivially short false matches
                if not span_text or len(span_text.strip()) < 3:
                    continue

                # Skip phone number regex matching dot-separated IP addresses
                if rule["entity_type"] == "PHONE_NUMBER" and span_text.count(".") >= 2:
                    continue

                entity_type = rule["entity_type"]
                category = rule["category"]
                severity = rule["severity"]
                placeholder = rule["placeholder"]
                explanation = rule["explanation"]

                # Differentiate private vs public IPv4 addresses
                if entity_type == "IPV4_ADDRESS":
                    if is_private_ipv4(span_text):
                        entity_type = "INTERNAL_IP"
                        category = CategoryType.INTERNAL_INFRASTRUCTURE
                        severity = SeverityLevel.MEDIUM
                        placeholder = "<INTERNAL_IP>"
                        explanation = "Exposing an internal/private IP can reveal internal network topology or infrastructure information and may assist reconnaissance."
                    else:
                        entity_type = "IP_ADDRESS"
                        category = CategoryType.INTERNAL_DATA
                        severity = SeverityLevel.LOW
                        placeholder = "<IP_ADDRESS>"
                        explanation = "Exposes a public IP address which may disclose network endpoints or user geographic location."

                spans.append(
                    DetectedSpan(
                        text=span_text,
                        start=start,
                        end=end,
                        entity_type=entity_type,
                        category=category,
                        severity=severity,
                        confidence=rule["confidence"],
                        risk_explanation=explanation,
                        suggested_placeholder=placeholder,
                        detector_source="regex",
                    )
                )

        # Contextual AWS Secret detection: If an AWS Access Key ID is detected in prompt,
        # scan for any 40-character base64 secret tokens that are not yet caught in spans
        has_aws_access_key = any(s.entity_type == "AWS_ACCESS_KEY" for s in spans)
        if has_aws_access_key:
            token_pattern = re.compile(r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])")
            for match in token_pattern.finditer(text):
                t_start, t_end = match.span(1)
                t_text = match.group(1)
                # Check overlap with existing spans
                if not any(s.start <= t_start and t_end <= s.end for s in spans):
                    has_upper = any(c.isupper() for c in t_text)
                    has_lower = any(c.islower() for c in t_text)
                    has_digit = any(c.isdigit() for c in t_text)
                    if (has_upper and has_lower) or (has_upper and has_digit) or ('/' in t_text or '+' in t_text):
                        spans.append(
                            DetectedSpan(
                                text=t_text,
                                start=t_start,
                                end=t_end,
                                entity_type="AWS_SECRET_ACCESS_KEY",
                                category=CategoryType.SECRET,
                                severity=SeverityLevel.CRITICAL,
                                confidence=0.98,
                                risk_explanation="Exposes an AWS Secret Access Key. This is a private cryptographic master key that provides programmatic access to AWS cloud services and must never be exposed.",
                                suggested_placeholder="<AWS_SECRET_ACCESS_KEY>",
                                detector_source="regex",
                            )
                        )

        # AWS Credential Pair Analysis: Elevate pair to CRITICAL with complete credential explanation
        has_aws_access_key = any(s.entity_type == "AWS_ACCESS_KEY" for s in spans)
        has_aws_secret_key = any(s.entity_type in ("AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY") for s in spans)

        if has_aws_access_key and has_aws_secret_key:
            for s in spans:
                if s.entity_type in ("AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY"):
                    s.severity = SeverityLevel.CRITICAL
                    s.risk_explanation = (
                        "Exposes a complete AWS credential pair (Access Key ID + Secret Access Key). "
                        "This combination represents highly sensitive cloud credentials that grant full unauthorized access "
                        "to AWS cloud infrastructure (S3, EC2, IAM) and creates an immediate account takeover risk."
                    )

        return spans
