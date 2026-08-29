"""
Unit tests for Secret Detection, PII Detection, and Span Conflict Resolution.
"""

import pytest
from core.models import SeverityLevel, CategoryType
from core.regex_detector import RegexDetector
from core.presidio_detector import PresidioDetector
from core.span_utils import merge_and_resolve_spans
from core.detector import GuardDetector
from core.anonymizer import Anonymizer


@pytest.fixture
def regex_detector():
    return RegexDetector()


@pytest.fixture
def presidio_detector():
    return PresidioDetector()


@pytest.fixture
def guard_detector():
    return GuardDetector()


def test_detect_aws_access_key_alone(guard_detector):
    """Test AWS Access Key ID alone: labeled accurately as HIGH severity, not complete credential."""
    text = "Deploying to AWS with aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE'. How do I list S3 buckets?"
    result = guard_detector.analyze_and_rewrite(text, prefer_ollama=False)
    spans = result.spans

    assert len(spans) == 1
    assert spans[0].entity_type == "AWS_ACCESS_KEY"
    assert spans[0].severity == SeverityLevel.HIGH
    assert spans[0].suggested_placeholder == "<AWS_ACCESS_KEY_ID>"
    assert "Access Key ID" in spans[0].risk_explanation
    assert "AKIAIOSFODNN7EXAMPLE" not in result.safe_rewritten_prompt


def test_detect_aws_secret_key_alone(guard_detector):
    """Test AWS Secret Access Key alone: detected as AWS_SECRET_ACCESS_KEY with CRITICAL severity."""
    text = "AWS Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    result = guard_detector.analyze_and_rewrite(text, prefer_ollama=False)
    spans = result.spans

    assert len(spans) == 1
    assert spans[0].entity_type in ("AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY")
    assert spans[0].severity == SeverityLevel.CRITICAL
    assert spans[0].suggested_placeholder == "<AWS_SECRET_ACCESS_KEY>"
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in result.safe_rewritten_prompt
    assert "<AWS_SECRET_ACCESS_KEY>" in result.safe_rewritten_prompt


def test_detect_aws_credential_pair_together(guard_detector):
    """Test AWS Access Key ID + Secret Key together: elevated to CRITICAL credential pair."""
    text = (
        "AWS Access Key ID: AKIAIOSFODNN7EXAMPLE\n"
        "AWS Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    )
    result = guard_detector.analyze_and_rewrite(text, prefer_ollama=False)
    spans = result.spans

    types = [s.entity_type for s in spans]
    assert "AWS_ACCESS_KEY" in types
    assert any(t in ("AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY") for t in types)
    assert all(s.severity == SeverityLevel.CRITICAL for s in spans)
    assert any("credential pair" in s.risk_explanation for s in spans)
    assert result.risk_summary.max_severity == SeverityLevel.CRITICAL

    # Safe rewrite removes BOTH values
    assert "AKIAIOSFODNN7EXAMPLE" not in result.safe_rewritten_prompt
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in result.safe_rewritten_prompt
    assert "<AWS_ACCESS_KEY_ID>" in result.safe_rewritten_prompt
    assert "<AWS_SECRET_ACCESS_KEY>" in result.safe_rewritten_prompt

    # Final Safe Prompt contains zero detectable AWS credentials
    rescan_spans = guard_detector.scan(result.safe_rewritten_prompt)
    assert len(rescan_spans) == 0


def test_detect_aws_secret_common_formats(guard_detector):
    """Test detection across all common AWS Secret Access Key formatting variations."""
    formats = [
        "AWS Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
        "secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "aws_secret_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
    ]
    for fmt in formats:
        res = guard_detector.analyze_and_rewrite(fmt, prefer_ollama=False)
        assert len(res.spans) == 1, f"Failed to detect secret in format: {fmt}"
        assert res.spans[0].entity_type in ("AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY")
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in res.safe_rewritten_prompt
        assert "<AWS_SECRET_ACCESS_KEY>" in res.safe_rewritten_prompt
        assert len(guard_detector.scan(res.safe_rewritten_prompt)) == 0


def test_detect_aws_and_db_secrets(regex_detector):
    text = (
        "Here is my config: aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE' and "
        "db_url = 'postgres://admin:SecretPass123@prod-db.internal:5432/main'"
    )
    spans = regex_detector.scan(text)
    types = [s.entity_type for s in spans]

    assert "AWS_ACCESS_KEY" in types
    assert "DATABASE_URI" in types
    assert any(s.severity == SeverityLevel.CRITICAL for s in spans)


def test_detect_openai_and_github_tokens(regex_detector):
    text = (
        "OPENAI_API_KEY='sk-proj-1234567890abcdef1234567890abcdef1234567890' "
        "GITHUB_TOKEN='ghp_1234567890abcdefghijklmnopqrstuvwxyz12'"
    )
    spans = regex_detector.scan(text)
    types = [s.entity_type for s in spans]

    assert "OPENAI_API_KEY" in types
    assert "GITHUB_TOKEN" in types


def test_detect_pii_entities(presidio_detector):
    text = "Please reach out to Alice Johnson at alice.johnson@example.com or call 415-555-0199."
    spans = presidio_detector.scan(text)
    types = [s.entity_type for s in spans]

    assert "EMAIL_ADDRESS" in types
    assert "PHONE_NUMBER" in types


def test_span_overlap_resolution():
    from core.models import DetectedSpan

    # Overlapping spans: span1 (0-20, CRITICAL), span2 (5-15, MEDIUM)
    span1 = DetectedSpan(
        text="postgres://user:pass",
        start=0,
        end=20,
        entity_type="DATABASE_URI",
        category=CategoryType.SECRET,
        severity=SeverityLevel.CRITICAL,
        confidence=0.99,
    )
    span2 = DetectedSpan(
        text="user:pass",
        start=5,
        end=15,
        entity_type="PASSWORD_ASSIGNMENT",
        category=CategoryType.SECRET,
        severity=SeverityLevel.MEDIUM,
        confidence=0.85,
    )

    resolved = merge_and_resolve_spans([span2, span1])
    assert len(resolved) == 1
    assert resolved[0].entity_type == "DATABASE_URI"


def test_clean_prompt_zero_leaks(guard_detector):
    clean_text = "How do I implement binary search in Python?"
    res = guard_detector.analyze_and_rewrite(clean_text, prefer_ollama=False)

    assert len(res.spans) == 0
    assert res.risk_summary.max_severity is None
    assert res.risk_summary.risk_score == 0
    assert res.task_preservation_score == 1.0


def test_detect_private_ip_10_range(guard_detector):
    """Test 10.20.5.15 classified as INTERNAL_IP and INTERNAL_INFRASTRUCTURE with MEDIUM severity."""
    text = "Connect to our staging server at 10.20.5.15 on port 8080."
    res = guard_detector.analyze_and_rewrite(text, prefer_ollama=False)
    spans = res.spans

    assert len(spans) == 1
    assert spans[0].entity_type == "INTERNAL_IP"
    assert spans[0].category == CategoryType.INTERNAL_INFRASTRUCTURE
    assert spans[0].severity == SeverityLevel.MEDIUM
    assert spans[0].suggested_placeholder == "<INTERNAL_IP>"
    assert "internal network topology" in spans[0].risk_explanation or "internal/private IP" in spans[0].risk_explanation
    assert "<INTERNAL_IP>" in res.safe_rewritten_prompt
    assert "10.20.5.15" not in res.safe_rewritten_prompt


def test_detect_private_ip_172_range(guard_detector):
    """Test 172.16.5.10 classified as INTERNAL_IP and INTERNAL_INFRASTRUCTURE."""
    text = "Database host is at 172.16.5.10. Please check query performance."
    res = guard_detector.analyze_and_rewrite(text, prefer_ollama=False)
    spans = res.spans

    assert len(spans) == 1
    assert spans[0].entity_type == "INTERNAL_IP"
    assert spans[0].category == CategoryType.INTERNAL_INFRASTRUCTURE
    assert spans[0].severity == SeverityLevel.MEDIUM
    assert spans[0].suggested_placeholder == "<INTERNAL_IP>"
    assert "<INTERNAL_IP>" in res.safe_rewritten_prompt
    assert "172.16.5.10" not in res.safe_rewritten_prompt


def test_detect_private_ip_192_range(guard_detector):
    """Test 192.168.1.20 classified as INTERNAL_IP and INTERNAL_INFRASTRUCTURE."""
    text = "Router admin gateway located at 192.168.1.20."
    res = guard_detector.analyze_and_rewrite(text, prefer_ollama=False)
    spans = res.spans

    assert len(spans) == 1
    assert spans[0].entity_type == "INTERNAL_IP"
    assert spans[0].category == CategoryType.INTERNAL_INFRASTRUCTURE
    assert spans[0].severity == SeverityLevel.MEDIUM
    assert spans[0].suggested_placeholder == "<INTERNAL_IP>"
    assert "<INTERNAL_IP>" in res.safe_rewritten_prompt
    assert "192.168.1.20" not in res.safe_rewritten_prompt


def test_detect_public_ip_not_internal(guard_detector):
    """Test public IP 93.184.216.34 is not classified as INTERNAL_IP or PII."""
    text = "Send web request to public endpoint 93.184.216.34."
    res = guard_detector.analyze_and_rewrite(text, prefer_ollama=False)
    spans = res.spans

    assert len(spans) == 1
    assert spans[0].entity_type != "INTERNAL_IP"
    assert spans[0].entity_type == "IP_ADDRESS"
    assert spans[0].category != CategoryType.PII
    assert spans[0].category == CategoryType.INTERNAL_DATA
    assert spans[0].severity == SeverityLevel.LOW


def test_detect_google_cloud_key(guard_detector):
    """Test Google Cloud API Key detection."""
    text = "Use Google Maps API with key AIzaSyD1234567890abcdefghijklmnopqrst-A to geocode this address."
    res = guard_detector.analyze_and_rewrite(text, prefer_ollama=False)
    types = [s.entity_type for s in res.spans]

    assert "GOOGLE_API_KEY" in types
    assert res.risk_summary.max_severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)
    assert "<GOOGLE_API_KEY>" in res.safe_rewritten_prompt


def test_detect_jwt_token(guard_detector):
    """Test JSON Web Token (JWT) detection."""
    jwt_sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    text = f"Bearer {jwt_sample} - why is this token rejected by the auth gateway?"
    res = guard_detector.analyze_and_rewrite(text, prefer_ollama=False)
    types = [s.entity_type for s in res.spans]

    assert "JWT_TOKEN" in types
    assert "<JWT_TOKEN>" in res.safe_rewritten_prompt
    assert jwt_sample not in res.safe_rewritten_prompt


def test_detect_private_rsa_key(guard_detector):
    """Test RSA private key block detection."""
    key_sample = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0DEMOMOCKKEYFORTESTINGPURPOSESONLYNOTAREALKEY...\n-----END RSA PRIVATE KEY-----"
    text = f"Here is my SSH private key: {key_sample}. How do I convert it to PEM format?"
    res = guard_detector.analyze_and_rewrite(text, prefer_ollama=False)
    types = [s.entity_type for s in res.spans]

    assert "PRIVATE_KEY" in types
    assert res.risk_summary.max_severity == SeverityLevel.CRITICAL
    assert "<PRIVATE_KEY>" in res.safe_rewritten_prompt


def test_detect_credit_card_pii(guard_detector):
    """Test payment credit card number detection."""
    text = "Please process refund for Visa card 4532-8921-9034-5821 expiring 12/28."
    res = guard_detector.analyze_and_rewrite(text, prefer_ollama=False)
    types = [s.entity_type for s in res.spans]

    assert "CREDIT_CARD" in types
    assert "<CREDIT_CARD>" in res.safe_rewritten_prompt
    assert "4532-8921-9034-5821" not in res.safe_rewritten_prompt


def test_detect_internal_hostname(guard_detector):
    """Test internal infrastructure hostname detection."""
    text = "Forward telemetry to internal broker at db.internal.corp on port 9092."
    res = guard_detector.analyze_and_rewrite(text, prefer_ollama=False)
    types = [s.entity_type for s in res.spans]

    assert "INTERNAL_HOST" in types
    assert "<INTERNAL_HOSTNAME>" in res.safe_rewritten_prompt
    assert "db.internal.corp" not in res.safe_rewritten_prompt


def test_safe_inputs_no_false_positives(guard_detector):
    """
    Test SAFE INPUTS:
    - Normal technical documentation
    - Python code without secrets
    - Ordinary numbers and loop variables
    - Example documentation placeholders like <YOUR_API_KEY>
    - Plain English query
    Ensure 0 leaks detected and no false positive alarms.
    """
    safe_prompts = [
        "How do I sort a dictionary by value in Python? Example: data = {'apple': 10, 'banana': 5}. for k, v in data.items(): print(k, v)",
        "Configure your API client: client = APIClient(api_key='<YOUR_API_KEY>'). Replace with your real token in production.",
        "The server port is 8080 and maximum timeout is 30 seconds. Calculate latency for 1000 requests.",
        "Write a Python regex to validate standard email format and explain how capture groups work.",
    ]

    for p in safe_prompts:
        res = guard_detector.analyze_and_rewrite(p, prefer_ollama=False)
        assert len(res.spans) == 0, f"False positive detected in safe prompt: '{p}', spans: {res.spans}"
        assert res.risk_summary.risk_score == 0
        assert res.task_preservation_score == 1.0

