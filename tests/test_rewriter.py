"""
Unit tests for Anonymization and Safe Prompt Rewriting.
"""

from core.detector import GuardDetector
from core.anonymizer import Anonymizer, TYPED_PLACEHOLDER_MAP


def test_anonymizer_placeholder_masking():
    anonymizer = Anonymizer()
    detector = GuardDetector()

    text = "Send an email to john.doe@work.com regarding ticket TICKET-10293."
    spans = detector.scan(text)

    masked = anonymizer.mask_with_placeholders(text, spans)
    assert "john.doe@work.com" not in masked
    assert "<EMAIL_ADDRESS>" in masked


def test_typed_placeholder_sanitization_for_pii_and_credentials():
    """
    Test Requirement 10:
    - Rahul Kumar becomes <PERSON_NAME>
    - rahul.kumar@example.com becomes <EMAIL_ADDRESS>
    - 10.20.5.15 becomes <INTERNAL_IP>
    - AKIAIOSFODNN7EXAMPLE becomes <AWS_ACCESS_KEY_ID>
    - No original sensitive values appear in the safe prompt
    - No fabricated identities (e.g. Alex Morgan) or mock credentials (AKIA_MOCK...) are introduced
    """
    detector = GuardDetector()
    prompt = (
        "Please send the deployment log to Rahul Kumar at rahul.kumar@example.com. "
        "The staging server is at 10.20.5.15 and uses aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE'. "
        "Generate a bash script to test SSH connectivity."
    )

    result = detector.analyze_and_rewrite(prompt, prefer_ollama=False)
    safe_prompt = result.safe_rewritten_prompt

    # 1. Exact typed placeholders present
    assert "<PERSON_NAME>" in safe_prompt
    assert "<EMAIL_ADDRESS>" in safe_prompt
    assert "<INTERNAL_IP>" in safe_prompt
    assert "<AWS_ACCESS_KEY_ID>" in safe_prompt

    # 2. No original sensitive data leaked
    assert "Rahul Kumar" not in safe_prompt
    assert "rahul.kumar@example.com" not in safe_prompt
    assert "10.20.5.15" not in safe_prompt
    assert "AKIAIOSFODNN7EXAMPLE" not in safe_prompt

    # 3. No fabricated identities or synthetic secrets
    assert "Alex Morgan" not in safe_prompt
    assert "Jordan Taylor" not in safe_prompt
    assert "AKIA_MOCK" not in safe_prompt
    assert "SafeMock" not in safe_prompt
    assert "user@example.com" not in safe_prompt

    # 4. Original technical task instructions preserved
    assert "deployment log" in safe_prompt
    assert "staging server" in safe_prompt
    assert "bash script" in safe_prompt
    assert "SSH connectivity" in safe_prompt
    assert result.task_preservation_score > 0.7


def test_safe_prompt_preserves_task_intent():
    detector = GuardDetector()
    prompt = (
        "Write a unit test for my S3 uploader: "
        "aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE' and "
        "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'. "
        "Make sure to mock the boto3 S3 client."
    )

    result = detector.analyze_and_rewrite(prompt, prefer_ollama=False)
    assert "AKIAIOSFODNN7EXAMPLE" not in result.safe_rewritten_prompt
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in result.safe_rewritten_prompt
    assert "<AWS_ACCESS_KEY_ID>" in result.safe_rewritten_prompt
    assert "<AWS_SECRET_ACCESS_KEY>" in result.safe_rewritten_prompt
    assert "unit test" in result.safe_rewritten_prompt.lower()
    assert "boto3" in result.safe_rewritten_prompt
    assert result.task_preservation_score > 0.6


def test_enforce_placeholder_safety_on_hallucinated_text():
    """Ensure enforce_placeholder_safety strips any surviving raw sensitive tokens."""
    anonymizer = Anonymizer()
    detector = GuardDetector()

    text = "Secret is AKIAIOSFODNN7EXAMPLE and user is Rahul Kumar."
    spans = detector.scan(text)

    # Simulate an LLM output that accidentally repeated one of the secrets
    llm_output = "Here is the result for AKIAIOSFODNN7EXAMPLE with user <PERSON_NAME>."
    safe_output = anonymizer.enforce_placeholder_safety(llm_output, spans)

    assert "AKIAIOSFODNN7EXAMPLE" not in safe_output
    assert "<AWS_ACCESS_KEY_ID>" in safe_output
    assert "<PERSON_NAME>" in safe_output
