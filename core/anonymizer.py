"""
Deterministic Anonymizer & Typed Placeholder Masking Engine.
Substitutes detected sensitive spans with clear, typed placeholders (e.g. <PERSON_NAME>, <AWS_ACCESS_KEY_ID>, <INTERNAL_IP>).
Ensures no fabricated identities or synthetic secret-looking strings are ever introduced.
"""

from typing import List, Dict, Set
from core.models import DetectedSpan
from core.span_utils import merge_and_resolve_spans


TYPED_PLACEHOLDER_MAP: Dict[str, str] = {
    "AWS_ACCESS_KEY": "<AWS_ACCESS_KEY_ID>",
    "AWS_ACCESS_KEY_ID": "<AWS_ACCESS_KEY_ID>",
    "AWS_SECRET_KEY": "<AWS_SECRET_ACCESS_KEY>",
    "AWS_SECRET_ACCESS_KEY": "<AWS_SECRET_ACCESS_KEY>",
    "INTERNAL_IP": "<INTERNAL_IP>",
    "PERSON": "<PERSON_NAME>",
    "EMAIL_ADDRESS": "<EMAIL_ADDRESS>",
    "PHONE_NUMBER": "<PHONE_NUMBER>",
    "PASSWORD": "<PASSWORD>",
    "PASSWORD_ASSIGNMENT": "<PASSWORD>",
    "CREDIT_CARD": "<CREDIT_CARD>",
    "JWT": "<JWT_TOKEN>",
    "JWT_TOKEN": "<JWT_TOKEN>",
    "PRIVATE_KEY": "<PRIVATE_KEY>",
    "DATABASE_URI": "<DATABASE_URI>",
    "OPENAI_API_KEY": "<OPENAI_API_KEY>",
    "GITHUB_TOKEN": "<GITHUB_ACCESS_TOKEN>",
    "SLACK_TOKEN": "<SLACK_TOKEN>",
    "GOOGLE_API_KEY": "<GOOGLE_API_KEY>",
    "HUGGINGFACE_TOKEN": "<HUGGINGFACE_TOKEN>",
    "STRIPE_KEY": "<STRIPE_API_KEY>",
    "US_SSN": "<US_SSN>",
    "US_BANK_NUMBER": "<BANK_ACCOUNT_NUMBER>",
    "IBAN_CODE": "<IBAN_CODE>",
    "EMPLOYEE_ID": "<EMPLOYEE_ID>",
    "TICKET_ID": "<INTERNAL_TICKET_ID>",
    "INTERNAL_HOST": "<INTERNAL_HOSTNAME>",
    "LOCATION": "<LOCATION>",
    "IP_ADDRESS": "<IP_ADDRESS>",
}


class Anonymizer:
    """Replaces sensitive spans with strictly typed placeholders."""

    def get_placeholder(
        self,
        entity_type: str,
        suggested_placeholder: str = "",
        count: int = 1,
        total_of_type: int = 1,
    ) -> str:
        """Return canonical typed placeholder for entity type."""
        if entity_type in TYPED_PLACEHOLDER_MAP:
            base = TYPED_PLACEHOLDER_MAP[entity_type]
        elif suggested_placeholder:
            base = suggested_placeholder
        else:
            base = f"<{entity_type.upper()}>"

        tag = base.strip("<>")
        if total_of_type > 1:
            return f"<{tag}_{count}>"
        return f"<{tag}>"

    def mask_with_placeholders(self, text: str, spans: List[DetectedSpan]) -> str:
        """
        Replace detected spans with canonical typed XML-style placeholders.
        Example: 'Rahul Kumar' -> '<PERSON_NAME>', '10.20.5.15' -> '<INTERNAL_IP>'
        """
        if not spans or not text:
            return text

        resolved_spans = merge_and_resolve_spans(spans)
        result = []
        last_idx = 0

        # Count distinct entity texts per type
        distinct_by_type: Dict[str, Set[str]] = {}
        for s in resolved_spans:
            distinct_by_type.setdefault(s.entity_type, set()).add(s.text)

        entity_map: Dict[str, str] = {}
        entity_counts: Dict[str, int] = {}

        for span in resolved_spans:
            if span.start > last_idx:
                result.append(text[last_idx:span.start])

            if span.text in entity_map:
                placeholder = entity_map[span.text]
            else:
                count = entity_counts.get(span.entity_type, 0) + 1
                entity_counts[span.entity_type] = count
                total_of_type = len(distinct_by_type.get(span.entity_type, set()))
                placeholder = self.get_placeholder(
                    span.entity_type,
                    span.suggested_placeholder,
                    count=count,
                    total_of_type=total_of_type,
                )
                entity_map[span.text] = placeholder

            result.append(placeholder)
            last_idx = span.end

        if last_idx < len(text):
            result.append(text[last_idx:])

        return "".join(result)

    def mask_with_synthetic_mock(self, text: str, spans: List[DetectedSpan]) -> str:
        """
        For backwards compatibility / consistent API: strictly uses typed placeholders.
        Fabricated identities and fake credentials are NEVER generated.
        """
        return self.mask_with_placeholders(text, spans)

    def enforce_placeholder_safety(self, rewritten_text: str, original_spans: List[DetectedSpan]) -> str:
        """
        Final safety enforcement layer: ensures no raw sensitive values remain in the prompt,
        replacing any surviving sensitive strings with their typed placeholders.
        """
        if not rewritten_text or not original_spans:
            return rewritten_text

        sanitized = rewritten_text
        # Sort longest first to avoid partial substring replacements
        for span in sorted(original_spans, key=lambda s: len(s.text), reverse=True):
            if span.text in sanitized:
                placeholder = (
                    TYPED_PLACEHOLDER_MAP.get(span.entity_type)
                    or span.suggested_placeholder
                    or f"<{span.entity_type}>"
                )
                sanitized = sanitized.replace(span.text, placeholder)

        return sanitized
