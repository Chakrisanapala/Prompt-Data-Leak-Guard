"""
Span Utilities: Conflict resolution, overlap merging, and visual HTML highlighting.
"""

import html
from typing import List
from core.models import DetectedSpan, SeverityLevel, CategoryType


SEVERITY_ORDER = {
    SeverityLevel.CRITICAL: 4,
    SeverityLevel.HIGH: 3,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.LOW: 1,
}

SPAN_STYLE_MAP = {
    CategoryType.SECRET: {
        "bg": "#FEE2E2",
        "border": "#FCA5A5",
        "text": "#991B1B",
    },
    CategoryType.PII: {
        "bg": "#FEF3C7",
        "border": "#FCD34D",
        "text": "#92400E",
    },
    CategoryType.INTERNAL_INFRASTRUCTURE: {
        "bg": "#FEF9C3",
        "border": "#FDE047",
        "text": "#854D0E",
    },
    CategoryType.INTERNAL_DATA: {
        "bg": "#FEF9C3",
        "border": "#FDE047",
        "text": "#854D0E",
    },
}


def merge_and_resolve_spans(spans: List[DetectedSpan]) -> List[DetectedSpan]:
    """
    Resolve overlapping and duplicate spans using priority sorting:
    1. Higher Severity Level (CRITICAL > HIGH > MEDIUM > LOW)
    2. Greater Span Length (longer match covers context better)
    3. Higher Confidence score
    """
    if not spans:
        return []

    # Sort spans by priority
    sorted_candidates = sorted(
        spans,
        key=lambda s: (
            SEVERITY_ORDER.get(s.severity, 0),
            (s.end - s.start),
            s.confidence,
        ),
        reverse=True,
    )

    accepted_spans: List[DetectedSpan] = []

    for candidate in sorted_candidates:
        # Check if candidate overlaps with any already accepted span
        overlaps = False
        for accepted in accepted_spans:
            # Overlap condition: max(start1, start2) < min(end1, end2)
            if max(candidate.start, accepted.start) < min(candidate.end, accepted.end):
                overlaps = True
                break

        if not overlaps:
            accepted_spans.append(candidate)

    # Finally, sort accepted spans by their character appearance order in the text
    return sorted(accepted_spans, key=lambda s: s.start)


def generate_highlighted_html(text: str, spans: List[DetectedSpan]) -> str:
    """
    Generate rich HTML highlighting all detected spans with light/biscuit color-coded pills.
    """
    if not spans:
        escaped = html.escape(text).replace("\n", "<br>")
        return f"<div style='font-family: \"JetBrains Mono\", monospace; font-size: 13.5px; line-height: 1.65; color: #2D2620; background-color: #FFFFFF; padding: 16px; border-radius: 8px; border: 1px solid #EAE4D9; min-height: 200px;'>{escaped}</div>"

    resolved = merge_and_resolve_spans(spans)

    html_parts = []
    last_idx = 0

    for span in resolved:
        # Append text before this span
        if span.start > last_idx:
            raw_chunk = html.escape(text[last_idx:span.start]).replace("\n", "<br>")
            html_parts.append(raw_chunk)

        span_content = html.escape(text[span.start:span.end])
        style = SPAN_STYLE_MAP.get(
            span.category,
            {"bg": "#FEE2E2", "border": "#FCA5A5", "text": "#991B1B"}
        )

        badge_html = (
            f"<mark style='"
            f"background-color: {style['bg']}; "
            f"border: 1px solid {style['border']}; "
            f"color: {style['text']}; "
            f"border-radius: 4px; "
            f"padding: 2px 6px; "
            f"margin: 0 1px; "
            f"font-family: inherit; "
            f"font-weight: 600; "
            f"display: inline-block;' "
            f"title='[{span.severity.value}] {span.entity_type}: {html.escape(span.risk_explanation)}'>"
            f"{span_content}"
            f"</mark>"
        )
        html_parts.append(badge_html)
        last_idx = span.end

    # Append remaining text
    if last_idx < len(text):
        raw_tail = html.escape(text[last_idx:]).replace("\n", "<br>")
        html_parts.append(raw_tail)

    full_html = "".join(html_parts)
    legend_html = (
        "<div style='margin-top: 16px; padding-top: 10px; border-top: 1px solid #EFECE6; display: flex; gap: 16px; font-size: 11.5px; color: #7E7469; font-family: Montserrat, sans-serif; font-weight: 500;'>"
        "<span><span style='display:inline-block;width:8px;height:8px;border-radius:50%;background:#EF4444;margin-right:4px;'></span> High (Secret)</span>"
        "<span><span style='display:inline-block;width:8px;height:8px;border-radius:50%;background:#F59E0B;margin-right:4px;'></span> Medium (PII)</span>"
        "<span><span style='display:inline-block;width:8px;height:8px;border-radius:50%;background:#EAB308;margin-right:4px;'></span> Medium (Infra)</span>"
        "</div>"
    )

    return f"<div style='font-family: \"JetBrains Mono\", monospace; font-size: 13.5px; line-height: 1.7; background-color: #FFFFFF; padding: 16px; border-radius: 8px; border: 1px solid #EAE4D9; color: #2D2620; min-height: 200px;'>{full_html}{legend_html}</div>"
