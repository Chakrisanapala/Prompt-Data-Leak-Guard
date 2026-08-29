"""
Reusable Streamlit UI Components matching White and Biscuit Aesthetic.
"""

import streamlit as st
import html
from typing import List, Dict, Any
from core.models import ScanResult, DetectedSpan, RiskSummary, SeverityLevel, CategoryType
from core.span_utils import generate_highlighted_html


def render_header(ollama_status: Dict[str, Any]):
    """Render the top clean header with application title and status pill."""
    is_online = ollama_status.get("available", False)
    status_text = (
        f"🟢 ONLINE ({len(ollama_status.get('models', []))} models)"
        if is_online
        else "⚪ OFFLINE MODE"
    )

    st.markdown(
        f"""
        <div class="main-header-container">
            <div>
                <div class="main-title">Prompt Data-Leak Guard</div>
                <div class="main-subtitle">
                    Real-time sensitive data interception, risk explainability, and task-preserving prompt rewriting for public AI tools.
                </div>
            </div>
            <div>
                <div class="mode-pill">{status_text}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_metric_cards(scan_res: ScanResult):
    """Render the 5-card metric row as shown in the mockup."""
    risk_summary = scan_res.risk_summary
    max_sev = risk_summary.max_severity.value if risk_summary.max_severity else "SAFE"

    # Category breakdown calculation
    n_secrets = risk_summary.category_counts.get("SECRET", 0)
    n_pii = risk_summary.category_counts.get("PII", 0)
    n_infra = risk_summary.category_counts.get("INTERNAL_INFRASTRUCTURE", 0) + risk_summary.category_counts.get("INTERNAL_DATA", 0)
    breakdown_parts = []
    if n_secrets > 0:
        breakdown_parts.append(f"{n_secrets} Secret{'s' if n_secrets > 1 else ''}")
    if n_pii > 0:
        breakdown_parts.append(f"{n_pii} PII")
    if n_infra > 0:
        breakdown_parts.append(f"{n_infra} Infra")
    breakdown_str = " · ".join(breakdown_parts) if breakdown_parts else "0 Leaks"

    sev_color = {
        "CRITICAL": "#DC2626",
        "HIGH": "#EA580C",
        "MEDIUM": "#D97706",
        "LOW": "#16A34A",
        "SAFE": "#16A34A",
    }.get(max_sev, "#16A34A")

    risk_sub_color = "#DC2626" if risk_summary.risk_score >= 50 else ("#D97706" if risk_summary.risk_score >= 25 else "#16A34A")
    risk_sub_label = f"{max_sev} RISK" if risk_summary.max_severity else "CLEAN & SAFE"

    st.markdown(
        f"""
        <div class="metric-row">
            <div class="summary-card">
                <div class="summary-card-label">🛡️ Risk Score</div>
                <div class="summary-card-value">{risk_summary.risk_score} <span style="font-size: 14px; font-weight: 500; color: #8C8275;">/ 100</span></div>
                <div class="summary-card-sub" style="color: {risk_sub_color}; font-weight: 700;">{risk_sub_label}</div>
            </div>
            <div class="summary-card">
                <div class="summary-card-label">⚠️ Max Severity</div>
                <div class="summary-card-value" style="color: {sev_color};">{max_sev}</div>
                <div class="summary-card-sub">Assessed Threat Level</div>
            </div>
            <div class="summary-card">
                <div class="summary-card-label">🎯 Detected Items</div>
                <div class="summary-card-value">{risk_summary.total_detected}</div>
                <div class="summary-card-sub">{breakdown_str}</div>
            </div>
            <div class="summary-card">
                <div class="summary-card-label">✅ Task Preservation</div>
                <div class="summary-card-value">{scan_res.task_preservation_score * 100:.1f}%</div>
                <div class="summary-card-sub">Intent & Structure Preserved</div>
            </div>
            <div class="summary-card">
                <div class="summary-card-label">⏱️ Total Latency</div>
                <div class="summary-card-value">{scan_res.total_latency_ms:.1f} <span style="font-size: 13px; font-weight: 500; color: #8C8275;">ms</span></div>
                <div class="summary-card-sub">Scan: {scan_res.scan_latency_ms:.1f}ms · Rewrite: {scan_res.rewrite_latency_ms:.1f}ms</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_risk_alert(risk_summary: RiskSummary):
    """Render executive risk overview banner with compliance standards."""
    if risk_summary.total_detected == 0:
        st.markdown(
            """
            <div class="alert-banner-safe">
                ✅ <strong>CLEAN PROMPT — Ready for Public AI</strong>: No API keys, credentials, or personal identifiers were detected.
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    sev = risk_summary.max_severity.value if risk_summary.max_severity else "HIGH"
    banner_cls = f"alert-banner-{sev.lower()}"

    standards = " · ".join(risk_summary.compliance_risks) if risk_summary.compliance_risks else "OWASP Top 10 · GDPR · SOC 2"

    st.markdown(
        f"""
        <div class="{banner_cls}">
            <div style="display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 700; margin-bottom: 4px;">
                <span>⚠️</span> <span>{sev} RISK: Prompt contains sensitive tokens or identifiers. Do NOT send this prompt to a public AI.</span>
            </div>
            <div style="font-size: 12px; opacity: 0.85; margin-left: 24px;">
                Impacted Standards: {standards}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_comparison_view(original_text: str, spans: List[DetectedSpan], safe_rewritten: str, backend_info: str):
    """Render side-by-side original prompt with visual highlighting vs safe rewritten prompt."""
    st.markdown('<div class="section-header">3. PROMPT COMPARISON</div>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            """
            <div class="comparison-box-header">
                <span>ORIGINAL PROMPT (HIGHLIGHTED)</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        highlighted_html = generate_highlighted_html(original_text, spans)
        st.markdown(highlighted_html, unsafe_allow_html=True)

    with col2:
        st.markdown(
            f"""
            <div class="comparison-box-header">
                <span>SAFE PROMPT — READY FOR PUBLIC AI</span>
                <span style="font-size: 11px; font-weight: 500; color: #8C8275; text-transform: none;">Engine: {backend_info}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        escaped_safe = html.escape(safe_rewritten).replace("\n", "<br>")
        st.markdown(
            f"""
            <div class="comparison-box-content">
                {escaped_safe}
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Bottom action buttons
        btn_col1, btn_col2 = st.columns([1, 1])
        with btn_col1:
            st.text_area(
                label="Copy Prompt Text:",
                value=safe_rewritten,
                height=70,
                key="safe_prompt_copy_box",
                help="Select all and copy (Ctrl+C / Cmd+C)",
            )
        with btn_col2:
            st.download_button(
                label="📥 Download .txt",
                data=safe_rewritten,
                file_name="safe_prompt.txt",
                mime="text/plain",
                use_container_width=True,
            )


def render_spans_table(spans: List[DetectedSpan]):
    """Render clean, modern threat analysis breakdown table matching mockup."""
    if not spans:
        return

    n = len(spans)
    st.markdown(
        f'<div class="section-header">4. DETAILED RISK & THREAT ANALYSIS ({n} ITEM{"S" if n > 1 else ""} DETECTED)</div>',
        unsafe_allow_html=True,
    )

    rows_html = []
    for s in spans:
        sev_class = f"severity-pill-{s.severity.value.lower()}"

        # Category icon
        cat_icon = {
            CategoryType.SECRET: "🔑",
            CategoryType.PII: "👤",
            CategoryType.INTERNAL_INFRASTRUCTURE: "🌐",
            CategoryType.INTERNAL_DATA: "📁",
        }.get(s.category, "🔍")

        row = (
            f"<tr>"
            f"<td style='font-weight: 600; white-space: nowrap;'><span style='margin-right: 6px;'>{cat_icon}</span> <code>{html.escape(s.entity_type)}</code></td>"
            f"<td style='font-family: \"JetBrains Mono\", monospace; font-size: 12.5px; color: #1E1E1E; font-weight: 600;'>{html.escape(s.text)}</td>"
            f"<td><span class='{sev_class}'>{s.severity.value}</span></td>"
            f"<td style='font-size: 12.5px; color: #5C5349; line-height: 1.45;'>{html.escape(s.risk_explanation)}</td>"
            f"<td style='font-family: \"JetBrains Mono\", monospace; font-size: 12.5px; font-weight: 600; color: #2D2620; white-space: nowrap;'><code>{html.escape(s.suggested_placeholder)}</code></td>"
            f"</tr>"
        )
        rows_html.append(row)

    table_html = (
        "<table class='leak-table'>"
        "<thead>"
        "<tr>"
        "<th style='width: 20%;'>TYPE</th>"
        "<th style='width: 22%;'>VALUE</th>"
        "<th style='width: 12%;'>SEVERITY</th>"
        "<th style='width: 28%;'>WHY THIS IS RISKY</th>"
        "<th style='width: 18%;'>SAFE MASK</th>"
        "</tr>"
        "</thead>"
        "<tbody>"
        + "".join(rows_html)
        + "</tbody>"
        "</table>"
    )

    st.markdown(table_html, unsafe_allow_html=True)
