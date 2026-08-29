"""
Live Guard view: Real-time sensitive prompt scanning, highlight visualization, and safe prompt rewriting.
"""

import streamlit as st
from config import PRESET_PROMPTS
from core.detector import GuardDetector
from ui.components import (
    render_metric_cards,
    render_risk_alert,
    render_spans_table,
    render_comparison_view,
)


def render_live_guard(detector: GuardDetector):
    """Render the main interactive playground structured cleanly."""
    
    # 1. ENTER PROMPT
    st.markdown('<div class="section-header">1. ENTER PROMPT</div>', unsafe_allow_html=True)
    
    # Preset Selector and Actions
    top_col1, top_col2 = st.columns([4, 1])
    with top_col1:
        preset_titles = ["-- Select Pre-configured Test Scenario --"] + [p["title"] for p in PRESET_PROMPTS]
        selected_preset = st.selectbox(
            "Load Test Scenario",
            options=preset_titles,
            index=0,
            label_visibility="collapsed",
        )
    with top_col2:
        if st.button("🗑️ Clear", use_container_width=True):
            st.session_state["live_prompt_input"] = ""
            st.session_state.pop("last_scanned_prompt", None)
            st.rerun()

    initial_text = ""
    if selected_preset != "-- Select Pre-configured Test Scenario --":
        for p in PRESET_PROMPTS:
            if p["title"] == selected_preset:
                initial_text = p["text"]
                break

    # Prompt Textarea
    prompt_input = st.text_area(
        label="Prompt input",
        value=initial_text if initial_text else st.session_state.get("live_prompt_input", ""),
        height=160,
        placeholder="Paste your prompt containing potential secrets, personal info, or internal infrastructure details...",
        key="live_prompt_input",
        label_visibility="collapsed",
    )

    # Bottom Actions Bar
    bot_col1, bot_col2, bot_col3 = st.columns([2, 1, 2])
    with bot_col1:
        sensitivity = st.selectbox(
            "Detection Sensitivity",
            options=["High Sensitivity (All Threats)", "Standard (Balanced)", "Strict Secrets Only"],
            index=0,
            label_visibility="collapsed",
        )
    with bot_col3:
        scan_button = st.button("🛡️ SCAN & GUARD PROMPT", type="primary", use_container_width=True)

    # Trigger scan if button clicked or if user has scanned
    should_scan = scan_button or (
        prompt_input and "last_scanned_prompt" in st.session_state and st.session_state["last_scanned_prompt"] == prompt_input
    )

    if should_scan:
        if not prompt_input.strip():
            st.warning("Please enter some prompt text to scan.")
            return

        st.session_state["last_scanned_prompt"] = prompt_input

        with st.spinner("Scanning for data leaks and generating safe rewrite..."):
            prefer_ollama = st.session_state.get("prefer_ollama", True)
            selected_model = st.session_state.get("selected_model", None)
            min_confidence = 0.3 if "High" in sensitivity else (0.5 if "Standard" in sensitivity else 0.7)

            scan_result = detector.analyze_and_rewrite(
                prompt=prompt_input,
                prefer_ollama=prefer_ollama,
                ollama_model=selected_model,
                min_confidence=min_confidence,
            )

        # 2. SCAN SUMMARY
        st.markdown('<div class="section-header">2. SCAN SUMMARY</div>', unsafe_allow_html=True)
        render_metric_cards(scan_result)
        render_risk_alert(scan_result.risk_summary)

        # 3. PROMPT COMPARISON
        render_comparison_view(
            original_text=prompt_input,
            spans=scan_result.spans,
            safe_rewritten=scan_result.safe_rewritten_prompt,
            backend_info=scan_result.rewriter_backend,
        )

        # 4. DETAILED THREAT ANALYSIS
        render_spans_table(scan_result.spans)

    # Footer note
    st.markdown(
        '<div class="footer-text">Leak Guard does not store or transmit your data. Everything runs locally on your machine.</div>',
        unsafe_allow_html=True,
    )
