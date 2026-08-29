"""
Settings & Diagnostic Configuration page.
Manage local Ollama connections, sensitivity thresholds, and view system health.
"""

import streamlit as st
from config import DEFAULT_OLLAMA_HOST, POPULAR_MODELS
from core.detector import GuardDetector


def render_settings(detector: GuardDetector):
    """Render the configuration settings and health diagnostic dashboard."""
    st.markdown("### ⚙️ Engine Settings & Diagnostics")

    # 1. Local LLM / Ollama Configuration
    st.markdown("#### 🦙 Local LLM (Ollama) Configuration")
    ollama_host = st.text_input(
        "Ollama Host Endpoint",
        value=st.session_state.get("ollama_host", DEFAULT_OLLAMA_HOST),
        help="Default local endpoint for Ollama daemon.",
    )

    ollama_status = detector.rewriter.check_ollama_status()
    st.session_state["ollama_status"] = ollama_status

    if ollama_status["available"]:
        st.success(f"✅ {ollama_status['status_message']}")
        available_models = ollama_status.get("models", [])
        model_options = available_models if available_models else POPULAR_MODELS
        selected_model = st.selectbox(
            "Select Local Model for Safe Rewriting",
            options=model_options,
            index=0,
        )
        st.session_state["selected_model"] = selected_model
    else:
        st.warning(f"⚠️ {ollama_status['status_message']}")
        st.info("💡 To enable local LLM rewriting, install Ollama from https://ollama.ai and run `ollama run llama3.2:3b` in your terminal.")

    prefer_ollama = st.toggle(
        "Enable Local LLM for Semantic Rewriting (when available)",
        value=st.session_state.get("prefer_ollama", True),
        help="If disabled, uses the ultra-fast deterministic synthetic masking rewriter (< 1ms).",
    )
    st.session_state["prefer_ollama"] = prefer_ollama

    st.divider()

    # 2. Detection Sensitivity Thresholds
    st.markdown("#### 🎚️ Detection Sensitivity")
    min_confidence = st.slider(
        "Presidio PII Confidence Threshold",
        min_value=0.1,
        max_value=1.0,
        value=st.session_state.get("min_confidence", 0.4),
        step=0.05,
        help="Lower threshold catches more potential PII (higher recall); higher threshold reduces false positives.",
    )
    st.session_state["min_confidence"] = min_confidence

    st.divider()

    # 3. Privacy-by-Design Compliance Checklist
    st.markdown("#### 🔒 Privacy-by-Design Architecture Verification")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(
            """
            * ✅ **100% Local Processing**: Microsoft Presidio & Regex run in local Python runtime.
            * ✅ **No Cloud Prompt Transmission**: Original raw prompt is never transmitted to external APIs.
            * ✅ **Pre-Anonymization Guarantee**: Sensitive tokens are replaced with synthetic placeholders *before* passing to local LLMs.
            """
        )
    with col2:
        st.markdown(
            f"""
            * 📦 **Active Regex Rules**: {len(detector.regex_detector.rules)} secret patterns
            * 🧠 **PII Recognizer**: Microsoft Presidio (`{'Loaded' if detector.presidio_detector._is_presidio_loaded else 'Fallback Mode'}`)
            * ⚡ **Rewriter Mode**: `{'Local LLM + Fallback' if prefer_ollama else 'Deterministic Ultra-Fast'}`
            """
        )
