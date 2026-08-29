"""
Prompt Data-Leak Guard for Public AI Tools
Main Streamlit Application Entrypoint.
"""

import streamlit as st
from config import DEFAULT_OLLAMA_HOST, DEFAULT_OLLAMA_MODEL
from core.detector import GuardDetector
from ui.styles import load_styles
from ui.components import render_header
from ui.pages.live_guard import render_live_guard
from ui.pages.batch_eval import render_batch_eval
from ui.pages.settings import render_settings


# Streamlit Page Configuration
st.set_page_config(
    page_title="Leak Guard — Prompt Data-Leak Guard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject White and Biscuit Theme CSS
st.markdown(load_styles(), unsafe_allow_html=True)


@st.cache_resource
def get_detector() -> GuardDetector:
    """Initialize and cache the core Guard Detector singleton."""
    return GuardDetector()


def main():
    detector = get_detector()
    ollama_status = detector.rewriter.check_ollama_status()

    # Sidebar Navigation & Capabilities
    with st.sidebar:
        # Brand Logo Header
        st.markdown(
            """
            <div class="sidebar-logo">
                <div class="sidebar-logo-icon">🛡️</div>
                <div>
                    <div class="sidebar-logo-text">LEAK GUARD</div>
                    <div class="sidebar-logo-sub">Prompt Data-Leak Guard</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Primary Navigation
        nav_choice = st.radio(
            "Navigation",
            options=["Live Guard", "Benchmarks", "Settings"],
            index=0,
            label_visibility="collapsed",
        )

        st.markdown('<div class="sidebar-section-label">CAPABILITIES</div>', unsafe_allow_html=True)
        st.markdown(
            """
            <div style="display: flex; flex-direction: column; gap: 12px; margin-bottom: 20px;">
                <div class="sidebar-cap-item">
                    <span style="font-size: 15px;">🔑</span>
                    <div>
                        <div class="sidebar-cap-title">Secrets Interception</div>
                        <div class="sidebar-cap-desc">Regex + entropy</div>
                    </div>
                </div>
                <div class="sidebar-cap-item">
                    <span style="font-size: 15px;">👤</span>
                    <div>
                        <div class="sidebar-cap-title">PII Detection</div>
                        <div class="sidebar-cap-desc">Presidio NER</div>
                    </div>
                </div>
                <div class="sidebar-cap-item">
                    <span style="font-size: 15px;">🛡️</span>
                    <div>
                        <div class="sidebar-cap-title">Risk Explainability</div>
                        <div class="sidebar-cap-desc">OWASP & GDPR</div>
                    </div>
                </div>
                <div class="sidebar-cap-item">
                    <span style="font-size: 15px;">🔄</span>
                    <div>
                        <div class="sidebar-cap-title">Safe Rewriting</div>
                        <div class="sidebar-cap-desc">Local LLM / Masker</div>
                    </div>
                </div>
                <div class="sidebar-cap-item">
                    <span style="font-size: 15px;">📈</span>
                    <div>
                        <div class="sidebar-cap-title">Empirical Metrics</div>
                        <div class="sidebar-cap-desc">Recall, F1, Latency</div>
                    </div>
                </div>
                <div class="sidebar-cap-item">
                    <span style="font-size: 15px;">🔒</span>
                    <div>
                        <div class="sidebar-cap-title">Privacy-by-Design</div>
                        <div class="sidebar-cap-desc">100% local processing</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Status Box at bottom of sidebar
        is_online = ollama_status.get("available", False)
        status_label = "🟢 ONLINE" if is_online else "🟢 OFFLINE MODE"
        status_sub = f"{len(ollama_status.get('models', []))} Ollama Models" if is_online else "100% Local & Fast"

        st.markdown(
            f"""
            <div class="sidebar-status-box">
                <div style="font-size: 12.5px; font-weight: 700; color: #1E1E1E; margin-bottom: 2px;">
                    {status_label}
                </div>
                <div style="font-size: 11px; color: #7E7469;">
                    {status_sub}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Render Main Header
    render_header(ollama_status)

    # Render selected view
    if nav_choice == "Live Guard":
        render_live_guard(detector)
    elif nav_choice == "Benchmarks":
        render_batch_eval(detector)
    elif nav_choice == "Settings":
        render_settings(detector)


if __name__ == "__main__":
    main()
