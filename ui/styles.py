"""
White and Warm Biscuit Theme for Prompt Data-Leak Guard.
Matches modern, elegant design with Montserrat typography, warm terracotta accents, and high-contrast readability.
"""

CUSTOM_CSS = """
<style>
/* Montserrat and JetBrains Mono Fonts */
@import url('https://fonts.googleapis.com/css2?family=Montserrat:ital,wght@0,300;0,400;0,500;0,600;0,700;0,800;1,400&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* Global Reset & Base */
html, body, [class*="css"], .stApp {
    font-family: 'Montserrat', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
    background-color: #FAF8F5 !important;
    color: #2C2621 !important;
}

/* Force light background on Streamlit header bar */
header[data-testid="stHeader"],
.stApp > header {
    background-color: #FAF8F5 !important;
}

/* Ensure all headings, text, labels, and paragraphs have crisp high-contrast dark color */
h1, h2, h3, h4, h5, h6, p, span, label, div, small, strong, em {
    color: #2C2621;
}

/* Code and mono elements */
code, pre, kbd, samp {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Top App Header / Main Title */
.main-header-container {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    padding: 8px 0 24px 0;
    border-bottom: 1px solid #ECE6DC;
    margin-bottom: 24px;
    flex-wrap: wrap;
    gap: 16px;
}

.main-title {
    font-family: 'Montserrat', sans-serif !important;
    font-size: 30px !important;
    font-weight: 800 !important;
    color: #1E1E1E !important;
    letter-spacing: -0.02em;
    line-height: 1.2;
    margin-bottom: 6px;
}

.main-subtitle {
    font-size: 14.5px;
    color: #6E665D !important;
    line-height: 1.5;
    font-weight: 400;
    max-width: 780px;
}

/* Sidebar Custom Styling */
[data-testid="stSidebar"] {
    background-color: #F5F1E9 !important;
    border-right: 1px solid #E6DFD3 !important;
}

[data-testid="stSidebar"] hr {
    border-color: #E6DFD3 !important;
    margin: 16px 0 !important;
}

/* Sidebar Radio Navigation */
div[data-testid="stRadio"] label,
div[data-testid="stRadio"] label p,
div[data-testid="stRadio"] span,
div[role="radiogroup"] label,
div[role="radiogroup"] label p {
    color: #2C2621 !important;
    font-family: 'Montserrat', sans-serif !important;
    font-size: 14px !important;
    font-weight: 600 !important;
}

div[data-testid="stRadio"] div[role="radiogroup"] {
    gap: 6px !important;
}

.sidebar-logo {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 24px;
}

.sidebar-logo-icon {
    width: 38px;
    height: 38px;
    background: #EAE2D5;
    border: 1px solid #D5CCC0;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
}

.sidebar-logo-text {
    font-family: 'Montserrat', sans-serif;
    font-weight: 800;
    font-size: 16px;
    color: #1E1E1E !important;
    letter-spacing: 0.04em;
}

.sidebar-logo-sub {
    font-size: 11px;
    color: #7E7469 !important;
    font-weight: 500;
}

.sidebar-section-label {
    font-size: 11px;
    font-weight: 700;
    color: #8C8275 !important;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin: 20px 0 10px 0;
}

.sidebar-cap-item {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 6px 0;
}

.sidebar-cap-title {
    font-size: 12.5px;
    font-weight: 600;
    color: #2D2620 !important;
    line-height: 1.2;
}

.sidebar-cap-desc {
    font-size: 11px;
    color: #8C8275 !important;
    line-height: 1.3;
}

.sidebar-status-box {
    background: #FFFFFF;
    border: 1px solid #E2D9CD;
    border-radius: 10px;
    padding: 12px 14px;
    margin-top: 24px;
}

/* Section Headings */
.section-header {
    font-family: 'Montserrat', sans-serif;
    font-size: 13px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #2C2621 !important;
    margin: 28px 0 12px 0;
    display: flex;
    align-items: center;
    gap: 8px;
}

/* White Card Containers */
.card-container {
    background-color: #FFFFFF;
    border: 1px solid #EAE4D9;
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.02);
    margin-bottom: 20px;
}

/* 5-Card Metric Row */
.metric-row {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    margin-bottom: 16px;
}

@media (max-width: 900px) {
    .metric-row {
        grid-template-columns: repeat(2, 1fr);
    }
}

.summary-card {
    background: #FFFFFF;
    border: 1px solid #EAE4D9;
    border-radius: 10px;
    padding: 16px 14px;
    text-align: center;
    box-shadow: 0 1px 2px rgba(0,0,0,0.02);
}

.summary-card-label {
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #7E7469 !important;
    margin-bottom: 6px;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 4px;
}

.summary-card-value {
    font-family: 'Montserrat', sans-serif;
    font-size: 22px;
    font-weight: 700;
    color: #1E1E1E !important;
    line-height: 1.2;
}

.summary-card-sub {
    font-size: 11px;
    color: #8C8275 !important;
    margin-top: 4px;
    font-weight: 500;
}

/* Risk Alert Banners */
.alert-banner-critical, .alert-banner-high {
    background-color: #FEF3EE !important;
    border: 1px solid #F6C8B2 !important;
    border-radius: 8px;
    padding: 14px 18px;
    color: #9C3412 !important;
    font-size: 13.5px;
    font-weight: 600;
    margin: 14px 0 20px 0;
}

.alert-banner-critical *, .alert-banner-high * {
    color: #9C3412 !important;
}

.alert-banner-medium {
    background-color: #FEF9EE !important;
    border: 1px solid #F6E0B2 !important;
    border-radius: 8px;
    padding: 14px 18px;
    color: #92580C !important;
    font-size: 13.5px;
    font-weight: 600;
    margin: 14px 0 20px 0;
}

.alert-banner-medium * {
    color: #92580C !important;
}

.alert-banner-safe {
    background-color: #F0FDF4 !important;
    border: 1px solid #BBF7D0 !important;
    border-radius: 8px;
    padding: 14px 18px;
    color: #166534 !important;
    font-size: 13.5px;
    font-weight: 600;
    margin: 14px 0 20px 0;
}

.alert-banner-safe * {
    color: #166534 !important;
}

/* Streamlit Standard Alerts (st.warning, st.info, st.success, st.error) */
div[data-testid="stAlert"] {
    border-radius: 8px !important;
    font-size: 13.5px !important;
}

div[data-testid="stAlert"] * {
    color: #1E1E1E !important;
}

/* Prompt Comparison Cards */
.comparison-box-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #4A423B !important;
    padding-bottom: 10px;
    border-bottom: 1px solid #EFECE6;
    margin-bottom: 12px;
}

.comparison-box-content {
    background-color: #FFFFFF;
    border: 1px solid #EAE4D9;
    border-radius: 10px;
    padding: 16px;
    min-height: 220px;
    font-size: 13.5px;
    line-height: 1.65;
    color: #2D2620 !important;
    white-space: pre-wrap;
    word-break: break-word;
}

.comparison-legend {
    display: flex;
    align-items: center;
    gap: 16px;
    font-size: 11.5px;
    color: #7E7469 !important;
    margin-top: 10px;
    flex-wrap: wrap;
}

.legend-dot {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    display: inline-block;
    margin-right: 4px;
}

/* Highlighted Spans */
.span-highlight-secret {
    background-color: #FEE2E2 !important;
    border: 1px solid #FCA5A5 !important;
    color: #B91C1C !important;
    padding: 2px 6px;
    border-radius: 4px;
    font-weight: 600;
}

.span-highlight-pii {
    background-color: #FEF3C7 !important;
    border: 1px solid #FCD34D !important;
    color: #B45309 !important;
    padding: 2px 6px;
    border-radius: 4px;
    font-weight: 600;
}

.span-highlight-infra {
    background-color: #FEF9C3 !important;
    border: 1px solid #FDE047 !important;
    color: #A16207 !important;
    padding: 2px 6px;
    border-radius: 4px;
    font-weight: 600;
}

/* Threat Analysis Table */
.leak-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    background: #FFFFFF;
    border: 1px solid #EAE4D9;
    border-radius: 8px;
    overflow: hidden;
    margin-top: 12px;
}

.leak-table th {
    background-color: #F7F4EE;
    color: #5C5349 !important;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 12px 14px;
    text-align: left;
    border-bottom: 1px solid #EAE4D9;
}

.leak-table td {
    padding: 12px 14px;
    border-bottom: 1px solid #F2EEE7;
    color: #2D2620 !important;
    vertical-align: middle;
}

.leak-table tr:last-child td {
    border-bottom: none;
}

.severity-pill-critical, .severity-pill-high {
    background-color: #FEF2F2 !important;
    border: 1px solid #FCA5A5 !important;
    color: #DC2626 !important;
    padding: 3px 8px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
}

.severity-pill-medium {
    background-color: #FEF3C7 !important;
    border: 1px solid #FCD34D !important;
    color: #D97706 !important;
    padding: 3px 8px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
}

.severity-pill-low {
    background-color: #F0FDF4 !important;
    border: 1px solid #BBF7D0 !important;
    color: #16A34A !important;
    padding: 3px 8px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
}

/* Pill badge top right */
.mode-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: #FFFFFF;
    border: 1px solid #DCD5C9;
    color: #6E665D !important;
    padding: 5px 14px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.03em;
}

/* Primary Button */
div.stButton > button[kind="primary"],
div.stButton > button:first-child {
    background-color: #7E4E28 !important;
    color: #FFFFFF !important;
    border: 1px solid #6E4220 !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    font-size: 13.5px !important;
    padding: 8px 18px !important;
    transition: all 0.15s ease !important;
    box-shadow: 0 1px 2px rgba(126, 78, 40, 0.2) !important;
}

div.stButton > button[kind="primary"]:hover,
div.stButton > button:first-child:hover {
    background-color: #6A3E1D !important;
    border-color: #5C3417 !important;
    box-shadow: 0 2px 6px rgba(126, 78, 40, 0.3) !important;
}

/* Secondary Button */
div.stButton > button[kind="secondary"] {
    background-color: #FFFFFF !important;
    color: #4A423B !important;
    border: 1px solid #D5CCC0 !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
}

div.stButton > button[kind="secondary"]:hover {
    background-color: #F7F4EE !important;
    border-color: #C8BEB0 !important;
}

/* Streamlit Input Elements (Text Inputs, Textareas, Selectboxes) */
.stTextInput input,
div[data-testid="stTextInput"] input {
    background-color: #FFFFFF !important;
    border: 1px solid #DCD5C9 !important;
    border-radius: 8px !important;
    font-size: 13.5px !important;
    color: #1E1E1E !important;
}

.stTextInput input:focus,
div[data-testid="stTextInput"] input:focus {
    border-color: #7E4E28 !important;
    box-shadow: 0 0 0 1px #7E4E28 !important;
}

.stTextArea textarea,
div[data-testid="stTextArea"] textarea {
    background-color: #FFFFFF !important;
    border: 1px solid #DCD5C9 !important;
    border-radius: 8px !important;
    font-size: 13.5px !important;
    color: #1E1E1E !important;
    line-height: 1.6 !important;
}

.stTextArea textarea::placeholder,
div[data-testid="stTextArea"] textarea::placeholder {
    color: #8C8275 !important;
    opacity: 0.9 !important;
}

.stTextArea textarea:focus,
div[data-testid="stTextArea"] textarea:focus {
    border-color: #7E4E28 !important;
    box-shadow: 0 0 0 1px #7E4E28 !important;
}

/* Complete BaseWeb & Streamlit Selectbox Overrides (Dropdowns) */
div[data-testid="stSelectbox"],
div[data-testid="stSelectbox"] * {
    color: #1E1E1E !important;
}

div[data-testid="stSelectbox"] [data-baseweb="select"],
div[data-testid="stSelectbox"] [data-baseweb="select"] > div,
div[data-testid="stSelectbox"] [data-baseweb="select"] div,
div[data-baseweb="select"],
div[data-baseweb="select"] > div,
div[data-baseweb="select"] div {
    background-color: #FFFFFF !important;
    border-color: #DCD5C9 !important;
    border-radius: 8px !important;
    color: #1E1E1E !important;
}

div[data-baseweb="select"] svg {
    fill: #2C2621 !important;
    color: #2C2621 !important;
}

/* Dropdown popover list */
div[data-baseweb="popover"],
div[data-baseweb="popover"] > div,
div[data-baseweb="popover"] div,
div[data-baseweb="popover"] ul,
ul[role="listbox"],
li[role="option"] {
    background-color: #FFFFFF !important;
    color: #1E1E1E !important;
    border-color: #DCD5C9 !important;
}

li[role="option"]:hover,
li[role="option"][aria-selected="true"] {
    background-color: #F5F1E9 !important;
    color: #7E4E28 !important;
}

/* Toggle switch labels */
div[data-testid="stToggle"] label p,
div[data-testid="stToggle"] span {
    color: #1E1E1E !important;
    font-weight: 600 !important;
}

/* Slider labels */
div[data-testid="stSlider"] label p,
div[data-testid="stSlider"] div {
    color: #1E1E1E !important;
}

/* Tab Bar */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    border-bottom: 1px solid #E6DFD3 !important;
    margin-bottom: 20px;
}

.stTabs [data-baseweb="tab"] {
    font-family: 'Montserrat', sans-serif !important;
    font-size: 13px !important;
    font-weight: 600 !important;
    color: #786F66 !important;
    border-radius: 8px 8px 0 0 !important;
    padding: 10px 16px !important;
}

.stTabs [aria-selected="true"] {
    color: #7E4E28 !important;
    border-bottom-color: #7E4E28 !important;
    font-weight: 700 !important;
}

/* Footer note */
.footer-text {
    text-align: center;
    font-size: 12px;
    color: #8C8275 !important;
    margin-top: 36px;
    padding: 16px 0;
    border-top: 1px solid #ECE6DC;
}
</style>
"""


def load_styles() -> str:
    """Return custom white and warm biscuit theme CSS."""
    return CUSTOM_CSS
