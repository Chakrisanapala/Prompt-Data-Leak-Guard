# 🛡️ Prompt Data-Leak Guard for Public AI Tools

> **Hackathon Project**: A privacy-first, local-first guardrail application that intercepts sensitive data (secrets, API keys, credentials, PII) in prompts, visualizes risks with explainability, and generates safe, task-preserving rewritten prompts for public LLMs (ChatGPT, Claude, Gemini).

---

## 🚀 Key Features

1. **🔑 Real-time Secret & Credential Detection**: High-precision regex pattern recognition for cloud API keys (OpenAI, AWS, GitHub, Google Cloud, HuggingFace, Slack, Stripe), JWT tokens, RSA private keys, database connection strings, and hardcoded passwords.
2. **👤 PII & NER Recognition**: Powered by **Microsoft Presidio** and spaCy to identify personal names, emails, phone numbers, locations, US SSNs, and credit card numbers.
3. **✨ Visual Span Highlighting**: Color-coded inline markers in the prompt with severity tooltips and tags.
4. **🚨 Risk Classification & Explainability**: Categorizes threats into **CRITICAL / HIGH / MEDIUM / LOW** and explains why each item is risky alongside compliance standard mappings (GDPR, PCI-DSS, SOC 2, ISO 27001).
5. **🔄 Task-Preserving Prompt Rewriting**:
   - **Local LLM via Ollama**: Natural rewriting with local privacy-preserving models (`llama3.2:3b`, `phi3:mini`, `qwen2.5:3b`, etc.).
   - **Deterministic Safe Fallback**: Zero-latency synthetic mock substitution that guarantees 100% demo reliability even if Ollama is offline.
6. **📊 Empirical Benchmark & Metrics Suite**: Automated test evaluation across 16 synthetic scenarios measuring **Recall, Precision, F1-Score, Task Preservation %, and Latency (ms)**.
7. **🔒 Privacy-by-Design**: 100% local processing. No raw sensitive prompt is ever sent to external cloud APIs.

---

## 🏗️ System Architecture

```text
User Input Prompt 
      │
      ▼
┌──────────────────────────────────────────────────────────┐
│  Detection Layer (Local & Fast)                          │
│  ├─ Regex Detector (Cloud Keys, DB Strings, Passwords)   │
│  ├─ Presidio Analyzer (PII, Names, Emails, SSNs, CC)     │
│  └─ Conflict & Overlap Resolver                          │
└──────────────────────────┬───────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────┐
│  Risk Engine (Classification & Explainability)           │
│  ├─ Severity Scoring (0-100) & Categorization            │
│  └─ Regulatory Compliance Mapping (GDPR, PCI-DSS, SOC-2) │
└──────────────────────────┬───────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────┐
│  Privacy-Preserving Rewriter Layer                       │
│  ├─ Pre-Anonymization (Typed Placeholders / Mocks)       │
│  ├─ Local LLM via Ollama (Intent Refinement)             │
│  └─ Deterministic Fallback Engine (< 1ms)                │
└──────────────────────────┬───────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────┐
│  Interactive Streamlit Dashboard                         │
│  ├─ Side-by-Side Diff Comparison                         │
│  ├─ One-Click Safe Prompt Copy                           │
│  └─ Automated Benchmark Evaluation Suite                 │
└──────────────────────────────────────────────────────────┘
```

---

## 🛠️ Quickstart Installation

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/Chakrisanapala/Prompt-Data-Leak-Guard.git
cd Prompt-Data-Leak-Guard

pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### 2. (Optional) Run Local LLM with Ollama
If you wish to use the local LLM semantic rewriter:
```bash
ollama run llama3.2:3b
```
*(Note: If Ollama is not running, the application seamlessly activates its **Deterministic Safe Fallback** engine with zero latency).*

### 3. Launch the Streamlit Web Application
```bash
streamlit run app.py
```

---

## 🧪 Running Automated Tests & Benchmarks

To execute the unit test suite:
```bash
pytest
```

To run the standalone synthetic dataset benchmark:
```bash
python -m evaluation.evaluator
```

---

## 📁 Repository Structure

```text
Prompt_Data_Leak_Guard/
├── app.py                      # Main Streamlit application entry point
├── config.py                   # Global configuration, presets, risk weights
├── requirements.txt            # Python dependencies
├── README.md                   # Documentation & overview
│
├── core/                       # Core detection & rewriting engines
│   ├── __init__.py
│   ├── models.py               # Pydantic data schemas
│   ├── detector.py             # Guard orchestrator pipeline
│   ├── regex_detector.py       # High-precision secrets regex detector
│   ├── presidio_detector.py    # Microsoft Presidio PII wrapper
│   ├── span_utils.py           # Span deduplication & HTML highlighter
│   ├── risk_explainer.py       # Severity classification & explainability
│   ├── rewriter.py             # Ollama & fallback prompt rewriter
│   └── anonymizer.py           # Synthetic masking & substitution
│
├── evaluation/                 # Metrics & benchmark suite
│   ├── __init__.py
│   ├── metrics.py              # Recall, Precision, F1, and Latency math
│   ├── evaluator.py            # Batch evaluator runner
│   └── synthetic_dataset.json  # 16 curated test scenarios
│
├── ui/                         # Streamlit user interface
│   ├── __init__.py
│   ├── components.py           # Metric cards, diff viewer, risk banners
│   ├── styles.py               # Modern sleek dark/light CSS
│   └── pages/                  # Modular view tabs
│       ├── live_guard.py       # Live prompt interceptor
│       ├── batch_eval.py       # Metrics & benchmark dashboard
│       └── settings.py         # Ollama connection & sensitivity settings
│
└── tests/                      # Automated test suite
    ├── __init__.py
    ├── test_detector.py        # Secrets & PII detection unit tests
    ├── test_rewriter.py        # Masking & intent preservation tests
    └── test_metrics.py         # Benchmark metric calculation tests
```

---

## 👥 Hackathon Team & Presentation Notes

* **Problem Addressed**: Accidental exposure of proprietary secrets, credentials, and personal data to public AI chatbots.
* **Core Differentiator**: True **Privacy-by-Design** (all detection and masking executes locally before any model sees it), combined with actionable **Risk Explainability** and **Zero-Downtime Fallback Architecture**.
