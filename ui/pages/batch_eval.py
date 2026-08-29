"""
Batch Evaluation & Benchmarking Dashboard.
Measures Sensitive Data Recall, Precision, F1-Score, Task Preservation, and End-to-End Latency.
"""

import streamlit as st
import pandas as pd
from evaluation.evaluator import BenchmarkEvaluator
from evaluation.metrics import compute_dataset_summary
from core.detector import GuardDetector


def render_batch_eval(detector: GuardDetector):
    """Render the evaluation and metrics benchmarking suite."""
    st.markdown("### 📊 Benchmark & Evaluation Suite")
    st.write(
        "Run an automated batch evaluation on our curated synthetic dataset to objectively measure **detection recall**, **precision**, **task preservation score**, and **latency (ms)**."
    )

    evaluator = BenchmarkEvaluator(detector=detector)

    col1, col2 = st.columns([2, 4])
    with col1:
        run_eval_btn = st.button("🚀 Run Full Benchmark Suite", type="primary", use_container_width=True)

    if run_eval_btn or "eval_results" in st.session_state:
        if run_eval_btn:
            with st.spinner("Running batch evaluation across synthetic test cases..."):
                results, summary = evaluator.run_evaluation(prefer_ollama=False)
                st.session_state["eval_results"] = results
                st.session_state["eval_summary"] = summary
        else:
            results = st.session_state["eval_results"]
            summary = st.session_state["eval_summary"]

        st.divider()

        # Summary Metric Cards
        st.markdown("#### 🎯 Overall Benchmark Performance")
        m1, m2, m3, m4, m5 = st.columns(5)
        with m1:
            st.metric(label="Detection Recall", value=f"{summary['avg_recall'] * 100:.1f}%")
        with m2:
            st.metric(label="Detection Precision", value=f"{summary['avg_precision'] * 100:.1f}%")
        with m3:
            st.metric(label="Average F1-Score", value=f"{summary['avg_f1']:.3f}")
        with m4:
            st.metric(label="Task Preservation", value=f"{summary['avg_task_preservation'] * 100:.1f}%")
        with m5:
            st.metric(label="Avg Scan Latency", value=f"{summary['avg_scan_latency_ms']:.1f} ms")

        st.markdown(f"**Passed Cases:** `{summary['passed_cases']}/{summary['total_cases']}` ({summary['pass_rate_pct']}%) · **Avg Rewrite Latency:** `{summary['avg_rewrite_latency_ms']:.1f} ms`")

        # Detailed Table
        st.markdown("#### 📋 Test Case Breakdown")
        table_records = compute_dataset_summary(results)
        df = pd.DataFrame(table_records)

        # Filters
        categories = ["All"] + sorted(list(df["Category"].unique()))
        selected_cat = st.selectbox("Filter by Category", categories)
        filtered_df = df if selected_cat == "All" else df[df["Category"] == selected_cat]

        st.dataframe(
            filtered_df,
            use_container_width=True,
            hide_index=True,
        )

        # Visual Chart: Latency & F1 Score Breakdown
        st.markdown("#### 📈 Performance Metrics by Test Case")
        chart_data = pd.DataFrame({
            "Case ID": [r.case_id for r in results],
            "F1-Score": [r.f1 for r in results],
            "Task Preservation": [r.task_preservation_score for r in results],
            "Scan Latency (ms)": [r.scan_latency_ms for r in results],
        }).set_index("Case ID")

        st.bar_chart(chart_data[["F1-Score", "Task Preservation"]])
