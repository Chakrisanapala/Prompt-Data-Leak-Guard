"""
Unit tests for Benchmarking and Metrics Calculation.
"""

from evaluation.evaluator import BenchmarkEvaluator


def test_evaluator_runs_on_synthetic_dataset():
    evaluator = BenchmarkEvaluator()
    results, summary = evaluator.run_evaluation(prefer_ollama=False)

    assert len(results) == 16
    assert summary["total_cases"] == 16
    assert summary["passed_cases"] >= 15
    assert summary["pass_rate_pct"] >= 90.0
    assert summary["avg_recall"] >= 0.90
    assert summary["avg_precision"] >= 0.75
    assert summary["avg_task_preservation"] >= 0.90
    assert summary["avg_scan_latency_ms"] < 100.0
