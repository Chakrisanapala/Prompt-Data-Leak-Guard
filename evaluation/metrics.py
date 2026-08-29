"""
Metrics calculation for Prompt Data-Leak Guard benchmark evaluation.
"""

from typing import List, Dict, Any
from core.models import BenchmarkCaseResult


def calculate_metrics(results: List[BenchmarkCaseResult]) -> Dict[str, Any]:
    """Calculate aggregate recall, precision, F1, latency, and preservation stats."""
    if not results:
        return {
            "total_cases": 0,
            "passed_cases": 0,
            "pass_rate_pct": 0.0,
            "avg_precision": 0.0,
            "avg_recall": 0.0,
            "avg_f1": 0.0,
            "avg_task_preservation": 0.0,
            "avg_scan_latency_ms": 0.0,
            "avg_rewrite_latency_ms": 0.0,
            "avg_total_latency_ms": 0.0,
        }

    total_cases = len(results)
    passed_cases = sum(1 for r in results if r.passed)
    avg_precision = sum(r.precision for r in results) / total_cases
    avg_recall = sum(r.recall for r in results) / total_cases
    avg_f1 = sum(r.f1 for r in results) / total_cases
    avg_preservation = sum(r.task_preservation_score for r in results) / total_cases
    avg_scan_latency = sum(r.scan_latency_ms for r in results) / total_cases
    avg_rewrite_latency = sum(r.rewrite_latency_ms for r in results) / total_cases
    avg_total_latency = avg_scan_latency + avg_rewrite_latency

    return {
        "total_cases": total_cases,
        "passed_cases": passed_cases,
        "pass_rate_pct": round((passed_cases / total_cases) * 100.0, 1),
        "avg_precision": round(avg_precision, 3),
        "avg_recall": round(avg_recall, 3),
        "avg_f1": round(avg_f1, 3),
        "avg_task_preservation": round(avg_preservation, 3),
        "avg_scan_latency_ms": round(avg_scan_latency, 2),
        "avg_rewrite_latency_ms": round(avg_rewrite_latency, 2),
        "avg_total_latency_ms": round(avg_total_latency, 2),
    }


def compute_dataset_summary(results: List[BenchmarkCaseResult]) -> List[Dict[str, Any]]:
    """Convert benchmark results into table-ready records."""
    records = []
    for r in results:
        records.append({
            "Case ID": r.case_id,
            "Title": r.title,
            "Category": r.category,
            "Expected Entities": ", ".join(r.expected_entities) if r.expected_entities else "None (Clean)",
            "Detected Entities": ", ".join(r.detected_entities) if r.detected_entities else "None",
            "Recall": f"{r.recall * 100:.0f}%",
            "Precision": f"{r.precision * 100:.0f}%",
            "F1-Score": f"{r.f1:.2f}",
            "Task Preservation": f"{r.task_preservation_score * 100:.0f}%",
            "Scan Latency (ms)": f"{r.scan_latency_ms:.1f}",
            "Status": "✅ PASS" if r.passed else "❌ FAIL",
        })
    return records
