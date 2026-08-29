"""
Benchmark Evaluator.
Executes batch scanning and rewriting against synthetic test cases and computes statistical metrics.
"""

import os
import json
import time
from typing import List, Dict, Any, Optional, Tuple
from core.detector import GuardDetector
from core.models import BenchmarkCaseResult
from evaluation.metrics import calculate_metrics, compute_dataset_summary


class BenchmarkEvaluator:
    """Runs automated evaluation on the synthetic benchmark dataset."""

    def __init__(self, dataset_path: Optional[str] = None, detector: Optional[GuardDetector] = None):
        if dataset_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            dataset_path = os.path.join(base_dir, "synthetic_dataset.json")
        self.dataset_path = dataset_path
        self.detector = detector or GuardDetector()

    def load_dataset(self) -> List[Dict[str, Any]]:
        """Load benchmark cases from JSON file."""
        if not os.path.exists(self.dataset_path):
            raise FileNotFoundError(f"Synthetic dataset not found at {self.dataset_path}")
        with open(self.dataset_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def run_evaluation(self, prefer_ollama: bool = False) -> Tuple[List[BenchmarkCaseResult], Dict[str, Any]]:
        """Run complete benchmark evaluation across all dataset cases."""
        cases = self.load_dataset()
        results: List[BenchmarkCaseResult] = []

        for case in cases:
            case_id = case.get("id", "tc_unk")
            title = case.get("title", "Untitled")
            category = case.get("category", "General")
            prompt = case.get("prompt", "")
            expected_entities = case.get("expected_entities", [])
            expected_min = case.get("expected_min_count", 0)

            # Analyze prompt
            scan_res = self.detector.analyze_and_rewrite(
                prompt=prompt,
                prefer_ollama=prefer_ollama,
            )

            detected_spans = scan_res.spans
            detected_types = list(set(s.entity_type for s in detected_spans))

            # Compute precision & recall
            if expected_min == 0:
                # Clean prompt case
                if len(detected_spans) == 0:
                    precision = 1.0
                    recall = 1.0
                    f1 = 1.0
                    passed = True
                    matched_entities = []
                    missed_entities = []
                    false_positives = []
                else:
                    precision = 0.0
                    recall = 1.0
                    f1 = 0.0
                    passed = False
                    matched_entities = []
                    missed_entities = []
                    false_positives = detected_types
            else:
                def _norm(e: str) -> str:
                    return "AWS_SECRET_ACCESS_KEY" if e in ("AWS_SECRET_KEY", "AWS_SECRET_ACCESS_KEY") else e

                norm_expected = [_norm(e) for e in expected_entities]
                norm_detected = [_norm(d) for d in detected_types]

                matched_entities = [e for e in expected_entities if _norm(e) in norm_detected]
                missed_entities = [e for e in expected_entities if _norm(e) not in norm_detected]
                false_positives = [d for d in detected_types if _norm(d) not in norm_expected]

                recall = len(matched_entities) / len(expected_entities) if expected_entities else 1.0
                precision = len(matched_entities) / len(detected_types) if detected_types else 0.0
                f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
                passed = recall >= 0.8 and len(detected_spans) >= expected_min

            results.append(
                BenchmarkCaseResult(
                    case_id=case_id,
                    title=title,
                    category=category,
                    expected_count=len(expected_entities) if expected_entities else expected_min,
                    detected_count=len(detected_spans),
                    expected_entities=expected_entities,
                    detected_entities=detected_types,
                    matched_entities=matched_entities,
                    missed_entities=missed_entities,
                    false_positives=false_positives,
                    precision=round(precision, 3),
                    recall=round(recall, 3),
                    f1=round(f1, 3),
                    task_preservation_score=round(scan_res.task_preservation_score, 3),
                    scan_latency_ms=round(scan_res.scan_latency_ms, 2),
                    rewrite_latency_ms=round(scan_res.rewrite_latency_ms, 2),
                    passed=passed,
                )
            )

        summary = calculate_metrics(results)
        return results, summary


if __name__ == "__main__":
    evaluator = BenchmarkEvaluator()
    results, summary = evaluator.run_evaluation(prefer_ollama=False)
    print("\n=========================================================================================")
    print("PROMPT DATA-LEAK GUARD -- 16-CASE SYNTHETIC BENCHMARK CASE-BY-CASE AUDIT")
    print("=========================================================================================")
    for r in results:
        status = "[PASS]" if r.passed else "[FAIL]"
        print(f"[{r.case_id}] {r.title} ({r.category}) -> {status}")
        print(f"     Expected : {r.expected_entities}")
        print(f"     Detected : {r.detected_entities}")
        print(f"     Matched  : {r.matched_entities}")
        print(f"     Missed   : {r.missed_entities}")
        print(f"     False Pos: {r.false_positives}")
        print(f"     Recall: {r.recall*100:.0f}% | Precision: {r.precision*100:.0f}% | F1: {r.f1:.2f} | Task Pres: {r.task_preservation_score*100:.0f}% | Latency: {r.scan_latency_ms:.1f}ms")
        print("-" * 89)

    print("\n==========================================")
    print("PROMPT DATA-LEAK GUARD BENCHMARK SUMMARY")
    print("==========================================")
    for k, v in summary.items():
        print(f"{k:25}: {v}")
    print("==========================================\n")
