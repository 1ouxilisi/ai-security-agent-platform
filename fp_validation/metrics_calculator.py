# -*- coding: utf-8 -*-
"""metrics_calculator.py — 误报率/漏报率/准确率/召回率/F1 计算。

口径（按任务定义）：
    误报率 FPR  = FP / (TP + FP)
    漏报率 FNR  = FN / 已知漏洞总数
    准确率 Accuracy = TP / 扫描结果总数
    召回率 Recall   = TP / 已知漏洞总数
    F1          = 2 * P * R / (P + R)
其中 Precision = TP / (TP + FP)，用于 F1。
"""
from __future__ import annotations

from typing import Any, Dict, List


class MetricsCalculator:
    """基于匹配结果计算混淆矩阵与指标。"""

    @staticmethod
    def compute_from_match(match: Dict[str, Any]) -> Dict[str, Any]:
        tp = len(match.get("true_positives", []))
        fp = len(match.get("false_positives", []))
        fn = len(match.get("false_negatives", []))
        known_total = match.get("known_total", tp + fn) or (tp + fn)
        detected_total = match.get("detected_total", tp + fp) or (tp + fp)
        return MetricsCalculator.compute(tp, fp, fn, known_total, detected_total)

    @staticmethod
    def compute(
        tp: int,
        fp: int,
        fn: int,
        known_total: int,
        detected_total: int,
    ) -> Dict[str, Any]:
        tp = int(tp); fp = int(fp); fn = int(fn)
        known_total = int(known_total or (tp + fn))
        detected_total = int(detected_total or (tp + fp))

        fpr = fp / (tp + fp) if (tp + fp) > 0 else 0.0
        fnr = fn / known_total if known_total > 0 else 0.0
        accuracy = tp / detected_total if detected_total > 0 else 0.0
        recall = tp / known_total if known_total > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        return {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "known_total": known_total,
            "detected_total": detected_total,
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }

    @staticmethod
    def aggregate(per_range: List[Dict[str, Any]]) -> Dict[str, Any]:
        """把每个靶场的指标聚合成总指标（混淆矩阵先求和再算比率）。"""
        tp = sum(int(m.get("tp", 0)) for m in per_range)
        fp = sum(int(m.get("fp", 0)) for m in per_range)
        fn = sum(int(m.get("fn", 0)) for m in per_range)
        known = sum(int(m.get("known_total", 0)) for m in per_range)
        detected = sum(int(m.get("detected_total", 0)) for m in per_range)
        agg = MetricsCalculator.compute(tp, fp, fn, known, detected)
        agg["per_range"] = per_range
        return agg


_singleton: MetricsCalculator | None = None


def get_calculator() -> MetricsCalculator:
    global _singleton
    if _singleton is None:
        _singleton = MetricsCalculator()
    return _singleton
