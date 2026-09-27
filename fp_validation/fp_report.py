# -*- coding: utf-8 -*-
"""fp_report.py — 误报率验证报告生成。

生成 Markdown 报告，写入 reports/ 目录，并返回结构化内容。
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, List


REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports",
)


class FPReportGenerator:
    """误报率报告生成器。"""

    def __init__(self, reports_dir: str = REPORTS_DIR) -> None:
        self.reports_dir = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)

    @staticmethod
    def _pct(x: float) -> str:
        return f"{x * 100:.2f}%"

    def render_markdown(self, aggregate: Dict[str, Any],
                         per_range: List[Dict[str, Any]],
                         before_metrics: Dict[str, Any] | None = None) -> str:
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        lines: List[str] = []
        lines.append("# 误报率验证报告（FP Validation Report）")
        lines.append("")
        lines.append(f"- 生成时间：{now}")
        lines.append(f"- 靶场总数：{len(per_range)}")
        lines.append("")
        lines.append("## 一、聚合指标")
        lines.append("")
        lines.append("| 指标 | 数值 |")
        lines.append("| --- | --- |")
        lines.append(f"| 真正例 TP | {aggregate.get('tp', 0)} |")
        lines.append(f"| 假正例 FP | {aggregate.get('fp', 0)} |")
        lines.append(f"| 假负例 FN | {aggregate.get('fn', 0)} |")
        lines.append(f"| 已知漏洞总数 | {aggregate.get('known_total', 0)} |")
        lines.append(f"| 扫描发现总数 | {aggregate.get('detected_total', 0)} |")
        lines.append(f"| **误报率 FPR** | **{self._pct(aggregate.get('false_positive_rate', 0))}** |")
        lines.append(f"| 漏报率 FNR | {self._pct(aggregate.get('false_negative_rate', 0))} |")
        lines.append(f"| 准确率 Accuracy | {self._pct(aggregate.get('accuracy', 0))} |")
        lines.append(f"| 精确率 Precision | {self._pct(aggregate.get('precision', 0))} |")
        lines.append(f"| 召回率 Recall | {self._pct(aggregate.get('recall', 0))} |")
        lines.append(f"| **F1 分数** | **{self._pct(aggregate.get('f1', 0))}** |")
        lines.append("")

        if before_metrics:
            lines.append("## 二、规则优化前后对比")
            lines.append("")
            lines.append("| 指标 | 优化前 | 优化后 |")
            lines.append("| --- | --- | --- |")
            for k, label in [
                ("false_positive_rate", "误报率"),
                ("false_negative_rate", "漏报率"),
                ("accuracy", "准确率"),
                ("recall", "召回率"),
                ("f1", "F1"),
            ]:
                b = self._pct(before_metrics.get(k, 0))
                a = self._pct(aggregate.get(k, 0))
                lines.append(f"| {label} | {b} | {a} |")
            lines.append("")

        lines.append("## 三、逐靶场明细")
        lines.append("")
        lines.append("| 靶场 | TP | FP | FN | 已知 | 发现 | 误报率 | 召回率 | F1 |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        for m in per_range:
            lines.append(
                f"| {m.get('range_id', '-')} | {m.get('tp', 0)} | {m.get('fp', 0)} | "
                f"{m.get('fn', 0)} | {m.get('known_total', 0)} | "
                f"{m.get('detected_total', 0)} | "
                f"{self._pct(m.get('false_positive_rate', 0))} | "
                f"{self._pct(m.get('recall', 0))} | "
                f"{self._pct(m.get('f1', 0))} |"
            )
        lines.append("")
        lines.append("## 四、结论")
        lines.append("")
        fpr = aggregate.get("false_positive_rate", 0)
        if fpr < 0.05:
            lines.append(f"✅ 误报率 {self._pct(fpr)}，已达到 < 5% 的目标。")
        else:
            lines.append(f"⚠️ 误报率 {self._pct(fpr)}，尚未达到 5% 目标，需继续收紧规则。")
        lines.append("")
        lines.append("---")
        lines.append("*由 fp_validation.fp_report 自动生成*")
        return "\n".join(lines)

    def save(self, markdown: str, filename: str | None = None) -> str:
        if not filename:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"fp_validation_report_{ts}.md"
        path = os.path.join(self.reports_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(markdown)
        return path

    def generate(self, aggregate: Dict[str, Any],
                 per_range: List[Dict[str, Any]],
                 before_metrics: Dict[str, Any] | None = None,
                 filename: str | None = None) -> Dict[str, Any]:
        md = self.render_markdown(aggregate, per_range, before_metrics)
        path = self.save(md, filename)
        return {"path": path, "markdown": md, "size": len(md)}


_singleton: FPReportGenerator | None = None


def get_report_generator() -> FPReportGenerator:
    global _singleton
    if _singleton is None:
        _singleton = FPReportGenerator()
    return _singleton
