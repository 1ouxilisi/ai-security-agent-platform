# -*- coding: utf-8 -*-
"""
report_exporter.py — 多格式导出与报告管理。

支持:
    - 写入 reports/ 目录
    - 历史报告查询
    - 报告对比
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional

from .report_generator import ReportGenerator, ReportData

REPORTS_ROOT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports")


class ReportExporter:
    """报告导出与历史管理。"""

    def __init__(self, root: str = REPORTS_ROOT) -> None:
        self.root = root
        os.makedirs(self.root, exist_ok=True)
        self.gen = ReportGenerator()
        # 内存索引
        self._index: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ #
    # 导出
    # ------------------------------------------------------------------ #
    def export(self, data: ReportData,
               fmts: Optional[List[str]] = None) -> Dict[str, str]:
        """生成并落盘，返回 {fmt: path}。"""
        fmts = fmts or ["html", "md", "json"]
        out: Dict[str, str] = {}
        for fmt in fmts:
            if fmt == "html":
                content = self.gen.generate_html(data)
            elif fmt == "md":
                content = self.gen.generate_markdown(data)
            elif fmt == "json":
                content = self.gen.generate_json(data)
            else:
                continue
            path = os.path.join(self.root,
                                f"{data.report_id}.{fmt}")
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            out[fmt] = path
        # 更新索引
        self._index[data.report_id] = {
            "report_id": data.report_id,
            "title": data.title,
            "target": data.target,
            "overall_risk": data.overall_risk(),
            "severity_summary": data.severity_summary(),
            "files": out,
            "created_at": data.finished_at or
                          time.strftime("%Y-%m-%d %H:%M:%S"),
            "finding_count": len(data.findings),
        }
        return out

    # ------------------------------------------------------------------ #
    # 历史
    # ------------------------------------------------------------------ #
    def list_reports(self) -> List[Dict[str, Any]]:
        # 同时扫描磁盘
        on_disk: Dict[str, Dict[str, Any]] = {}
        if os.path.isdir(self.root):
            for fn in os.listdir(self.root):
                stem, ext = os.path.splitext(fn)
                if ext not in (".html", ".md", ".json"):
                    continue
                stat = os.stat(os.path.join(self.root, fn))
                on_disk.setdefault(stem, {"files": {}})
                on_disk[stem]["files"][ext.lstrip(".")] = fn
                on_disk[stem]["report_id"] = stem
                on_disk[stem]["mtime"] = stat.st_mtime
        # 合并内存索引
        merged = {}
        for stem, info in on_disk.items():
            merged[stem] = {**info, **self._index.get(stem, {})}
        for stem, info in self._index.items():
            merged.setdefault(stem, info)
        return sorted(merged.values(),
                      key=lambda x: x.get("mtime", 0), reverse=True)

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        return self._index.get(report_id)

    def read_file(self, report_id: str, fmt: str = "html") -> Optional[str]:
        path = os.path.join(self.root, f"{report_id}.{fmt}")
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    # ------------------------------------------------------------------ #
    # 对比
    # ------------------------------------------------------------------ #
    def compare(self, report_a: str,
                report_b: str) -> Dict[str, Any]:
        """对比两份报告的风险变化。"""
        a = self._index.get(report_a, {})
        b = self._index.get(report_b, {})
        if not a or not b:
            # 尝试从磁盘读 json
            for rid in (report_a, report_b):
                jp = os.path.join(self.root, f"{rid}.json")
                if os.path.exists(jp):
                    with open(jp, "r", encoding="utf-8") as f:
                        body = json.load(f)
                    self._index[rid] = {
                        "report_id": rid,
                        "severity_summary": body.get("severity_summary", {}),
                        "overall_risk": body.get("overall_risk", ""),
                        "finding_count": len(body.get("findings", [])),
                    }
            a = self._index.get(report_a, {})
            b = self._index.get(report_b, {})

        sa = a.get("severity_summary", {})
        sb = b.get("severity_summary", {})
        diff = {}
        for sev in ("critical", "high", "medium", "low", "info"):
            diff[sev] = sb.get(sev, 0) - sa.get(sev, 0)
        return {
            "report_a": report_a,
            "report_b": report_b,
            "summary_a": sa,
            "summary_b": sb,
            "delta": diff,
            "improved": sum(1 for v in diff.values() if v < 0),
            "worsened": sum(1 for v in diff.values() if v > 0),
        }


_default_exporter: Optional[ReportExporter] = None


def get_exporter() -> ReportExporter:
    global _default_exporter
    if _default_exporter is None:
        _default_exporter = ReportExporter()
    return _default_exporter
