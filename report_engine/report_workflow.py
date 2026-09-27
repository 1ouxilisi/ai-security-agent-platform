# -*- coding: utf-8 -*-
"""report_workflow.py — 综合报告工作流。

串联：选择模板 → 数据导入 → 智能生成 → 质量校验 → 协作审批 → 多格式导出 → 归档。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from .template_library import get_template_library
from .smart_generator import get_smart_generator
from .quality_checker import get_quality_checker
from .multi_format_export import get_exporter, SUPPORTED_FORMATS
from .collaboration_approval import get_collab
from .report_analytics import get_analytics


class ReportWorkflow:
    def __init__(self) -> None:
        self.library = get_template_library()
        self.generator = get_smart_generator()
        self.checker = get_quality_checker()
        self.exporter = get_exporter()
        self.collab = get_collab()
        self.analytics = get_analytics()
        self.runs: Dict[str, Dict[str, Any]] = {}

    # ---------------- 一键跑完整流程 ---------------- #
    def run(self, template_id: str,
            scan_results: List[Dict[str, Any]],
            assets: List[Dict[str, Any]],
            meta: Optional[Dict[str, Any]] = None,
            export_formats: Optional[List[str]] = None) -> Dict[str, Any]:
        run_id = f"WF-{uuid.uuid4().hex[:10].upper()}"
        meta = meta or {}
        steps: List[Dict[str, Any]] = []

        # Step 1: 选择模板
        tpl = self.library.get_template(template_id)
        steps.append({"step": "select_template", "ok": tpl is not None,
                      "detail": tpl["name"] if tpl else None})
        if not tpl:
            return {"run_id": run_id, "success": False, "error": "模板不存在", "steps": steps}

        # Step 2: 数据导入（scan_results/assets 已在调用方准备好）
        steps.append({"step": "import_data", "ok": True,
                      "detail": f"assets={len(assets)} vulns={len(scan_results)}"})

        # Step 3: 智能生成
        t0 = time.time()
        report = self.generator.generate(tpl, scan_results, assets, meta)
        steps.append({"step": "smart_generate", "ok": True,
                      "detail": f"report_id={report['report_id']} 耗时{round(time.time()-t0,2)}s"})

        # Step 4: 质量校验
        qr = self.checker.check(report, required_sections=tpl["required_sections"])
        steps.append({"step": "quality_check", "ok": qr["passed"],
                      "detail": f"score={qr['score']} grade={qr['grade']}"})

        # Step 5: 协作审批 — 创建文档并推到 review
        doc = self.collab.create_document(report, owner=meta.get("author", "author"))
        self.collab.advance_stage(doc["doc_id"], meta.get("author", "author"),
                                  note="自动生成完成，进入审核")
        steps.append({"step": "collab_create", "ok": True,
                      "detail": f"doc_id={doc['doc_id']} stage=review"})

        # Step 6: 多格式导出
        formats = export_formats or ["html", "markdown", "json"]
        exports = []
        for f in formats:
            res = self.exporter.export(report, f, style=meta.get("style"))
            exports.append(res)
        steps.append({"step": "multi_export", "ok": all(e["success"] for e in exports),
                      "detail": f"formats={[e['format'] for e in exports]}"})

        # Step 7: 归档到分析库
        self.analytics.ingest(report)
        self.analytics.set_quality(report["report_id"], qr["score"], qr["grade"])
        self.analytics.set_stage(report["report_id"], doc["stage"])
        steps.append({"step": "archive", "ok": True,
                      "detail": f"ingested to library, stage={doc['stage']}"})

        result = {
            "run_id": run_id,
            "success": qr["passed"],
            "report_id": report["report_id"],
            "doc_id": doc["doc_id"],
            "quality": qr,
            "exports": exports,
            "steps": steps,
            "finished_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.runs[run_id] = result
        return result

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        return self.runs.get(run_id)

    def list_runs(self) -> List[Dict[str, Any]]:
        return list(self.runs.values())


_WF: ReportWorkflow | None = None


def get_workflow() -> ReportWorkflow:
    global _WF
    if _WF is None:
        _WF = ReportWorkflow()
    return _WF
