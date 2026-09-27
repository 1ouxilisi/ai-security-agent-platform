# -*- coding: utf-8 -*-
"""
report_center.py — 统一报告中心（内存字典存储 + 磁盘文件）。

功能：
    - 报告注册/列表/详情/删除/重新生成
    - 多格式（MD/HTML/PDF）下载路径
    - 批量导出（ZIP）
    - 两报告对比（新增/删除/修改高亮）
    - 报告统计
"""

from __future__ import annotations

import io
import os
import re
import time
import uuid
import zipfile
from typing import Any, Dict, List, Optional

from . import pdf_engine
from .domain_pdf_adapters import DOMAINS, build_domain_content
from .pdf_templates import get_template_manager

REPORT_ROOT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports", "_report_center")


class ReportCenter:
    """统一报告中心。"""

    def __init__(self) -> None:
        os.makedirs(REPORT_ROOT, exist_ok=True)
        self._reports: Dict[str, Dict[str, Any]] = {}
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._seed_demo()

    # ------------------------------------------------------------------ #
    def _seed_demo(self) -> None:
        """注入 3 份演示报告，便于前端立即展示。"""
        for i, dk in enumerate(["web_pentest_pro", "soc_pro", "cloud_security_pro"]):
            rid = f"rc_{uuid.uuid4().hex[:10]}"
            self._reports[rid] = {
                "id": rid, "domain": dk,
                "domain_name": DOMAINS[dk]["name"],
                "title": DOMAINS[dk]["title"],
                "task_id": f"demo-{i+1}",
                "formats": {"md": "", "html": "", "pdf": ""},
                "size_kb": 0, "status": "ready",
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S",
                                            time.localtime(time.time() - i * 86400)),
                "summary": "演示报告（可重新生成真实 PDF）",
            }

    # ------------------------------------------------------------------ #
    def list(self, *, domain: str = "", keyword: str = "",
             limit: int = 100) -> List[Dict[str, Any]]:
        rows = sorted(self._reports.values(),
                      key=lambda x: x["created_at"], reverse=True)
        if domain:
            rows = [r for r in rows if r["domain"] == domain]
        if keyword:
            kw = keyword.lower()
            rows = [r for r in rows
                    if kw in r["title"].lower() or kw in r["task_id"].lower()]
        return rows[:limit]

    def get(self, rid: str) -> Optional[Dict[str, Any]]:
        return self._reports.get(rid)

    def register(self, domain: str, task_id: str, title: str,
                 summary: str = "") -> str:
        rid = f"rc_{uuid.uuid4().hex[:10]}"
        self._reports[rid] = {
            "id": rid, "domain": domain,
            "domain_name": DOMAINS.get(domain, {}).get("name", domain),
            "title": title, "task_id": task_id,
            "formats": {"md": "", "html": "", "pdf": ""},
            "size_kb": 0, "status": "generated",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": summary,
        }
        return rid

    def delete(self, rid: str) -> bool:
        r = self._reports.pop(rid, None)
        if r:
            for p in r["formats"].values():
                if p and os.path.exists(p):
                    try:
                        os.remove(p)
                    except OSError:
                        pass
            return True
        return False

    # ------------------------------------------------------------------ #
    def generate_pdf(self, rid: str, tpl_id: str = "") -> Dict[str, Any]:
        """为某报告生成 PDF（走统一引擎）。"""
        r = self._reports.get(rid)
        if r is None:
            return {"ok": False, "error": "报告不存在"}
        tpl = get_template_manager().get(tpl_id) or \
            get_template_manager().get_default()
        out_dir = os.path.join(REPORT_ROOT, rid)
        content = build_domain_content(r["domain"], r["task_id"])
        res = pdf_engine.generate(content, tpl, out_dir,
                                  filename=f"{rid}.pdf")
        r["formats"]["pdf"] = res["path"]
        r["size_kb"] = res["size_kb"]
        r["status"] = "ready"
        # 同时落一份 md/html 便于多格式切换
        md_path = os.path.join(out_dir, f"{rid}.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(self._content_to_md(content))
        r["formats"]["md"] = md_path
        html_path = os.path.join(out_dir, f"{rid}.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(f"<h1>{content['title']}</h1><p>{content['subtitle']}</p>")
        r["formats"]["html"] = html_path
        return {"ok": True, "report": r, "engine": pdf_engine.engine_info(),
                "pdf_path": res["path"], "size_kb": res["size_kb"]}

    @staticmethod
    def _content_to_md(c: Dict[str, Any]) -> str:
        lines = [f"# {c['title']}", "", f"_{c['subtitle']}_", "",
                 "## 执行摘要", ""]
        for l in c.get("executive_summary", []):
            lines.append(f"- {l}")
        for s in c.get("sections", []):
            lines += ["", f"## {s['heading']}", ""]
            lines += s.get("paragraphs", [])
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    def batch_export(self, rids: List[str]) -> Dict[str, Any]:
        """把多份报告打包成 ZIP。"""
        job_id = f"job_{uuid.uuid4().hex[:10]}"
        self._jobs[job_id] = {"id": job_id, "total": len(rids),
                              "done": 0, "status": "running", "zip": ""}
        zip_path = os.path.join(REPORT_ROOT, f"batch_{job_id}.zip")
        found = 0
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for rid in rids:
                r = self._reports.get(rid)
                if not r:
                    continue
                for fmt, p in r["formats"].items():
                    if p and os.path.exists(p):
                        arc = f"{rid}/{os.path.basename(p)}"
                        zf.write(p, arc)
                        found += 1
                self._jobs[job_id]["done"] += 1
        self._jobs[job_id].update({"status": "done", "zip": zip_path,
                                    "files": found})
        return self._jobs[job_id]

    def job(self, job_id: str) -> Optional[Dict[str, Any]]:
        return self._jobs.get(job_id)

    # ------------------------------------------------------------------ #
    def compare(self, rid_a: str, rid_b: str) -> Dict[str, Any]:
        """对比两份报告（同领域不同时间）的差异。"""
        a = self._reports.get(rid_a)
        b = self._reports.get(rid_b)
        if not a or not b:
            return {"ok": False, "error": "报告不存在"}
        ca = build_domain_content(a["domain"], a["task_id"])
        cb = build_domain_content(b["domain"], b["task_id"])
        ta = set(self._content_lines(ca))
        tb = set(self._content_lines(cb))
        added = sorted(tb - ta)
        removed = sorted(ta - tb)
        common = ta & tb
        return {
            "ok": True, "a": {"id": rid_a, "title": a["title"]},
            "b": {"id": rid_b, "title": b["title"]},
            "stats": {"added": len(added), "removed": len(removed),
                      "common": len(common)},
            "added_lines": added[:50], "removed_lines": removed[:50],
        }

    @staticmethod
    def _content_lines(c: Dict[str, Any]) -> List[str]:
        out: List[str] = []
        for s in c.get("sections", []):
            out.append(s.get("heading", ""))
            out += s.get("paragraphs", [])
        return [x for x in out if x]

    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        by_domain: Dict[str, int] = {}
        total_size = 0
        for r in self._reports.values():
            by_domain[r["domain_name"]] = by_domain.get(r["domain_name"], 0) + 1
            total_size += r.get("size_kb", 0)
        return {"total": len(self._reports),
                "by_domain": by_domain,
                "total_size_kb": round(total_size, 1),
                "ready": sum(1 for r in self._reports.values()
                            if r["status"] == "ready")}


_center: Optional[ReportCenter] = None


def get_report_center() -> ReportCenter:
    global _center
    if _center is None:
        _center = ReportCenter()
    return _center
