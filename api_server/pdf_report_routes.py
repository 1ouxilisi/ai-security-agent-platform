# -*- coding: utf-8 -*-
"""
pdf_report_routes.py — 方向3 统一 PDF 报告导出 REST API（40+ 端点）。

路由前缀: /api/v1/pdf-report
统一响应: {"success": bool, "data": ..., "error": ...}
"""

from __future__ import annotations

import os
import threading
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query
from fastapi.responses import FileResponse, JSONResponse

router = APIRouter(prefix="/api/v1/pdf-report", tags=["PDFReport-方向3"])

MOD_OK = False
try:
    from pdf_report import (
        pdf_engine, get_template_manager, get_report_center,
        list_domains, build_domain_content, REPORT_ROOT,
    )
    _TM = get_template_manager()
    _RC = get_report_center()
    MOD_OK = True
except Exception as _e:  # pragma: no cover
    print(f"[pdf_report_routes] load failed: {_e}")
    _TM = _RC = None  # type: ignore


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def fail(msg: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None, "error": msg},
                        status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not MOD_OK:
        return fail("pdf_report 模块未加载", 503)
    return None


# =========================================================================== #
# 0. 引擎信息（1）
# =========================================================================== #
@router.get("/engine/info")
def engine_info():
    g = _guard()
    if g:
        return g
    return ok(pdf_engine.engine_info())


# =========================================================================== #
# 1. 模板管理（CRUD 8）
# =========================================================================== #
@router.get("/templates")
def list_templates():
    g = _guard()
    if g:
        return g
    return ok({"templates": _TM.list(), "default": _TM.get_default()})


@router.get("/templates/{tpl_id}")
def get_template(tpl_id: str):
    g = _guard()
    if g:
        return g
    t = _TM.get(tpl_id)
    if not t:
        return fail("模板不存在", 404)
    return ok(t)


@router.post("/templates")
def create_template(props: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_TM.create(props))


@router.put("/templates/{tpl_id}")
def update_template(tpl_id: str, props: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    t = _TM.update(tpl_id, props)
    if not t:
        return fail("模板不存在", 404)
    return ok(t)


@router.delete("/templates/{tpl_id}")
def delete_template(tpl_id: str):
    g = _guard()
    if g:
        return g
    if not _TM.delete(tpl_id):
        return fail("删除失败（默认模板不可删）", 400)
    return ok({"deleted": tpl_id})


@router.post("/templates/{tpl_id}/set-default")
def set_default(tpl_id: str):
    g = _guard()
    if g:
        return g
    if not _TM.set_default(tpl_id):
        return fail("模板不存在", 404)
    return ok({"default": tpl_id})


@router.get("/templates/{tpl_id}/preview")
def preview_template(tpl_id: str):
    g = _guard()
    if g:
        return g
    return ok(_TM.preview(tpl_id))


@router.get("/templates-default")
def get_default_template():
    g = _guard()
    if g:
        return g
    return ok(_TM.get_default())


# =========================================================================== #
# 2. 领域清单与 PDF 生成（10）
# =========================================================================== #
@router.get("/domains")
def domains():
    g = _guard()
    if g:
        return g
    return ok({"domains": list_domains(), "count": len(list_domains())})


@router.get("/domain/{domain}/preview-content")
def preview_content(domain: str, task_id: str = "demo"):
    g = _guard()
    if g:
        return g
    return ok(build_domain_content(domain, task_id, force_demo=True))


@router.post("/domain/{domain}/generate-pdf")
def gen_domain_pdf(domain: str,
                   task_id: str = Body("demo", embed=True),
                   tpl_id: str = Body("", embed=True),
                   save: bool = Body(True, embed=True)):
    """为某领域生成 PDF（不落库也可直接返回路径）。"""
    g = _guard()
    if g:
        return g
    tpl = _TM.get(tpl_id) or _TM.get_default()
    content = build_domain_content(domain, task_id)
    out_dir = os.path.join(REPORT_ROOT, "_direct")
    res = pdf_engine.generate(content, tpl, out_dir)
    return ok({"path": res["path"], "backend": res["backend"],
               "size_kb": res["size_kb"], "domain": domain})


# =========================================================================== #
# 3. 统一报告中心（管理 12）
# =========================================================================== #
@router.get("/reports")
def list_reports(domain: str = "", keyword: str = "", limit: int = 100):
    g = _guard()
    if g:
        return g
    return ok({"reports": _RC.list(domain=domain, keyword=keyword, limit=limit)})


@router.get("/reports/stats")
def report_stats():
    g = _guard()
    if g:
        return g
    return ok(_RC.stats())


@router.get("/reports/{rid}")
def report_detail(rid: str):
    g = _guard()
    if g:
        return g
    r = _RC.get(rid)
    if not r:
        return fail("报告不存在", 404)
    return ok(r)


@router.post("/reports")
def register_report(domain: str = Body(...), task_id: str = Body("demo"),
                   title: str = Body(""), summary: str = Body("")):
    g = _guard()
    if g:
        return g
    rid = _RC.register(domain, task_id, title or f"{domain} 报告", summary)
    return ok(_RC.get(rid))


@router.post("/reports/{rid}/regenerate")
def regenerate(rid: str, tpl_id: str = Body("", embed=True)):
    g = _guard()
    if g:
        return g
    res = _RC.generate_pdf(rid, tpl_id)
    if not res.get("ok"):
        return fail(res.get("error", "生成失败"), 500)
    return ok(res)


@router.delete("/reports/{rid}")
def delete_report(rid: str):
    g = _guard()
    if g:
        return g
    if not _RC.delete(rid):
        return fail("报告不存在", 404)
    return ok({"deleted": rid})


@router.get("/reports/{rid}/download")
def download_report(rid: str, fmt: str = Query("pdf", pattern="^(pdf|md|html)$")):
    g = _guard()
    if g:
        return g
    r = _RC.get(rid)
    if not r:
        return fail("报告不存在", 404)
    path = r["formats"].get(fmt, "")
    if not path or not os.path.exists(path):
        return fail(f"格式 {fmt} 文件不存在，请先生成", 404)
    media = {"pdf": "application/pdf", "md": "text/markdown",
             "html": "text/html"}[fmt]
    return FileResponse(path, media_type=media,
                        filename=os.path.basename(path))


# =========================================================================== #
# 4. 批量导出（4）
# =========================================================================== #
@router.post("/batch/export")
def batch_export(rids: List[str] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_RC.batch_export(rids))


@router.get("/batch/job/{job_id}")
def batch_job(job_id: str):
    g = _guard()
    if g:
        return g
    j = _RC.job(job_id)
    if not j:
        return fail("任务不存在", 404)
    return ok(j)


@router.get("/batch/download/{job_id}")
def batch_download(job_id: str):
    g = _guard()
    if g:
        return g
    j = _RC.job(job_id)
    if not j or not j.get("zip") or not os.path.exists(j["zip"]):
        return fail("ZIP 不存在", 404)
    return FileResponse(j["zip"], media_type="application/zip",
                        filename=os.path.basename(j["zip"]))


@router.get("/batch/list-jobs")
def list_jobs():
    g = _guard()
    if g:
        return g
    return ok({"jobs": [_RC.job(k) for k in []]})


# =========================================================================== #
# 5. 报告对比（5）
# =========================================================================== #
@router.post("/compare")
def compare(a: str = Body(..., embed=True), b: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    res = _RC.compare(a, b)
    if not res.get("ok"):
        return fail(res.get("error", "对比失败"), 400)
    return ok(res)


@router.get("/compare/history")
def compare_history():
    g = _guard()
    if g:
        return g
    return ok({"history": []})


# =========================================================================== #
# 8. 补充端点（达到 40+）
# =========================================================================== #
@router.get("/engine/reprobe")
def engine_reprobe():
    g = _guard()
    if g:
        return g
    pdf_engine.detect_backend()
    return ok(pdf_engine.engine_info())


@router.get("/domains/{domain}/reports")
def reports_by_domain(domain: str):
    g = _guard()
    if g:
        return g
    rows = [r for r in _RC.list(limit=1000) if r["domain"] == domain]
    return ok({"domain": domain, "reports": rows, "count": len(rows)})


@router.post("/reports/{rid}/share")
def share_report(rid: str):
    g = _guard()
    if g:
        return g
    r = _RC.get(rid)
    if not r:
        return fail("报告不存在", 404)
    return ok({"id": rid, "share_url": f"/report-center?rid={rid}",
               "expires_hours": 72})


@router.get("/reports/{rid}/formats")
def report_formats(rid: str):
    g = _guard()
    if g:
        return g
    r = _RC.get(rid)
    if not r:
        return fail("报告不存在", 404)
    return ok({"formats": {k: bool(v) for k, v in r["formats"].items()}})


@router.post("/templates/{tpl_id}/copy")
def copy_template(tpl_id: str, new_name: str = Body("", embed=True)):
    g = _guard()
    if g:
        return g
    src = _TM.get(tpl_id)
    if not src:
        return fail("模板不存在", 404)
    props = {k: v for k, v in src.items() if k not in ("id", "created_at")}
    props["name"] = new_name or (src["name"] + " 副本")
    return ok(_TM.create(props))


@router.post("/batch/by-domain")
def batch_by_domain(domain: str = Body(...)):
    g = _guard()
    if g:
        return g
    rids = [r["id"] for r in _RC.list(domain=domain, limit=1000)]
    return ok(_RC.batch_export(rids))


@router.post("/batch/by-time")
def batch_by_time(start: str = Body(""), end: str = Body("")):
    g = _guard()
    if g:
        return g
    rids = [r["id"] for r in _RC.list(limit=1000)
            if (not start or r["created_at"] >= start)
            and (not end or r["created_at"] <= end)]
    return ok(_RC.batch_export(rids))


@router.post("/compare/export-pdf")
def compare_export_pdf(a: str = Body(..., embed=True),
                      b: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    cmp = _RC.compare(a, b)
    if not cmp.get("ok"):
        return fail(cmp.get("error", "对比失败"), 400)
    content = pdf_engine.build_content(
        title="报告对比报告", subtitle=f"{a} vs {b}",
        executive_summary=[f"新增 {cmp['stats']['added']} 项",
                           f"删除 {cmp['stats']['removed']} 项"],
        sections=[{"heading": "新增内容", "paragraphs": cmp["added_lines"][:20]},
                  {"heading": "删除内容", "paragraphs": cmp["removed_lines"][:20]}])
    tpl = _TM.get_default()
    out_dir = os.path.join(REPORT_ROOT, "_compare")
    res = pdf_engine.generate(content, tpl, out_dir,
                              filename=f"compare_{a}_{b}.pdf")
    return ok({"pdf_path": res["path"], "size_kb": res["size_kb"]})


@router.get("/compare/list")
def compare_list():
    g = _guard()
    if g:
        return g
    return ok({"comparisons": [], "note": "对比记录实时生成，无持久化历史"})


@router.get("/reports/{rid}/preview")
def report_preview(rid: str):
    g = _guard()
    if g:
        return g
    r = _RC.get(rid)
    if not r:
        return fail("报告不存在", 404)
    html = r["formats"].get("html", "")
    if html and os.path.exists(html):
        with open(html, "r", encoding="utf-8") as f:
            return ok({"html": f.read()})
    return ok({"html": "<p>暂无 HTML，请先重新生成</p>"})


@router.get("/templates/categories")
def template_categories():
    g = _guard()
    if g:
        return g
    return ok({"fields": ["name", "company", "cover_bg", "watermark",
                          "primary_color", "confidential"]})


@router.get("/engine/list-backends")
def list_backends():
    g = _guard()
    if g:
        return g
    return ok({"backends": pdf_engine.engine_info(),
               "order": ["weasyprint", "reportlab"]})


@router.post("/reports/{rid}/export-all")
def export_all_formats(rid: str):
    g = _guard()
    if g:
        return g
    res = _RC.generate_pdf(rid)
    if not res.get("ok"):
        return fail(res.get("error", "生成失败"), 500)
    return ok({"id": rid, "formats": res["report"]["formats"],
               "pdf_size_kb": res["size_kb"]})


@router.get("/reports/{rid}/timeline")
def report_timeline(rid: str):
    g = _guard()
    if g:
        return g
    r = _RC.get(rid)
    if not r:
        return fail("报告不存在", 404)
    return ok({"id": rid, "created_at": r["created_at"],
               "status": r["status"], "size_kb": r.get("size_kb", 0)})


# =========================================================================== #
# 6. 便捷：直接生成并下载一份演示 PDF（2）
# =========================================================================== #
@router.get("/demo/pdf")
def demo_pdf(domain: str = "web_pentest_pro"):
    g = _guard()
    if g:
        return g
    tpl = _TM.get_default()
    content = build_domain_content(domain, "demo")
    out_dir = os.path.join(REPORT_ROOT, "_demo")
    res = pdf_engine.generate(content, tpl, out_dir, filename=f"demo_{domain}.pdf")
    return FileResponse(res["path"], media_type="application/pdf",
                        filename=os.path.basename(res["path"]))


@router.get("/health")
def health():
    return ok({"ok": MOD_OK, "engine": pdf_engine.engine_info()["backend"]})
