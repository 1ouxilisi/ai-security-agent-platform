# -*- coding: utf-8 -*-
"""
report_pro_routes.py — 专业安全报告引擎 REST API（20+ 端点）。

路由前缀: /api/v1/report-pro
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query
from fastapi.responses import JSONResponse, FileResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/report-pro",
                   tags=["专业安全报告引擎"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from report_pro import (
        ReportTemplates, ReportCharts,
        ReportGenerator, ReportData, ReportExporter,
    )
    from report_pro.report_exporter import get_exporter
    _EXPORTER = get_exporter()
    _GEN = ReportGenerator()
    _MOD_AVAILABLE = True
    logger.info("report_pro_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("report_pro_routes: load failed: %s", e)
    _EXPORTER = None  # type: ignore
    _GEN = None       # type: ignore


def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return "".join(c for c in obj if c == "\n" or c == "\t"
                       or ord(c) >= 32)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data),
                         "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("Report Pro 模块未加载", 503)
    return None


# --------------------------------------------------------------------------- #
# 1. 生成报告
# --------------------------------------------------------------------------- #
@router.post("/generate")
def generate_report(
    target: str = Body(...),
    title: str = Body("安全评估报告"),
    findings: List[Dict[str, Any]] = Body(default_factory=list),
    assets: List[Dict[str, Any]] = Body(default_factory=list),
    scope: str = Body("授权范围内的安全评估"),
    consultant: str = Body("AI Report Pro"),
    fmts: List[str] = Body(default_factory=lambda: ["html", "md", "json"]),
):
    """根据漏洞数据生成专业报告。"""
    g = _guard()
    if g:
        return g
    try:
        data = ReportData(
            title=title, target=target,
            findings=findings, assets=assets,
            scope=scope, consultant=consultant,
        )
        data.finished_at = ""
        paths = _EXPORTER.export(data, fmts=fmts)
        return ok({
            "report_id": data.report_id,
            "overall_risk": data.overall_risk(),
            "severity_summary": data.severity_summary(),
            "files": paths,
            "html": _GEN.generate_html(data) if "html" in fmts else None,
        })
    except Exception as e:  # noqa: BLE001
        return fail(f"生成失败: {e}")


@router.post("/generate/sample")
def generate_sample():
    """生成一份示例报告（演示用）。"""
    g = _guard()
    if g:
        return g
    sample_findings = [
        {"name": "SQL注入", "severity": "critical",
         "cvss_score": 9.8, "cwe": "CWE-89",
         "url": "http://target/page?id=1",
         "impact": "可读取数据库", "repro": "加单引号触发错误",
         "fix": "参数化查询"},
        {"name": "XSS", "severity": "medium",
         "cvss_score": 6.1, "cwe": "CWE-79",
         "url": "http://target/search?q=",
         "impact": "窃取会话", "repro": "提交 <script>alert(1)</script>",
         "fix": "输出编码"},
        {"name": "信息泄露", "severity": "high",
         "cvss_score": 7.5, "cwe": "CWE-200",
         "url": "http://target/.git/HEAD",
         "impact": "源码泄露", "repro": "直接访问",
         "fix": "删除 .git 目录"},
        {"name": "弱口令", "severity": "high",
         "cvss_score": 9.1, "cwe": "CWE-521",
         "url": "http://target/admin",
         "impact": "后台登录", "repro": "admin/admin",
         "fix": "强密码+MFA"},
        {"name": "目录遍历", "severity": "medium",
         "cvss_score": 5.3, "cwe": "CWE-22",
         "url": "http://target/download?file=",
         "impact": "读任意文件", "repro": "../../../../etc/passwd",
         "fix": "白名单"},
    ]
    sample_assets = [
        {"name": "web-01", "critical": 1, "high": 2, "medium": 1, "low": 0},
        {"name": "web-02", "critical": 0, "high": 1, "medium": 2, "low": 3},
        {"name": "api-01", "critical": 1, "high": 0, "medium": 0, "low": 1},
    ]
    data = ReportData(
        title="示例安全评估报告",
        target="https://demo.example.com",
        findings=sample_findings, assets=sample_assets,
    )
    data.finished_at = ""
    paths = _EXPORTER.export(data)
    return ok({"report_id": data.report_id,
               "overall_risk": data.overall_risk(),
               "files": paths})


# --------------------------------------------------------------------------- #
# 2. 历史报告
# --------------------------------------------------------------------------- #
@router.get("/list")
def list_reports():
    g = _guard()
    if g:
        return g
    return ok({"reports": _EXPORTER.list_reports()})


@router.get("/{report_id}")
def get_report(report_id: str,
               fmt: str = Query("html", description="html/md/json")):
    g = _guard()
    if g:
        return g
    content = _EXPORTER.read_file(report_id, fmt)
    if content is None:
        return fail("report not found", 404)
    return ok({"report_id": report_id, "format": fmt,
               "content": content})


@router.get("/{report_id}/download")
def download_report(report_id: str,
                    fmt: str = Query("html")):
    g = _guard()
    if g:
        return g
    path = None
    import os
    for f in _EXPORTER.list_reports():
        if f.get("report_id") == report_id:
            path = f.get("files", {}).get(fmt)
            if path and not os.path.isabs(path):
                path = os.path.join(_EXPORTER.root, path)
            break
    if not path or not os.path.exists(path):
        return fail("file not found", 404)
    media = {"html": "text/html; charset=utf-8",
             "md": "text/markdown; charset=utf-8",
             "json": "application/json"}.get(fmt, "text/plain")
    return FileResponse(path, media_type=media,
                        filename=os.path.basename(path))


@router.delete("/{report_id}")
def delete_report(report_id: str):
    g = _guard()
    if g:
        return g
    import os
    removed = []
    for ext in ("html", "md", "json"):
        p = os.path.join(_EXPORTER.root, f"{report_id}.{ext}")
        if os.path.exists(p):
            try:
                os.remove(p)
                removed.append(p)
            except OSError:
                pass
    _EXPORTER._index.pop(report_id, None)  # noqa: SLF001
    return ok({"removed": removed})


# --------------------------------------------------------------------------- #
# 3. 对比
# --------------------------------------------------------------------------- #
from pydantic import BaseModel

class CompareReq(BaseModel):
    report_a: str
    report_b: str


@router.post("/compare/v2")
def compare_v2(req: CompareReq):
    g = _guard()
    if g:
        return g
    return ok(_EXPORTER.compare(req.report_a, req.report_b))


# --------------------------------------------------------------------------- #
# 4. 图表
# --------------------------------------------------------------------------- #
@router.post("/charts/preview")
def charts_preview(
    findings: List[Dict[str, Any]] = Body(default_factory=list),
    assets: List[Dict[str, Any]] = Body(default_factory=list),
):
    """预览图表数据（不生成报告）。"""
    g = _guard()
    if g:
        return g
    return ok(_GEN.charts.all_charts(findings, assets=assets))


# --------------------------------------------------------------------------- #
# 5. 模板/知识库
# --------------------------------------------------------------------------- #
@router.get("/templates/catalog")
def vuln_catalog():
    """返回内置漏洞知识库（CVE/CWE/CVSS/修复）。"""
    g = _guard()
    if g:
        return g
    from report_pro.report_templates import VULN_DB
    return ok(VULN_DB)


@router.get("/templates/severity-meta")
def severity_meta():
    from report_pro.report_templates import CVSS_SEVERITY, SEVERITY_ORDER
    return ok({"order": SEVERITY_ORDER,
               "meta": {k: {"range": v[0:2], "color": v[2]}
                        for k, v in CVSS_SEVERITY.items()}})


@router.post("/templates/render-vuln")
def render_vuln_card(vuln: Dict[str, Any] = Body(...)):
    """渲染单条漏洞详情 HTML 卡片。"""
    g = _guard()
    if g:
        return g
    return ok({"html": ReportTemplates.render_vuln_detail(1, vuln)})


# --------------------------------------------------------------------------- #
# 6. 工作流
# --------------------------------------------------------------------------- #
@router.post("/workflow/from-pentest")
def from_pentest(task_id: str = Body(..., embed=True)):
    """从 web_pentest_full 的任务结果生成报告。"""
    g = _guard()
    if g:
        return g
    try:
        from web_pentest_full.pentest_workflow import get_orchestrator
        orch = get_orchestrator()
        t = orch.get_task(task_id)
        if t is None:
            return fail("pentest task not found", 404)
        data = ReportData(
            title=f"渗透测试报告 - {t.target}",
            target=t.target,
            findings=t.findings,
            assets=[{"name": t.target,
                     **{k: v for k, v in t and {}}}] if False else [],
            started_at=t.created_at,
            finished_at=t.finished_at or "",
        )
        paths = _EXPORTER.export(data)
        return ok({"report_id": data.report_id,
                   "files": paths,
                   "overall_risk": data.overall_risk()})
    except Exception as e:  # noqa: BLE001
        return fail(f"失败: {e}")


@router.get("/health")
def health():
    return ok({"service": "report-pro",
               "module_loaded": _MOD_AVAILABLE,
               "report_count": len(_EXPORTER.list_reports())})


# --------------------------------------------------------------------------- #
# 7. 统计 / 扩展
# --------------------------------------------------------------------------- #
@router.get("/stats/overview")
def stats_overview():
    """全局报告统计。"""
    g = _guard()
    if g:
        return g
    reps = _EXPORTER.list_reports()
    total = len(reps)
    by_risk: Dict[str, int] = {}
    total_findings = 0
    for r in reps:
        risk = r.get("overall_risk", "info")
        by_risk[risk] = by_risk.get(risk, 0) + 1
        total_findings += r.get("finding_count", 0)
    return ok({"total_reports": total,
               "by_risk": by_risk,
               "total_findings": total_findings})


@router.get("/stats/by-severity")
def stats_by_severity():
    """聚合所有报告的严重程度分布。"""
    g = _guard()
    if g:
        return g
    agg = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in _EXPORTER.list_reports():
        s = r.get("severity_summary", {}) or {}
        for k in agg:
            agg[k] += s.get(k, 0)
    return ok(agg)


@router.get("/templates/vuln/{name}")
def vuln_detail(name: str):
    """查询单个漏洞知识库条目。"""
    g = _guard()
    if g:
        return g
    from report_pro.report_templates import VULN_DB
    if name not in VULN_DB:
        return fail("not found", 404)
    return ok({"name": name, **VULN_DB[name]})


@router.post("/charts/trend")
def trend_chart(reports: List[Dict[str, Any]] = Body(...)):
    """根据历史数据生成趋势图。"""
    g = _guard()
    if g:
        return g
    from report_pro.report_charts import ReportCharts
    return ok(ReportCharts.trend_compare(reports))


@router.post("/batch/generate")
def batch_generate(targets: List[str] = Body(...),
                   findings_per_target:
                   List[List[Dict[str, Any]]] = Body(...)):
    """批量生成报告。"""
    g = _guard()
    if g:
        return g
    out = []
    for i, target in enumerate(targets):
        f = findings_per_target[i] if i < len(findings_per_target) else []
        data = ReportData(title=f"安全评估 - {target}",
                          target=target, findings=f)
        data.finished_at = ""
        paths = _EXPORTER.export(data, fmts=["html", "json"])
        out.append({"target": target, "report_id": data.report_id,
                    "files": paths})
    return ok({"generated": len(out), "items": out})


@router.get("/{report_id}/summary")
def report_summary(report_id: str):
    """返回报告摘要（不返回完整 HTML）。"""
    g = _guard()
    if g:
        return g
    info = _EXPORTER.get_report(report_id)
    if info is None:
        return fail("not found", 404)
    return ok(info)


@router.get("/templates/all")
def list_all_templates():
    """列出所有内置报告模板名称。"""
    g = _guard()
    if g:
        return g
    return ok({"templates": ["exec_summary", "vuln_detail_card",
                              "heatmap", "charts_doughnut",
                              "charts_bar", "charts_line"],
               "formats": ["html", "md", "json"]})
