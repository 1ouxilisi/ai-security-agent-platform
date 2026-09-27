#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
全域安全评估统一 API 路由

提供：评估执行、结果查询、领域列表、知识库查询、报告生成与下载、统计等接口。
所有领域评估器采用延迟导入，单个领域模块异常不影响整体路由。
"""
import os
import traceback
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from unified.models import ReportConfig, DomainType


router = APIRouter(prefix="/api/v1/unified", tags=["全域安全评估"])


# ---------------- 请求模型 ----------------

class AssessmentRequest(BaseModel):
    """创建全域评估请求"""
    target: str = Field(..., description="评估目标（IP/域名/APK路径/合约地址/AI端点）")
    assessment_type: str = Field(
        "comprehensive",
        description="评估类型: pentest(渗透测试)/mobile(移动安全)/blockchain(区块链)/ai_agent(AI智能体)/comprehensive(综合)",
    )
    domains: Optional[List[str]] = Field(None, description="指定领域列表（custom 模式下使用）")
    options: Optional[Dict[str, Any]] = Field(None, description="各领域选项，key 为领域名")


class ReportGenerateRequest(BaseModel):
    """生成报告请求"""
    assessment_id: str = Field(..., description="评估编号")
    format: str = Field("html", description="报告格式: html/markdown/json")
    title: Optional[str] = Field(None, description="报告标题（可选）")


# ---------------- 内部工具 ----------------

def _get_engine():
    """获取统一引擎单例（延迟导入）"""
    from unified.engine import get_engine
    return get_engine()


def _get_kb():
    """获取知识库单例（延迟导入）"""
    from unified.knowledge_base import get_knowledge_base
    return get_knowledge_base()


def _register_all_domains(engine) -> None:
    """延迟导入并注册所有领域评估器，单个失败不影响其他"""
    registrars = [
        ("unified.pentest_assessor", "渗透测试"),
        ("unified.mobile_assessor", "移动安全"),
        ("unified.blockchain_assessor", "区块链安全"),
        ("unified.ai_assessor", "AI智能体安全"),
    ]
    for module_path, name in registrars:
        try:
            import importlib
            mod = importlib.import_module(module_path)
            if hasattr(mod, "register"):
                mod.register(engine)
        except Exception as e:
            print(f"[unified_routes] 领域 {name} 注册失败: {e}")


# 报告缓存：assessment_id -> {format: path}
_report_cache: Dict[str, Dict[str, str]] = {}


# ---------------- 端点 ----------------

@router.post("/assessment", summary="创建并执行全域评估",
             description="根据目标和评估类型，调度已注册的领域评估器执行安全评估，返回聚合结果。")
async def create_assessment(req: AssessmentRequest):
    engine = _get_engine()
    # 每次执行前确保领域评估器已注册（幂等）
    _register_all_domains(engine)

    try:
        result = engine.run_assessment(
            target=req.target,
            assessment_type=req.assessment_type,
            domains=req.domains,
            options=req.options or {},
        )
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"评估执行失败: {e}")

    return {
        "status": "success",
        "assessment_id": result.assessment_id,
        "result": result.to_dict(),
    }


@router.get("/assessment/{assessment_id}", summary="获取评估结果",
            description="根据评估编号获取完整的评估结果详情。")
async def get_assessment(assessment_id: str):
    engine = _get_engine()
    result = engine.get_result(assessment_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"未找到评估: {assessment_id}")
    return {"status": "success", "assessment_id": assessment_id, "result": result.to_dict()}


@router.get("/assessments", summary="获取评估历史列表",
            description="获取最近执行过的评估记录列表，可通过 limit 控制数量。")
async def list_assessments(limit: int = Query(20, ge=1, le=200, description="返回数量上限")):
    engine = _get_engine()
    items = engine.list_results(limit=limit)
    return {"status": "success", "total": len(items), "items": items}


@router.get("/domains", summary="获取可用领域列表",
            description="返回当前已注册的所有安全评估领域。")
async def get_domains():
    engine = _get_engine()
    _register_all_domains(engine)
    domains = engine.available_domains()
    # 同时返回所有内置领域（含未注册的）
    all_domains = [
        {"domain": d.value, "label": d.label(), "registered": any(x["domain"] == d.value for x in domains)}
        for d in DomainType.all_domains()
    ]
    return {
        "status": "success",
        "registered": domains,
        "all_domains": all_domains,
    }


@router.get("/knowledge/stats", summary="获取知识库统计",
            description="返回知识库中的漏洞条目总数、各领域数量等统计信息。")
async def knowledge_stats():
    kb = _get_kb()
    return {"status": "success", "statistics": kb.get_statistics()}


@router.get("/knowledge/search", summary="搜索知识库",
            description="按关键词跨领域搜索漏洞知识库。")
async def search_knowledge(keyword: str = Query(..., description="搜索关键词")):
    kb = _get_kb()
    items = kb.search(keyword)
    return {"status": "success", "keyword": keyword, "total": len(items), "items": items}


@router.get("/knowledge/{domain}", summary="获取指定领域Top漏洞知识库",
            description="返回指定领域的常见漏洞、攻击模式与修复建议。")
async def get_domain_knowledge(domain: str):
    kb = _get_kb()
    try:
        d = DomainType(domain)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"未知领域: {domain}")
    items = kb.get_domain_top(d)
    return {"status": "success", "domain": domain, "domain_label": d.label(), "total": len(items), "items": items}


@router.post("/report/generate", summary="生成报告",
             description="根据评估结果生成 HTML / Markdown / JSON 格式报告，并返回下载路径。")
async def generate_report(req: ReportGenerateRequest):
    from unified.report_generator import UnifiedReportGenerator

    engine = _get_engine()
    result = engine.get_result(req.assessment_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"未找到评估: {req.assessment_id}")

    fmt = (req.format or "html").lower()
    if fmt not in ("html", "markdown", "md", "json"):
        raise HTTPException(status_code=400, detail=f"不支持的格式: {req.format}")

    cfg = ReportConfig(format=fmt, output_dir="reports/unified")
    if req.title:
        cfg.title = req.title

    try:
        gen = UnifiedReportGenerator(output_root="reports/unified")
        path = gen.generate(result, cfg)
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"报告生成失败: {e}")

    _report_cache.setdefault(req.assessment_id, {})[fmt] = path
    rel_url = f"/api/v1/unified/report/{req.assessment_id}?format={fmt}"
    return {
        "status": "success",
        "report_path": path,
        "report_url": rel_url,
        "format": fmt,
    }


@router.get("/report/{assessment_id}", summary="下载报告",
            description="根据评估编号与格式参数下载已生成的报告文件。")
async def download_report(assessment_id: str, format: str = Query("html", description="报告格式: html/markdown/json")):
    fmt = format.lower()
    path = _report_cache.get(assessment_id, {}).get(fmt)
    if not path or not os.path.exists(path):
        # 尝试自动生成
        engine = _get_engine()
        result = engine.get_result(assessment_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"未找到评估或报告: {assessment_id}")
        from unified.report_generator import UnifiedReportGenerator
        cfg = ReportConfig(format=fmt, output_dir="reports/unified")
        gen = UnifiedReportGenerator(output_root="reports/unified")
        path = gen.generate(result, cfg)
        _report_cache.setdefault(assessment_id, {})[fmt] = path

    media_type = {
        "html": "text/html; charset=utf-8",
        "markdown": "text/markdown; charset=utf-8",
        "md": "text/markdown; charset=utf-8",
        "json": "application/json; charset=utf-8",
    }.get(fmt, "text/plain; charset=utf-8")

    filename = os.path.basename(path)
    return FileResponse(path, media_type=media_type, filename=filename)


@router.get("/stats", summary="获取统一框架统计",
            description="返回统一框架的总体统计：评估总数、各领域评估数、漏洞总数等。")
async def unified_stats():
    engine = _get_engine()
    _register_all_domains(engine)

    results = engine.list_results(limit=1000)
    total_assessments = len(results)
    total_findings = sum(r.get("findings_count", 0) for r in results)
    domain_counts: Dict[str, int] = {}
    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # 从缓存中聚合
    for r in engine._results_cache.values():
        sev = r._severity_counts()
        for k in severity_totals:
            severity_totals[k] += sev.get(k, 0)
        dom_counts = r._domain_counts()
        for k, v in dom_counts.items():
            domain_counts[k] = domain_counts.get(k, 0) + v

    kb = _get_kb()
    return {
        "status": "success",
        "total_assessments": total_assessments,
        "total_findings": total_findings,
        "findings_by_domain": domain_counts,
        "findings_by_severity": severity_totals,
        "registered_domains": [d["domain"] for d in engine.available_domains()],
        "knowledge_base": kb.get_statistics(),
    }
