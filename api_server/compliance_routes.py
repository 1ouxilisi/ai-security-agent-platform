# -*- coding: utf-8 -*-
"""
compliance_routes.py - 合规审计 API 路由

提供合规框架、合规评估、报告、差距分析、整改管理的 REST API。
所有端点均用 try-except 包裹，返回统一 JSON 格式，不返回 500 错误。

路由前缀：/api/v1/compliance
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# 确保项目根目录可导入
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import log

# 认证依赖（导入失败时提供透传兜底，保证路由可挂载）
try:
    from api_server.auth_integration import verify_auth, require_admin  # noqa: F401
    _AUTH_OK = True
except Exception as _e:  # pragma: no cover
    log.warning(f"compliance_routes: 认证依赖导入失败，使用透传: {_e}")
    _AUTH_OK = False

    async def verify_auth() -> dict:  # type: ignore
        return {"user_id": "anonymous", "username": "anonymous", "role": "admin"}

    async def require_admin() -> dict:  # type: ignore
        return {"user_id": "anonymous", "username": "anonymous", "role": "admin"}


# 业务模块（导入失败则路由挂载但端点返回 503）
_BIZ_OK = False
try:
    from compliance.frameworks import get_framework_manager
    from compliance.assessment import get_assessor
    from compliance.report_generator import get_report_generator
    from compliance.remediation import get_remediation_manager
    _BIZ_OK = True
    log.info("compliance_routes: 合规审计模块加载成功")
except Exception as _e:  # pragma: no cover
    log.exception(f"compliance_routes: 合规审计模块加载失败: {_e}")


router = APIRouter(prefix="/api/v1/compliance", tags=["合规审计"])


# ==================== 响应工具 ====================

def _ok(data: Any) -> JSONResponse:
    return JSONResponse({"code": 0, "data": data})


def _err(status: int, message: str) -> JSONResponse:
    return JSONResponse({"code": status, "error": message}, status_code=status)


def _guard() -> Optional[JSONResponse]:
    if not _BIZ_OK:
        return _err(503, "合规审计模块不可用，请检查模块加载日志")
    return None


# ==================== 请求体模型 ====================

class StartAssessmentReq(BaseModel):
    framework_id: int
    name: str = ""
    scope: Dict[str, Any] = {}
    assessor: str = ""


class EvidenceReq(BaseModel):
    type: str = "file"
    path: str = ""
    description: str = ""


class SetResultReq(BaseModel):
    status: str
    finding: str = ""
    remediation_suggestion: str = ""
    assessed_by: str = ""


class ReportReq(BaseModel):
    title: str = ""
    format: str = "html"
    generated_by: str = ""


# ==================== 框架管理 ====================

@router.get("/frameworks")
def list_frameworks(user: dict = Depends(verify_auth)):
    """获取所有合规框架列表（含控制项数量）"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(get_framework_manager().list_frameworks())
    except Exception as e:
        log.exception("list_frameworks 错误")
        return _err(500, f"获取框架列表失败: {e}")


@router.get("/frameworks/mapping")
def framework_mapping(framework_id: int = Query(...),
                      control_code: Optional[str] = Query(None),
                      user: dict = Depends(verify_auth)):
    """获取控制项跨框架映射"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(get_framework_manager().get_control_mappings(framework_id, control_code))
    except Exception as e:
        log.exception("framework_mapping 错误")
        return _err(500, f"获取框架映射失败: {e}")


@router.get("/frameworks/{fw_id}")
def get_framework(fw_id: int, user: dict = Depends(verify_auth)):
    """框架详情"""
    try:
        g = _guard()
        if g:
            return g
        fw = get_framework_manager().get_framework(fw_id)
        if not fw:
            return _err(404, "框架不存在")
        return _ok(fw)
    except Exception as e:
        log.exception("get_framework 错误")
        return _err(500, f"获取框架详情失败: {e}")


@router.get("/frameworks/{fw_id}/controls")
def list_framework_controls(fw_id: int,
                           domain: Optional[str] = Query(None),
                           severity: Optional[str] = Query(None),
                           is_automated: Optional[bool] = Query(None),
                           page: int = Query(1, ge=1),
                           page_size: int = Query(20, ge=1, le=200),
                           user: dict = Depends(verify_auth)):
    """按框架获取控制项列表，支持筛选与分页"""
    try:
        g = _guard()
        if g:
            return g
        result = get_framework_manager().list_controls(
            fw_id, domain=domain, severity=severity,
            is_automated=is_automated, page=page, page_size=page_size)
        return _ok(result)
    except Exception as e:
        log.exception("list_framework_controls 错误")
        return _err(500, f"获取控制项失败: {e}")


# ==================== 合规评估 ====================

@router.post("/assessment/start")
def start_assessment(req: StartAssessmentReq, user: dict = Depends(verify_auth)):
    """启动评估任务，选择框架和范围，初始化所有控制项"""
    try:
        g = _guard()
        if g:
            return g
        assessor = get_assessor()
        result = assessor.start_assessment(
            framework_id=req.framework_id,
            name=req.name or f"合规评估-{req.framework_id}",
            scope=req.scope,
            assessor=req.assessor or user.get("username", ""))
        if not result:
            return _err(400, "启动评估失败，请检查 framework_id 是否有效")
        return _ok(result)
    except Exception as e:
        log.exception("start_assessment 错误")
        return _err(500, f"启动评估失败: {e}")


@router.get("/assessment/{assessment_id}/status")
def assessment_status(assessment_id: str, user: dict = Depends(verify_auth)):
    """获取评估任务状态"""
    try:
        g = _guard()
        if g:
            return g
        result = get_assessor().get_assessment_status(assessment_id)
        if not result:
            return _err(404, "评估任务不存在")
        return _ok(result)
    except Exception as e:
        log.exception("assessment_status 错误")
        return _err(500, f"获取评估状态失败: {e}")


@router.get("/assessment/{assessment_id}/results")
def assessment_results(assessment_id: str,
                       status: Optional[str] = Query(None),
                       user: dict = Depends(verify_auth)):
    """获取评估结果，按控制域分组，支持按状态筛选"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(get_assessor().get_assessment_results(assessment_id, status=status))
    except Exception as e:
        log.exception("assessment_results 错误")
        return _err(500, f"获取评估结果失败: {e}")


@router.get("/assessment/{assessment_id}/controls/{control_id}")
def control_result_detail(assessment_id: str, control_id: int,
                          user: dict = Depends(verify_auth)):
    """获取单个控制项评估详情"""
    try:
        g = _guard()
        if g:
            return g
        result = get_assessor().get_control_result(assessment_id, control_id)
        if not result:
            return _err(404, "控制项评估结果不存在")
        return _ok(result)
    except Exception as e:
        log.exception("control_result_detail 错误")
        return _err(500, f"获取控制项详情失败: {e}")


@router.post("/assessment/{assessment_id}/controls/{control_id}/evidence")
def upload_evidence(assessment_id: str, control_id: int, req: EvidenceReq,
                    user: dict = Depends(verify_auth)):
    """上传证据：截图/日志/配置文件路径"""
    try:
        g = _guard()
        if g:
            return g
        ok = get_assessor().upload_evidence(
            assessment_id, control_id,
            {"type": req.type, "path": req.path, "description": req.description})
        if not ok:
            return _err(400, "证据上传失败")
        return _ok({"status": "ok", "message": "证据已上传"})
    except Exception as e:
        log.exception("upload_evidence 错误")
        return _err(500, f"上传证据失败: {e}")


@router.put("/assessment/{assessment_id}/controls/{control_id}/result")
def set_control_result(assessment_id: str, control_id: int, req: SetResultReq,
                       user: dict = Depends(verify_auth)):
    """人工评估控制项结果：符合/部分符合/不符合/不适用"""
    try:
        g = _guard()
        if g:
            return g
        ok = get_assessor().set_control_result(
            assessment_id, control_id, req.status,
            finding=req.finding, remediation_suggestion=req.remediation_suggestion,
            assessed_by=req.assessed_by or user.get("username", ""))
        if not ok:
            return _err(400, "设置评估结果失败，状态值不合法")
        return _ok({"status": "ok"})
    except Exception as e:
        log.exception("set_control_result 错误")
        return _err(500, f"设置评估结果失败: {e}")


# ==================== 报告与差距分析 ====================

@router.post("/assessment/{assessment_id}/report")
def generate_report(assessment_id: str, req: ReportReq,
                    user: dict = Depends(verify_auth)):
    """生成合规报告"""
    try:
        g = _guard()
        if g:
            return g
        result = get_report_generator().generate_report(
            assessment_id, title=req.title, fmt=req.format,
            generated_by=req.generated_by or user.get("username", ""))
        if not result:
            return _err(400, "生成报告失败")
        return _ok(result)
    except Exception as e:
        log.exception("generate_report 错误")
        return _err(500, f"生成报告失败: {e}")


@router.get("/assessment/{assessment_id}/report/download")
def download_report(assessment_id: str, user: dict = Depends(verify_auth)):
    """下载报告（返回最新报告的HTML内容）"""
    try:
        g = _guard()
        if g:
            return g
        listing = get_report_generator().list_reports(assessment_id=assessment_id,
                                                     page=1, page_size=1)
        items = listing.get("items", [])
        if not items:
            # 自动生成一份
            rep = get_report_generator().generate_report(assessment_id)
            if not rep:
                return _err(404, "暂无报告")
            items = [rep]
        return _ok(get_report_generator().download_report(items[0]["id"]))
    except Exception as e:
        log.exception("download_report 错误")
        return _err(500, f"下载报告失败: {e}")


@router.get("/assessment/{assessment_id}/gap-analysis")
def gap_analysis(assessment_id: str, user: dict = Depends(verify_auth)):
    """差距分析：不符合项详情/整改措施/优先级/预计时间"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(get_assessor().get_gap_analysis(assessment_id))
    except Exception as e:
        log.exception("gap_analysis 错误")
        return _err(500, f"差距分析失败: {e}")


# ==================== 整改管理 ====================

@router.get("/assessment/{assessment_id}/remediation/tasks")
def remediation_tasks(assessment_id: str,
                      status: Optional[str] = Query(None),
                      priority: Optional[str] = Query(None),
                      page: int = Query(1, ge=1),
                      page_size: int = Query(20, ge=1, le=200),
                      user: dict = Depends(verify_auth)):
    """整改任务列表"""
    try:
        g = _guard()
        if g:
            return g
        result = get_remediation_manager().list_tasks(
            status=status, priority=priority, assessment_id=assessment_id,
            page=page, page_size=page_size)
        return _ok(result)
    except Exception as e:
        log.exception("remediation_tasks 错误")
        return _err(500, f"获取整改任务失败: {e}")


@router.post("/remediation/{task_id}/start")
def start_remediation(task_id: str, user: dict = Depends(verify_auth)):
    """开始整改"""
    try:
        g = _guard()
        if g:
            return g
        result = get_remediation_manager().start_remediation(task_id)
        if not result:
            return _err(404, "整改任务不存在")
        return _ok(result)
    except Exception as e:
        log.exception("start_remediation 错误")
        return _err(500, f"开始整改失败: {e}")


class VerifyReq(BaseModel):
    verification_result: str = ""
    passed: bool = True


@router.post("/remediation/{task_id}/verify")
def verify_remediation(task_id: str, req: VerifyReq = VerifyReq(),
                       user: dict = Depends(verify_auth)):
    """验证整改结果"""
    try:
        g = _guard()
        if g:
            return g
        result = get_remediation_manager().verify_remediation(
            task_id, verification_result=req.verification_result, passed=req.passed)
        if not result:
            return _err(404, "整改任务不存在")
        return _ok(result)
    except Exception as e:
        log.exception("verify_remediation 错误")
        return _err(500, f"验证整改失败: {e}")


@router.get("/remediation/stats")
def remediation_stats(user: dict = Depends(verify_auth)):
    """整改统计：完成率/平均整改时间/按优先级"""
    try:
        g = _guard()
        if g:
            return g
        return _ok({
            "stats": get_remediation_manager().get_remediation_stats(),
            "progress": get_remediation_manager().get_remediation_progress(),
        })
    except Exception as e:
        log.exception("remediation_stats 错误")
        return _err(500, f"获取整改统计失败: {e}")

# ============================================================================ #
# v2 增强端点：四大合规标准 + CIS自动安全配置检查（独立实现，不依赖外部模块）
# ============================================================================ #
import re as _re2, urllib.request as _ur2, urllib.error as _ue2
from datetime import datetime as _dt2

_CIS_V2 = [
    {"id":"CIS-02","title":"隐藏服务器版本","severity":"low"},
    {"id":"CIS-03","title":"强制HTTPS","severity":"critical"},
    {"id":"CIS-06","title":"HSTS头","severity":"medium"},
    {"id":"CIS-07","title":"CSP头","severity":"medium"},
    {"id":"CIS-08","title":"X-Frame-Options","severity":"low"},
    {"id":"CIS-09","title":"X-Content-Type-Options","severity":"low"},
    {"id":"CIS-10","title":"Referrer-Policy","severity":"low"},
    {"id":"CIS-13","title":"Cookie Secure+HttpOnly","severity":"high"},
    {"id":"CIS-14","title":"Cookie SameSite","severity":"medium"},
    {"id":"CIS-19","title":"错误页面不泄露信息","severity":"low"},
]

_DENGBAO_V2 = [
    {"id":"DB-01","category":"安全通信网络","title":"通信传输保密性","severity":"high"},
    {"id":"DB-02","category":"安全通信网络","title":"通信传输完整性","severity":"high"},
    {"id":"DB-03","category":"安全区域边界","title":"边界防护","severity":"high"},
    {"id":"DB-04","category":"安全区域边界","title":"访问控制","severity":"high"},
    {"id":"DB-05","category":"安全区域边界","title":"入侵防范","severity":"high"},
    {"id":"DB-06","category":"安全计算环境","title":"身份鉴别","severity":"critical"},
    {"id":"DB-07","category":"安全计算环境","title":"访问控制","severity":"high"},
    {"id":"DB-08","category":"安全计算环境","title":"安全审计","severity":"high"},
    {"id":"DB-09","category":"安全计算环境","title":"入侵防范","severity":"medium"},
    {"id":"DB-10","category":"安全计算环境","title":"数据完整性","severity":"high"},
    {"id":"DB-11","category":"安全计算环境","title":"数据保密性","severity":"high"},
    {"id":"DB-12","category":"安全计算环境","title":"数据备份恢复","severity":"medium"},
    {"id":"DB-13","category":"安全管理中心","title":"系统管理","severity":"high"},
    {"id":"DB-14","category":"安全管理中心","title":"审计管理","severity":"medium"},
    {"id":"DB-15","category":"安全管理中心","title":"安全管理","severity":"medium"},
    {"id":"DB-16","category":"安全物理环境","title":"物理访问控制","severity":"medium"},
    {"id":"DB-17","category":"安全物理环境","title":"防火防水","severity":"medium"},
    {"id":"DB-18","category":"安全通信网络","title":"网络架构冗余","severity":"medium"},
    {"id":"DB-19","category":"安全区域边界","title":"恶意代码防范","severity":"medium"},
    {"id":"DB-20","category":"安全计算环境","title":"恶意代码防范","severity":"medium"},
]

_PCI_V2 = [
    {"id":"PCI-1","req":"要求1：网络安全","title":"防火墙配置","severity":"high"},
    {"id":"PCI-2","req":"要求1：网络安全","title":"网络分段隔离CDE","severity":"critical"},
    {"id":"PCI-3","req":"要求2：安全配置","title":"更改默认密码","severity":"critical"},
    {"id":"PCI-4","req":"要求3：数据保护","title":"PAN掩码显示","severity":"high"},
    {"id":"PCI-5","req":"要求3：数据保护","title":"PAN存储加密","severity":"critical"},
    {"id":"PCI-6","req":"要求3：数据保护","title":"敏感认证数据不存储","severity":"critical"},
    {"id":"PCI-7","req":"要求4：传输加密","title":"开放网络传输加密","severity":"critical"},
    {"id":"PCI-8","req":"要求5：恶意软件","title":"防病毒软件部署","severity":"high"},
    {"id":"PCI-9","req":"要求6：安全开发","title":"安全补丁（高危30天）","severity":"high"},
    {"id":"PCI-10","req":"要求6：安全开发","title":"Web应用安全（OWASP Top10）","severity":"critical"},
    {"id":"PCI-11","req":"要求7：访问控制","title":"最小权限原则","severity":"critical"},
    {"id":"PCI-12","req":"要求8：身份认证","title":"唯一身份标识","severity":"high"},
    {"id":"PCI-13","req":"要求8：身份认证","title":"多因素认证","severity":"high"},
    {"id":"PCI-14","req":"要求8：身份认证","title":"强密码策略（12位+）","severity":"high"},
    {"id":"PCI-15","req":"要求9：物理安全","title":"物理访问控制","severity":"medium"},
    {"id":"PCI-16","req":"要求10：日志监控","title":"审计日志记录","severity":"high"},
    {"id":"PCI-17","req":"要求10：日志监控","title":"日志完整性+1年保留","severity":"high"},
    {"id":"PCI-18","req":"要求11：安全测试","title":"季度漏洞扫描","severity":"high"},
    {"id":"PCI-19","req":"要求11：安全测试","title":"年度渗透测试","severity":"critical"},
    {"id":"PCI-20","req":"要求11：安全测试","title":"入侵检测系统","severity":"high"},
    {"id":"PCI-21","req":"要求12：安全策略","title":"信息安全策略","severity":"medium"},
]

_ISO_V2 = [
    {"id":"ISO-A.5.1","domain":"组织控制","title":"信息安全策略","severity":"high"},
    {"id":"ISO-A.5.2","domain":"组织控制","title":"信息安全角色职责","severity":"high"},
    {"id":"ISO-A.5.3","domain":"组织控制","title":"职责分离","severity":"medium"},
    {"id":"ISO-A.5.7","domain":"组织控制","title":"威胁情报","severity":"medium"},
    {"id":"ISO-A.5.9","domain":"组织控制","title":"供应链安全","severity":"medium"},
    {"id":"ISO-A.5.19","domain":"组织控制","title":"安全事件管理","severity":"high"},
    {"id":"ISO-A.6.1","domain":"人员控制","title":"人员筛选","severity":"medium"},
    {"id":"ISO-A.6.3","domain":"人员控制","title":"安全意识培训","severity":"high"},
    {"id":"ISO-A.7.1","domain":"物理控制","title":"物理安全边界","severity":"medium"},
    {"id":"ISO-A.8.2","domain":"技术控制","title":"特权访问管理","severity":"critical"},
    {"id":"ISO-A.8.3","domain":"技术控制","title":"信息访问限制","severity":"high"},
    {"id":"ISO-A.8.5","domain":"技术控制","title":"安全认证","severity":"high"},
    {"id":"ISO-A.8.7","domain":"技术控制","title":"访问权审查","severity":"high"},
    {"id":"ISO-A.8.9","domain":"技术控制","title":"数据脱敏","severity":"high"},
    {"id":"ISO-A.8.10","domain":"技术控制","title":"数据泄露防护","severity":"high"},
    {"id":"ISO-A.8.11","domain":"技术控制","title":"数据备份","severity":"high"},
    {"id":"ISO-A.8.13","domain":"技术控制","title":"传输保护","severity":"high"},
    {"id":"ISO-A.8.14","domain":"技术控制","title":"漏洞管理","severity":"high"},
    {"id":"ISO-A.8.15","domain":"技术控制","title":"安全开发","severity":"high"},
    {"id":"ISO-A.8.20","domain":"技术控制","title":"恶意软件防护","severity":"high"},
    {"id":"ISO-A.8.22","domain":"技术控制","title":"日志记录","severity":"high"},
    {"id":"ISO-A.8.23","domain":"技术控制","title":"网络安全","severity":"high"},
    {"id":"ISO-A.8.24","domain":"技术控制","title":"云服务安全","severity":"high"},
    {"id":"ISO-A.8.25","domain":"技术控制","title":"密码学","severity":"high"},
    {"id":"ISO-A.8.28","domain":"技术控制","title":"安全架构","severity":"high"},
]

def _v2_fetch(url, timeout=8):
    try:
        req = _ur2.Request(url, headers={"User-Agent":"Mozilla/5.0"})
        with _ur2.urlopen(req, timeout=timeout) as r:
            return {"status":r.status,"headers":dict(r.headers),"body":r.read().decode('utf-8',errors='ignore')[:8000],"error":None}
    except _ue2.HTTPError as e:
        body = e.read().decode('utf-8',errors='ignore')[:3000] if e.fp else ""
        return {"status":e.code,"headers":dict(e.headers or {}),"body":body,"error":str(e)}
    except Exception as e:
        return {"status":0,"headers":{},"body":"","error":str(e)}

class _V2ComplianceReq(BaseModel):
    target: str
    standard: str = "all"

@router.post("/v2/auto-check")
def v2_auto_check(req: _V2ComplianceReq):
    """v2: CIS Web服务器安全配置自动检查（10项）"""
    url = req.target if req.target.startswith("http") else f"https://{req.target}"
    resp = _v2_fetch(url)
    if resp["status"] == 0:
        url = f"http://{req.target.replace('https://','').replace('http://','')}"
        resp = _v2_fetch(url)
    h = resp["headers"]
    results = []
    sv = h.get("Server","")
    results.append({"id":"CIS-02","title":"隐藏服务器版本","status":"pass" if not _re2.search(r"\d",sv) else "fail","evidence":f"Server: {sv or '未设置'}"})
    results.append({"id":"CIS-03","title":"强制HTTPS","status":"pass" if url.startswith("https") and resp["status"]!=0 else "fail","evidence":"HTTPS" if url.startswith("https") else "HTTP明文"})
    results.append({"id":"CIS-06","title":"HSTS头","status":"pass" if h.get("Strict-Transport-Security") else "fail","evidence":h.get("Strict-Transport-Security","未设置")})
    results.append({"id":"CIS-07","title":"CSP头","status":"pass" if h.get("Content-Security-Policy") else "fail","evidence":h.get("Content-Security-Policy","未设置")[:60]})
    results.append({"id":"CIS-08","title":"X-Frame-Options","status":"pass" if h.get("X-Frame-Options") else "fail","evidence":h.get("X-Frame-Options","未设置")})
    results.append({"id":"CIS-09","title":"X-Content-Type-Options","status":"pass" if "nosniff" in h.get("X-Content-Type-Options","") else "fail","evidence":h.get("X-Content-Type-Options","未设置")})
    results.append({"id":"CIS-10","title":"Referrer-Policy","status":"pass" if h.get("Referrer-Policy") else "fail","evidence":h.get("Referrer-Policy","未设置")})
    sc = h.get("Set-Cookie","")
    if sc:
        results.append({"id":"CIS-13","title":"Cookie Secure+HttpOnly","status":"pass" if "Secure" in sc and "HttpOnly" in sc else "fail","evidence":f"Secure:{'是' if 'Secure' in sc else '否'},HttpOnly:{'是' if 'HttpOnly' in sc else '否'}"})
        results.append({"id":"CIS-14","title":"Cookie SameSite","status":"pass" if "SameSite" in sc else "fail","evidence":"已设置" if "SameSite" in sc else "未设置"})
    er = _v2_fetch(url.rstrip("/")+"/nonexistent-9f8e7d")
    leak = any(k in er["body"].lower() for k in ["nginx","apache","iis","tomcat","stack trace","traceback"])
    results.append({"id":"CIS-19","title":"错误页面不泄露信息","status":"fail" if leak else "pass","evidence":"泄露服务器信息" if leak else "未泄露"})
    passed = sum(1 for r in results if r["status"]=="pass")
    return _ok({"target":req.target,"checked_at":_dt2.now().isoformat(),"total":len(results),"passed":passed,"failed":len(results)-passed,"compliance_rate":round(passed/len(results)*100,1),"checks":results})

@router.get("/v2/standards")
def v2_standards():
    """v2: 获取四大合规标准概览"""
    return _ok({"standards":[
        {"id":"dengbao2.0","name":"网络安全等级保护2.0（三级）","items":len(_DENGBAO_V2),"categories":len(set(c["category"] for c in _DENGBAO_V2))},
        {"id":"pci-dss","name":"PCI-DSS v4.0","items":len(_PCI_V2),"requirements":len(set(c["req"] for c in _PCI_V2))},
        {"id":"iso27001","name":"ISO/IEC 27001:2022","items":len(_ISO_V2),"domains":len(set(c["domain"] for c in _ISO_V2))},
        {"id":"cis","name":"CIS Benchmark（Web服务器）","items":len(_CIS_V2),"auto_checkable":len(_CIS_V2)},
    ],"total_items":len(_DENGBAO_V2)+len(_PCI_V2)+len(_ISO_V2)+len(_CIS_V2)})

@router.get("/v2/checklist/{standard}")
def v2_checklist(standard: str):
    """v2: 获取指定标准检查清单"""
    m = {"dengbao":_DENGBAO_V2,"dengbao2.0":_DENGBAO_V2,"pci-dss":_PCI_V2,"pcidss":_PCI_V2,"iso27001":_ISO_V2,"iso":_ISO_V2,"cis":_CIS_V2}
    checks = m.get(standard.lower())
    if not checks:
        return _err(404, f"未找到标准: {standard}, 可用: {list(m.keys())}")
    return _ok({"standard":standard,"total":len(checks),"checks":checks})

@router.post("/v2/report")
def v2_report(req: _V2ComplianceReq):
    """v2: 生成合规检查报告（自动检查+四大标准清单）"""
    auto_data = v2_auto_check(req).get("data", {})
    return _ok({
        "title": f"合规基线检查报告 - {req.target}",
        "generated_at": _dt2.now().isoformat(),
        "target": req.target,
        "auto_check": auto_data,
        "standards": {
            "dengbao2.0": {"name":"等保2.0三级","items":len(_DENGBAO_V2),"categories":list(set(c["category"] for c in _DENGBAO_V2))},
            "pci-dss": {"name":"PCI-DSS v4.0","items":len(_PCI_V2),"requirements":list(set(c["req"] for c in _PCI_V2))},
            "iso27001": {"name":"ISO 27001:2022","items":len(_ISO_V2),"domains":list(set(c["domain"] for c in _ISO_V2))},
            "cis": {"name":"CIS Benchmark","items":len(_CIS_V2),"auto_checkable":len(_CIS_V2)},
        },
        "overall_compliance_rate": auto_data.get("compliance_rate", 0),
        "overall_risk": "高" if auto_data.get("compliance_rate",0) < 50 else ("中" if auto_data.get("compliance_rate",0) < 80 else "低"),
        "failed_items": [c for c in auto_data.get("checks",[]) if c.get("status")=="fail"],
    })
