# -*- coding: utf-8 -*-
"""
api_security_pro_routes.py — API 安全专业级深化 REST API（33 个端点）。

路由前缀: /api/v1/api-security-pro
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典模拟异步。

设计定位：仅用于经过授权的 API 安全评估，输出检测报告与修复建议。
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/api-security-pro", tags=["API安全专业级"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from api_security_pro.openapi_parser import OpenAPIProParser
    from api_security_pro.auth_authorization import AuthAuthorizationTester
    from api_security_pro.injection_tester import InjectionTester, INJECTION_PAYLOAD_LIBRARY
    from api_security_pro.business_logic import BusinessLogicDetector
    from api_security_pro.security_config import SecurityConfigChecker
    from api_security_pro.fuzz_engine import FuzzEngine, FUZZ_PAYLOAD_LIBRARY
    from api_security_pro.api_scan_workflow import (
        APISecurityProWorkflow, get_pro_workflow, WORKFLOW_STEPS,
    )
    _MOD_AVAILABLE = True
    logger.info("api_security_pro_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("api_security_pro_routes: load failed: %s", e)


# --------------------------------------------------------------------------- #
# 任务存储（内存字典模拟异步）
# --------------------------------------------------------------------------- #
_TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    task_id = uuid.uuid4().hex[:16]
    _TASKS[task_id] = {
        "task_id": task_id, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return task_id


def _finish_task(task_id: str, result: Any, error: Optional[str] = None) -> None:
    if task_id in _TASKS:
        t = _TASKS[task_id]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


def _get_task(task_id: str) -> Optional[Dict[str, Any]]:
    return _TASKS.get(task_id)


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _sanitize_unicode(obj: Any) -> Any:
    """递归清理数据中的无效Unicode代理对字符，防止UTF-8编码失败。"""
    if isinstance(obj, str):
        return obj.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _sanitize_unicode(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_unicode(item) for item in obj]
    if isinstance(obj, tuple):
        return tuple(_sanitize_unicode(item) for item in obj)
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _sanitize_unicode(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None, "error": _sanitize_unicode(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("API 安全专业级模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class ParseOpenAPIRequest(BaseModel):
    url: str = ""
    content: str = ""
    content_type: str = "json"


class AuthTestRequest(BaseModel):
    endpoints: List[Dict[str, Any]] = Field(default_factory=list)
    jwt_token: str = ""
    api_key: str = ""
    cookie_flags: Dict[str, bool] = Field(default_factory=dict)


class InjectionTestRequest(BaseModel):
    parameters: List[Dict[str, Any]] = Field(default_factory=list)
    options: Dict[str, Any] = Field(default_factory=dict)


class BusinessLogicRequest(BaseModel):
    endpoints: List[Dict[str, Any]] = Field(default_factory=list)
    options: Dict[str, Any] = Field(default_factory=dict)


class SecurityConfigRequest(BaseModel):
    response_headers: Dict[str, str] = Field(default_factory=dict)
    options: Dict[str, Any] = Field(default_factory=dict)


class FuzzRequest(BaseModel):
    parameters: List[Dict[str, Any]] = Field(default_factory=list)
    samples: List[Any] = Field(default_factory=list)
    options: Dict[str, Any] = Field(default_factory=dict)


class ScanRequest(BaseModel):
    openapi_url: str = ""
    openapi_content: str = ""
    content_type: str = "json"
    base_url: str = ""
    jwt_token: str = ""
    api_key: str = ""
    response_headers: Dict[str, str] = Field(default_factory=dict)
    sample_response: str = ""
    incremental: bool = False
    baseline_endpoints: List[str] = Field(default_factory=list)
    debug_mode: bool = False


# =========================================================================== #
# 1. OpenAPI 解析（5 个端点）
# =========================================================================== #
@router.post("/openapi/parse")
def openapi_parse(req: ParseOpenAPIRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("openapi_parse")
        parser = OpenAPIProParser()
        if req.url:
            result = parser.parse_from_url(req.url)
        elif req.content:
            result = parser.parse_from_string(req.content, req.content_type)
        else:
            return fail("必须提供 url 或 content")
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("openapi_parse error")
        return fail(f"解析失败: {e}", 500)


@router.get("/openapi/{task_id}/status")
def openapi_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok({"task_id": task_id, "status": t["status"], "kind": t["kind"],
                   "created_at": t["created_at"], "finished_at": t["finished_at"]})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/openapi/{task_id}/results")
def openapi_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/openapi/{task_id}/report")
def openapi_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t or t["status"] != "done":
            return fail("任务不存在或未完成", 404)
        parser = OpenAPIProParser()
        md = parser.get_report_markdown(t["result"])
        return ok({"task_id": task_id, "report_markdown": md})
    except Exception as e:
        return fail(f"报告生成失败: {e}", 500)


@router.get("/openapi/endpoints")
def openapi_endpoints():
    try:
        g = _guard()
        if g is not None:
            return g
        # 返回最近一次 parse 任务中的端点（若有）
        last = None
        for t in _TASKS.values():
            if t["kind"] == "openapi_parse" and t["status"] == "done":
                last = t
        if not last or not last.get("result"):
            return ok({"endpoints": [], "message": "请先调用 POST /openapi/parse"})
        eps = last["result"].get("endpoints", [])
        flat = [{"method": e["method"], "path": e["path"],
                 "operation_id": e.get("operation_id", ""),
                 "tags": e.get("tags", []),
                 "deprecated": e.get("deprecated", False)} for e in eps]
        return ok({"endpoints": flat, "total": len(flat)})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 2. 认证授权（5 个端点）
# =========================================================================== #
@router.post("/auth/test")
def auth_test(req: AuthTestRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("auth_test")
        tester = AuthAuthorizationTester()
        result = tester.run_tests(
            req.endpoints,
            {"jwt_token": req.jwt_token, "api_key": req.api_key,
             "cookie_flags": req.cookie_flags},
        )
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("auth_test error")
        return fail(f"测试失败: {e}", 500)


@router.get("/auth/{task_id}/status")
def auth_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok({"task_id": task_id, "status": t["status"], "kind": t["kind"],
                   "created_at": t["created_at"], "finished_at": t["finished_at"]})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/auth/{task_id}/results")
def auth_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/auth/{task_id}/report")
def auth_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t or t["status"] != "done":
            return fail("任务不存在或未完成", 404)
        r = t["result"]
        lines = ["# 认证授权测试报告", "", f"- 发现总数: {r.get('total_findings')}",
                 f"- 风险等级: {r.get('summary', {}).get('risk_level')}", "",
                 "## 按严重程度"]
        for s, c in (r.get("by_severity") or {}).items():
            lines.append(f"- {s}: {c}")
        lines += ["", "## 修复建议"]
        for rec in (r.get("recommendations") or [])[:15]:
            lines.append(f"- [{rec.get('category')}] {rec.get('action')}")
        return ok({"task_id": task_id, "report_markdown": "\n".join(lines)})
    except Exception as e:
        return fail(f"报告生成失败: {e}", 500)


@router.get("/auth/payloads")
def auth_payloads():
    try:
        g = _guard()
        if g is not None:
            return g
        tester = AuthAuthorizationTester()
        return ok(tester.get_payloads_reference())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 3. 注入测试（5 个端点）
# =========================================================================== #
@router.post("/injection/test")
def injection_test(req: InjectionTestRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("injection_test")
        tester = InjectionTester()
        result = tester.run_tests(req.parameters, req.options)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("injection_test error")
        return fail(f"测试失败: {e}", 500)


@router.get("/injection/{task_id}/status")
def injection_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok({"task_id": task_id, "status": t["status"], "kind": t["kind"]})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/injection/{task_id}/results")
def injection_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/injection/{task_id}/report")
def injection_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t or t["status"] != "done":
            return fail("任务不存在或未完成", 404)
        r = t["result"]
        lines = ["# 注入测试报告", "", f"- 发现总数: {r.get('total_findings')}",
                 f"- 可用 Payload: {r.get('payload_library_size')}",
                 f"- 风险等级: {r.get('summary', {}).get('risk_level')}", "",
                 "## 按类别"]
        for c, n in (r.get("by_category") or {}).items():
            lines.append(f"- {c}: {n}")
        lines += ["", "## 修复建议"]
        for rec in (r.get("recommendations") or [])[:15]:
            lines.append(f"- [{rec.get('category')}] {rec.get('action')}")
        return ok({"task_id": task_id, "report_markdown": "\n".join(lines)})
    except Exception as e:
        return fail(f"报告生成失败: {e}", 500)


@router.get("/injection/payloads")
def injection_payloads(category: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        tester = InjectionTester()
        return ok(tester.get_payloads(category))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 4. 业务逻辑（4 个端点）
# =========================================================================== #
@router.post("/business-logic/detect")
def business_logic_detect(req: BusinessLogicRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("business_logic")
        detector = BusinessLogicDetector()
        result = detector.detect(req.endpoints, req.options)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("business_logic_detect error")
        return fail(f"检测失败: {e}", 500)


@router.get("/business-logic/{task_id}/status")
def business_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok({"task_id": task_id, "status": t["status"], "kind": t["kind"]})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/business-logic/{task_id}/results")
def business_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/business-logic/{task_id}/report")
def business_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t or t["status"] != "done":
            return fail("任务不存在或未完成", 404)
        r = t["result"]
        lines = ["# 业务逻辑漏洞检测报告", "",
                 f"- 发现总数: {r.get('total_findings')}",
                 f"- 风险等级: {r.get('summary', {}).get('risk_level')}", "",
                 "## 按类别"]
        for c, n in (r.get("by_category") or {}).items():
            lines.append(f"- {c}: {n}")
        lines += ["", "## 修复建议"]
        for rec in (r.get("recommendations") or [])[:15]:
            lines.append(f"- [{rec.get('category')}] {rec.get('action')}")
        return ok({"task_id": task_id, "report_markdown": "\n".join(lines)})
    except Exception as e:
        return fail(f"报告生成失败: {e}", 500)


# =========================================================================== #
# 5. 安全配置（4 个端点）
# =========================================================================== #
@router.post("/security-config/check")
def security_config_check(req: SecurityConfigRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("security_config")
        checker = SecurityConfigChecker()
        result = checker.check(req.response_headers, req.options)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("security_config_check error")
        return fail(f"检查失败: {e}", 500)


@router.get("/security-config/{task_id}/status")
def config_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok({"task_id": task_id, "status": t["status"], "kind": t["kind"]})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/security-config/{task_id}/results")
def config_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/security-config/{task_id}/report")
def config_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t or t["status"] != "done":
            return fail("任务不存在或未完成", 404)
        r = t["result"]
        lines = ["# API 安全配置检查报告", "",
                 f"- 安全评分: {r.get('score')}/100 ({r.get('grade')})",
                 f"- 发现总数: {r.get('total_findings')}", "",
                 "## 加固建议"]
        for h in (r.get("hardening") or [])[:15]:
            lines.append(f"- [{h.get('priority')}][{h.get('category')}] {h.get('action')}")
        return ok({"task_id": task_id, "report_markdown": "\n".join(lines)})
    except Exception as e:
        return fail(f"报告生成失败: {e}", 500)


# =========================================================================== #
# 6. Fuzz 测试（5 个端点）
# =========================================================================== #
@router.post("/fuzz/run")
def fuzz_run(req: FuzzRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("fuzz")
        engine = FuzzEngine()
        result = engine.run(req.parameters, {"samples": req.samples, **req.options})
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("fuzz_run error")
        return fail(f"Fuzz 失败: {e}", 500)


@router.get("/fuzz/{task_id}/status")
def fuzz_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok({"task_id": task_id, "status": t["status"], "kind": t["kind"]})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/fuzz/{task_id}/results")
def fuzz_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/fuzz/{task_id}/report")
def fuzz_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t or t["status"] != "done":
            return fail("任务不存在或未完成", 404)
        r = t["result"]
        s = r.get("summary", {})
        lines = ["# API Fuzz 测试报告", "",
                 f"- 生成用例: {s.get('fuzz_cases')}",
                 f"- 可用 Payload: {s.get('payloads_available')}",
                 f"- 异常检测规则: {s.get('anomaly_rules')}", "",
                 "## 异常检测规则"]
        for f in (r.get("findings") or []):
            lines.append(f"- [{f.get('severity')}] {f.get('name')}: {f.get('description')}")
        return ok({"task_id": task_id, "report_markdown": "\n".join(lines)})
    except Exception as e:
        return fail(f"报告生成失败: {e}", 500)


@router.get("/fuzz/payloads")
def fuzz_payloads(category: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        engine = FuzzEngine()
        return ok(engine.get_payloads(category))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 7. 综合扫描（5 个端点）
# =========================================================================== #
@router.post("/scan/run")
def scan_run(req: ScanRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("scan")
        wf = get_pro_workflow()
        result = wf.run_scan({
            "scan_id": task_id,
            "openapi_url": req.openapi_url,
            "openapi_content": req.openapi_content,
            "content_type": req.content_type,
            "base_url": req.base_url,
            "jwt_token": req.jwt_token,
            "api_key": req.api_key,
            "response_headers": req.response_headers,
            "sample_response": req.sample_response,
            "incremental": req.incremental,
            "baseline_endpoints": req.baseline_endpoints,
            "debug_mode": req.debug_mode,
        })
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("scan_run error")
        return fail(f"扫描失败: {e}", 500)


@router.get("/scan/{task_id}/status")
def scan_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok({"task_id": task_id, "status": t["status"], "kind": t["kind"],
                   "created_at": t["created_at"], "finished_at": t["finished_at"]})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/scan/{task_id}/results")
def scan_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/scan/{task_id}/report")
def scan_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t or t["status"] != "done":
            return fail("任务不存在或未完成", 404)
        r = t["result"]
        agg = r.get("aggregate", {})
        rating = r.get("rating", {})
        lines = [
            "# API 安全综合扫描报告", "",
            f"- 扫描 ID: {r.get('scan_id')}",
            f"- 开始时间: {r.get('started_at')}",
            f"- 完成时间: {r.get('finished_at')}",
            f"- 风险等级: {rating.get('risk_level')}",
            f"- 风险评分: {rating.get('risk_score')}",
            f"- 总发现: {agg.get('total_findings')}", "",
            "## 工作流步骤",
        ]
        for s in r.get("workflow_steps", []):
            lines.append(f"- [{s.get('status')}] {s.get('step')}: {s.get('message')}")
        lines += ["", "## 风险分布"]
        for s, c in (agg.get("by_severity") or {}).items():
            lines.append(f"- {s}: {c}")
        lines += ["", "## 结论", r.get("conclusion", "")]
        return ok({"task_id": task_id, "report_markdown": "\n".join(lines)})
    except Exception as e:
        return fail(f"报告生成失败: {e}", 500)


@router.get("/scan/history")
def scan_history():
    try:
        g = _guard()
        if g is not None:
            return g
        wf = get_pro_workflow()
        return ok({"history": wf.list_scans(), "workflow_steps": WORKFLOW_STEPS})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)
