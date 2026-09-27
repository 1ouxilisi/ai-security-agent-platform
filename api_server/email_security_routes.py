# -*- coding: utf-8 -*-
"""
email_security_routes.py — 邮件安全 REST API（第18轮升级方向1）。

路由前缀: /api/v1/email-security
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。

设计定位：仅用于经过授权的邮件安全运营（钓鱼/BEC/认证/附件/情报/仪表盘）。
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

router = APIRouter(prefix="/api/v1/email-security", tags=["邮件安全"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from email_security.phishing_detector import PhishingDetector
    from email_security.bec_detector import BECDetector
    from email_security.email_authentication import EmailAuthenticationSuite
    from email_security.attachment_sandbox import AttachmentSandbox
    from email_security.email_threat_intel import EmailThreatIntel
    from email_security.email_dashboard import EmailDashboard
    _MOD_AVAILABLE = True
    logger.info("email_security_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("email_security_routes: load failed: %s", e)


def _engines():
    return {
        "phishing": PhishingDetector(),
        "bec": BECDetector(),
        "auth": EmailAuthenticationSuite(),
        "sandbox": AttachmentSandbox(),
        "intel": EmailThreatIntel(),
        "dashboard": EmailDashboard(),
    }


# --------------------------------------------------------------------------- #
# 任务存储（内存字典）
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
# 统一响应 / _clean()
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    """递归清理控制字符与无效 Unicode。"""
    if isinstance(obj, str):
        out = []
        for ch in obj:
            if ord(ch) < 32 and ch not in "\n\r\t":
                continue
            out.append(ch)
        return "".join(out).encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_clean(v) for v in obj)
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("邮件安全模块不可用，请检查加载日志", 503)
    return None


def _task_view(t: Dict[str, Any]) -> Dict[str, Any]:
    return {"task_id": t["task_id"], "status": t["status"], "kind": t["kind"],
            "created_at": t["created_at"], "finished_at": t["finished_at"]}


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class PhishingScanReq(BaseModel):
    raw_email: str = ""
    from_addr: str = ""
    attachments: List[Dict[str, Any]] = Field(default_factory=list)


class UrlCheckReq(BaseModel):
    url: str = ""


class BECScanReq(BaseModel):
    email_text: str = ""
    meta: Dict[str, Any] = Field(default_factory=dict)


class RuleToggleReq(BaseModel):
    rule_id: str
    enabled: bool


class AuthCheckReq(BaseModel):
    signals: Dict[str, Any] = Field(default_factory=dict)


class SandboxReq(BaseModel):
    filename: str = "sample.bin"
    payload_b64: str = ""
    size_bytes: int = 0
    attachments: List[Dict[str, Any]] = Field(default_factory=list)


class IOCAddReq(BaseModel):
    bucket: str = "urls"
    entry: Dict[str, Any] = Field(default_factory=dict)


class IOCRemoveReq(BaseModel):
    bucket: str = "urls"
    value: str = ""


class IOCRmMatchReq(BaseModel):
    urls: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    senders: List[str] = Field(default_factory=list)


class IOCImportReq(BaseModel):
    format: str = "json"
    raw: str = ""


class AlertActionReq(BaseModel):
    action: str = "confirm"
    note: str = ""


class SimulationCreateReq(BaseModel):
    name: str = "新演练"
    template: str = "通用钓鱼模板"
    target_group: str = "全员"


# =========================================================================== #
# 1. 钓鱼检测（6 端点）
# =========================================================================== #
@router.post("/phishing/analyze")
def phishing_analyze(req: PhishingScanReq):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("phishing")
        det = PhishingDetector()
        result = det.detect(req.raw_email, req.attachments, req.from_addr)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("phishing_analyze error")
        return fail(f"钓鱼分析失败: {e}", 500)


@router.get("/phishing/{task_id}/status")
def phishing_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(_task_view(t))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/phishing/{task_id}/results")
def phishing_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/phishing/rules")
def phishing_rules():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(PhishingDetector().list_rules())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/phishing/sender-reputation")
def phishing_sender(email: str = Query(...)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(PhishingDetector().analyze_sender(email))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/phishing/url-check")
def phishing_url_check(req: UrlCheckReq):
    try:
        g = _guard()
        if g is not None:
            return g
        det = PhishingDetector()
        result = det.analyze_urls(req.url)
        return ok(result)
    except Exception as e:
        return fail(f"URL 检查失败: {e}", 500)


# =========================================================================== #
# 2. BEC 检测（6 端点）
# =========================================================================== #
@router.post("/bec/analyze")
def bec_analyze(req: BECScanReq):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("bec")
        result = BECDetector().detect(req.email_text, req.meta)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("bec_analyze error")
        return fail(f"BEC 分析失败: {e}", 500)


@router.get("/bec/{task_id}/status")
def bec_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(_task_view(t))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/bec/rules")
def bec_rules(category: Optional[str] = Query(default=None),
              enabled_only: bool = Query(default=False)):
    try:
        g = _guard()
        if g is not None:
            return g
        det = BECDetector()
        rules = det.list_rules(category, enabled_only)
        return ok({"rules": rules, "total": len(rules),
                   "categories": det.rule_categories()})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/bec/rules/toggle")
def bec_rules_toggle(req: RuleToggleReq):
    try:
        g = _guard()
        if g is not None:
            return g
        ok_flag = BECDetector().set_rule_enabled(req.rule_id, req.enabled)
        if not ok_flag:
            return fail("规则不存在", 404)
        return ok({"rule_id": req.rule_id, "enabled": req.enabled})
    except Exception as e:
        return fail(f"规则切换失败: {e}", 500)


@router.get("/bec/suppliers")
def bec_suppliers():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(BECDetector().supplier_watchlist())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/bec/personas")
def bec_personas():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(EmailThreatIntel().list_personas())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 3. 邮件认证（6 端点）
# =========================================================================== #
@router.post("/auth/check")
def auth_check(req: AuthCheckReq):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("auth")
        result = EmailAuthenticationSuite().run(req.signals)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("auth_check error")
        return fail(f"认证检查失败: {e}", 500)


@router.get("/auth/{task_id}/status")
def auth_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(_task_view(t))
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


@router.get("/auth/spf/parse")
def auth_spf(record: str = Query(...), sender_ip: str = Query("203.0.113.10"),
             mail_from: str = Query("user@example.com")):
    try:
        g = _guard()
        if g is not None:
            return g
        from email_security.email_authentication import SPFValidator
        return ok(SPFValidator().check(record, sender_ip, mail_from.split("@")[-1]))
    except Exception as e:
        return fail(f"SPF 解析失败: {e}", 500)


@router.get("/auth/dmarc/parse")
def auth_dmarc(record: str = Query(...)):
    try:
        g = _guard()
        if g is not None:
            return g
        from email_security.email_authentication import DMARCValidator
        return ok(DMARCValidator().parse(record))
    except Exception as e:
        return fail(f"DMARC 解析失败: {e}", 500)


@router.get("/auth/smtp-check")
def auth_smtp(host: str = Query(...)):
    try:
        g = _guard()
        if g is not None:
            return g
        from email_security.email_authentication import SMTPSecurityChecker
        return ok(SMTPSecurityChecker().check(host))
    except Exception as e:
        return fail(f"SMTP 检查失败: {e}", 500)


# =========================================================================== #
# 4. 附件沙箱（6 端点）
# =========================================================================== #
@router.post("/sandbox/analyze")
def sandbox_analyze(req: SandboxReq):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("sandbox")
        result = AttachmentSandbox().analyze(req.filename, req.payload_b64,
                                              req.attachments)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("sandbox_analyze error")
        return fail(f"沙箱分析失败: {e}", 500)


@router.get("/sandbox/{task_id}/results")
def sandbox_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/sandbox/yara-rules")
def sandbox_yara():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(AttachmentSandbox().list_yara_rules())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/sandbox/extract")
def sandbox_extract(req: SandboxReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(AttachmentSandbox().extract_suspicious(req.attachments or
                                                          [{"filename": req.filename}]))
    except Exception as e:
        return fail(f"可疑文件提取失败: {e}", 500)


@router.get("/sandbox/report/{task_id}")
def sandbox_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t or t["status"] != "done":
            return fail("任务不存在或未完成", 404)
        r = t["result"]
        lines = [
            "# 附件沙箱分析报告", "",
            f"- 文件: {r['static']['filename']}",
            f"- 类型: {r['static']['file_type']}",
            f"- 大小: {r['static']['size_bytes']} bytes",
            f"- MD5: {r['static']['hashes']['md5']}",
            f"- SHA256: {r['static']['hashes']['sha256']}", "",
            f"- 综合评分: {r['final_score']}",
            f"- 结论: {r['verdict_name']} ({r['verdict']})", "",
            "## YARA 命中",
        ]
        for h in r["yara"]["hits"]:
            lines.append(f"- [{h['severity']}] {h['name']}")
        lines += ["", "## 行为",
                  f"- 网络连接: {len(r['dynamic']['network'])}",
                  f"- 文件操作: {len(r['dynamic']['file_ops'])}",
                  f"- 注册表项: {len(r['dynamic']['registry'])}",
                  "", "## 建议"]
        for a in r["disposition_advice"]:
            lines.append(f"- {a}")
        return ok({"task_id": task_id, "report_markdown": "\n".join(lines)})
    except Exception as e:
        return fail(f"报告生成失败: {e}", 500)


@router.get("/sandbox/hash-db")
def sandbox_hash_db():
    try:
        g = _guard()
        if g is not None:
            return g
        from email_security.attachment_sandbox import MALWARE_HASH_DB
        return ok({"hashes": MALWARE_HASH_DB,
                   "total": len(MALWARE_HASH_DB)})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 5. 威胁情报（7 端点）
# =========================================================================== #
@router.get("/intel/iocs")
def intel_iocs(type: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(EmailThreatIntel().list_iocs(type))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/intel/iocs/add")
def intel_add(req: IOCAddReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(EmailThreatIntel().add_ioc(req.bucket, req.entry))
    except Exception as e:
        return fail(f"添加失败: {e}", 500)


@router.post("/intel/iocs/remove")
def intel_remove(req: IOCRemoveReq):
    try:
        g = _guard()
        if g is not None:
            return g
        removed = EmailThreatIntel().remove_ioc(req.bucket, req.value)
        return ok({"removed": removed, "value": req.value})
    except Exception as e:
        return fail(f"删除失败: {e}", 500)


@router.post("/intel/match")
def intel_match(req: IOCRmMatchReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(EmailThreatIntel().match(
            urls=req.urls, hashes=req.hashes, domains=req.domains,
            ips=req.ips, senders=req.senders))
    except Exception as e:
        return fail(f"匹配失败: {e}", 500)


@router.get("/intel/enrich")
def intel_enrich(value: str = Query(...), kind: str = Query("domain")):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(EmailThreatIntel().enrich(value, kind))
    except Exception as e:
        return fail(f"富化失败: {e}", 500)


@router.get("/intel/export")
def intel_export(format: str = Query("json")):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(EmailThreatIntel().export(format))
    except Exception as e:
        return fail(f"导出失败: {e}", 500)


@router.post("/intel/import")
def intel_import(req: IOCImportReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(EmailThreatIntel().import_iocs(req.format, req.raw))
    except Exception as e:
        return fail(f"导入失败: {e}", 500)


# =========================================================================== #
# 6. 运营仪表盘（7 端点）
# =========================================================================== #
@router.get("/dashboard/overview")
def dash_overview():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(EmailDashboard().overview())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/dashboard/mail-flow")
def dash_flow():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(EmailDashboard().mail_flow())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/dashboard/alerts")
def dash_alerts(status: Optional[str] = Query(default=None),
                type: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(EmailDashboard().list_alerts(status, type))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/dashboard/alerts/{alert_id}/action")
def dash_alert_action(alert_id: str, req: AlertActionReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(EmailDashboard().update_alert(alert_id, req.action, req.note))
    except Exception as e:
        return fail(f"告警操作失败: {e}", 500)


@router.get("/dashboard/trends")
def dash_trends():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(EmailDashboard().trends())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/dashboard/metrics")
def dash_metrics():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(EmailDashboard().metrics())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/dashboard/simulations")
def dash_simulations():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(EmailDashboard().list_simulations())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/dashboard/simulations")
def dash_simulation_create(req: SimulationCreateReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(EmailDashboard().create_simulation(req.name, req.template,
                                                     req.target_group))
    except Exception as e:
        return fail(f"创建演练失败: {e}", 500)


@router.get("/dashboard/simulations/{campaign_id}/report")
def dash_simulation_report(campaign_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(EmailDashboard().simulation_report(campaign_id))
    except Exception as e:
        return fail(f"生成报告失败: {e}", 500)
