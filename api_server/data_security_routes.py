# -*- coding: utf-8 -*-
"""
data_security_routes.py — 数据安全与隐私保护 REST API（35 个端点）。

路由前缀: /api/v1/data-security
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典模拟异步。

设计定位：仅用于经过授权的数据安全治理，输出检测/评估报告与加固建议。
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

router = APIRouter(prefix="/api/v1/data-security", tags=["数据安全"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from data_security.data_classification import (
        DataClassifier, SENSITIVE_TYPES_LIBRARY, CLASSIFICATION_LEVELS,
    )
    from data_security.dlp_engine import DLPEngine, DLP_POLICY_LIBRARY
    from data_security.privacy_compliance import PrivacyComplianceAssessor, COMPLIANCE_FRAMEWORKS
    from data_security.encryption_key_management import (
        EncryptionKeyManager, CRYPTO_ALGORITHM_LIBRARY,
    )
    from data_security.access_control import DataAccessController, PRIVILEGE_RISK_LIBRARY
    from data_security.data_security_workflow import (
        DataSecurityWorkflow, get_security_workflow, SECURITY_WORKFLOW_STEPS,
    )
    _MOD_AVAILABLE = True
    logger.info("data_security_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("data_security_routes: load failed: %s", e)


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
    return JSONResponse({"success": False, "data": None,
                         "error": _sanitize_unicode(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("数据安全模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class ClassifyScanRequest(BaseModel):
    content: str = ""
    assets: List[Dict[str, Any]] = Field(default_factory=list)
    source: str = "inline_text"
    owner: str = "unknown"


class DLPScanRequest(BaseModel):
    content: str = ""
    channel: str = "email"
    context: Dict[str, Any] = Field(default_factory=dict)


class PrivacyAssessRequest(BaseModel):
    framework: str = "ALL"
    signals: Dict[str, Any] = Field(default_factory=dict)


class EncryptionCheckRequest(BaseModel):
    code_sample: str = ""
    declared_bits: int = 256
    algorithm: str = "AES"
    keys: List[Dict[str, Any]] = Field(default_factory=list)
    certificates: List[Dict[str, Any]] = Field(default_factory=list)
    tls: Dict[str, Any] = Field(default_factory=dict)
    assets: List[Dict[str, Any]] = Field(default_factory=list)


class AccessAuditRequest(BaseModel):
    users: List[Dict[str, Any]] = Field(default_factory=list)
    roles: List[Dict[str, Any]] = Field(default_factory=list)
    accounts: List[Dict[str, Any]] = Field(default_factory=list)
    logs: List[Dict[str, Any]] = Field(default_factory=list)
    samples: List[Dict[str, Any]] = Field(default_factory=list)


class AssessmentRunRequest(BaseModel):
    assets: List[Dict[str, Any]] = Field(default_factory=list)
    crypto_signals: Dict[str, Any] = Field(default_factory=dict)
    access_signals: Dict[str, Any] = Field(default_factory=dict)
    privacy_signals: Dict[str, Any] = Field(default_factory=dict)
    dlp_sample: str = ""


def _task_view(t: Dict[str, Any]) -> Dict[str, Any]:
    return {"task_id": t["task_id"], "status": t["status"], "kind": t["kind"],
            "created_at": t["created_at"], "finished_at": t["finished_at"]}


# =========================================================================== #
# 1. 数据分类分级（6 个端点）
# =========================================================================== #
@router.post("/classification/scan")
def classification_scan(req: ClassifyScanRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("classification")
        clf = DataClassifier()
        if req.assets:
            result = clf.scan_assets(req.assets)
        else:
            r = clf.scan_text(req.content, req.source, req.owner)
            result = {
                "scan_id": r["scan_id"], "assets_scanned": 1,
                "assets": [r.get("asset", {})],
                "level_distribution": {r.get("level", "public"): 1},
                "category_distribution": {}, "overall_level": r.get("level", "public"),
                "overall_level_name": r.get("level_name", "公开"),
                "total_sensitive_hits": r.get("total_hits", 0),
                "inline_hit_detail": {
                    "hits": r.get("hits", []), "distinct_types": r.get("distinct_types", 0),
                },
                "generated_at": r.get("scanned_at", ""),
            }
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("classification_scan error")
        return fail(f"分类分级扫描失败: {e}", 500)


@router.get("/classification/{task_id}/status")
def classification_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(_task_view(t))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/classification/{task_id}/results")
def classification_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/classification/{task_id}/report")
def classification_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t or t["status"] != "done":
            return fail("任务不存在或未完成", 404)
        md = DataClassifier().get_report_markdown(t["result"])
        return ok({"task_id": task_id, "report_markdown": md})
    except Exception as e:
        return fail(f"报告生成失败: {e}", 500)


@router.get("/classification/types")
def classification_types(category: Optional[str] = Query(default=None),
                         industry: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(DataClassifier().list_types(category, industry))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/classification/assets")
def classification_assets(level: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        clf = DataClassifier()
        assets = clf.list_assets()
        # 若无历史扫描，返回示例资产清单
        if not assets:
            assets = [
                {"asset_id": "demo1", "location": "db/table_customer", "owner": "数据平台",
                 "level": "confidential", "level_name": "机密",
                 "sensitive_types": ["手机号", "身份证"], "count": 2,
                 "encryption_status": "TDE", "access_control": "RBAC"},
                {"asset_id": "demo2", "location": "share/finance.xlsx", "owner": "财务",
                 "level": "top_secret", "level_name": "绝密",
                 "sensitive_types": ["合同金额", "银行卡"], "count": 2,
                 "encryption_status": "未加密", "access_control": "全员可读"},
            ]
        if level:
            assets = [a for a in assets if a.get("level") == level]
        return ok({"assets": assets, "total": len(assets),
                   "levels": CLASSIFICATION_LEVELS})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 2. DLP（6 个端点）
# =========================================================================== #
@router.post("/dlp/scan")
def dlp_scan(req: DLPScanRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("dlp")
        engine = DLPEngine()
        simulated = engine.simulate_policy(req.content, req.channel, req.context)
        result = {
            "simulation": simulated,
            "channel_monitor": engine.channel_monitor(),
            "watermark": engine.watermark_plan(req.channel,
                                               req.context.get("user", "unknown")),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("dlp_scan error")
        return fail(f"DLP 扫描失败: {e}", 500)


@router.get("/dlp/{task_id}/status")
def dlp_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(_task_view(t))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/dlp/{task_id}/results")
def dlp_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/dlp/{task_id}/report")
def dlp_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t or t["status"] != "done":
            return fail("任务不存在或未完成", 404)
        r = t["result"]
        sim = r.get("simulation", {})
        md = DLPEngine().get_report_markdown({
            "events": [{"severity": f["risk"], "alert_level": "P2",
                        "channel": "sim", "type": f["label"], "count": f["count"],
                        "block_suggestion": f["risk"] in ("critical", "high")}
                       for f in sim.get("content", {}).get("detected", [])],
            "uncovered": r.get("channel_monitor", {}).get("uncovered_channels", []),
            "generated_at": r.get("generated_at"),
        })
        return ok({"task_id": task_id, "report_markdown": md})
    except Exception as e:
        return fail(f"报告生成失败: {e}", 500)


@router.get("/dlp/policies")
def dlp_policies():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(DLPEngine().list_policies())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/dlp/events")
def dlp_events(severity: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        engine = DLPEngine()
        sample = "身份证110101199001011234 手机13812345678 银行卡6222021234567890123 password=abc123456"
        events = engine.generate_events(engine.detect_content(sample), "email")
        if severity:
            events = [e for e in events if e["severity"] == severity]
        return ok({"events": events, "total": len(events)})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 3. 隐私合规（6 个端点）
# =========================================================================== #
@router.post("/privacy/assess")
def privacy_assess(req: PrivacyAssessRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("privacy")
        assessor = PrivacyComplianceAssessor()
        result = assessor.assess(req.signals)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("privacy_assess error")
        return fail(f"隐私合规评估失败: {e}", 500)


@router.get("/privacy/{task_id}/status")
def privacy_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(_task_view(t))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/privacy/{task_id}/results")
def privacy_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/privacy/{task_id}/report")
def privacy_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t or t["status"] != "done":
            return fail("任务不存在或未完成", 404)
        md = PrivacyComplianceAssessor().get_report_markdown(t["result"])
        return ok({"task_id": task_id, "report_markdown": md})
    except Exception as e:
        return fail(f"报告生成失败: {e}", 500)


@router.get("/privacy/frameworks")
def privacy_frameworks():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(PrivacyComplianceAssessor().list_frameworks())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/privacy/dpia")
def privacy_dpia(scope: str = Query(default=""),
                 framework: str = Query(default="PIPL")):
    try:
        g = _guard()
        if g is not None:
            return g
        assessor = PrivacyComplianceAssessor()
        result = assessor.run_dpia(scope, {})
        result["framework"] = framework
        return ok(result)
    except Exception as e:
        return fail(f"DPIA 生成失败: {e}", 500)


# =========================================================================== #
# 4. 加密与密钥（6 个端点）
# =========================================================================== #
@router.post("/encryption/check")
def encryption_check(req: EncryptionCheckRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("encryption")
        mgr = EncryptionKeyManager()
        result = mgr.assess({
            "code_sample": req.code_sample,
            "declared_bits": req.declared_bits,
            "algorithm": req.algorithm,
            "keys": req.keys,
            "certificates": req.certificates,
            "tls": req.tls,
            "assets": req.assets,
        })
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("encryption_check error")
        return fail(f"加密检查失败: {e}", 500)


@router.get("/encryption/{task_id}/status")
def encryption_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(_task_view(t))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/encryption/{task_id}/results")
def encryption_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/encryption/{task_id}/report")
def encryption_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t or t["status"] != "done":
            return fail("任务不存在或未完成", 404)
        md = EncryptionKeyManager().get_report_markdown(t["result"])
        return ok({"task_id": task_id, "report_markdown": md})
    except Exception as e:
        return fail(f"报告生成失败: {e}", 500)


@router.get("/encryption/algorithms")
def encryption_algorithms():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(EncryptionKeyManager().list_algorithms())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/encryption/certificates")
def encryption_certificates():
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = EncryptionKeyManager()
        return ok(mgr.assess_certificates())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 5. 访问控制（6 个端点）
# =========================================================================== #
@router.post("/access/audit")
def access_audit(req: AccessAuditRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("access")
        ctrl = DataAccessController()
        result = ctrl.assess({
            "users": req.users, "roles": req.roles, "accounts": req.accounts,
            "logs": req.logs, "samples": req.samples,
        })
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("access_audit error")
        return fail(f"访问审计失败: {e}", 500)


@router.get("/access/{task_id}/status")
def access_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(_task_view(t))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/access/{task_id}/results")
def access_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/access/{task_id}/report")
def access_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t or t["status"] != "done":
            return fail("任务不存在或未完成", 404)
        md = DataAccessController().get_report_markdown(t["result"])
        return ok({"task_id": task_id, "report_markdown": md})
    except Exception as e:
        return fail(f"报告生成失败: {e}", 500)


@router.get("/access/matrix")
def access_matrix():
    try:
        g = _guard()
        if g is not None:
            return g
        ctrl = DataAccessController()
        return ok(ctrl.build_matrix())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/access/anomalies")
def access_anomalies():
    try:
        g = _guard()
        if g is not None:
            return g
        ctrl = DataAccessController()
        return ok(ctrl.list_anomalies())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 6. 综合评估（5 个端点）
# =========================================================================== #
@router.post("/assessment/run")
def assessment_run(req: AssessmentRunRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("assessment")
        wf = get_security_workflow()
        result = wf.run_assessment({
            "scan_id": task_id,
            "assets": req.assets,
            "crypto_signals": req.crypto_signals,
            "access_signals": req.access_signals,
            "privacy_signals": req.privacy_signals,
            "dlp_sample": req.dlp_sample,
        })
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("assessment_run error")
        return fail(f"综合评估失败: {e}", 500)


@router.get("/assessment/{task_id}/status")
def assessment_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(_task_view(t))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/assessment/{task_id}/results")
def assessment_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/assessment/{task_id}/report")
def assessment_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t or t["status"] != "done":
            return fail("任务不存在或未完成", 404)
        r = t["result"]
        rating = r.get("rating", {})
        agg = r.get("aggregate", {})
        lines = [
            "# 数据安全综合评估报告", "",
            f"- 评估 ID: {r.get('scan_id')}",
            f"- 开始: {r.get('started_at')}",
            f"- 完成: {r.get('finished_at')}",
            f"- 风险等级: {rating.get('risk_level')}",
            f"- 风险评分: {rating.get('risk_score')}",
            f"- 总发现: {agg.get('total_findings')}", "",
            "## 各模块得分",
            f"- 加密: {r.get('encryption', {}).get('score')} ({r.get('encryption', {}).get('grade')})",
            f"- 访问控制: {r.get('access', {}).get('score')} ({r.get('access', {}).get('grade')})",
            f"- 隐私合规: {r.get('privacy', {}).get('score')} ({r.get('privacy', {}).get('grade')})",
            f"- DLP 事件: {r.get('dlp', {}).get('events')}", "",
            "## 风险分布",
        ]
        for s, c in (agg.get("by_severity") or {}).items():
            lines.append(f"- {s}: {c}")
        lines += ["", "## 修复优先级"]
        for p in rating.get("top_priorities", [])[:15]:
            lines.append(f"- [{p['severity']}/{p['action']}] {p['title']}")
        lines += ["", "## 结论", r.get("conclusion", "")]
        return ok({"task_id": task_id, "report_markdown": "\n".join(lines)})
    except Exception as e:
        return fail(f"报告生成失败: {e}", 500)


@router.get("/assessment/history")
def assessment_history():
    try:
        g = _guard()
        if g is not None:
            return g
        wf = get_security_workflow()
        return ok({"history": wf.list_history(),
                   "workflow_steps": SECURITY_WORKFLOW_STEPS})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)
