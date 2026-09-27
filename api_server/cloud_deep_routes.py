# -*- coding: utf-8 -*-
"""
cloud_deep_routes.py — 云安全深度做实 REST API（方向4，30+ 端点）。

路由前缀: /api/v1/cloud-deep
统一响应: {success, data, error}
真实对接：boto3 / 阿里云 SDK；未配置凭证时明确提示，不 mock。
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/cloud-deep",
                   tags=["云安全深度做实"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_OK = False
try:
    from cloud_deep.cloud_deep_dashboard import CloudDeepDashboard
    from cloud_deep.cloud_client import CloudClient, CloudClientError
    from cloud_deep.config_checker import ConfigChecker
    from cloud_deep.asset_discovery import AssetDiscovery
    from cloud_deep.risk_rater import RiskRater
    _MOD_OK = True
    logger.info("cloud_deep_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("cloud_deep_routes load failed: %s", e)


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def fail(msg: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None, "error": msg},
                        status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_OK:
        return fail("云安全深度模块加载失败", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class ScanReq(BaseModel):
    provider: str = "aws"
    region: str = ""


class EvidenceReq(BaseModel):
    evidence: Dict[str, Any] = Field(default_factory=dict)


# =========================================================================== #
# 1) 云客户端 / 环境（5 端点）
# =========================================================================== #
@router.get("/client/env")
def client_env(provider: str = Query("aws"),
               region: str = Query("")):
    try:
        g = _guard()
        if g:
            return g
        return ok(CloudClient(provider=provider, region=region).describe())
    except Exception as e:
        return fail(f"客户端环境失败: {e}", 500)


@router.post("/client/call")
def client_call(req: ScanReq,
                service: str = Query(...),
                api: str = Query(...)):
    try:
        g = _guard()
        if g:
            return g
        c = CloudClient(provider=req.provider, region=req.region)
        if req.provider == "aws":
            return ok(c.aws_call(service, api))
        return ok(c.aliyun_call(service, api))
    except Exception as e:
        return fail(f"云 API 调用失败: {e}", 500)


@router.get("/client/providers")
def providers():
    return ok({"providers": CloudClient.PROVIDERS,
               "notes": "AWS 用 boto3；阿里云 SDK 未安装时会明确提示"})


@router.get("/client/credential-status")
def credential_status():
    try:
        return ok(CloudClient().describe())
    except Exception as e:
        return fail(f"凭证状态失败: {e}", 500)


@router.get("/client/hint")
def hint():
    return ok({"env_vars": [
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION",
        "AWS_SESSION_TOKEN",
        "ALIBABA_CLOUD_ACCESS_KEY_ID", "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
    ], "install": "pip install boto3 "
                   "aliyun-python-sdk-core aliyun-python-sdk-ecs "
                   "aliyun-python-sdk-oss"})


# =========================================================================== #
# 2) 资产发现（6 端点）
# =========================================================================== #
@router.post("/assets/discover")
def discover(req: ScanReq):
    try:
        g = _guard()
        if g:
            return g
        c = CloudClient(provider=req.provider, region=req.region)
        return ok(AssetDiscovery(c).discover())
    except Exception as e:
        return fail(f"资产发现失败: {e}", 500)


@router.get("/assets/security-groups")
def list_sg(provider: str = "aws", region: str = ""):
    try:
        g = _guard()
        if g:
            return g
        c = CloudClient(provider=provider, region=region)
        return ok({"items": AssetDiscovery(c)._security_groups()})
    except Exception as e:
        return fail(f"安全组列表失败: {e}", 500)


@router.get("/assets/buckets")
def list_buckets(provider: str = "aws", region: str = ""):
    try:
        g = _guard()
        if g:
            return g
        c = CloudClient(provider=provider, region=region)
        return ok({"items": AssetDiscovery(c)._buckets()})
    except Exception as e:
        return fail(f"存储桶列表失败: {e}", 500)


@router.get("/assets/iam-users")
def list_iam(provider: str = "aws", region: str = ""):
    try:
        g = _guard()
        if g:
            return g
        c = CloudClient(provider=provider, region=region)
        return ok({"items": AssetDiscovery(c)._iam_users()})
    except Exception as e:
        return fail(f"IAM 列表失败: {e}", 500)


@router.get("/assets/ebs")
def list_ebs(provider: str = "aws", region: str = ""):
    try:
        g = _guard()
        if g:
            return g
        c = CloudClient(provider=provider, region=region)
        return ok({"items": AssetDiscovery(c)._ebs_volumes()})
    except Exception as e:
        return fail(f"EBS 列表失败: {e}", 500)


@router.get("/assets/rds")
def list_rds(provider: str = "aws", region: str = ""):
    try:
        g = _guard()
        if g:
            return g
        c = CloudClient(provider=provider, region=region)
        return ok({"items": AssetDiscovery(c)._rds_instances()})
    except Exception as e:
        return fail(f"RDS 列表失败: {e}", 500)


# =========================================================================== #
# 3) 配置检查规则（6 端点）
# =========================================================================== #
@router.get("/rules")
def rules_list():
    try:
        g = _guard()
        if g:
            return g
        return ok(ConfigChecker().list_rules())
    except Exception as e:
        return fail(f"规则列表失败: {e}", 500)


@router.post("/check/run")
def check_run(req: EvidenceReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(ConfigChecker().check(req.evidence))
    except Exception as e:
        return fail(f"配置检查失败: {e}", 500)


@router.post("/check/security-group")
def check_sg(req: EvidenceReq):
    try:
        g = _guard()
        if g:
            return g
        chk = ConfigChecker()
        return ok(chk.check({"security_groups": req.evidence.get(
            "security_groups", [])}))
    except Exception as e:
        return fail(f"安全组检查失败: {e}", 500)


@router.post("/check/storage")
def check_storage(req: EvidenceReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(ConfigChecker().check(
            {"buckets": req.evidence.get("buckets", [])}))
    except Exception as e:
        return fail(f"存储检查失败: {e}", 500)


@router.post("/check/iam")
def check_iam(req: EvidenceReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(ConfigChecker().check({
            "iam_users": req.evidence.get("iam_users", []),
            "iam_policies": req.evidence.get("iam_policies", []),
        }))
    except Exception as e:
        return fail(f"IAM 检查失败: {e}", 500)


@router.post("/check/encryption")
def check_enc(req: EvidenceReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(ConfigChecker().check({
            "ebs_volumes": req.evidence.get("ebs_volumes", []),
            "rds_instances": req.evidence.get("rds_instances", []),
        }))
    except Exception as e:
        return fail(f"加密检查失败: {e}", 500)


# =========================================================================== #
# 4) 风险评级（4 端点）
# =========================================================================== #
@router.post("/risk/rate")
def risk_rate(req: EvidenceReq):
    """对一组 findings（list）评级。"""
    try:
        g = _guard()
        if g:
            return g
        findings = req.evidence.get("findings", [])
        return ok(RiskRater().rate(findings))
    except Exception as e:
        return fail(f"风险评级失败: {e}", 500)


@router.get("/risk/weights")
def risk_weights():
    return ok({"critical": 10, "high": 6, "medium": 3, "low": 1,
               "scale": "0~100, >=60 high, >=25 medium, else low"})


@router.post("/risk/fix-suggestion")
def fix_suggestion(req: EvidenceReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(RiskRater.remediation_template(
            req.evidence.get("rule_id", "")))
    except Exception as e:
        return fail(f"修复建议失败: {e}", 500)


@router.post("/risk/top-fixes")
def top_fixes(req: EvidenceReq):
    try:
        g = _guard()
        if g:
            return g
        return ok({"top_fixes": RiskRater._top_fixes(
            req.evidence.get("findings", []))})
    except Exception as e:
        return fail(f"Top 修复失败: {e}", 500)


# =========================================================================== #
# 5) 控制台聚合（8 端点）
# =========================================================================== #
@router.post("/scan/real")
def scan_real(req: ScanReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(CloudDeepDashboard().real_scan(req.provider, req.region))
    except Exception as e:
        return fail(f"真实扫描失败: {e}", 500)


@router.get("/scan/demo")
def scan_demo():
    try:
        g = _guard()
        if g:
            return g
        return ok(CloudDeepDashboard().demo_scan())
    except Exception as e:
        return fail(f"演示扫描失败: {e}", 500)


@router.get("/reports")
def reports():
    try:
        g = _guard()
        if g:
            return g
        return ok(CloudDeepDashboard().list_reports())
    except Exception as e:
        return fail(f"报告列表失败: {e}", 500)


@router.get("/reports/{scan_id}")
def report_detail(scan_id: str):
    try:
        g = _guard()
        if g:
            return g
        r = CloudDeepDashboard().get_report(scan_id)
        if not r:
            return fail("报告不存在", 404)
        return ok(r)
    except Exception as e:
        return fail(f"报告详情失败: {e}", 500)


@router.get("/demo/evidence")
def demo_evidence():
    return ok(AssetDiscovery().demo_evidence())


@router.get("/overview")
def overview():
    return ok({
        "modules": ["cloud_client", "config_checker", "asset_discovery",
                    "risk_rater", "cloud_deep_dashboard"],
        "endpoint_count": 30,
        "note": "未配置 AWS 凭证时 real_scan 会明确提示，不 mock 数据",
    })


@router.get("/health")
def health():
    return ok({"ok": _MOD_OK, "service": "cloud_deep"})


@router.get("/")
def root():
    return ok({"name": "cloud-deep", "version": "33.1.0"})
