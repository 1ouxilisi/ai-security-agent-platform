# -*- coding: utf-8 -*-
"""
cloud_security_real_routes.py — 真实云安全 REST API（60+ 端点）。

路由前缀: /api/v1/cloud-security-real
统一响应: {"success": bool, "data": ..., "error": ...}
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/cloud-security-real",
                   tags=["云安全真实版-方向3"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_OK = False
try:
    from cloud_security_real import (
        get_aws_checker, get_azure_checker, get_aliyun_checker,
        get_container_checker, get_cis_benchmark, get_real_orchestrator,
        get_real_dashboard, get_real_report_generator,
        detect_aws_status, detect_azure_status, detect_aliyun_status,
        detect_k8s_status, detect_docker_status, detect_scanner, scan_image,
        STAGES, AWS_INSTALL, AZURE_INSTALL, ALIYUN_INSTALL,
    )
    _ORCH = get_real_orchestrator()
    _DASH = get_real_dashboard()
    _RPT = get_real_report_generator()
    _OK = True
    logger.info("cloud_security_real_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("cloud_security_real_routes: load failed: %s", e)
    _ORCH = None  # type: ignore
    _DASH = None  # type: ignore
    _RPT = None  # type: ignore


def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return "".join(c for c in obj if c == "\n" or c == "\t" or ord(c) >= 32)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    if isinstance(obj, tuple):
        return [_clean(i) for i in obj]
    return obj


def ok(data: Any = None):
    return {"success": True, "data": _clean(data), "error": None}


def err(msg: str):
    return {"success": False, "data": None, "error": _clean(msg)}


def guard():
    if not _OK or _ORCH is None:
        return err("云安全真实版模块未加载")
    return None


# =========================================================================== #
# 0. 元信息 / 健康
# =========================================================================== #
@router.get("/meta")
def meta():
    g = guard()
    if g:
        return g
    return ok({"module": "cloud_security_real",
               "goal": "方向3 云安全真实化 6.5->8.5",
               "providers": ["aws", "azure", "aliyun"],
               "container": ["k8s", "docker", "trivy/grype"],
               "cis_frameworks": get_cis_benchmark().frameworks(),
               "stages": [{"key": k, "label": n, "progress": p}
                          for k, n, p in STAGES]})


@router.get("/health")
def health():
    return ok({"status": "up", "module_loaded": _OK})


# =========================================================================== #
# 1. 凭证 / SDK 状态
# =========================================================================== #
@router.get("/credential/status/{provider}")
def cred_status(provider: str):
    g = guard()
    if g:
        return g
    p = provider.lower()
    if p == "aws":
        return ok(detect_aws_status())
    if p == "azure":
        return ok(detect_azure_status())
    if p == "aliyun":
        return ok(detect_aliyun_status())
    if p == "k8s":
        return ok(detect_k8s_status())
    if p == "docker":
        return ok(detect_docker_status())
    return err(f"未知 provider: {provider}")


@router.get("/credential/matrix")
def cred_matrix():
    g = guard()
    if g:
        return g
    return ok({
        "aws": detect_aws_status(),
        "azure": detect_azure_status(),
        "aliyun": detect_aliyun_status(),
        "k8s": detect_k8s_status(),
        "docker": detect_docker_status(),
        "image_scanner": detect_scanner(),
    })


@router.get("/credential/guide/{provider}")
def cred_guide(provider: str):
    g = guard()
    if g:
        return g
    guides = {
        "aws": {"install": AWS_INSTALL,
                "config": "aws configure 或环境变量 AWS_ACCESS_KEY_ID / "
                          "AWS_SECRET_ACCESS_KEY / AWS_DEFAULT_REGION；建议只读审计角色"},
        "azure": {"install": AZURE_INSTALL,
                  "config": "az login 或 AZURE_TENANT_ID/AZURE_CLIENT_ID/"
                            "AZURE_CLIENT_SECRET/AZURE_SUBSCRIPTION_ID"},
        "aliyun": {"install": ALIYUN_INSTALL,
                   "config": "ALIBABA_CLOUD_ACCESS_KEY_ID / "
                             "ALIBABA_CLOUD_ACCESS_KEY_SECRET / "
                             "ALIBABA_CLOUD_REGION_ID"},
        "k8s": {"install": "pip install kubernetes",
                "config": "配置 KUBECONFIG 或 ~/.kube/config"},
        "docker": {"install": "pip install docker",
                   "config": "启动 Docker Desktop / dockerd"},
        "scanner": {"install": "brew install trivy  (或 grype)；"
                               "Windows: choco install trivy",
                    "config": "确保 trivy/grype 在 PATH"},
    }
    if provider.lower() not in guides:
        return err(f"未知 provider: {provider}")
    return ok({"provider": provider, **guides[provider.lower()]})


@router.get("/install/commands")
def install_commands():
    g = guard()
    if g:
        return g
    return ok({
        "aws": AWS_INSTALL, "azure": AZURE_INSTALL,
        "aliyun": ALIYUN_INSTALL,
        "k8s": "pip install kubernetes",
        "docker": "pip install docker",
        "scanner": "brew install trivy  # 或 choco install trivy",
    })


# =========================================================================== #
# 2. 真实 AWS 检查
# =========================================================================== #
@router.post("/aws/scan")
def aws_scan(services: Optional[List[str]] = Body(default=None),
             region: Optional[str] = Body(default=None)):
    g = guard()
    if g:
        return g
    try:
        return ok(get_aws_checker(region).run(services))
    except Exception as e:  # noqa: BLE001
        return err(f"AWS 扫描失败: {e}")


@router.post("/aws/iam")
def aws_iam(region: Optional[str] = Body(default=None)):
    g = guard()
    if g:
        return g
    try:
        return ok(get_aws_checker(region).check_iam().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/aws/s3")
def aws_s3(region: Optional[str] = Body(default=None)):
    g = guard()
    if g:
        return g
    try:
        return ok(get_aws_checker(region).check_s3().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/aws/ec2")
def aws_ec2(region: Optional[str] = Body(default=None)):
    g = guard()
    if g:
        return g
    try:
        return ok(get_aws_checker(region).check_ec2().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/aws/rds")
def aws_rds(region: Optional[str] = Body(default=None)):
    g = guard()
    if g:
        return g
    try:
        return ok(get_aws_checker(region).check_rds().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/aws/vpc")
def aws_vpc(region: Optional[str] = Body(default=None)):
    g = guard()
    if g:
        return g
    try:
        return ok(get_aws_checker(region).check_vpc().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/aws/cloudtrail")
def aws_cloudtrail(region: Optional[str] = Body(default=None)):
    g = guard()
    if g:
        return g
    try:
        return ok(get_aws_checker(region).check_cloudtrail().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/aws/guardduty")
def aws_guardduty(region: Optional[str] = Body(default=None)):
    g = guard()
    if g:
        return g
    try:
        return ok(get_aws_checker(region).check_guardduty().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/aws/config")
def aws_config(region: Optional[str] = Body(default=None)):
    g = guard()
    if g:
        return g
    try:
        return ok(get_aws_checker(region).check_config().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.get("/aws/services")
def aws_services():
    g = guard()
    if g:
        return g
    return ok(["iam", "s3", "ec2", "rds", "vpc",
               "cloudtrail", "guardduty", "config"])


# =========================================================================== #
# 3. 真实 Azure 检查
# =========================================================================== #
@router.post("/azure/scan")
def azure_scan(services: Optional[List[str]] = Body(default=None)):
    g = guard()
    if g:
        return g
    try:
        return ok(get_azure_checker().run(services))
    except Exception as e:  # noqa: BLE001
        return err(f"Azure 扫描失败: {e}")


@router.post("/azure/ad")
def azure_ad():
    g = guard()
    if g:
        return g
    try:
        return ok(get_azure_checker().check_ad().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/azure/storage")
def azure_storage():
    g = guard()
    if g:
        return g
    try:
        return ok(get_azure_checker().check_storage().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/azure/vm")
def azure_vm():
    g = guard()
    if g:
        return g
    try:
        return ok(get_azure_checker().check_vm().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/azure/sql")
def azure_sql():
    g = guard()
    if g:
        return g
    try:
        return ok(get_azure_checker().check_sql().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/azure/keyvault")
def azure_kv():
    g = guard()
    if g:
        return g
    try:
        return ok(get_azure_checker().check_keyvault().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/azure/securitycenter")
def azure_sc():
    g = guard()
    if g:
        return g
    try:
        return ok(get_azure_checker().check_security_center().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.get("/azure/services")
def azure_services():
    g = guard()
    if g:
        return g
    return ok(["ad", "storage", "vm", "sql", "keyvault", "securitycenter"])


# =========================================================================== #
# 4. 真实阿里云检查
# =========================================================================== #
@router.post("/aliyun/scan")
def aliyun_scan(services: Optional[List[str]] = Body(default=None),
                region: Optional[str] = Body(default=None)):
    g = guard()
    if g:
        return g
    try:
        return ok(get_aliyun_checker(region).run(services))
    except Exception as e:  # noqa: BLE001
        return err(f"阿里云扫描失败: {e}")


@router.post("/aliyun/ram")
def aliyun_ram(region: Optional[str] = Body(default=None)):
    g = guard()
    if g:
        return g
    try:
        return ok(get_aliyun_checker(region).check_ram().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/aliyun/oss")
def aliyun_oss(region: Optional[str] = Body(default=None)):
    g = guard()
    if g:
        return g
    try:
        return ok(get_aliyun_checker(region).check_oss().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/aliyun/ecs")
def aliyun_ecs(region: Optional[str] = Body(default=None)):
    g = guard()
    if g:
        return g
    try:
        return ok(get_aliyun_checker(region).check_ecs().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/aliyun/rds")
def aliyun_rds(region: Optional[str] = Body(default=None)):
    g = guard()
    if g:
        return g
    try:
        return ok(get_aliyun_checker(region).check_rds().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/aliyun/vpc")
def aliyun_vpc(region: Optional[str] = Body(default=None)):
    g = guard()
    if g:
        return g
    try:
        return ok(get_aliyun_checker(region).check_vpc().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/aliyun/actiontrail")
def aliyun_at(region: Optional[str] = Body(default=None)):
    g = guard()
    if g:
        return g
    try:
        return ok(get_aliyun_checker(region).check_actiontrail().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.get("/aliyun/services")
def aliyun_services():
    g = guard()
    if g:
        return g
    return ok(["ram", "oss", "ecs", "rds", "vpc", "actiontrail"])


# =========================================================================== #
# 5. 真实容器安全
# =========================================================================== #
@router.post("/container/k8s")
def container_k8s():
    g = guard()
    if g:
        return g
    try:
        from cloud_security_real.container_security_check import KubernetesChecker
        return ok(KubernetesChecker().run().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/container/docker")
def container_docker():
    g = guard()
    if g:
        return g
    try:
        from cloud_security_real.container_security_check import DockerChecker
        return ok(DockerChecker().run().to_dict())
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/container/run")
def container_run(kinds: Optional[List[str]] = Body(default=None),
                  scan_images: Optional[List[str]] = Body(default=None)):
    g = guard()
    if g:
        return g
    try:
        return ok(get_container_checker().run(kinds, scan_images))
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/container/scan-image")
def container_scan_image(image: str = Body(..., embed=True),
                         scanner: Optional[str] = Body(default=None)):
    g = guard()
    if g:
        return g
    try:
        return ok(scan_image(image, scanner))
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.get("/container/scanner-status")
def container_scanner_status():
    g = guard()
    if g:
        return g
    return ok(detect_scanner())


@router.get("/container/status")
def container_status():
    g = guard()
    if g:
        return g
    return ok({"k8s": detect_k8s_status(), "docker": detect_docker_status(),
               "scanner": detect_scanner()})


# =========================================================================== #
# 6. CIS 基线
# =========================================================================== #
@router.get("/cis/frameworks")
def cis_frameworks():
    g = guard()
    if g:
        return g
    return ok({"frameworks": get_cis_benchmark().frameworks()})


@router.get("/cis/{framework}/items")
def cis_items(framework: str):
    g = guard()
    if g:
        return g
    items = get_cis_benchmark().items(framework)
    if not items:
        return err(f"未知 CIS 框架: {framework}")
    return ok({"framework": framework, "count": len(items), "items": items})


@router.post("/cis/{framework}/evaluate")
def cis_evaluate(framework: str,
                 findings: Optional[List[Dict[str, Any]]] = Body(default=None)):
    g = guard()
    if g:
        return g
    try:
        return ok(get_cis_benchmark().evaluate(framework, findings or []))
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.post("/cis/evaluate-all")
def cis_evaluate_all(payload: Dict[str, List[Dict[str, Any]]] = Body(...)):
    g = guard()
    if g:
        return g
    try:
        return ok(get_cis_benchmark().evaluate_all(payload))
    except Exception as e:  # noqa: BLE001
        return err(str(e))


# =========================================================================== #
# 7. 任务编排
# =========================================================================== #
@router.post("/start")
def start_task(provider: str = Body(default="aws"),
               region: Optional[str] = Body(default=None),
               async_mode: bool = Body(default=True)):
    g = guard()
    if g:
        return g
    if async_mode:
        t = _ORCH.start_async(provider, region)
    else:
        t = _ORCH.run(provider, region)
    return ok(t.to_dict())


@router.get("/tasks")
def list_tasks():
    g = guard()
    if g:
        return g
    return ok({"tasks": _ORCH.list_tasks()})


@router.get("/task/{task_id}")
def task_detail(task_id: str):
    g = guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return err("task not found")
    return ok(t.to_dict())


@router.get("/task/{task_id}/status")
def task_status(task_id: str):
    g = guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return err("task not found")
    return ok({"task_id": task_id, "status": t.status,
               "stage": t.stage, "progress": t.progress,
               "log": t.log[-30:]})


@router.get("/task/{task_id}/result")
def task_result(task_id: str):
    g = guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return err("task not found")
    return ok(t.result)


@router.delete("/task/{task_id}")
def cancel_task(task_id: str):
    g = guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return err("task not found")
    t.status = "cancelled"
    return ok({"task_id": task_id, "status": "cancelled"})


# =========================================================================== #
# 8. 报告
# =========================================================================== #
@router.get("/report/{task_id}")
def get_report(task_id: str, fmt: str = Query(default="html")):
    g = guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return err("task not found")
    path = t.report_path
    content = ""
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:  # noqa: BLE001
        content = "(报告文件未找到)"
    return ok({"path": path, "format": fmt, "content": content})


@router.get("/report/list")
def report_list():
    g = guard()
    if g:
        return g
    import glob
    import os
    from cloud_security_real.real_report_generator import REPORTS_DIR
    files = sorted(glob.glob(os.path.join(REPORTS_DIR, "*.*")),
                   key=os.path.getmtime, reverse=True)
    return ok({"dir": REPORTS_DIR,
               "reports": [{"name": os.path.basename(f), "path": f}
                           for f in files[:50]]})


# =========================================================================== #
# 9. 仪表盘
# =========================================================================== #
@router.get("/dashboard/overview")
def dash_overview():
    g = guard()
    if g:
        return g
    return ok(_DASH.overview())


@router.get("/dashboard/credentials")
def dash_credentials():
    g = guard()
    if g:
        return g
    return ok(_DASH.credential_matrix())


@router.get("/dashboard/stages")
def dash_stages():
    g = guard()
    if g:
        return g
    return ok({"stages": [{"key": k, "label": n, "progress": p}
                          for k, n, p in STAGES]})


# =========================================================================== #
# 11. Findings 查询 / 服务目录 / 便捷入口
# =========================================================================== #
@router.get("/findings")
def list_findings(severity: Optional[str] = Query(default=None),
                  service: Optional[str] = Query(default=None),
                  limit: int = Query(default=200)):
    """汇总最近一次任务的 findings，可按严重度/服务过滤。"""
    g = guard()
    if g:
        return g
    tasks = _ORCH.list_tasks()
    pool: List[Dict[str, Any]] = []
    for t in tasks[:5]:
        cloud = (t.get("result") or {}).get("cloud") or {}
        pool.extend(cloud.get("findings", []))
    if service:
        pool = [f for f in pool if f.get("service") == service]
    if severity:
        pool = [f for f in pool if f.get("severity") == severity]
    return ok({"count": len(pool[:limit]), "findings": pool[:limit]})


@router.get("/findings/by-severity")
def findings_by_severity():
    g = guard()
    if g:
        return g
    tasks = _ORCH.list_tasks()
    sev: Dict[str, int] = {}
    for t in tasks[:5]:
        cloud = (t.get("result") or {}).get("cloud") or {}
        for f in cloud.get("findings", []):
            sev[f.get("severity", "info")] = sev.get(f.get("severity", "info"), 0) + 1
    return ok({"by_severity": sev})


@router.get("/services/catalog")
def services_catalog():
    g = guard()
    if g:
        return g
    return ok({
        "aws": ["iam", "s3", "ec2", "rds", "vpc",
                "cloudtrail", "guardduty", "config"],
        "azure": ["ad", "storage", "vm", "sql", "keyvault", "securitycenter"],
        "aliyun": ["ram", "oss", "ecs", "rds", "vpc", "actiontrail"],
        "container": ["k8s", "docker", "scan_image"],
        "cis": [fw["key"] for fw in get_cis_benchmark().frameworks()],
    })


@router.get("/task/{task_id}/log")
def task_log(task_id: str, limit: int = Query(default=200)):
    g = guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return err("task not found")
    return ok({"task_id": task_id, "log": t.log[-limit:]})


@router.post("/container/scan-images")
def container_scan_images(images: List[str] = Body(...)):
    """批量镜像扫描。"""
    g = guard()
    if g:
        return g
    out = [scan_image(img) for img in images]
    return ok({"results": out})


@router.post("/quick/{provider}")
def quick_all(provider: str, region: Optional[str] = Body(default=None)):
    """同步执行某云厂商全量检查（不生成报告，只返回结果）。"""
    g = guard()
    if g:
        return g
    p = provider.lower()
    try:
        if p == "aws":
            return ok(get_aws_checker(region).run())
        if p == "azure":
            return ok(get_azure_checker().run())
        if p == "aliyun":
            return ok(get_aliyun_checker(region).run())
        return err(f"未知 provider: {provider}")
    except Exception as e:  # noqa: BLE001
        return err(str(e))


@router.get("/dashboard/recent")
def dashboard_recent(limit: int = Query(default=10)):
    g = guard()
    if g:
        return g
    return ok({"tasks": _ORCH.list_tasks()[:limit]})


@router.get("/cis/{framework}/evaluate")
def cis_evaluate_get(framework: str):
    """GET 便捷入口：不带 findings，仅返回检查项元数据与空评估。"""
    g = guard()
    if g:
        return g
    try:
        return ok(get_cis_benchmark().evaluate(framework, []))
    except Exception as e:  # noqa: BLE001
        return err(str(e))


# =========================================================================== #
# 10. 单步快速触发
# =========================================================================== #
@router.post("/step/{provider}/{service}")
def step_quick(provider: str, service: str,
               region: Optional[str] = Body(default=None)):
    g = guard()
    if g:
        return g
    p = provider.lower()
    try:
        if p == "aws":
            ck = get_aws_checker(region)
            fn = {"iam": ck.check_iam, "s3": ck.check_s3,
                  "ec2": ck.check_ec2, "rds": ck.check_rds,
                  "vpc": ck.check_vpc, "cloudtrail": ck.check_cloudtrail,
                  "guardduty": ck.check_guardduty,
                  "config": ck.check_config}.get(service)
            if not fn:
                return err(f"未知 AWS 服务: {service}")
            return ok(fn().to_dict())
        if p == "azure":
            ck = get_azure_checker()
            fn = {"ad": ck.check_ad, "storage": ck.check_storage,
                  "vm": ck.check_vm, "sql": ck.check_sql,
                  "keyvault": ck.check_keyvault,
                  "securitycenter": ck.check_security_center}.get(service)
            if not fn:
                return err(f"未知 Azure 服务: {service}")
            return ok(fn().to_dict())
        if p == "aliyun":
            ck = get_aliyun_checker(region)
            fn = {"ram": ck.check_ram, "oss": ck.check_oss,
                  "ecs": ck.check_ecs, "rds": ck.check_rds,
                  "vpc": ck.check_vpc,
                  "actiontrail": ck.check_actiontrail}.get(service)
            if not fn:
                return err(f"未知阿里云服务: {service}")
            return ok(fn().to_dict())
        return err(f"未知 provider: {provider}")
    except Exception as e:  # noqa: BLE001
        return err(str(e))
