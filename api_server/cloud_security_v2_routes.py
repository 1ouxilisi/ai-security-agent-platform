# -*- coding: utf-8 -*-
"""
cloud_security_v2_routes.py - 云安全 V2 REST API（第11轮深化模块）。

路由前缀：/api/v1/cloud-v2
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 包裹，不返回 500。
任务用内存字典模拟异步任务（task_id -> status/results）。
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from utils.logger import log  # type: ignore
except Exception:  # pragma: no cover
    import logging as log  # type: ignore

try:
    from cloud_security.aws_audit import AWSAudit, create_aws_audit
    from cloud_security.azure_audit import AzureAudit, create_azure_audit
    from cloud_security.aliyun_audit import AliyunAudit, create_aliyun_audit
    from cloud_security.gcp_audit import GCPAudit, create_gcp_audit
    from cloud_security.container_scanner import ContainerScanner
    from cloud_security.k8s_security import K8sSecurityAudit, create_k8s_audit
    from cloud_security.cloud_asset_discovery import CloudAssetDiscovery
    from cloud_security.cloud_threat_detection import CloudThreatDetection
    _MODULES_OK = True
except Exception as _e:  # pragma: no cover
    log.warning("cloud_security_v2_routes: 模块导入失败: %s", _e)
    _MODULES_OK = False


router = APIRouter(prefix="/api/v1/cloud-v2", tags=["云安全V2"])


# ==================== 响应工具 ====================

def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def _fail(err: str, data: Any = None) -> JSONResponse:
    return JSONResponse({"success": False, "data": data, "error": err})


# ==================== 内存任务存储 ====================
# task_id -> {"status": pending/running/success/failed, "type": ..., "result": ..., "created_at": ...}
TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(task_type: str) -> str:
    tid = f"{task_type}-{uuid.uuid4().hex[:12]}"
    TASKS[tid] = {
        "task_id": tid, "type": task_type,
        "status": "pending", "result": None, "error": None,
        "created_at": datetime.now().isoformat(),
    }
    return tid


def _get_task(task_id: str) -> Optional[Dict[str, Any]]:
    return TASKS.get(task_id)


# ==================== 请求模型 ====================

class CloudAuditReq(BaseModel):
    credentials: Dict[str, str] = {}
    region: str = "cn-north-1"
    categories: Optional[List[str]] = None
    subscription_id: Optional[str] = None   # Azure
    project_id: Optional[str] = None        # GCP
    kubeconfig: Optional[str] = None        # K8s
    account_id: Optional[str] = None


class ContainerScanReq(BaseModel):
    image: str
    scan_types: Optional[List[str]] = None
    tool: str = "auto"


class AssetDiscoveryReq(BaseModel):
    accounts: Optional[List[Dict[str, str]]] = None


class ThreatDetectReq(BaseModel):
    detection_types: Optional[List[str]] = None
    time_window_hours: int = 24


# ==================== 异步执行器（同步模拟） ====================

async def _run_task(task_id: str, fn) -> None:
    """在线程/异步上下文中执行任务，更新 TASKS。"""
    task = TASKS.get(task_id)
    if not task:
        return
    task["status"] = "running"
    try:
        # 给事件循环一个喘息机会
        await asyncio.sleep(0)
        result = fn()
        task["status"] = "success"
        task["result"] = result
    except Exception as e:  # pragma: no cover
        task["status"] = "failed"
        task["error"] = str(e)
    finally:
        task["finished_at"] = datetime.now().isoformat()


# ==================== AWS (5 个) ====================

@router.post("/aws/audit", summary="启动 AWS 配置检查")
async def aws_audit(req: CloudAuditReq):
    try:
        tid = _new_task("aws-audit")

        def _job():
            a = create_aws_audit(credentials=req.credentials,
                                 region=req.region,
                                 categories=req.categories)
            return {"audit": a.run_audit(), "report": a.generate_report()}

        asyncio.create_task(_run_task(tid, _job))
        return _ok({"task_id": tid, "status": "pending"})
    except Exception as e:
        log.exception("aws audit 启动失败: %s", e)
        return _fail(f"启动失败: {e}")


@router.get("/aws/{task_id}/status", summary="AWS 任务状态")
async def aws_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"],
                    "error": t.get("error"), "created_at": t["created_at"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/aws/{task_id}/results", summary="AWS 检查结果")
async def aws_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", data=t)
        return _ok(t["result"]["audit"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/aws/{task_id}/report", summary="AWS 检查报告")
async def aws_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", data=t)
        return _ok(t["result"]["report"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/aws/rules", summary="AWS CIS 规则列表")
async def aws_rules(category: Optional[str] = Query(None)):
    try:
        a = create_aws_audit()
        return _ok({"rules": a.list_rules(category),
                    "categories": a.CATEGORY_NAMES,
                    "total": len(a.RULES)})
    except Exception as e:
        return _fail(f"查询失败: {e}")


# ==================== Azure (4 个) ====================

@router.post("/azure/audit", summary="启动 Azure 配置检查")
async def azure_audit(req: CloudAuditReq):
    try:
        tid = _new_task("azure-audit")

        def _job():
            a = create_azure_audit(credentials=req.credentials,
                                   subscription_id=req.subscription_id or "",
                                   categories=req.categories)
            return {"audit": a.run_audit(), "report": a.generate_report()}

        asyncio.create_task(_run_task(tid, _job))
        return _ok({"task_id": tid, "status": "pending"})
    except Exception as e:
        return _fail(f"启动失败: {e}")


@router.get("/azure/{task_id}/status", summary="Azure 任务状态")
async def azure_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t.get("error")})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/azure/{task_id}/results", summary="Azure 检查结果")
async def azure_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", data=t)
        return _ok(t["result"]["audit"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/azure/{task_id}/report", summary="Azure 检查报告")
async def azure_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", data=t)
        return _ok(t["result"]["report"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


# ==================== 阿里云 (4 个) ====================

@router.post("/aliyun/audit", summary="启动阿里云配置检查")
async def aliyun_audit(req: CloudAuditReq):
    try:
        tid = _new_task("aliyun-audit")

        def _job():
            a = create_aliyun_audit(credentials=req.credentials,
                                     region=req.region,
                                     categories=req.categories)
            return {"audit": a.run_audit(), "report": a.generate_report()}

        asyncio.create_task(_run_task(tid, _job))
        return _ok({"task_id": tid, "status": "pending"})
    except Exception as e:
        return _fail(f"启动失败: {e}")


@router.get("/aliyun/{task_id}/status", summary="阿里云任务状态")
async def aliyun_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t.get("error")})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/aliyun/{task_id}/results", summary="阿里云检查结果")
async def aliyun_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", data=t)
        return _ok(t["result"]["audit"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/aliyun/{task_id}/report", summary="阿里云检查报告")
async def aliyun_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", data=t)
        return _ok(t["result"]["report"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


# ==================== GCP (4 个) ====================

@router.post("/gcp/audit", summary="启动 GCP 配置检查")
async def gcp_audit(req: CloudAuditReq):
    try:
        tid = _new_task("gcp-audit")

        def _job():
            a = create_gcp_audit(credentials=req.credentials,
                                 project_id=req.project_id or "",
                                 categories=req.categories)
            return {"audit": a.run_audit(), "report": a.generate_report()}

        asyncio.create_task(_run_task(tid, _job))
        return _ok({"task_id": tid, "status": "pending"})
    except Exception as e:
        return _fail(f"启动失败: {e}")


@router.get("/gcp/{task_id}/status", summary="GCP 任务状态")
async def gcp_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t.get("error")})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/gcp/{task_id}/results", summary="GCP 检查结果")
async def gcp_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", data=t)
        return _ok(t["result"]["audit"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/gcp/{task_id}/report", summary="GCP 检查报告")
async def gcp_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", data=t)
        return _ok(t["result"]["report"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


# ==================== 容器扫描 (4 个) ====================

@router.post("/container/scan", summary="启动容器镜像扫描")
async def container_scan(req: ContainerScanReq):
    try:
        tid = _new_task("container-scan")

        def _job():
            s = ContainerScanner(image=req.image, scan_types=req.scan_types, tool=req.tool)
            return {"scan": s.run_scan(), "report": s.generate_report()}

        asyncio.create_task(_run_task(tid, _job))
        return _ok({"task_id": tid, "status": "pending"})
    except Exception as e:
        return _fail(f"启动失败: {e}")


@router.get("/container/{task_id}/status", summary="容器扫描状态")
async def container_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t.get("error")})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/container/{task_id}/results", summary="容器扫描结果")
async def container_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", data=t)
        return _ok(t["result"]["scan"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/container/{task_id}/report", summary="容器扫描报告")
async def container_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", data=t)
        return _ok(t["result"]["report"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


# ==================== K8s (4 个) ====================

@router.post("/k8s/audit", summary="启动 K8s 安全检查")
async def k8s_audit(req: CloudAuditReq):
    try:
        tid = _new_task("k8s-audit")

        def _job():
            a = create_k8s_audit(kubeconfig=req.kubeconfig, categories=req.categories)
            return {"audit": a.run_audit(), "report": a.generate_report()}

        asyncio.create_task(_run_task(tid, _job))
        return _ok({"task_id": tid, "status": "pending"})
    except Exception as e:
        return _fail(f"启动失败: {e}")


@router.get("/k8s/{task_id}/status", summary="K8s 任务状态")
async def k8s_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t.get("error")})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/k8s/{task_id}/results", summary="K8s 检查结果")
async def k8s_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", data=t)
        return _ok(t["result"]["audit"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/k8s/{task_id}/report", summary="K8s 检查报告")
async def k8s_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", data=t)
        return _ok(t["result"]["report"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


# ==================== 云资产 (6 个) ====================

@router.post("/asset/discovery", summary="启动云资产发现")
async def asset_discovery(req: AssetDiscoveryReq):
    try:
        tid = _new_task("asset-discovery")

        def _job():
            d = CloudAssetDiscovery(accounts=req.accounts)
            return {"discovery": d.discover(), "report": d.generate_report()}

        asyncio.create_task(_run_task(tid, _job))
        return _ok({"task_id": tid, "status": "pending"})
    except Exception as e:
        return _fail(f"启动失败: {e}")


@router.get("/asset/{task_id}/status", summary="资产发现状态")
async def asset_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t.get("error")})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/asset/{task_id}/results", summary="资产发现结果")
async def asset_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", data=t)
        return _ok(t["result"]["discovery"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/asset/list", summary="资产列表（直接查询最近一次）")
async def asset_list(group: Optional[str] = Query(None),
                    provider: Optional[str] = Query(None),
                    risk_level: Optional[str] = Query(None),
                    page: int = Query(1, ge=1),
                    page_size: int = Query(20, ge=1, le=200)):
    try:
        d = CloudAssetDiscovery()
        # 直接生成一份
        d.discover()
        return _ok(d.list_assets(group=group, provider=provider,
                                 risk_level=risk_level,
                                 page=page, page_size=page_size))
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/asset/changes", summary="资产变更")
async def asset_changes():
    try:
        d = CloudAssetDiscovery()
        r = d.discover()
        return _ok(r.get("changes", []))
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/asset/report", summary="资产报告")
async def asset_report():
    try:
        d = CloudAssetDiscovery()
        return _ok(d.generate_report())
    except Exception as e:
        return _fail(f"查询失败: {e}")


# ==================== 云威胁 (5 个) ====================

@router.post("/threat/detect", summary="启动云威胁检测")
async def threat_detect(req: ThreatDetectReq):
    try:
        tid = _new_task("threat-detect")

        def _job():
            d = CloudThreatDetection(detection_types=req.detection_types,
                                     time_window_hours=req.time_window_hours)
            return {"detection": d.detect(), "report": d.generate_report()}

        asyncio.create_task(_run_task(tid, _job))
        return _ok({"task_id": tid, "status": "pending"})
    except Exception as e:
        return _fail(f"启动失败: {e}")


@router.get("/threat/{task_id}/status", summary="威胁检测状态")
async def threat_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t.get("error")})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/threat/{task_id}/results", summary="威胁检测结果")
async def threat_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", data=t)
        return _ok(t["result"]["detection"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/threat/alerts", summary="当前活跃告警")
async def threat_alerts(severity: Optional[str] = Query(None),
                       status: Optional[str] = Query(None)):
    try:
        d = CloudThreatDetection()
        d.detect()
        return _ok({"alerts": d.list_alerts(severity=severity, status=status)})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/threat/report", summary="威胁报告")
async def threat_report():
    try:
        d = CloudThreatDetection()
        return _ok(d.generate_report())
    except Exception as e:
        return _fail(f"查询失败: {e}")


# ==================== 健康检查 ====================

@router.get("/health", summary="云安全 V2 健康检查")
async def health():
    return _ok({
        "service": "cloud-security-v2",
        "modules_loaded": _MODULES_OK,
        "tasks": len(TASKS),
        "endpoints": {
            "aws": 5, "azure": 4, "aliyun": 4, "gcp": 4,
            "container": 4, "k8s": 4, "asset": 6, "threat": 5,
        },
        "time": datetime.now().isoformat(),
    })
