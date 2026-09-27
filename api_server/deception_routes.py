# -*- coding: utf-8 -*-
"""
deception_routes.py — 蜜罐与欺骗技术 REST API（第13轮升级）。

路由前缀：/api/v1/deception
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 包裹，不返回 500。
任务用内存字典模拟异步任务。

合法边界：仅用于防御检测与研究。
"""

from __future__ import annotations

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
    from deception.honeypot_manager import get_honeypot_manager
    from deception.attack_detector import get_attack_detector
    from deception.threat_intel_generator import get_threat_intel_generator
    from deception.decoy_breadcrumb import get_decoy_designer
    from deception.honeynet_distributed import get_honeynet_distributed
    from deception.deception_operations import get_deception_operations
    _MODULES_OK = True
except Exception as _e:  # pragma: no cover
    log.warning("deception_routes: 模块导入失败: %s", _e)
    _MODULES_OK = False


router = APIRouter(prefix="/api/v1/deception", tags=["蜜罐与欺骗技术"])


# ==================== 响应工具 ====================

def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def _fail(err: str, data: Any = None) -> JSONResponse:
    return JSONResponse({"success": False, "data": data, "error": err})


# ==================== 内存任务存储 ====================

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


def _run_task(task_type: str, func, *args, **kwargs) -> str:
    tid = _new_task(task_type)
    TASKS[tid]["status"] = "running"
    try:
        result = func(*args, **kwargs)
        TASKS[tid]["status"] = "success"
        TASKS[tid]["result"] = result
    except Exception as e:
        TASKS[tid]["status"] = "failed"
        TASKS[tid]["error"] = str(e)
    return tid


# ==================== 请求模型 ====================

class HoneypotDeployReq(BaseModel):
    honeypot_type: str = "web_http"
    name: str = ""
    listen_port: Optional[int] = None
    listen_host: str = "0.0.0.0"
    interaction_level: str = "medium"
    custom_banner: str = ""
    max_connections: int = 100


class AttackDetectReq(BaseModel):
    source_ip: str = "192.168.1.100"
    commands: List[str] = []
    connections: List[Dict[str, Any]] = []
    uploads: List[Dict[str, Any]] = []


class ThreatGenerateReq(BaseModel):
    source_ip: str = "185.220.10.1"
    attack_count: int = 20
    tools: List[str] = []
    commands: List[str] = []


class DecoyCreateReq(BaseModel):
    decoy_type: str = "fake_config"
    name: str = ""
    path: str = ""


class HoneynetDeployReq(BaseModel):
    node_type: str = "honeypot_node"
    name: str = ""
    region: str = "cn-east-1"
    zone: str = "dmz"
    count: int = 1


class OperationsAssessReq(BaseModel):
    policy_name: str = ""
    goal: str = ""
    scenario: str = "recon"


# ==================== 蜜罐管理 API ====================

@router.post("/honeypot/deploy")
def honeypot_deploy(req: HoneypotDeployReq):
    """部署蜜罐"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        mgr = get_honeypot_manager()
        result = mgr.deploy(
            honeypot_type=req.honeypot_type,
            name=req.name,
            listen_port=req.listen_port,
            listen_host=req.listen_host,
            interaction_level=req.interaction_level,
            custom_banner=req.custom_banner,
            max_connections=req.max_connections,
        )
        if not result.get("success"):
            return _fail(result.get("error", "部署失败"))
        return _ok(result)
    except Exception as e:
        return _fail(f"蜜罐部署失败: {e}")


@router.get("/honeypot/list")
def honeypot_list():
    """列出蜜罐实例"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        mgr = get_honeypot_manager()
        return _ok({"instances": mgr.list_instances(),
                    "statistics": mgr.get_statistics()})
    except Exception as e:
        return _fail(f"获取蜜罐列表失败: {e}")


@router.get("/honeypot/{instance_id}/detail")
def honeypot_detail(instance_id: str):
    """蜜罐实例详情"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        mgr = get_honeypot_manager()
        inst = mgr.get_instance(instance_id)
        if not inst:
            return _fail("实例不存在")
        return _ok(inst)
    except Exception as e:
        return _fail(f"获取详情失败: {e}")


@router.post("/honeypot/{instance_id}/start")
def honeypot_start(instance_id: str):
    """启动蜜罐"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        mgr = get_honeypot_manager()
        result = mgr.start(instance_id)
        if not result.get("success"):
            return _fail(result.get("error", "启动失败"))
        return _ok(result)
    except Exception as e:
        return _fail(f"启动失败: {e}")


@router.post("/honeypot/{instance_id}/stop")
def honeypot_stop(instance_id: str):
    """停止蜜罐"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        mgr = get_honeypot_manager()
        result = mgr.stop(instance_id)
        if not result.get("success"):
            return _fail(result.get("error", "停止失败"))
        return _ok(result)
    except Exception as e:
        return _fail(f"停止失败: {e}")


@router.delete("/honeypot/{instance_id}")
def honeypot_delete(instance_id: str):
    """删除蜜罐"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        mgr = get_honeypot_manager()
        result = mgr.delete(instance_id)
        if not result.get("success"):
            return _fail(result.get("error", "删除失败"))
        return _ok(result)
    except Exception as e:
        return _fail(f"删除失败: {e}")


@router.get("/honeypot/types")
def honeypot_types():
    """获取蜜罐类型库"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        mgr = get_honeypot_manager()
        return _ok({"types": mgr.list_types()})
    except Exception as e:
        return _fail(f"获取类型库失败: {e}")


# ==================== 攻击检测 API ====================

@router.post("/attack/detect")
def attack_detect(req: AttackDetectReq):
    """启动攻击检测任务"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        detector = get_attack_detector()

        def _do_detect():
            for c in req.commands:
                detector.record_command(req.source_ip, c)
            for conn in req.connections:
                detector.record_connection(
                    req.source_ip, conn.get("source_port", 12345),
                    conn.get("target_port", 80), conn.get("protocol", "TCP"))
            for up in req.uploads:
                detector.record_upload(
                    req.source_ip, up.get("filename", "unknown"),
                    up.get("file_size", 0))
            chain = detector.rebuild_attack_chain(req.source_ip)
            return {"source_ip": req.source_ip, "chain": chain,
                    "alerts": len(detector.alerts)}

        tid = _run_task("attack_detect", _do_detect)
        return _ok({"task_id": tid, "message": "攻击检测任务已启动"})
    except Exception as e:
        return _fail(f"攻击检测启动失败: {e}")


@router.get("/attack/{task_id}/status")
def attack_status(task_id: str):
    """查询检测任务状态"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/attack/{task_id}/results")
def attack_results(task_id: str):
    """获取检测结果"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/attack/{task_id}/report")
def attack_report(task_id: str):
    """获取检测报告"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        detector = get_attack_detector()
        return _ok(detector.generate_report())
    except Exception as e:
        return _fail(f"生成报告失败: {e}")


@router.get("/attack/alerts")
def attack_alerts(severity: Optional[str] = Query(None),
                  source_ip: Optional[str] = Query(None)):
    """获取告警列表"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        detector = get_attack_detector()
        return _ok({"alerts": detector.list_alerts(severity=severity, source_ip=source_ip)})
    except Exception as e:
        return _fail(f"获取告警失败: {e}")


@router.get("/attack/attack-chain")
def attack_chain(source_ip: str = Query("185.220.10.1")):
    """重建攻击链"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        detector = get_attack_detector()
        chain = detector.rebuild_attack_chain(source_ip)
        return _ok(chain)
    except Exception as e:
        return _fail(f"攻击链重建失败: {e}")


# ==================== 威胁情报 API ====================

@router.post("/threat/generate")
def threat_generate(req: ThreatGenerateReq):
    """生成威胁情报"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        intel = get_threat_intel_generator()

        def _do_generate():
            profile = intel.profile_actor(
                req.source_ip, req.attack_count, req.tools, req.commands)
            intel.extract_iocs_from_actor(
                next(iter(intel.actors.values()), None) or type("A", (), {"ip": req.source_ip, "actor_id": "", "tools": []})()
            )
            return profile

        tid = _run_task("threat_gen", _do_generate)
        return _ok({"task_id": tid, "message": "威胁情报生成任务已启动"})
    except Exception as e:
        return _fail(f"情报生成启动失败: {e}")


@router.get("/threat/{task_id}/status")
def threat_status(task_id: str):
    """查询情报任务状态"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/threat/{task_id}/results")
def threat_results(task_id: str):
    """获取情报结果"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/threat/{task_id}/report")
def threat_report(task_id: str):
    """获取情报报告"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        intel = get_threat_intel_generator()
        return _ok(intel.generate_report())
    except Exception as e:
        return _fail(f"生成报告失败: {e}")


@router.get("/threat/iocs")
def threat_iocs(ioc_type: Optional[str] = Query(None)):
    """获取IOC列表"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        intel = get_threat_intel_generator()
        return _ok({"iocs": intel.list_iocs(ioc_type=ioc_type)})
    except Exception as e:
        return _fail(f"获取IOC失败: {e}")


@router.get("/threat/actors")
def threat_actors():
    """获取攻击者画像"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        intel = get_threat_intel_generator()
        return _ok({"actors": intel.list_actors()})
    except Exception as e:
        return _fail(f"获取攻击者失败: {e}")


@router.get("/threat/export")
def threat_export(fmt: str = Query("json")):
    """导出威胁情报"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        intel = get_threat_intel_generator()
        if fmt == "stix":
            return _ok({"format": "stix", "data": intel.export_stix()})
        elif fmt == "openioc":
            return _ok({"format": "openioc", "data": intel.export_openioc()})
        elif fmt == "csv":
            return _ok({"format": "csv", "data": intel.export_csv()})
        return _ok({"format": "json", "data": intel.export_json()})
    except Exception as e:
        return _fail(f"导出失败: {e}")


# ==================== 诱饵面包屑 API ====================

@router.post("/decoy/create")
def decoy_create(req: DecoyCreateReq):
    """创建诱饵"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        designer = get_decoy_designer()
        result = designer.create_decoy(req.decoy_type, req.name, req.path)
        if not result.get("success"):
            return _fail(result.get("error", "创建失败"))
        return _ok(result)
    except Exception as e:
        return _fail(f"创建诱饵失败: {e}")


@router.get("/decoy/list")
def decoy_list():
    """列出诱饵"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        designer = get_decoy_designer()
        return _ok({"decoys": designer.list_decoys(),
                    "statistics": designer.get_statistics()})
    except Exception as e:
        return _fail(f"获取诱饵列表失败: {e}")


@router.get("/decoy/{decoy_id}/detail")
def decoy_detail(decoy_id: str):
    """诱饵详情"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        designer = get_decoy_designer()
        d = designer.get_decoy(decoy_id)
        if not d:
            return _fail("诱饵不存在")
        return _ok(d)
    except Exception as e:
        return _fail(f"获取详情失败: {e}")


@router.delete("/decoy/{decoy_id}")
def decoy_delete(decoy_id: str):
    """删除诱饵"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        designer = get_decoy_designer()
        result = designer.delete_decoy(decoy_id)
        if not result.get("success"):
            return _fail(result.get("error", "删除失败"))
        return _ok(result)
    except Exception as e:
        return _fail(f"删除失败: {e}")


@router.get("/decoy/types")
def decoy_types():
    """获取诱饵类型库"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        designer = get_decoy_designer()
        return _ok({"types": designer.list_types()})
    except Exception as e:
        return _fail(f"获取类型库失败: {e}")


@router.get("/decoy/detections")
def decoy_detections():
    """获取诱饵检测事件"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        designer = get_decoy_designer()
        return _ok({"events": designer.list_detections()})
    except Exception as e:
        return _fail(f"获取检测事件失败: {e}")


# ==================== 蜜网分布式 API ====================

@router.post("/honeynet/deploy")
def honeynet_deploy(req: HoneynetDeployReq):
    """部署蜜网节点"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        hn = get_honeynet_distributed()
        results = []
        for _ in range(req.count):
            r = hn.register_node(req.name, req.node_type, req.region, req.zone)
            results.append(r)
        return _ok({"deployed": results, "count": len(results)})
    except Exception as e:
        return _fail(f"蜜网部署失败: {e}")


@router.get("/honeynet/list")
def honeynet_list():
    """列出蜜网节点"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        hn = get_honeynet_distributed()
        return _ok({"nodes": hn.list_nodes()})
    except Exception as e:
        return _fail(f"获取节点列表失败: {e}")


@router.get("/honeynet/{node_id}/detail")
def honeynet_detail(node_id: str):
    """节点详情"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        hn = get_honeynet_distributed()
        n = hn.get_node(node_id)
        if not n:
            return _fail("节点不存在")
        return _ok(n)
    except Exception as e:
        return _fail(f"获取详情失败: {e}")


@router.get("/honeynet/nodes")
def honeynet_nodes():
    """节点概览"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        hn = get_honeynet_distributed()
        return _ok({"nodes": hn.list_nodes(),
                    "health": hn.cluster_health()})
    except Exception as e:
        return _fail(f"获取节点概览失败: {e}")


@router.get("/honeynet/topology")
def honeynet_topology():
    """蜜网拓扑"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        hn = get_honeynet_distributed()
        return _ok(hn.build_topology())
    except Exception as e:
        return _fail(f"获取拓扑失败: {e}")


@router.get("/honeynet/health")
def honeynet_health():
    """集群健康状态"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        hn = get_honeynet_distributed()
        return _ok(hn.cluster_health())
    except Exception as e:
        return _fail(f"获取健康状态失败: {e}")


# ==================== 综合运营 API ====================

@router.post("/operations/assess")
def operations_assess(req: OperationsAssessReq):
    """启动运营评估任务"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        ops = get_deception_operations()

        def _do_assess():
            if req.policy_name:
                ops.create_policy(req.policy_name, req.goal or "提升检测覆盖")
            eff = ops.assess_effectiveness()
            drill = ops.run_drill(req.scenario)
            mat = ops.assess_maturity()
            return {"effectiveness": eff, "drill": drill, "maturity": mat}

        tid = _run_task("ops_assess", _do_assess)
        return _ok({"task_id": tid, "message": "运营评估任务已启动"})
    except Exception as e:
        return _fail(f"运营评估启动失败: {e}")


@router.get("/operations/{task_id}/status")
def operations_status(task_id: str):
    """查询运营任务状态"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/operations/{task_id}/results")
def operations_results(task_id: str):
    """获取运营评估结果"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/operations/{task_id}/report")
def operations_report(task_id: str):
    """获取运营报告"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        ops = get_deception_operations()
        return _ok(ops.generate_report())
    except Exception as e:
        return _fail(f"生成报告失败: {e}")


@router.get("/operations/metrics")
def operations_metrics():
    """获取运营指标"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        ops = get_deception_operations()
        return _ok(ops.get_metrics())
    except Exception as e:
        return _fail(f"获取指标失败: {e}")


@router.get("/operations/history")
def operations_history():
    """获取运营历史"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        ops = get_deception_operations()
        return _ok({"history": ops.get_history(),
                    "policies": ops.list_policies(),
                    "drills": ops.list_drills()})
    except Exception as e:
        return _fail(f"获取历史失败: {e}")
