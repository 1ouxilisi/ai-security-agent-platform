# -*- coding: utf-8 -*-
"""
cloud_native_security_routes.py - 云原生安全深度 (CNAPP) REST API（第25轮升级方向2）。

路由前缀：/api/v1/cloud-native-security
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
    from cloud_native_security.k8s_runtime import create_k8s_runtime
    from cloud_native_security.container_security import create_container_security
    from cloud_native_security.service_mesh import create_service_mesh
    from cloud_native_security.cwpp import create_cwpp
    from cloud_native_security.cspm import create_cspm
    from cloud_native_security.cnapp_dashboard import create_cnapp_dashboard
    _MODULES_OK = True
except Exception as _e:  # pragma: no cover
    log.warning("cloud_native_security_routes: 模块导入失败: %s", _e)
    _MODULES_OK = False


router = APIRouter(prefix="/api/v1/cloud-native-security", tags=["云原生安全CNAPP"])


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


async def _run_task(task_id: str, fn) -> None:
    task = TASKS.get(task_id)
    if not task:
        return
    task["status"] = "running"
    try:
        await asyncio.sleep(0)
        result = fn()
        task["status"] = "success"
        task["result"] = result
    except Exception as e:  # pragma: no cover
        task["status"] = "failed"
        task["error"] = str(e)
    finally:
        task["finished_at"] = datetime.now().isoformat()


# ==================== 请求模型 ====================

class ContainerScanReq(BaseModel):
    image: str
    scan_types: Optional[List[str]] = None


class K8sIsolateReq(BaseModel):
    pod_name: str
    namespace: str
    cluster: Optional[str] = None


class K8sDeleteReq(BaseModel):
    resource_type: str
    name: str
    namespace: Optional[str] = ""
    cluster: Optional[str] = None


class MeshIsolateReq(BaseModel):
    service: str
    namespace: str
    mesh: Optional[str] = None


class CWPPIsolateReq(BaseModel):
    instance_id: str
    cloud: str = "aws"


# ==================== 懒加载单例 ====================

_k8s_instance = None
_container_instance = None
_mesh_instance = None
_cwpp_instance = None
_cspm_instance = None
_dashboard_instance = None


def _k8s():
    global _k8s_instance
    if _k8s_instance is None:
        _k8s_instance = create_k8s_runtime()
    return _k8s_instance


def _container():
    global _container_instance
    if _container_instance is None:
        _container_instance = create_container_security()
    return _container_instance


def _mesh():
    global _mesh_instance
    if _mesh_instance is None:
        _mesh_instance = create_service_mesh()
    return _mesh_instance


def _cwpp():
    global _cwpp_instance
    if _cwpp_instance is None:
        _cwpp_instance = create_cwpp()
    return _cwpp_instance


def _cspm():
    global _cspm_instance
    if _cspm_instance is None:
        _cspm_instance = create_cspm()
    return _cspm_instance


def _dashboard():
    global _dashboard_instance
    if _dashboard_instance is None:
        _dashboard_instance = create_cnapp_dashboard()
    return _dashboard_instance


# ==================== 任务状态通用端点 ====================

@router.get("/tasks/{task_id}/status", summary="查询异步任务状态")
async def task_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"],
                    "error": t.get("error"), "created_at": t["created_at"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/tasks/{task_id}/results", summary="获取异步任务结果")
async def task_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", data=t)
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


# ==================== 1. K8s 运行时安全 (22端点) ====================

@router.get("/k8s/clusters", summary="K8s 集群发现")
async def k8s_clusters():
    try:
        return _ok(_k8s().discover_clusters())
    except Exception as e:
        return _fail(f"集群发现失败: {e}")


@router.get("/k8s/nodes", summary="K8s 节点发现")
async def k8s_nodes(cluster: Optional[str] = Query(None)):
    try:
        return _ok(_k8s().discover_nodes(cluster or ""))
    except Exception as e:
        return _fail(f"节点发现失败: {e}")


@router.get("/k8s/namespaces", summary="K8s 命名空间发现")
async def k8s_namespaces(cluster: Optional[str] = Query(None)):
    try:
        return _ok(_k8s().discover_namespaces(cluster or ""))
    except Exception as e:
        return _fail(f"命名空间发现失败: {e}")


@router.get("/k8s/pods", summary="K8s Pod 发现")
async def k8s_pods(cluster: Optional[str] = Query(None), namespace: Optional[str] = Query(None)):
    try:
        return _ok(_k8s().discover_pods(cluster or "", namespace or ""))
    except Exception as e:
        return _fail(f"Pod 发现失败: {e}")


@router.get("/k8s/services", summary="K8s Service 发现")
async def k8s_services(cluster: Optional[str] = Query(None), namespace: Optional[str] = Query(None)):
    try:
        return _ok(_k8s().discover_services(cluster or "", namespace or ""))
    except Exception as e:
        return _fail(f"Service 发现失败: {e}")


@router.get("/k8s/configmaps", summary="K8s ConfigMap 发现")
async def k8s_configmaps(cluster: Optional[str] = Query(None), namespace: Optional[str] = Query(None)):
    try:
        return _ok(_k8s().discover_configmaps(cluster or "", namespace or ""))
    except Exception as e:
        return _fail(f"ConfigMap 发现失败: {e}")


@router.get("/k8s/secrets", summary="K8s Secret 发现")
async def k8s_secrets(cluster: Optional[str] = Query(None), namespace: Optional[str] = Query(None)):
    try:
        return _ok(_k8s().discover_secrets(cluster or "", namespace or ""))
    except Exception as e:
        return _fail(f"Secret 发现失败: {e}")


@router.get("/k8s/service-accounts", summary="K8s ServiceAccount 发现")
async def k8s_service_accounts(cluster: Optional[str] = Query(None)):
    try:
        return _ok(_k8s().discover_service_accounts(cluster or ""))
    except Exception as e:
        return _fail(f"ServiceAccount 发现失败: {e}")


@router.get("/k8s/roles", summary="K8s Role 发现")
async def k8s_roles(cluster: Optional[str] = Query(None)):
    try:
        return _ok(_k8s().discover_roles(cluster or ""))
    except Exception as e:
        return _fail(f"Role 发现失败: {e}")


@router.get("/k8s/role-bindings", summary="K8s RoleBinding 发现")
async def k8s_role_bindings(cluster: Optional[str] = Query(None)):
    try:
        return _ok(_k8s().discover_role_bindings(cluster or ""))
    except Exception as e:
        return _fail(f"RoleBinding 发现失败: {e}")


@router.get("/k8s/network-policies", summary="K8s NetworkPolicy 发现")
async def k8s_network_policies(cluster: Optional[str] = Query(None)):
    try:
        return _ok(_k8s().discover_network_policies(cluster or ""))
    except Exception as e:
        return _fail(f"NetworkPolicy 发现失败: {e}")


@router.get("/k8s/audit/rbac", summary="K8s RBAC 配置审计")
async def k8s_audit_rbac(cluster: Optional[str] = Query(None)):
    try:
        return _ok(_k8s().audit_rbac(cluster or ""))
    except Exception as e:
        return _fail(f"RBAC 审计失败: {e}")


@router.get("/k8s/audit/security-context", summary="K8s 安全上下文审计")
async def k8s_audit_security_context(cluster: Optional[str] = Query(None)):
    try:
        return _ok(_k8s().audit_security_context(cluster or ""))
    except Exception as e:
        return _fail(f"安全上下文审计失败: {e}")


@router.get("/k8s/audit/resource-limits", summary="K8s 资源限制审计")
async def k8s_audit_resource_limits(cluster: Optional[str] = Query(None)):
    try:
        return _ok(_k8s().audit_resource_limits(cluster or ""))
    except Exception as e:
        return _fail(f"资源限制审计失败: {e}")


@router.get("/k8s/audit/pod-standards", summary="K8s Pod 安全标准审计")
async def k8s_audit_pod_standards(cluster: Optional[str] = Query(None)):
    try:
        return _ok(_k8s().audit_pod_standards(cluster or ""))
    except Exception as e:
        return _fail(f"Pod 安全标准审计失败: {e}")


@router.get("/k8s/monitor/processes", summary="K8s 进程监控")
async def k8s_monitor_processes(cluster: Optional[str] = Query(None), namespace: Optional[str] = Query(None)):
    try:
        return _ok(_k8s().monitor_processes(cluster or "", namespace or ""))
    except Exception as e:
        return _fail(f"进程监控失败: {e}")


@router.get("/k8s/monitor/network", summary="K8s 网络监控")
async def k8s_monitor_network(cluster: Optional[str] = Query(None)):
    try:
        return _ok(_k8s().monitor_network(cluster or ""))
    except Exception as e:
        return _fail(f"网络监控失败: {e}")


@router.get("/k8s/detect/escape", summary="K8s 容器逃逸检测")
async def k8s_detect_escape(cluster: Optional[str] = Query(None)):
    try:
        data = {
            "privileged": _k8s().detect_privileged_containers(cluster or ""),
            "host_mounts": _k8s().detect_host_mounts(cluster or ""),
            "capabilities": _k8s().detect_kernel_capabilities(cluster or ""),
            "techniques": _k8s().detect_escape_techniques(cluster or ""),
        }
        return _ok(data)
    except Exception as e:
        return _fail(f"逃逸检测失败: {e}")


@router.get("/k8s/detect/threats", summary="K8s 威胁检测")
async def k8s_detect_threats(cluster: Optional[str] = Query(None)):
    try:
        data = {
            "anomalous_pod_creation": _k8s().detect_anomalous_pod_creation(cluster or ""),
            "anomalous_service_exposure": _k8s().detect_anomalous_service_exposure(cluster or ""),
            "anomalous_config_changes": _k8s().detect_anomalous_config_changes(cluster or ""),
            "lateral_movement": _k8s().detect_lateral_movement(cluster or ""),
        }
        return _ok(data)
    except Exception as e:
        return _fail(f"威胁检测失败: {e}")


@router.post("/k8s/response/isolate-pod", summary="K8s 响应: Pod 隔离")
async def k8s_resp_isolate_pod(req: K8sIsolateReq):
    try:
        return _ok(_k8s().isolate_pod(req.pod_name, req.namespace, req.cluster or ""))
    except Exception as e:
        return _fail(f"Pod 隔离失败: {e}")


@router.post("/k8s/response/forensics", summary="K8s 响应: 取证收集")
async def k8s_resp_forensics(req: K8sIsolateReq):
    try:
        return _ok(_k8s().collect_forensics(req.pod_name, req.namespace, req.cluster or ""))
    except Exception as e:
        return _fail(f"取证收集失败: {e}")


@router.get("/k8s/response/history", summary="K8s 响应历史")
async def k8s_resp_history(limit: int = Query(50)):
    try:
        return _ok(_k8s().get_response_history(limit))
    except Exception as e:
        return _fail(f"响应历史查询失败: {e}")


# ==================== 2. 容器安全深度 (12端点) ====================

@router.post("/container/scan", summary="容器镜像扫描")
async def container_scan(req: ContainerScanReq):
    try:
        tid = _new_task("container-scan")

        def _job():
            return _container().scan_image(req.image, req.scan_types)

        asyncio.create_task(_run_task(tid, _job))
        return _ok({"task_id": tid, "status": "pending"})
    except Exception as e:
        return _fail(f"启动扫描失败: {e}")


@router.get("/container/runtime/anomalies", summary="容器运行时异常检测")
async def container_runtime_anomalies():
    try:
        return _ok(_container().runtime_anomaly_detection())
    except Exception as e:
        return _fail(f"异常检测失败: {e}")


@router.get("/container/runtime/whitelist", summary="容器进程白名单")
async def container_runtime_whitelist():
    try:
        return _ok(_container().runtime_process_whitelist())
    except Exception as e:
        return _fail(f"白名单查询失败: {e}")


@router.get("/container/runtime/syscall-filter", summary="容器系统调用过滤")
async def container_runtime_syscall():
    try:
        return _ok(_container().runtime_syscall_filter())
    except Exception as e:
        return _fail(f"系统调用过滤查询失败: {e}")


@router.get("/container/hardening/rules", summary="容器逃逸防护规则")
async def container_hardening_rules():
    try:
        return _ok(_container().get_escape_hardening_rules())
    except Exception as e:
        return _fail(f"防护规则查询失败: {e}")


@router.post("/container/hardening/assess", summary="容器加固评估")
async def container_hardening_assess(container_name: str = Query("")):
    try:
        return _ok(_container().assess_container_hardening(container_name))
    except Exception as e:
        return _fail(f"加固评估失败: {e}")


@router.get("/container/network/topology", summary="容器网络拓扑")
async def container_network_topology():
    try:
        return _ok(_container().get_network_visualization())
    except Exception as e:
        return _fail(f"网络拓扑查询失败: {e}")


@router.get("/container/network/tunnels", summary="容器隧道检测")
async def container_network_tunnels():
    try:
        return _ok(_container().detect_tunnels())
    except Exception as e:
        return _fail(f"隧道检测失败: {e}")


@router.get("/container/compliance/{framework}", summary="容器合规报告")
async def container_compliance(framework: str):
    try:
        return _ok(_container().get_compliance_report(framework))
    except Exception as e:
        return _fail(f"合规报告查询失败: {e}")


@router.get("/container/lifecycle/build", summary="容器构建安全")
async def container_lifecycle_build():
    try:
        return _ok(_container().lifecycle_build_security())
    except Exception as e:
        return _fail(f"构建安全查询失败: {e}")


@router.get("/container/lifecycle/signing", summary="容器镜像签名")
async def container_lifecycle_signing():
    try:
        return _ok(_container().lifecycle_image_signing())
    except Exception as e:
        return _fail(f"镜像签名查询失败: {e}")


@router.get("/container/lifecycle/destroy", summary="容器销毁安全")
async def container_lifecycle_destroy():
    try:
        return _ok(_container().lifecycle_destroy_security())
    except Exception as e:
        return _fail(f"销毁安全查询失败: {e}")


# ==================== 3. 服务网格安全 (12端点) ====================

@router.get("/mesh/meshes", summary="服务网格发现")
async def mesh_discover():
    try:
        return _ok(_mesh().discover_meshes())
    except Exception as e:
        return _fail(f"网格发现失败: {e}")


@router.get("/mesh/services", summary="服务网格服务发现")
async def mesh_services(mesh: Optional[str] = Query(None)):
    try:
        return _ok(_mesh().discover_services(mesh or ""))
    except Exception as e:
        return _fail(f"服务发现失败: {e}")


@router.get("/mesh/virtual-services", summary="服务网格虚拟服务")
async def mesh_virtual_services(mesh: Optional[str] = Query(None)):
    try:
        return _ok(_mesh().discover_virtual_services(mesh or ""))
    except Exception as e:
        return _fail(f"虚拟服务查询失败: {e}")


@router.get("/mesh/gateways", summary="服务网格网关")
async def mesh_gateways(mesh: Optional[str] = Query(None)):
    try:
        return _ok(_mesh().discover_gateways(mesh or ""))
    except Exception as e:
        return _fail(f"网关查询失败: {e}")


@router.get("/mesh/audit/mtls", summary="服务网格 mTLS 审计")
async def mesh_audit_mtls(mesh: Optional[str] = Query(None)):
    try:
        return _ok(_mesh().audit_mtls(mesh or ""))
    except Exception as e:
        return _fail(f"mTLS 审计失败: {e}")


@router.get("/mesh/audit/authz-policies", summary="服务网格授权策略审计")
async def mesh_audit_authz(mesh: Optional[str] = Query(None)):
    try:
        return _ok(_mesh().audit_authorization_policies(mesh or ""))
    except Exception as e:
        return _fail(f"授权策略审计失败: {e}")


@router.get("/mesh/certificates", summary="服务网格证书状态")
async def mesh_certificates(mesh: Optional[str] = Query(None)):
    try:
        return _ok(_mesh().get_certificate_status(mesh or ""))
    except Exception as e:
        return _fail(f"证书状态查询失败: {e}")


@router.get("/mesh/detect/threats", summary="服务网格威胁检测")
async def mesh_detect_threats(mesh: Optional[str] = Query(None)):
    try:
        data = {
            "anomalous_calls": _mesh().detect_anomalous_calls(mesh or ""),
            "unauthorized_access": _mesh().detect_unauthorized_access(mesh or ""),
            "certificate_anomalies": _mesh().detect_certificate_anomalies(mesh or ""),
        }
        return _ok(data)
    except Exception as e:
        return _fail(f"威胁检测失败: {e}")


@router.get("/mesh/topology", summary="服务网格拓扑")
async def mesh_topology(mesh: Optional[str] = Query(None)):
    try:
        return _ok(_mesh().get_service_topology(mesh or ""))
    except Exception as e:
        return _fail(f"拓扑查询失败: {e}")


@router.get("/mesh/security-graph", summary="服务网格安全图")
async def mesh_security_graph(mesh: Optional[str] = Query(None)):
    try:
        return _ok(_mesh().get_security_graph(mesh or ""))
    except Exception as e:
        return _fail(f"安全图查询失败: {e}")


@router.post("/mesh/response/isolate-service", summary="服务网格响应: 服务隔离")
async def mesh_resp_isolate(req: MeshIsolateReq):
    try:
        return _ok(_mesh().isolate_service(req.service, req.namespace, req.mesh or ""))
    except Exception as e:
        return _fail(f"服务隔离失败: {e}")


@router.post("/mesh/response/revoke-cert", summary="服务网格响应: 证书吊销")
async def mesh_resp_revoke_cert(cert_name: str = Query(...), mesh: Optional[str] = Query(None)):
    try:
        return _ok(_mesh().revoke_certificate(cert_name, mesh or ""))
    except Exception as e:
        return _fail(f"证书吊销失败: {e}")


# ==================== 4. CWPP (11端点) ====================

@router.get("/cwpp/workloads", summary="CWPP 工作负载发现")
async def cwpp_workloads(cloud: Optional[str] = Query(None)):
    try:
        return _ok(_cwpp().discover_workloads(cloud or ""))
    except Exception as e:
        return _fail(f"工作负载发现失败: {e}")


@router.get("/cwpp/audit/security-groups", summary="CWPP 安全组审计")
async def cwpp_audit_sg():
    try:
        return _ok(_cwpp().audit_security_groups())
    except Exception as e:
        return _fail(f"安全组审计失败: {e}")


@router.get("/cwpp/audit/encryption", summary="CWPP 加密审计")
async def cwpp_audit_encryption():
    try:
        return _ok(_cwpp().audit_encryption())
    except Exception as e:
        return _fail(f"加密审计失败: {e}")


@router.get("/cwpp/runtime/ids", summary="CWPP 入侵检测")
async def cwpp_runtime_ids(workload_id: Optional[str] = Query(None)):
    try:
        return _ok(_cwpp().runtime_intrusion_detection(workload_id or ""))
    except Exception as e:
        return _fail(f"入侵检测失败: {e}")


@router.post("/cwpp/vuln/scan", summary="CWPP 漏洞扫描")
async def cwpp_vuln_scan(workload_id: Optional[str] = Query(None)):
    try:
        tid = _new_task("cwpp-vuln-scan")

        def _job():
            return _cwpp().scan_workload_vulnerabilities(workload_id or "")

        asyncio.create_task(_run_task(tid, _job))
        return _ok({"task_id": tid, "status": "pending"})
    except Exception as e:
        return _fail(f"启动漏洞扫描失败: {e}")


@router.get("/cwpp/vuln/trends", summary="CWPP 漏洞趋势")
async def cwpp_vuln_trends():
    try:
        return _ok(_cwpp().get_vulnerability_trends())
    except Exception as e:
        return _fail(f"漏洞趋势查询失败: {e}")


@router.get("/cwpp/compliance/{framework}", summary="CWPP 合规报告")
async def cwpp_compliance(framework: str):
    try:
        return _ok(_cwpp().get_compliance_status(framework))
    except Exception as e:
        return _fail(f"合规报告查询失败: {e}")


@router.post("/cwpp/response/isolate", summary="CWPP 响应: 实例隔离")
async def cwpp_resp_isolate(req: CWPPIsolateReq):
    try:
        return _ok(_cwpp().isolate_instance(req.instance_id, req.cloud))
    except Exception as e:
        return _fail(f"实例隔离失败: {e}")


@router.post("/cwpp/response/terminate", summary="CWPP 响应: 实例终止")
async def cwpp_resp_terminate(instance_id: str = Query(...), cloud: str = Query("aws")):
    try:
        return _ok(_cwpp().terminate_instance(instance_id, cloud))
    except Exception as e:
        return _fail(f"实例终止失败: {e}")


@router.post("/cwpp/response/snapshot", summary="CWPP 响应: 创建快照")
async def cwpp_resp_snapshot(resource_id: str = Query(...), resource_type: str = Query("ebs"), cloud: str = Query("aws")):
    try:
        return _ok(_cwpp().create_snapshot(resource_id, resource_type, cloud))
    except Exception as e:
        return _fail(f"快照创建失败: {e}")


@router.get("/cwpp/response/history", summary="CWPP 响应历史")
async def cwpp_resp_history(limit: int = Query(50)):
    try:
        return _ok(_cwpp().get_response_history(limit))
    except Exception as e:
        return _fail(f"响应历史查询失败: {e}")


# ==================== 5. CSPM (10端点) ====================

@router.get("/cspm/assets", summary="CSPM 云资产发现")
async def cspm_assets(cloud: str = Query("aws")):
    try:
        return _ok(_cspm().discover_assets(cloud))
    except Exception as e:
        return _fail(f"云资产发现失败: {e}")


@router.get("/cspm/audit/security-groups", summary="CSPM 安全组审计")
async def cspm_audit_sg(cloud: str = Query("aws")):
    try:
        return _ok(_cspm().audit_security_groups(cloud))
    except Exception as e:
        return _fail(f"安全组审计失败: {e}")


@router.get("/cspm/audit/storage", summary="CSPM 存储桶审计")
async def cspm_audit_storage(cloud: str = Query("aws")):
    try:
        return _ok(_cspm().audit_storage_buckets(cloud))
    except Exception as e:
        return _fail(f"存储桶审计失败: {e}")


@router.get("/cspm/audit/iam", summary="CSPM IAM 审计")
async def cspm_audit_iam(cloud: str = Query("aws")):
    try:
        return _ok(_cspm().audit_iam(cloud))
    except Exception as e:
        return _fail(f"IAM 审计失败: {e}")


@router.get("/cspm/audit/logging", summary="CSPM 日志审计")
async def cspm_audit_logging(cloud: str = Query("aws")):
    try:
        return _ok(_cspm().audit_logging(cloud))
    except Exception as e:
        return _fail(f"日志审计失败: {e}")


@router.get("/cspm/compliance/{framework}", summary="CSPM 合规评估")
async def cspm_compliance(framework: str, cloud: str = Query("aws")):
    try:
        return _ok(_cspm().evaluate_compliance(framework, cloud))
    except Exception as e:
        return _fail(f"合规评估失败: {e}")


@router.get("/cspm/risk-score", summary="CSPM 风险评分")
async def cspm_risk_score(cloud: str = Query("aws")):
    try:
        return _ok(_cspm().get_risk_score(cloud))
    except Exception as e:
        return _fail(f"风险评分查询失败: {e}")


@router.get("/cspm/attack-paths", summary="CSPM 攻击路径分析")
async def cspm_attack_paths(cloud: str = Query("aws")):
    try:
        return _ok(_cspm().analyze_attack_paths(cloud))
    except Exception as e:
        return _fail(f"攻击路径分析失败: {e}")


@router.get("/cspm/recommendations", summary="CSPM 安全改进建议")
async def cspm_recommendations(cloud: str = Query("aws")):
    try:
        return _ok(_cspm().get_remediation_recommendations(cloud))
    except Exception as e:
        return _fail(f"改进建议查询失败: {e}")


# ==================== 6. CNAPP 控制台总览 (7端点) ====================

@router.get("/dashboard/overview", summary="CNAPP 总览")
async def dashboard_overview():
    try:
        return _ok(_dashboard().get_overview())
    except Exception as e:
        return _fail(f"总览查询失败: {e}")


@router.get("/dashboard/k8s-summary", summary="CNAPP K8s 汇总")
async def dashboard_k8s():
    try:
        return _ok(_dashboard().get_k8s_summary())
    except Exception as e:
        return _fail(f"K8s 汇总查询失败: {e}")


@router.get("/dashboard/container-summary", summary="CNAPP 容器汇总")
async def dashboard_container():
    try:
        return _ok(_dashboard().get_container_summary())
    except Exception as e:
        return _fail(f"容器汇总查询失败: {e}")


@router.get("/dashboard/mesh-summary", summary="CNAPP 服务网格汇总")
async def dashboard_mesh():
    try:
        return _ok(_dashboard().get_mesh_summary())
    except Exception as e:
        return _fail(f"服务网格汇总查询失败: {e}")


@router.get("/dashboard/cwpp-summary", summary="CNAPP CWPP 汇总")
async def dashboard_cwpp():
    try:
        return _ok(_dashboard().get_cwpp_summary())
    except Exception as e:
        return _fail(f"CWPP 汇总查询失败: {e}")


@router.get("/dashboard/cspm-summary", summary="CNAPP CSPM 汇总")
async def dashboard_cspm():
    try:
        return _ok(_dashboard().get_cspm_summary())
    except Exception as e:
        return _fail(f"CSPM 汇总查询失败: {e}")


@router.get("/dashboard/settings", summary="CNAPP 系统设置")
async def dashboard_settings():
    try:
        return _ok(_dashboard().get_settings())
    except Exception as e:
        return _fail(f"系统设置查询失败: {e}")
