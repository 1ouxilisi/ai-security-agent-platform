"""增强模块API路由。

整合：真实工具集成、内网渗透增强、云安全增强、
性能监控、多用户管理、分布式扫描等6大新模块的API端点。

注意：本模块仅用于授权的安全测试，使用前请确保已获得相关授权。
"""
import os
import time
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Depends, Header, Query
from pydantic import BaseModel, Field
from utils.logger import log

router = APIRouter(prefix="/api/v1/enhanced", tags=["增强模块"])


# ============== 请求模型 ==============

class NmapScanRequest(BaseModel):
    """Nmap扫描请求"""
    target: str = Field(..., description="目标IP或域名")
    scan_type: str = Field("quick", description="扫描类型: quick/full/os")
    ports: str = Field("1-1000", description="端口范围")
    timeout: int = Field(120, description="超时时间（秒）")


class SqlmapScanRequest(BaseModel):
    """SQLMap扫描请求"""
    url: str = Field(..., description="目标URL")
    data: str = Field("", description="POST数据")
    cookie: str = Field("", description="Cookie")
    level: int = Field(3, description="测试级别 1-5")
    risk: int = Field(2, description="风险等级 1-3")
    timeout: int = Field(600, description="超时时间（秒）")


class NucleiScanRequest(BaseModel):
    """Nuclei扫描请求"""
    target: str = Field(..., description="目标URL")
    templates: str = Field("", description="模板路径（可选）")
    severity: str = Field("", description="严重程度过滤: critical/high/medium/low/info")
    timeout: int = Field(300, description="超时时间（秒）")


class InternalScanRequest(BaseModel):
    """内网扫描请求"""
    target: str = Field(..., description="目标IP、CIDR或范围")
    scan_type: str = Field("full", description="扫描类型: full/ports/smb/netbios")
    ports: List[int] = Field(default_factory=list, description="端口列表")
    max_workers: int = Field(10, description="并发线程数")


class SMBEnumRequest(BaseModel):
    """SMB枚举请求"""
    ip: str = Field(..., description="目标IP")
    username: str = Field("", description="用户名（空会话留空）")
    password: str = Field("", description="密码")
    domain: str = Field("", description="域")


class LDAPQueryRequest(BaseModel):
    """LDAP域查询请求"""
    dc_ip: str = Field(..., description="域控制器IP")
    username: str = Field("", description="用户名")
    password: str = Field("", description="密码")
    domain: str = Field("", description="域名")
    query_type: str = Field("all", description="查询类型: all/users/computers/groups/spns/kerberoast")


class CloudScanRequest(BaseModel):
    """云安全扫描请求"""
    provider: str = Field("all", description="云服务商: all/aws/azure/aliyun")
    aws_access_key: str = Field("", description="AWS Access Key")
    aws_secret_key: str = Field("", description="AWS Secret Key")
    aws_region: str = Field("us-east-1", description="AWS区域")


class DockerfileCheckRequest(BaseModel):
    """Dockerfile检查请求"""
    path: str = Field(..., description="Dockerfile文件路径")


class K8sManifestCheckRequest(BaseModel):
    """K8s清单检查请求"""
    path: str = Field(..., description="K8s清单文件路径")


class UserCreateRequest(BaseModel):
    """用户创建请求"""
    username: str = Field(..., description="用户名")
    password: str = Field(..., description="密码")
    email: str = Field("", description="邮箱")
    role: str = Field("user", description="角色: admin/security_analyst/auditor/user")
    tenant_id: str = Field("default", description="租户ID")


class UserLoginRequest(BaseModel):
    """用户登录请求"""
    username: str = Field(..., description="用户名")
    password: str = Field(..., description="密码")


class APIKeyCreateRequest(BaseModel):
    """API密钥创建请求"""
    username: str = Field(..., description="用户名")
    name: str = Field("", description="密钥名称")
    expires_days: int = Field(365, description="过期天数")


class DistributedScanRequest(BaseModel):
    """分布式扫描请求"""
    target: str = Field(..., description="目标")
    scan_type: str = Field("port_scan", description="扫描类型")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="扫描参数")
    priority: int = Field(5, description="优先级 1-10")


class NodeRegisterRequest(BaseModel):
    """节点注册请求"""
    name: str = Field(..., description="节点名称")
    address: str = Field(..., description="节点地址 IP:端口")
    capabilities: List[str] = Field(default_factory=lambda: ["port_scan", "vuln_scan"], description="支持的扫描类型")


class ProxyAddRequest(BaseModel):
    """代理添加请求"""
    address: str = Field(..., description="代理地址 IP:端口")
    protocol: str = Field("http", description="协议: http/socks4/socks5")
    username: str = Field("", description="用户名")
    password: str = Field("", description="密码")


# ============== 工具集成API ==============

@router.post("/tools/nmap/scan", summary="Nmap端口扫描")
async def nmap_scan(request: NmapScanRequest):
    """使用Nmap进行端口扫描、服务识别和OS检测"""
    try:
        from tools.integration import tool_manager
        nmap = tool_manager.get_tool("nmap")
        
        if not nmap or not nmap.is_available():
            raise HTTPException(status_code=503, detail="Nmap工具不可用，请先安装nmap")
        
        if request.scan_type == "quick":
            result = nmap.quick_scan(request.target, request.ports, request.timeout)
        elif request.scan_type == "full":
            result = nmap.full_scan(request.target, request.timeout)
        elif request.scan_type == "os":
            result = nmap.os_detection(request.target, request.timeout)
        else:
            raise HTTPException(status_code=400, detail=f"不支持的扫描类型: {request.scan_type}")
        
        return {
            "success": result.success,
            "command": result.command,
            "execution_time": result.execution_time,
            "parsed_data": result.parsed_data,
            "error": result.error
        }
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Nmap扫描失败: {e}")
        raise HTTPException(status_code=500, detail=f"Nmap扫描失败: {e}")


@router.post("/tools/sqlmap/scan", summary="SQLMap注入扫描")
async def sqlmap_scan(request: SqlmapScanRequest):
    """使用SQLMap扫描SQL注入漏洞"""
    try:
        from tools.integration import tool_manager
        sqlmap = tool_manager.get_tool("sqlmap")
        
        if not sqlmap or not sqlmap.is_available():
            raise HTTPException(status_code=503, detail="SQLMap工具不可用，请先安装sqlmap")
        
        result = sqlmap.scan_url(
            url=request.url,
            data=request.data or None,
            cookie=request.cookie or None,
            level=request.level,
            risk=request.risk,
            timeout=request.timeout
        )
        
        return {
            "success": result.success,
            "command": result.command,
            "execution_time": result.execution_time,
            "parsed_data": result.parsed_data,
            "error": result.error
        }
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"SQLMap扫描失败: {e}")
        raise HTTPException(status_code=500, detail=f"SQLMap扫描失败: {e}")


@router.post("/tools/nuclei/scan", summary="Nuclei漏洞扫描")
async def nuclei_scan(request: NucleiScanRequest):
    """使用Nuclei进行漏洞模板扫描"""
    try:
        from tools.integration import tool_manager
        nuclei = tool_manager.get_tool("nuclei")
        
        if not nuclei or not nuclei.is_available():
            raise HTTPException(status_code=503, detail="Nuclei工具不可用，请先安装nuclei")
        
        result = nuclei.scan_target(
            target=request.target,
            templates=request.templates or None,
            severity=request.severity or None,
            timeout=request.timeout
        )
        
        return {
            "success": result.success,
            "command": result.command,
            "execution_time": result.execution_time,
            "parsed_data": result.parsed_data,
            "error": result.error
        }
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Nuclei扫描失败: {e}")
        raise HTTPException(status_code=500, detail=f"Nuclei扫描失败: {e}")


@router.get("/tools/status", summary="获取工具状态")
async def get_tools_status():
    """获取所有安全工具的可用性状态"""
    try:
        from tools.integration import tool_manager
        return tool_manager.get_tool_status()
    except Exception as e:
        log.error(f"获取工具状态失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取工具状态失败: {e}")


# ============== 内网渗透增强API ==============

@router.post("/internal/scan", summary="内网扫描")
async def internal_scan(request: InternalScanRequest):
    """内网多线程扫描（端口/服务/SMB/NetBIOS）"""
    try:
        from internal_pentest.enhanced import InternalPentestEnhanced
        scanner = InternalPentestEnhanced(max_workers=request.max_workers)
        hosts = scanner.scan_network(request.target, request.ports or None)
        return scanner.get_report()
    except Exception as e:
        log.error(f"内网扫描失败: {e}")
        raise HTTPException(status_code=500, detail=f"内网扫描失败: {e}")


@router.post("/internal/smb/enum", summary="SMB共享枚举")
async def smb_enum(request: SMBEnumRequest):
    """枚举SMB共享和空会话测试"""
    try:
        from internal_pentest.enhanced import SMBEnumerator
        enumerator = SMBEnumerator()
        
        shares = enumerator.enumerate_shares(
            ip=request.ip,
            username=request.username or None,
            password=request.password or None,
            domain=request.domain or None
        )
        
        null_session = enumerator.null_session_test(request.ip)
        
        return {
            "ip": request.ip,
            "shares": shares,
            "null_session": null_session,
            "total_shares": len(shares),
            "sensitive_shares": sum(1 for s in shares if s.get("sensitive", False))
        }
    except Exception as e:
        log.error(f"SMB枚举失败: {e}")
        raise HTTPException(status_code=500, detail=f"SMB枚举失败: {e}")


@router.post("/internal/netbios/query", summary="NetBIOS名称查询")
async def netbios_query(ip: str = Query(..., description="目标IP")):
    """查询NetBIOS名称、域名、用户和MAC地址"""
    try:
        from internal_pentest.enhanced import NetBIOSEnumerator
        enumerator = NetBIOSEnumerator()
        return enumerator.get_name(ip)
    except Exception as e:
        log.error(f"NetBIOS查询失败: {e}")
        raise HTTPException(status_code=500, detail=f"NetBIOS查询失败: {e}")


@router.post("/internal/ldap/query", summary="LDAP域查询")
async def ldap_query(request: LDAPQueryRequest):
    """LDAP域信息查询（用户/计算机/组/SPN/Kerberoasting）"""
    try:
        from internal_pentest.enhanced import LDAPDomainQuerier
        querier = LDAPDomainQuerier(
            dc_ip=request.dc_ip,
            username=request.username or None,
            password=request.password or None,
            domain=request.domain or None
        )
        
        if not querier.connect():
            raise HTTPException(status_code=503, detail="LDAP连接失败，请检查凭证和网络")
        
        try:
            if request.query_type == "kerberoast":
                result = querier.kerberoast()
                return {"type": "kerberoast", "spn_targets": result, "total": len(result)}
            else:
                domain_info = querier.get_domain_info()
                from dataclasses import asdict
                return asdict(domain_info)
        finally:
            querier.disconnect()
            
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"LDAP查询失败: {e}")
        raise HTTPException(status_code=500, detail=f"LDAP查询失败: {e}")


# ============== 云安全增强API ==============

@router.post("/cloud/scan", summary="云安全扫描")
async def cloud_scan(request: CloudScanRequest):
    """云服务商安全配置检查（AWS/Azure/阿里云）"""
    try:
        from cloud_security.enhanced import cloud_security_manager
        
        # 配置AWS凭证（如果提供）
        if request.aws_access_key and request.aws_secret_key:
            cloud_security_manager.aws_checker.access_key = request.aws_access_key
            cloud_security_manager.aws_checker.secret_key = request.aws_secret_key
            cloud_security_manager.aws_checker.region = request.aws_region
        
        if request.provider == "all":
            return cloud_security_manager.check_all_providers()
        elif request.provider == "aws":
            findings = cloud_security_manager.aws_checker.run_all_checks()
            return {"provider": "AWS", "total_findings": len(findings), 
                    "findings": [vars(f) for f in findings]}
        elif request.provider == "azure":
            findings = cloud_security_manager.azure_checker.run_all_checks()
            return {"provider": "Azure", "total_findings": len(findings),
                    "findings": [vars(f) for f in findings]}
        elif request.provider == "aliyun":
            findings = cloud_security_manager.aliyun_checker.run_all_checks()
            return {"provider": "Aliyun", "total_findings": len(findings),
                    "findings": [vars(f) for f in findings]}
        else:
            raise HTTPException(status_code=400, detail=f"不支持的云服务商: {request.provider}")
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"云安全扫描失败: {e}")
        raise HTTPException(status_code=500, detail=f"云安全扫描失败: {e}")


@router.post("/cloud/dockerfile/check", summary="Dockerfile安全检查")
async def dockerfile_check(request: DockerfileCheckRequest):
    """检查Dockerfile的安全配置"""
    try:
        from cloud_security.enhanced import cloud_security_manager
        return cloud_security_manager.check_dockerfile(request.path)
    except Exception as e:
        log.error(f"Dockerfile检查失败: {e}")
        raise HTTPException(status_code=500, detail=f"Dockerfile检查失败: {e}")


@router.post("/cloud/k8s/check", summary="K8s清单安全检查")
async def k8s_manifest_check(request: K8sManifestCheckRequest):
    """检查Kubernetes清单的安全配置"""
    try:
        from cloud_security.enhanced import cloud_security_manager
        return cloud_security_manager.check_k8s_manifest(request.path)
    except Exception as e:
        log.error(f"K8s清单检查失败: {e}")
        raise HTTPException(status_code=500, detail=f"K8s清单检查失败: {e}")


# ============== 性能监控API ==============

@router.get("/performance/stats", summary="获取性能统计")
async def get_performance_stats():
    """获取系统性能监控统计（延迟/缓存/资源使用）"""
    try:
        from utils.performance import performance_monitor, global_cache
        return {
            "performance_monitor": performance_monitor.get_all_stats(),
            "global_cache": global_cache.get_stats()
        }
    except Exception as e:
        log.error(f"获取性能统计失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取性能统计失败: {e}")


@router.post("/performance/cache/clear", summary="清空缓存")
async def clear_cache():
    """清空全局缓存"""
    try:
        from utils.performance import global_cache
        global_cache.clear()
        return {"success": True, "message": "缓存已清空"}
    except Exception as e:
        log.error(f"清空缓存失败: {e}")
        raise HTTPException(status_code=500, detail=f"清空缓存失败: {e}")


# ============== 多用户管理API ==============

@router.post("/users/create", summary="创建用户")
async def create_user(request: UserCreateRequest):
    """创建新用户"""
    try:
        from utils.multi_user import user_manager
        user = user_manager.create_user(
            username=request.username,
            password=request.password,
            email=request.email,
            role=request.role,
            tenant_id=request.tenant_id
        )
        if not user:
            raise HTTPException(status_code=400, detail="用户创建失败，可能用户名已存在或角色无效")
        from dataclasses import asdict
        user_dict = asdict(user)
        user_dict.pop("password_hash", None)
        user_dict.pop("salt", None)
        return {"success": True, "user": user_dict}
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"创建用户失败: {e}")
        raise HTTPException(status_code=500, detail=f"创建用户失败: {e}")


@router.post("/users/login", summary="用户登录")
async def user_login(request: UserLoginRequest):
    """用户登录，返回会话ID"""
    try:
        from utils.multi_user import user_manager
        session = user_manager.authenticate(request.username, request.password)
        if not session:
            raise HTTPException(status_code=401, detail="用户名或密码错误")
        from dataclasses import asdict
        return {"success": True, "session": asdict(session)}
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"用户登录失败: {e}")
        raise HTTPException(status_code=500, detail=f"用户登录失败: {e}")


@router.post("/users/logout", summary="用户登出")
async def user_logout(session_id: str = Query(..., description="会话ID")):
    """用户登出"""
    try:
        from utils.multi_user import user_manager
        user_manager.logout(session_id)
        return {"success": True, "message": "已登出"}
    except Exception as e:
        log.error(f"用户登出失败: {e}")
        raise HTTPException(status_code=500, detail=f"用户登出失败: {e}")


@router.get("/users/list", summary="列出用户")
async def list_users():
    """列出所有用户"""
    try:
        from utils.multi_user import user_manager
        from dataclasses import asdict
        users = user_manager.list_users()
        user_list = []
        for u in users:
            u_dict = asdict(u)
            u_dict.pop("password_hash", None)
            u_dict.pop("salt", None)
            user_list.append(u_dict)
        return {"total": len(user_list), "users": user_list}
    except Exception as e:
        log.error(f"列出用户失败: {e}")
        raise HTTPException(status_code=500, detail=f"列出用户失败: {e}")


@router.get("/users/roles", summary="列出角色")
async def list_roles():
    """列出所有角色和权限"""
    try:
        from utils.multi_user import user_manager, PERMISSIONS
        from dataclasses import asdict
        roles = [asdict(r) for r in user_manager.list_roles()]
        return {"roles": roles, "all_permissions": PERMISSIONS}
    except Exception as e:
        log.error(f"列出角色失败: {e}")
        raise HTTPException(status_code=500, detail=f"列出角色失败: {e}")


@router.post("/users/api-key/create", summary="创建API密钥")
async def create_api_key(request: APIKeyCreateRequest):
    """为用户创建API密钥（仅返回一次明文）"""
    try:
        from utils.multi_user import user_manager
        api_key = user_manager.create_api_key(
            username=request.username,
            name=request.name,
            expires_days=request.expires_days
        )
        if not api_key:
            raise HTTPException(status_code=400, detail="API密钥创建失败")
        return {"success": True, "api_key": api_key, "message": "请妥善保存，仅显示一次"}
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"创建API密钥失败: {e}")
        raise HTTPException(status_code=500, detail=f"创建API密钥失败: {e}")


@router.get("/users/audit-logs", summary="获取审计日志")
async def get_audit_logs(username: str = Query(None, description="用户名过滤"),
                          action: str = Query(None, description="动作过滤"),
                          limit: int = Query(100, description="返回数量")):
    """获取操作审计日志"""
    try:
        from utils.multi_user import user_manager
        from dataclasses import asdict
        logs = user_manager.get_audit_logs(username=username, action=action, limit=limit)
        return {"total": len(logs), "logs": [asdict(l) for l in logs]}
    except Exception as e:
        log.error(f"获取审计日志失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取审计日志失败: {e}")


@router.get("/users/stats", summary="获取用户系统统计")
async def get_user_stats():
    """获取多用户系统统计信息"""
    try:
        from utils.multi_user import user_manager
        return user_manager.get_stats()
    except Exception as e:
        log.error(f"获取用户统计失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取用户统计失败: {e}")


# ============== 分布式扫描API ==============

@router.post("/distributed/scan", summary="提交分布式扫描任务")
async def distributed_scan(request: DistributedScanRequest):
    """提交分布式扫描任务到任务队列"""
    try:
        from distributed.core import distributed_scanner
        task_id = distributed_scanner.scan(
            target=request.target,
            scan_type=request.scan_type,
            parameters=request.parameters,
            priority=request.priority
        )
        return {"success": True, "task_id": task_id, "message": "任务已提交"}
    except Exception as e:
        log.error(f"分布式扫描提交失败: {e}")
        raise HTTPException(status_code=500, detail=f"分布式扫描提交失败: {e}")


@router.get("/distributed/scan/{task_id}", summary="获取扫描任务结果")
async def get_distributed_scan_result(task_id: str):
    """获取分布式扫描任务的状态和结果"""
    try:
        from distributed.core import distributed_scanner
        result = distributed_scanner.get_scan_result(task_id)
        if not result:
            raise HTTPException(status_code=404, detail="任务不存在")
        return result
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"获取扫描结果失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取扫描结果失败: {e}")


@router.post("/distributed/nodes/register", summary="注册扫描节点")
async def register_node(request: NodeRegisterRequest):
    """注册新的扫描节点"""
    try:
        from distributed.core import distributed_scanner
        from dataclasses import asdict
        node = distributed_scanner.node_manager.register_node(
            name=request.name,
            address=request.address,
            capabilities=request.capabilities
        )
        return {"success": True, "node": asdict(node)}
    except Exception as e:
        log.error(f"注册节点失败: {e}")
        raise HTTPException(status_code=500, detail=f"注册节点失败: {e}")


@router.get("/distributed/nodes/list", summary="列出扫描节点")
async def list_nodes():
    """列出所有扫描节点及其状态"""
    try:
        from distributed.core import distributed_scanner
        from dataclasses import asdict
        nodes = distributed_scanner.node_manager.list_nodes()
        return {"total": len(nodes), "nodes": [asdict(n) for n in nodes]}
    except Exception as e:
        log.error(f"列出节点失败: {e}")
        raise HTTPException(status_code=500, detail=f"列出节点失败: {e}")


@router.post("/distributed/nodes/{node_id}/heartbeat", summary="节点心跳")
async def node_heartbeat(node_id: str, cpu_usage: float = Query(0), 
                          memory_usage: float = Query(0), current_tasks: int = Query(0)):
    """扫描节点心跳上报"""
    try:
        from distributed.core import distributed_scanner
        success = distributed_scanner.node_manager.heartbeat(
            node_id=node_id,
            cpu_usage=cpu_usage,
            memory_usage=memory_usage,
            current_tasks=current_tasks
        )
        if not success:
            raise HTTPException(status_code=404, detail="节点不存在")
        return {"success": True, "message": "心跳已更新"}
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"节点心跳失败: {e}")
        raise HTTPException(status_code=500, detail=f"节点心跳失败: {e}")


@router.post("/distributed/proxies/add", summary="添加代理")
async def add_proxy(request: ProxyAddRequest):
    """添加代理服务器到代理池"""
    try:
        from distributed.core import distributed_scanner
        from dataclasses import asdict
        proxy = distributed_scanner.proxy_pool.add_proxy(
            address=request.address,
            protocol=request.protocol,
            username=request.username,
            password=request.password
        )
        return {"success": True, "proxy": asdict(proxy)}
    except Exception as e:
        log.error(f"添加代理失败: {e}")
        raise HTTPException(status_code=500, detail=f"添加代理失败: {e}")


@router.get("/distributed/proxies/list", summary="列出代理")
async def list_proxies():
    """列出代理池中的所有代理"""
    try:
        from distributed.core import distributed_scanner
        from dataclasses import asdict
        proxies = distributed_scanner.proxy_pool.list_proxies()
        return {"total": len(proxies), "proxies": [asdict(p) for p in proxies]}
    except Exception as e:
        log.error(f"列出代理失败: {e}")
        raise HTTPException(status_code=500, detail=f"列出代理失败: {e}")


@router.get("/distributed/stats", summary="获取分布式系统统计")
async def get_distributed_stats():
    """获取分布式扫描系统的整体统计"""
    try:
        from distributed.core import distributed_scanner
        return distributed_scanner.get_overall_stats()
    except Exception as e:
        log.error(f"获取分布式统计失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取分布式统计失败: {e}")


@router.get("/distributed/tasks/list", summary="列出分布式任务")
async def list_distributed_tasks(status: str = Query(None, description="状态过滤"),
                                  limit: int = Query(100, description="返回数量")):
    """列出分布式扫描任务"""
    try:
        from distributed.core import distributed_scanner
        from dataclasses import asdict
        tasks = distributed_scanner.task_distributor.list_tasks(status=status, limit=limit)
        return {"total": len(tasks), "tasks": [asdict(t) for t in tasks]}
    except Exception as e:
        log.error(f"列出分布式任务失败: {e}")
        raise HTTPException(status_code=500, detail=f"列出分布式任务失败: {e}")


# ============== 综合状态API ==============

@router.get("/status", summary="增强模块综合状态")
async def get_enhanced_status():
    """获取所有增强模块的综合状态和统计"""
    try:
        from tools.integration import tool_manager
        from utils.performance import performance_monitor, global_cache
        from utils.multi_user import user_manager
        from distributed.core import distributed_scanner
        
        return {
            "tools": tool_manager.get_tool_status(),
            "performance": {
                "monitor": performance_monitor.get_all_stats(),
                "cache": global_cache.get_stats()
            },
            "users": user_manager.get_stats(),
            "distributed": distributed_scanner.get_overall_stats(),
            "modules": {
                "tools_integration": "available",
                "internal_pentest_enhanced": "available",
                "cloud_security_enhanced": "available",
                "performance_optimization": "available",
                "multi_user_system": "available",
                "distributed_scanning": "available"
            }
        }
    except Exception as e:
        log.error(f"获取综合状态失败: {e}")
        raise HTTPException(status_code=500, detail=f"获取综合状态失败: {e}")
