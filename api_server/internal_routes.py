#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
内网渗透API路由模块，提供SMB扫描、LDAP查询、Kerberos攻击、哈希传递等内网渗透功能的REST API接口。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
from datetime import datetime

router = APIRouter(prefix="/api/v1/internal", tags=["内网渗透"])


# ========== 请求模型 ==========

class TargetRequest(BaseModel):
    """TargetRequest类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    target: str
    port: Optional[int] = None
    timeout: Optional[int] = 10


class SMBRequest(BaseModel):
    """SMBRequest类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    target: str
    ports: Optional[List[int]] = [139, 445]
    timeout: Optional[int] = 10
    enumerate_shares: Optional[bool] = True


class LDAPRequest(BaseModel):
    """LDAPRequest类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    server: str
    domain: str = ""
    username: str = ""
    password: str = ""
    filter: str = ""
    base_dn: str = ""


class KerberosRequest(BaseModel):
    """KerberosRequest类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    domain: str
    dc_ip: str = ""
    username: str = ""
    password: str = ""
    target_users: Optional[List[str]] = None


class HashPassRequest(BaseModel):
    """HashPassRequest类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    target: str
    username: str
    ntlm_hash: str
    domain: str = ""
    protocol: str = "smb"  # smb, wmi, winrm, rdp
    command: str = ""


class LateralMoveRequest(BaseModel):
    """LateralMoveRequest类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    target: str
    method: str = "psexec"  # wmi, psexec, winrm, smb, schtasks, sc, dcom
    command: str = "whoami"
    username: str = ""
    password: str = ""
    ntlm_hash: str = ""
    domain: str = ""


class PortForwardRequest(BaseModel):
    """PortForwardRequest类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    local_port: int
    target_host: str
    target_port: int
    forward_type: str = "local"  # local, remote, dynamic
    local_host: str = "127.0.0.1"


class DNSRequest(BaseModel):
    """DNSRequest类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    domain: str
    record_type: str = "all"  # a, aaaa, mx, ns, txt, soa, srv, all
    wordlist: Optional[List[str]] = None


class ADAssessRequest(BaseModel):
    """ADAssessRequest类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    domain: str
    dc_ip: str = ""
    username: str = ""
    password: str = ""


# ========== SMB扫描路由 ==========

@router.post("/smb/scan", summary="SMB端口扫描")
async def smb_scan(request: SMBRequest):
    """扫描目标的SMB端口（139/445）"""
    try:
        from internal.smb_scanner import smb_scanner
        results = smb_scanner.scan_target(request.target, request.ports, request.timeout)
        return {
            "status": "success",
            "target": request.target,
            "results": [r.to_dict() for r in results],
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/smb/enumerate", summary="SMB共享枚举")
async def smb_enumerate(request: SMBRequest):
    """枚举目标的SMB共享"""
    try:
        from internal.smb_scanner import smb_scanner
        shares = smb_scanner.enumerate_shares(request.target, request.timeout)
        return {
            "status": "success",
            "target": request.target,
            "shares": [s.to_dict() for s in shares],
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/smb/stats", summary="SMB扫描统计")
async def smb_stats():
    """获取SMB扫描统计信息"""
    from internal.smb_scanner import smb_scanner
    return smb_scanner.get_statistics()


# ========== LDAP查询路由 ==========

@router.post("/ldap/query", summary="LDAP查询")
async def ldap_query(request: LDAPRequest):
    """执行LDAP查询"""
    try:
        from internal.ldap_query import LDAPQuerier
        querier = LDAPQuerier(
            server=request.server,
            domain=request.domain,
            username=request.username,
            password=request.password,
        )
        connected = querier.connect()
        if not connected:
            raise HTTPException(status_code=400, detail="LDAP连接失败")

        entries = querier.query(request.filter)
        return {
            "status": "success",
            "server": request.server,
            "domain": request.domain,
            "entries_count": len(entries),
            "entries": [e.to_dict() for e in entries],
            "timestamp": datetime.now().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ldap/filters", summary="获取LDAP过滤器列表")
async def ldap_filters():
    """获取内置的LDAP过滤器"""
    from internal.ldap_query import LDAPQuerier
    return {
        "filters": LDAPQuerier.FILTERS,
        "total": len(LDAPQuerier.FILTERS),
    }


# ========== Kerberos攻击路由 ==========

@router.post("/kerberos/kerberoast", summary="Kerberoasting攻击")
async def kerberoast(request: KerberosRequest):
    """执行Kerberoasting攻击，请求服务账户TGS票据"""
    try:
        from internal.kerberos import KerberosTools
        tools = KerberosTools(
            domain=request.domain,
            dc_ip=request.dc_ip,
            username=request.username,
            password=request.password,
        )
        results = tools.kerberoast(request.target_users)
        return {
            "status": "success",
            "domain": request.domain,
            "results_count": len(results),
            "results": [r.to_dict() for r in results],
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/kerberos/asrep-roast", summary="AS-REP Roasting攻击")
async def asrep_roast(request: KerberosRequest):
    """执行AS-REP Roasting攻击"""
    try:
        from internal.kerberos import KerberosTools
        tools = KerberosTools(
            domain=request.domain,
            dc_ip=request.dc_ip,
            username=request.username,
            password=request.password,
        )
        results = tools.asrep_roast(request.target_users)
        return {
            "status": "success",
            "domain": request.domain,
            "results_count": len(results),
            "results": [r.to_dict() for r in results],
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/kerberos/golden-ticket", summary="创建黄金票据")
async def golden_ticket(request: KerberosRequest):
    """创建黄金票据（需要KRBTGT哈希）"""
    try:
        from internal.kerberos import KerberosTools
        tools = KerberosTools(domain=request.domain, dc_ip=request.dc_ip)
        # 注意：实际使用需要提供krbtgt_hash和domain_sid
        ticket = tools.create_golden_ticket(
            krbtgt_hash=request.password or "placeholder",
            domain_sid="S-1-5-21-placeholder",
            target_user=request.username or "Administrator",
        )
        return {
            "status": "success",
            "ticket": ticket.to_dict(),
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ========== 哈希传递路由 ==========

@router.post("/hash-pass", summary="哈希传递攻击")
async def hash_pass(request: HashPassRequest):
    """使用NTLM哈希进行身份验证"""
    try:
        from internal.hash_pass import HashPasser
        passer = HashPasser(
            username=request.username,
            ntlm_hash=request.ntlm_hash,
            domain=request.domain,
        )

        if request.protocol == "smb":
            result = passer.pass_hash_smb(request.target, request.command)
        elif request.protocol == "wmi":
            result = passer.pass_hash_wmi(request.target, request.command)
        elif request.protocol == "winrm":
            result = passer.pass_hash_winrm(request.target, request.command)
        elif request.protocol == "rdp":
            result = passer.pass_hash_rdp(request.target)
        else:
            raise HTTPException(status_code=400, detail=f"不支持的协议: {request.protocol}")

        return {
            "status": "success",
            "result": result.to_dict(),
            "timestamp": datetime.now().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/hash-pass/protocols", summary="获取支持的哈希传递协议")
async def hash_pass_protocols():
    """获取支持的哈希传递协议列表"""
    from internal.hash_pass import HashPasser
    return {
        "protocols": HashPasser.PROTOCOLS,
        "total": len(HashPasser.PROTOCOLS),
    }


# ========== 横向移动路由 ==========

@router.post("/lateral-move", summary="横向移动")
async def lateral_move(request: LateralMoveRequest):
    """在目标系统上执行命令（横向移动）"""
    try:
        from internal.lateral_movement import LateralMover
        mover = LateralMover(
            username=request.username,
            password=request.password,
            ntlm_hash=request.ntlm_hash,
            domain=request.domain,
        )

        method = request.method.lower()
        if method == "wmi":
            result = mover.execute_wmi(request.target, request.command)
        elif method == "psexec":
            result = mover.execute_psexec(request.target, request.command)
        elif method == "winrm":
            result = mover.execute_winrm(request.target, request.command)
        elif method == "smb":
            result = mover.execute_smb(request.target, request.command)
        elif method == "schtasks":
            result = mover.execute_schtasks(request.target, request.command)
        elif method == "sc":
            result = mover.execute_sc(request.target, request.command)
        elif method == "dcom":
            result = mover.execute_dcom(request.target, request.command)
        else:
            raise HTTPException(status_code=400, detail=f"不支持的方法: {request.method}")

        return {
            "status": "success",
            "method": method,
            "result": result.to_dict(),
            "timestamp": datetime.now().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/lateral-move/methods", summary="获取支持的横向移动方法")
async def lateral_move_methods():
    """获取支持的横向移动方法列表"""
    from internal.lateral_movement import LateralMover
    return {
        "methods": LateralMover.METHODS,
        "total": len(LateralMover.METHODS),
    }


# ========== 端口转发路由 ==========

@router.post("/port-forward/start", summary="启动端口转发")
async def port_forward_start(request: PortForwardRequest):
    """启动端口转发会话"""
    try:
        from internal.port_forward import port_forwarder

        if request.forward_type == "local":
            session = port_forwarder.local_forward(
                local_port=request.local_port,
                target_host=request.target_host,
                target_port=request.target_port,
                local_host=request.local_host,
            )
        elif request.forward_type == "dynamic":
            session = port_forwarder.dynamic_forward(
                local_port=request.local_port,
                local_host=request.local_host,
            )
        else:
            raise HTTPException(status_code=400, detail=f"不支持的转发类型: {request.forward_type}")

        return {
            "status": "success",
            "session": session.to_dict(),
            "timestamp": datetime.now().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/port-forward/stop/{session_id}", summary="停止端口转发")
async def port_forward_stop(session_id: str):
    """停止指定的端口转发会话"""
    from internal.port_forward import port_forwarder
    success = port_forwarder.stop_session(session_id)
    return {
        "status": "success" if success else "failed",
        "session_id": session_id,
    }


@router.get("/port-forward/sessions", summary="列出端口转发会话")
async def port_forward_sessions():
    """列出所有端口转发会话"""
    from internal.port_forward import port_forwarder
    sessions = port_forwarder.list_sessions()
    return {
        "sessions": [s.to_dict() for s in sessions],
        "total": len(sessions),
    }


# ========== DNS枚举路由 ==========

@router.post("/dns/query", summary="DNS查询")
async def dns_query(request: DNSRequest):
    """执行DNS记录查询"""
    try:
        from internal.dns_enum import DNSEnumerator
        enumerator = DNSEnumerator(domain=request.domain)

        record_type = request.record_type.lower()
        if record_type == "all":
            records = enumerator.query_all(request.domain)
        elif record_type == "a":
            records = enumerator.query_a(request.domain)
        elif record_type == "mx":
            records = enumerator.query_mx(request.domain)
        elif record_type == "ns":
            records = enumerator.query_ns(request.domain)
        elif record_type == "txt":
            records = enumerator.query_txt(request.domain)
        elif record_type == "soa":
            records = enumerator.query_soa(request.domain)
        else:
            records = enumerator.query_all(request.domain)

        return {
            "status": "success",
            "domain": request.domain,
            "record_type": record_type,
            "records_count": len(records),
            "records": [r.to_dict() for r in records],
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/dns/subdomains", summary="子域名枚举")
async def dns_subdomains(request: DNSRequest):
    """枚举子域名"""
    try:
        from internal.dns_enum import DNSEnumerator
        enumerator = DNSEnumerator(domain=request.domain)
        subdomains = enumerator.enumerate_subdomains(request.domain, request.wordlist)
        return {
            "status": "success",
            "domain": request.domain,
            "subdomains_found": len(subdomains),
            "subdomains": subdomains,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ========== AD安全评估路由 ==========

@router.post("/ad/assess", summary="AD域安全评估")
async def ad_assess(request: ADAssessRequest):
    """执行Active Directory域安全评估"""
    try:
        from internal.ad_assessment import ADAssessor
        assessor = ADAssessor(
            domain=request.domain,
            dc_ip=request.dc_ip,
            username=request.username,
            password=request.password,
        )
        report = assessor.assess_domain(request.domain)
        summary = assessor.get_report_summary(report)
        return {
            "status": "success",
            "domain": request.domain,
            "summary": summary,
            "report": report.to_dict(),
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ad/vulnerabilities", summary="获取已知AD漏洞列表")
async def ad_vulnerabilities():
    """获取已知的AD漏洞列表"""
    from internal.ad_assessment import ADAssessor
    return {
        "vulnerabilities": ADAssessor.AD_VULNERABILITIES,
        "total": len(ADAssessor.AD_VULNERABILITIES),
    }


# ========== 内网渗透总览路由 ==========

@router.get("/overview", summary="内网渗透模块总览")
async def internal_overview():
    """获取内网渗透模块总览信息"""
    return {
        "module": "内网渗透",
        "version": "1.0.0",
        "capabilities": {
            "smb_scan": "SMB端口扫描与共享枚举",
            "ldap_query": "LDAP查询（用户/组/计算机/OU）",
            "kerberos": "Kerberoasting/AS-REP Roasting/黄金票据/白银票据",
            "hash_pass": "哈希传递（SMB/WMI/WinRM/RDP）",
            "lateral_move": "横向移动（7种方法）",
            "port_forward": "端口转发（本地/远程/动态）",
            "dns_enum": "DNS枚举（9种记录类型）",
            "ad_assessment": "AD域安全评估（漏洞检测+攻击路径分析）",
        },
        "api_endpoints": 25,
        "timestamp": datetime.now().isoformat(),
    }
