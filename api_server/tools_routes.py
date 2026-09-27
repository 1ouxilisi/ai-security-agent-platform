#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
工具集成API路由模块，提供网络扫描、目录爆破、密码攻击、Web扫描等安全工具调用的REST API接口。

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

router = APIRouter(prefix="/api/v1/tools", tags=["工具集成"])


# ========== 请求模型 ==========

class ScanRequest(BaseModel):
    """ScanRequest类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    target: str
    ports: str = "1-1000"
    scan_type: str = "quick"  # quick, full, service, os, vuln, aggressive, stealth, custom
    rate: int = 1000


class DirectoryBruteRequest(BaseModel):
    """DirectoryBruteRequest类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    url: str
    tool: str = "gobuster"  # gobuster, ffuf, dirsearch
    wordlist: str = ""
    extensions: List[str] = None


class PasswordAttackRequest(BaseModel):
    """PasswordAttackRequest类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    target: str
    service: str = "ssh"  # ssh, ftp, smb, rdp, mysql, http-form
    username: str = ""
    wordlist: str = ""
    attack_type: str = "brute_force"  # brute_force, dictionary


class HashIdentifyRequest(BaseModel):
    """HashIdentifyRequest类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    hash_value: str


class WebScanRequest(BaseModel):
    """WebScanRequest类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    url: str
    scan_type: str = "nikto"  # nikto, whatweb, wpscan
    ssl: bool = False


# ========== 网络扫描路由 ==========

@router.post("/network/nmap/scan", summary="Nmap扫描")
async def nmap_scan(request: ScanRequest):
    """执行Nmap扫描"""
    try:
        from tools.network_scanners import nmap_advanced
        scan_type = request.scan_type.lower()

        if scan_type == "quick":
            result = nmap_advanced.quick_scan(request.target)
        elif scan_type == "full":
            result = nmap_advanced.full_scan(request.target)
        elif scan_type == "service":
            result = nmap_advanced.service_scan(request.target, request.ports)
        elif scan_type == "os":
            result = nmap_advanced.os_detection(request.target)
        elif scan_type == "vuln":
            result = nmap_advanced.vulnerability_scan(request.target, request.ports)
        elif scan_type == "aggressive":
            result = nmap_advanced.aggressive_scan(request.target)
        elif scan_type == "stealth":
            result = nmap_advanced.stealth_scan(request.target, request.ports)
        else:
            result = nmap_advanced.quick_scan(request.target)

        return {
            "status": "success",
            "scan_type": scan_type,
            "target": request.target,
            "result": result.to_dict(),
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/network/masscan/scan", summary="Masscan高速扫描")
async def masscan_scan(request: ScanRequest):
    """执行Masscan高速端口扫描"""
    try:
        from tools.network_scanners import masscan_scanner
        results = masscan_scanner.scan(request.target, request.ports, request.rate)
        return {
            "status": "success",
            "target": request.target,
            "rate": request.rate,
            "results": [r.to_dict() for r in results],
            "total": len(results),
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ========== 目录爆破路由 ==========

@router.post("/directory/brute", summary="目录爆破")
async def directory_brute(request: DirectoryBruteRequest):
    """执行目录爆破"""
    try:
        tool = request.tool.lower()

        if tool == "gobuster":
            from tools.directory_bruteforce import gobuster
            results = gobuster.dir_scan(request.url, request.wordlist, request.extensions)
        elif tool == "ffuf":
            from tools.directory_bruteforce import ffuf
            results = ffuf.fuzz_directory(request.url, request.wordlist)
        elif tool == "dirsearch":
            from tools.directory_bruteforce import dirsearch
            results = dirsearch.scan(request.url, ",".join(request.extensions or []), request.wordlist)
        else:
            raise HTTPException(status_code=400, detail=f"不支持的工具: {request.tool}")

        return {
            "status": "success",
            "tool": tool,
            "url": request.url,
            "results": [r.to_dict() for r in results],
            "total": len(results),
            "timestamp": datetime.now().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ========== 密码攻击路由 ==========

@router.post("/password/brute-force", summary="在线暴力破解")
async def password_brute_force(request: PasswordAttackRequest):
    """执行在线暴力破解（Hydra）"""
    try:
        from tools.password_attacks import hydra
        result = hydra.brute_force(
            target=request.target,
            service=request.service,
            username=request.username,
            wordlist=request.wordlist,
        )
        return {
            "status": "success",
            "target": request.target,
            "service": request.service,
            "result": result.to_dict(),
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/password/identify-hash", summary="哈希类型识别")
async def identify_hash(request: HashIdentifyRequest):
    """识别哈希类型"""
    try:
        from tools.password_attacks import hash_identifier
        results = hash_identifier.identify(request.hash_value)
        return {
            "status": "success",
            "hash": request.hash_value[:20] + "..." if len(request.hash_value) > 20 else request.hash_value,
            "possible_types": results,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/password/services", summary="获取支持的暴力破解服务")
async def password_services():
    """获取Hydra支持的服务列表"""
    from tools.password_attacks import Hydra
    return {
        "services": Hydra.SUPPORTED_SERVICES,
        "total": len(Hydra.SUPPORTED_SERVICES),
    }


# ========== Web扫描路由 ==========

@router.post("/web/scan", summary="Web扫描")
async def web_scan(request: WebScanRequest):
    """执行Web扫描"""
    try:
        scan_type = request.scan_type.lower()

        if scan_type == "nikto":
            from tools.web_scanners import nikto
            results = nikto.scan(request.url, ssl=request.ssl)
        elif scan_type == "whatweb":
            from tools.web_scanners import whatweb
            result = whatweb.identify(request.url)
            return {
                "status": "success",
                "scan_type": scan_type,
                "url": request.url,
                "result": result.to_dict(),
                "timestamp": datetime.now().isoformat(),
            }
        elif scan_type == "wpscan":
            from tools.web_scanners import wpscan
            result = wpscan.scan(request.url)
            return {
                "status": "success",
                "scan_type": scan_type,
                "url": request.url,
                "result": result,
                "timestamp": datetime.now().isoformat(),
            }
        else:
            raise HTTPException(status_code=400, detail=f"不支持的扫描类型: {request.scan_type}")

        return {
            "status": "success",
            "scan_type": scan_type,
            "url": request.url,
            "results": [r.to_dict() for r in results],
            "total": len(results),
            "timestamp": datetime.now().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ========== 工具管理路由 ==========

@router.get("/manager/list", summary="列出所有工具")
async def tool_list(category: str = ""):
    """列出所有已注册的安全工具"""
    from tools.tool_manager import tool_manager
    tools = tool_manager.list_tools(category)
    return {
        "tools": [t.to_dict() for t in tools],
        "total": len(tools),
        "categories": tool_manager.list_categories(),
    }


@router.get("/manager/stats", summary="工具管理统计")
async def tool_stats():
    """获取工具管理统计信息"""
    from tools.tool_manager import tool_manager
    return tool_manager.get_statistics()


@router.post("/manager/check", summary="检查工具安装状态")
async def tool_check(name: str):
    """检查指定工具的安装状态"""
    from tools.tool_manager import tool_manager
    installed = tool_manager.check_installed(name)
    tool = tool_manager.get_tool(name)
    return {
        "name": name,
        "installed": installed,
        "info": tool.to_dict() if tool else None,
    }


@router.post("/manager/check-all", summary="检查所有工具安装状态")
async def tool_check_all():
    """检查所有工具的安装状态"""
    from tools.tool_manager import tool_manager
    results = tool_manager.check_all_installed()
    return {
        "results": results,
        "total": len(results),
        "installed": sum(1 for v in results.values() if v),
        "not_installed": sum(1 for v in results.values() if not v),
    }


@router.get("/manager/search", summary="搜索工具")
async def tool_search(keyword: str):
    """搜索安全工具"""
    from tools.tool_manager import tool_manager
    results = tool_manager.search_tools(keyword)
    return {
        "keyword": keyword,
        "results": [t.to_dict() for t in results],
        "total": len(results),
    }


@router.get("/manager/install-script", summary="生成工具安装脚本")
async def tool_install_script(os_type: str = "kali"):
    """生成工具安装脚本"""
    from tools.tool_manager import tool_manager
    script = tool_manager.generate_install_script(os_type=os_type)
    return {
        "os_type": os_type,
        "script": script,
    }


# ========== 工具集成总览路由 ==========

@router.get("/overview", summary="工具集成模块总览")
async def tools_overview():
    """获取工具集成模块总览信息"""
    from tools.tool_manager import tool_manager
    stats = tool_manager.get_statistics()
    return {
        "module": "工具集成",
        "version": "1.0.0",
        "capabilities": {
            "network_scanning": "网络扫描（Nmap高级 + Masscan高速）",
            "directory_bruteforce": "目录爆破（Gobuster + FFuF + Dirsearch）",
            "password_attacks": "密码攻击（Hydra + John + Hash识别）",
            "web_scanning": "Web扫描（Nikto + WhatWeb + WPScan）",
            "tool_management": "工具管理器（57+工具统一管理）",
        },
        "total_tools": stats["total_tools"],
        "installed_tools": stats["installed"],
        "categories": stats["categories"],
        "api_endpoints": 18,
        "timestamp": datetime.now().isoformat(),
    }
