# -*- coding: utf-8 -*-
"""真实工具链API路由 - Nmap/Nuclei/Subfinder/Httpx/Nikto/Sqlmap"""
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

router = APIRouter(prefix="/api/v1/real-tools", tags=["真实工具链"])


class NmapScanReq(BaseModel):
    target: str
    mode: str = "quick"
    timeout: int = 180


class NucleiScanReq(BaseModel):
    target: str
    severity: str = "critical,high"
    timeout: int = 120


class SubfinderReq(BaseModel):
    domain: str
    timeout: int = 60


class HttpxReq(BaseModel):
    targets: List[str] = Field(default_factory=list)


class NiktoReq(BaseModel):
    target: str
    timeout: int = 120


class SqlmapReq(BaseModel):
    target: str
    data: str = ""
    level: int = 3
    risk: int = 2
    timeout: int = 180


@router.get("/check")
def tools_check():
    """检查所有真实工具可用性"""
    from asm.real_tools import RealToolExecutor
    return {"success": True, "data": RealToolExecutor.check_tools()}


@router.post("/nmap/scan")
def nmap_scan(req: NmapScanReq):
    """Nmap真实扫描"""
    from asm.real_tools import NmapRunner
    runner = NmapRunner(req.target, req.timeout)
    if req.mode == "detailed":
        return {"success": True, "data": runner.detailed_scan()}
    elif req.mode == "vuln":
        return {"success": True, "data": runner.vuln_scan()}
    else:
        return {"success": True, "data": runner.quick_scan()}


@router.post("/nuclei/scan")
def nuclei_scan(req: NucleiScanReq):
    """Nuclei真实漏洞扫描"""
    from asm.real_tools import NucleiRunner
    runner = NucleiRunner(req.target, req.timeout)
    return {"success": True, "data": runner.scan(req.severity)}


@router.post("/subfinder/enum")
def subfinder_enum(req: SubfinderReq):
    """Subfinder子域名枚举"""
    from asm.real_tools import SubfinderRunner
    runner = SubfinderRunner(req.domain, req.timeout)
    return {"success": True, "data": runner.enumerate()}


@router.post("/httpx/probe")
def httpx_probe(req: HttpxReq):
    """Httpx存活探测"""
    from asm.real_tools import HttpxRunner
    if not req.targets:
        return {"success": False, "error": "targets不能为空"}
    runner = HttpxRunner(req.targets)
    return {"success": True, "data": runner.probe()}


@router.post("/nikto/scan")
def nikto_scan(req: NiktoReq):
    """Nikto Web服务器扫描"""
    from asm.real_tools import NiktoRunner
    runner = NiktoRunner(req.target, req.timeout)
    return {"success": True, "data": runner.scan()}


@router.post("/sqlmap/scan")
def sqlmap_scan(req: SqlmapReq):
    """SQLMap SQL注入检测"""
    from asm.real_tools import SqlmapRunner
    runner = SqlmapRunner(req.target, req.timeout)
    return {"success": True, "data": runner.scan(data=req.data, level=req.level, risk=req.risk)}
