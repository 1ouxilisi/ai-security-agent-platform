#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vuln_routesAPI服务模块，提供相关REST API接口和Web服务功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import asyncio
from typing import Any, Dict, List, Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field

from utils.logger import log
from knowledge.vuln_database import get_vuln_db, Vulnerability
from knowledge.nvd_sync import NVDSync
from knowledge.exploit_db import ExploitDB
from knowledge.vulners_api import VulnersAPI
from knowledge.vuln_intel import VulnIntelligence

router = APIRouter(prefix="/api/v1/vuln", tags=["漏洞数据库"])


# ============== 请求/响应模型 ==============

class VulnSearchResponse(BaseModel):
    """VulnSearchResponse类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    total: int
    results: List[Dict[str, Any]]
    limit: int
    offset: int


class VulnSyncRequest(BaseModel):
    """VulnSyncRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    days: int = Field(30, description="同步最近N天的漏洞")
    max_results: int = Field(5000, description="最大同步数量")


class VulnSyncResponse(BaseModel):
    """VulnSyncResponse类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    status: str
    synced: int = 0
    added: int = 0
    updated: int = 0
    errors: int = 0
    message: str = ""


class VulnMatchRequest(BaseModel):
    """VulnMatchRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    service: str = Field(..., description="服务名称，如 Apache、Nginx")
    version: str = Field("", description="版本号，如 2.4.49")


class VulnAlertResponse(BaseModel):
    """VulnAlertResponse类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    total: int
    alerts: List[Dict[str, Any]]


class VulnAlertCheckResponse(BaseModel):
    """VulnAlertCheckResponse类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    status: str
    new_alerts: int
    alerts: List[Dict[str, Any]]


# ============== 漏洞查询接口 ==============

@router.get("/search", response_model=VulnSearchResponse)
async def search_vulnerabilities(
    keyword: str = Query("", description="搜索关键词"),
    severity: str = Query("", description="严重程度: critical/high/medium/low/info"),
    vendor: str = Query("", description="厂商名称"),
    product: str = Query("", description="产品名称"),
    cwe: str = Query("", description="CWE编号，如 CWE-89"),
    has_exploit: bool = Query(False, description="仅显示有利用代码的漏洞"),
    has_poc: bool = Query(False, description="仅显示有POC的漏洞"),
    kev_only: bool = Query(False, description="仅显示CISA KEV漏洞"),
    limit: int = Query(50, ge=1, le=500, description="返回数量"),
    offset: int = Query(0, ge=0, description="偏移量"),
):
    """搜索漏洞数据库"""
    try:
        db = get_vuln_db()
        results, total = db.search(
            keyword=keyword,
            severity=severity,
            vendor=vendor,
            product=product,
            cwe=cwe,
            has_exploit=has_exploit,
            has_poc=has_poc,
            kev_only=kev_only,
            limit=limit,
            offset=offset,
        )
        return {
            "total": total,
            "results": [v.to_dict() for v in results],
            "limit": limit,
            "offset": offset,
        }
    except Exception as e:
        log.error(f"搜索漏洞失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_vuln_stats():
    """获取漏洞数据库统计信息"""
    try:
        db = get_vuln_db()
        return db.get_stats()
    except Exception as e:
        log.error(f"获取统计失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/recent")
async def get_recent_vulnerabilities(
    days: int = Query(30, description="最近N天"),
    limit: int = Query(50, ge=1, le=200, description="返回数量"),
):
    """获取最近发布的漏洞"""
    try:
        db = get_vuln_db()
        results = db.get_recent(days=days, limit=limit)
        return {
            "days": days,
            "total": len(results),
            "results": [v.to_dict() for v in results],
        }
    except Exception as e:
        log.error(f"获取最近漏洞失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/top-exploitable")
async def get_top_exploitable(
    limit: int = Query(20, ge=1, le=100, description="返回数量"),
):
    """获取最可能被利用的漏洞（KEV + 有EXP + 高CVSS）"""
    try:
        db = get_vuln_db()
        results = db.get_top_exploitable(limit=limit)
        return {
            "total": len(results),
            "results": [v.to_dict() for v in results],
        }
    except Exception as e:
        log.error(f"获取高危漏洞失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{cve_id}")
async def get_vulnerability(cve_id: str):
    """获取单个漏洞详情"""
    try:
        db = get_vuln_db()
        vuln = db.get(cve_id)
        if not vuln:
            raise HTTPException(status_code=404, detail=f"漏洞 {cve_id} 不存在")
        return vuln.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"获取漏洞详情失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/match")
async def match_vulnerabilities(request: VulnMatchRequest):
    """根据服务/版本匹配已知漏洞"""
    try:
        db = get_vuln_db()
        results = db.match_by_service(request.service, request.version)
        return {
            "service": request.service,
            "version": request.version,
            "total": len(results),
            "results": [v.to_dict() for v in results],
        }
    except Exception as e:
        log.error(f"匹配漏洞失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============== 漏洞同步接口 ==============

@router.post("/sync/nvd", response_model=VulnSyncResponse)
async def sync_nvd(request: VulnSyncRequest, background_tasks: BackgroundTasks):
    """同步NVD漏洞数据（后台执行）"""
    try:
        background_tasks.add_task(_run_nvd_sync, request.days, request.max_results)
        return {
            "status": "running",
            "message": f"NVD同步已启动，同步最近{request.days}天，最多{request.max_results}条",
        }
    except Exception as e:
        log.error(f"启动NVD同步失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def _run_nvd_sync(days: int, max_results: int):
    """后台执行NVD同步"""
    try:
        log.info(f"开始NVD同步: days={days}, max={max_results}")
        nvd = NVDSync()
        result = await nvd.sync_recent(days=days, max_results=max_results)
        await nvd.close()
        log.info(f"NVD同步完成: {result}")
    except Exception as e:
        log.error(f"NVD同步失败: {e}")


@router.post("/sync/exploit-db", response_model=VulnSyncResponse)
async def sync_exploit_db(
    max_cves: int = Query(100, description="最多处理的CVE数量"),
    background_tasks: BackgroundTasks = None,
):
    """同步Exploit-DB POC数据（后台执行）"""
    try:
        background_tasks.add_task(_run_exploit_sync, max_cves)
        return {
            "status": "running",
            "message": f"Exploit-DB同步已启动，最多处理{max_cves}个CVE",
        }
    except Exception as e:
        log.error(f"启动Exploit-DB同步失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def _run_exploit_sync(max_cves: int):
    """后台执行Exploit-DB同步"""
    try:
        log.info(f"开始Exploit-DB同步: max_cves={max_cves}")
        edb = ExploitDB()
        result = await edb.sync_exploits_to_db(max_cves=max_cves)
        await edb.close()
        log.info(f"Exploit-DB同步完成: {result}")
    except Exception as e:
        log.error(f"Exploit-DB同步失败: {e}")


@router.get("/sync/status")
async def get_sync_status():
    """获取同步状态"""
    try:
        db = get_vuln_db()
        return {
            "last_sync": db.last_sync,
            "total_vulnerabilities": db.stats["total"],
            "by_source": db.stats["by_source"],
        }
    except Exception as e:
        log.error(f"获取同步状态失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============== POC接口 ==============

@router.get("/poc/{cve_id}")
async def get_poc_list(cve_id: str):
    """获取指定CVE的POC/EXP列表"""
    try:
        db = get_vuln_db()
        vuln = db.get(cve_id)
        if not vuln:
            raise HTTPException(status_code=404, detail=f"漏洞 {cve_id} 不存在")

        edb = ExploitDB(db=db)
        online_pocs = await edb.match_cve_to_exploits(cve_id)
        await edb.close()

        return {
            "cve_id": cve_id,
            "local_exploits": vuln.exploits,
            "local_poc_urls": vuln.poc_urls,
            "online_pocs": online_pocs,
            "total": len(vuln.exploits) + len(online_pocs),
        }
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"获取POC列表失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============== 漏洞告警接口 ==============

@router.get("/alerts", response_model=VulnAlertResponse)
async def get_alerts(
    status: str = Query("", description="告警状态: new/acknowledged/ignored"),
    severity: str = Query("", description="严重程度"),
    limit: int = Query(50, ge=1, le=200, description="返回数量"),
    offset: int = Query(0, ge=0, description="偏移量"),
):
    """获取漏洞告警列表"""
    try:
        intel = VulnIntelligence()
        alerts, total = intel.get_alerts(status=status, severity=severity, limit=limit, offset=offset)
        return {
            "total": total,
            "alerts": [a.to_dict() for a in alerts],
        }
    except Exception as e:
        log.error(f"获取告警失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/alerts/check", response_model=VulnAlertCheckResponse)
async def check_new_alerts(
    hours: int = Query(24, description="检查最近N小时的新漏洞"),
    background_tasks: BackgroundTasks = None,
):
    """检查新漏洞并生成告警（后台执行）"""
    try:
        background_tasks.add_task(_run_alert_check, hours)
        return {
            "status": "running",
            "new_alerts": 0,
            "alerts": [],
            "message": f"漏洞检查已启动，检查最近{hours}小时",
        }
    except Exception as e:
        log.error(f"启动漏洞检查失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def _run_alert_check(hours: int):
    """后台执行漏洞检查"""
    try:
        log.info(f"开始漏洞检查: hours={hours}")
        intel = VulnIntelligence()
        alerts = await intel.check_new_vulnerabilities(hours=hours)
        for alert in alerts:
            await intel.send_notification(alert)
        await intel.close()
        log.info(f"漏洞检查完成: 发现{len(alerts)}个新告警")
    except Exception as e:
        log.error(f"漏洞检查失败: {e}")


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str):
    """确认告警"""
    try:
        intel = VulnIntelligence()
        success = intel.acknowledge_alert(alert_id)
        if not success:
            raise HTTPException(status_code=404, detail=f"告警 {alert_id} 不存在")
        return {"status": "success", "alert_id": alert_id, "message": "告警已确认"}
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"确认告警失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts/stats")
async def get_alert_stats():
    """获取告警统计"""
    try:
        intel = VulnIntelligence()
        return intel.get_stats()
    except Exception as e:
        log.error(f"获取告警统计失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============== Vulners API接口 ==============

@router.get("/vulners/search")
async def vulners_search(
    query: str = Query(..., description="Lucene搜索语法，如 type:cve AND severity:critical"),
    limit: int = Query(20, ge=1, le=100, description="返回数量"),
):
    """通过Vulners API搜索漏洞情报（需配置VULNERS_API_KEY）"""
    try:
        from config.settings import settings
        api_key = getattr(settings, 'vulners_api_key', '') or os.environ.get('VULNERS_API_KEY', '')
        vulners = VulnersAPI(api_key=api_key)
        results = await vulners.search(query, limit=limit)
        await vulners.close()
        return {
            "query": query,
            "total": len(results),
            "results": results,
        }
    except Exception as e:
        log.error(f"Vulners搜索失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vulners/software")
async def vulners_check_software(
    software: str = Query(..., description="软件名称，如 apache"),
    version: str = Query(..., description="版本号，如 2.4.49"),
):
    """通过Vulners检查软件版本是否存在已知漏洞"""
    try:
        from config.settings import settings
        api_key = getattr(settings, 'vulners_api_key', '') or os.environ.get('VULNERS_API_KEY', '')
        vulners = VulnersAPI(api_key=api_key)
        results = await vulners.check_software(software, version)
        await vulners.close()
        return {
            "software": software,
            "version": version,
            "total": len(results),
            "vulnerabilities": results,
        }
    except Exception as e:
        log.error(f"Vulners软件检查失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============== 数据导入导出 ==============

@router.post("/import")
async def import_vulnerabilities(
    filepath: str = Query(..., description="JSON文件路径"),
):
    """从JSON文件导入漏洞数据"""
    try:
        db = get_vuln_db()
        added = db.import_json(filepath)
        return {"status": "success", "added": added, "message": f"成功导入{added}条漏洞"}
    except Exception as e:
        log.error(f"导入漏洞失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/export")
async def export_vulnerabilities(
    filepath: str = Query("./data/vuln_export.json", description="导出文件路径"),
):
    """导出漏洞数据库为JSON文件"""
    try:
        db = get_vuln_db()
        success = db.export_json(filepath)
        if not success:
            raise HTTPException(status_code=500, detail="导出失败")
        return {"status": "success", "filepath": filepath, "total": db.stats["total"]}
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"导出漏洞失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))
