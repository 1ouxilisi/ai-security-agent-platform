#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
漏洞真实验证 API 路由（模块一：1.5）。

端点：
    POST /api/v1/verify/web            Web 漏洞验证（异步）
    POST /api/v1/verify/service        服务漏洞验证（异步）
    POST /api/v1/verify/target         目标全量验证
    GET  /api/v1/verify/result/{task_id}  获取验证结果
    GET  /api/v1/verify/stats          验证统计/误报率
    POST /api/v1/verify/report         生成验证报告
    GET  /api/v1/verify/history        验证历史记录

合法安全边界：所有端点仅做存在性探测，不获取 shell、不窃取数据、不上传 webshell。
"""

import os
import sys
from typing import Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

# 保证项目根目录可 import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from verification.verification_manager import verification_manager

try:
    from loguru import logger
except Exception:  # pragma: no cover
    import logging

    logger = logging.getLogger("verification_routes")

router = APIRouter(prefix="/api/v1", tags=["漏洞真实验证"])


# ==================== 请求模型 ====================

class WebVerifyRequest(BaseModel):
    """Web 漏洞验证请求。"""
    url: str = Field(..., description="目标 URL，如 http://example.com/page?id=1")
    vuln_type: str = Field(
        "sql_injection",
        description="漏洞类型: sql_injection/xss/path_traversal/ssrf/command_injection/file_upload",
    )
    param: str = Field("", description="待测试参数名")
    method: str = Field("GET", description="HTTP 方法: GET/POST")
    file_field: str = Field("file", description="文件上传字段名（file_upload 时使用）")


class ServiceVerifyRequest(BaseModel):
    """服务漏洞验证请求。"""
    host: str = Field(..., description="目标主机")
    port: int = Field(..., description="目标端口")
    service: str = Field("", description="服务名: ftp/ssh/smb/mysql/redis/mongodb/...")
    vuln_type: str = Field(
        "weak_password",
        description="漏洞类型: weak_password/unauthorized_access/anonymous_access/default_credentials/version_cve_match",
    )
    username: Optional[str] = Field("admin", description="弱口令测试用户名")
    password_list: Optional[list] = Field(None, description="自定义弱口令列表（可选）")
    version: Optional[str] = Field(None, description="服务版本（version_cve_match 时使用）")


class TargetVerifyRequest(BaseModel):
    """目标全量验证请求。"""
    target: str = Field(..., description="目标，URL 或 host:port")


class ReportRequest(BaseModel):
    """报告生成请求。"""
    task_id: Optional[str] = Field(None, description="指定 task_id；不传则生成全部统计报告")


# ==================== 端点 ====================

@router.post("/verify/web")
def verify_web(req: WebVerifyRequest):
    """提交 Web 漏洞验证任务，返回 task_id。"""
    try:
        task_id = verification_manager.submit_verification(
            task_type="web",
            target=req.url,
            vuln_type=req.vuln_type,
            param=req.param,
            method=req.method,
            file_field=req.file_field,
        )
        return {"status": "queued", "task_id": task_id,
                "message": "Web 漏洞验证任务已提交，请轮询 /verify/result/{task_id}"}
    except Exception as e:
        logger.exception("verify_web 异常")
        return {"status": "error", "message": f"提交失败: {e}"}


@router.post("/verify/service")
def verify_service(req: ServiceVerifyRequest):
    """提交服务漏洞验证任务，返回 task_id。"""
    try:
        target = f"{req.host}:{req.port}"
        task_id = verification_manager.submit_verification(
            task_type="service",
            target=target,
            vuln_type=req.vuln_type,
            host=req.host,
            port=req.port,
            service=req.service,
            username=req.username,
            password_list=req.password_list,
            version=req.version,
        )
        return {"status": "queued", "task_id": task_id,
                "message": "服务漏洞验证任务已提交，请轮询 /verify/result/{task_id}"}
    except Exception as e:
        logger.exception("verify_service 异常")
        return {"status": "error", "message": f"提交失败: {e}"}


@router.post("/verify/target")
def verify_target(req: TargetVerifyRequest):
    """对目标做全量验证：自动按 target 形态分发到 Web 或服务验证。"""
    try:
        target = req.target.strip()
        is_web = target.startswith("http://") or target.startswith("https://")
        task_ids = []
        if is_web:
            for vt in ("sql_injection", "xss"):
                tid = verification_manager.submit_verification(
                    task_type="web", target=target, vuln_type=vt)
                task_ids.append({"vuln_type": vt, "task_id": tid})
        else:
            # 按 host:port 解析
            host = target.split(":")[0]
            port = 0
            if ":" in target:
                try:
                    port = int(target.split(":")[1].split("/")[0])
                except Exception:
                    port = 0
            for vt in ("unauthorized_access", "weak_password"):
                tid = verification_manager.submit_verification(
                    task_type="service", target=target, vuln_type=vt,
                    host=host, port=port, service="")
                task_ids.append({"vuln_type": vt, "task_id": tid})
        return {"status": "queued", "target": target, "tasks": task_ids,
                "message": "全量验证任务已提交"}
    except Exception as e:
        logger.exception("verify_target 异常")
        return {"status": "error", "message": f"提交失败: {e}"}


@router.get("/verify/result/{task_id}")
def get_verify_result(task_id: str):
    """获取指定 task_id 的验证结果。"""
    try:
        return verification_manager.get_result(task_id)
    except Exception as e:
        logger.exception("get_verify_result 异常")
        return {"status": "error", "message": f"查询失败: {e}"}


@router.get("/verify/stats")
def get_verify_stats():
    """获取验证统计与误报率。"""
    try:
        return verification_manager.get_stats()
    except Exception as e:
        logger.exception("get_verify_stats 异常")
        return {"status": "error", "message": f"查询失败: {e}"}


@router.post("/verify/report")
def generate_verify_report(req: ReportRequest):
    """生成验证报告。task_id 不传则汇总全部。"""
    try:
        return verification_manager.generate_report(req.task_id)
    except Exception as e:
        logger.exception("generate_verify_report 异常")
        return {"status": "error", "message": f"生成失败: {e}"}


@router.get("/verify/history")
def get_verify_history(limit: int = Query(50, ge=1, le=500),
                       status: Optional[str] = Query(None)):
    """获取验证历史记录，可按 status 筛选。"""
    try:
        report = verification_manager.generate_report()
        results = report.get("results", [])
        if status:
            results = [r for r in results if r.get("status") == status]
        results = results[-limit:]
        return {"total": len(results), "results": results}
    except Exception as e:
        logger.exception("get_verify_history 异常")
        return {"status": "error", "message": f"查询失败: {e}",
                "results": []}
