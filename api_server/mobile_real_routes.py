# -*- coding: utf-8 -*-
"""移动安全真实分析 API 路由（20+ 端点）。"""
from __future__ import annotations

import os
import tempfile
from typing import List, Optional

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from mobile_real_analysis.mobile_real_dashboard import dashboard

router = APIRouter(prefix="/api/v1/mobile-real", tags=["移动安全真实分析"])


def ok(data, error=None):
    return {"success": error is None, "data": data, "error": error}


class ApkPathReq(BaseModel):
    path: str = Field(..., description="服务器上 APK 的绝对路径")


class PermListReq(BaseModel):
    permissions: List[str]


# ---------- 环境 ----------
@router.get("/env")
def env():
    return ok(dashboard.env())


@router.get("/list")
def list_apks():
    return ok(dashboard.list())


@router.get("/analysis/{aid}")
def get_analysis(aid: str):
    a = dashboard.get(aid)
    if not a:
        raise HTTPException(404, "analysis not found")
    return ok(a)


# ---------- 上传 + 完整分析 ----------
@router.post("/upload")
async def upload_apk(file: UploadFile = File(...)):
    suffix = os.path.splitext(file.filename)[1] or ".apk"
    tmp = os.path.join(tempfile.gettempdir(), f"upload_{os.urandom(6).hex()}{suffix}")
    with open(tmp, "wb") as f:
        f.write(await file.read())
    r = dashboard.analyze(tmp)
    return ok(r)


@router.post("/analyze-path")
def analyze_path(req: ApkPathReq):
    return ok(dashboard.analyze(req.path))


# ---------- 单项能力 ----------
@router.post("/parse")
def parse_apk(req: ApkPathReq):
    return ok(dashboard.parser.parse(req.path))


@router.post("/permissions")
def list_perms(req: ApkPathReq):
    p = dashboard.parser.parse(req.path)
    return ok({"permissions": p.get("permissions", []), "package": p.get("package")})


@router.post("/components")
def components(req: ApkPathReq):
    p = dashboard.parser.parse(req.path)
    return ok({k: p.get(k) for k in ("activities", "services", "receivers", "providers")})


@router.post("/version")
def version(req: ApkPathReq):
    p = dashboard.parser.parse(req.path)
    return ok({k: p.get(k) for k in ("package", "version_code", "version_name", "min_sdk", "target_sdk")})


@router.post("/permission-risk")
def permission_risk(req: PermListReq):
    return ok(dashboard.perm.analyze(req.permissions))


@router.post("/static-scan")
def static_scan(req: ApkPathReq):
    return ok(dashboard.vuln.scan_apk(req.path))


@router.post("/hardcoded-secrets")
def hardcoded(req: ApkPathReq):
    r = dashboard.vuln.scan_apk(req.path)
    hits = [f for f in r.get("findings", []) if f.get("id") == "hardcoded_secret"]
    return ok({"count": len(hits), "hits": hits})


@router.post("/webview-check")
def webview_check(req: ApkPathReq):
    r = dashboard.vuln.scan_apk(req.path)
    ids = {"webview_js", "webview_file", "webview_jsinterface"}
    hits = [f for f in r.get("findings", []) if f.get("id") in ids]
    return ok({"count": len(hits), "hits": hits})


@router.post("/log-leak")
def log_leak(req: ApkPathReq):
    r = dashboard.vuln.scan_apk(req.path)
    hits = [f for f in r.get("findings", []) if f.get("id") == "log_leak"]
    return ok({"count": len(hits), "hits": hits})


@router.post("/exported-check")
def exported_check(req: ApkPathReq):
    r = dashboard.vuln.scan_apk(req.path)
    hits = [f for f in r.get("findings", []) if f.get("id") == "exported_component"]
    return ok({"count": len(hits), "hits": hits})


@router.post("/storage-check")
def storage_check(req: ApkPathReq):
    r = dashboard.vuln.scan_apk(req.path)
    ids = {"sharedpref", "http_url"}
    hits = [f for f in r.get("findings", []) if f.get("id") in ids]
    return ok({"count": len(hits), "hits": hits})


# ---------- 动态 ----------
@router.get("/dynamic/status")
def dyn_status():
    return ok(dashboard.dyn.status())


@router.get("/dynamic/devices")
def dyn_devices():
    return ok(dashboard.dyn.list_devices())


@router.post("/dynamic/objection")
def dyn_objection(package: str):
    return ok(dashboard.dyn.start_objection(package))


@router.post("/vuln-summary")
def vuln_summary(req: ApkPathReq):
    """聚合静态扫描严重级别统计。"""
    r = dashboard.vuln.scan_apk(req.path)
    return ok({"total": r.get("total_findings"), "by_severity": r.get("severity")})


@router.post("/full-report")
def full_report(req: ApkPathReq):
    """完整报告：manifest + 权限风险 + 静态漏洞。"""
    a = dashboard.analyze(req.path)
    return ok(a)
