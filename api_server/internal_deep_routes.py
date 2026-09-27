# -*- coding: utf-8 -*-
"""internal_deep_routes.py — 内网渗透深度做实路由（方向2，25+端点）。

统一响应 {success, data, error}。
"""
from __future__ import annotations

import re
from typing import Any, Dict

from fastapi import APIRouter
from pydantic import BaseModel, Field

from internal_deep import (
    get_smb_enumerator, get_ad_querier, get_cred_extractor,
    get_lateral_mover, get_privesc_detector, get_attack_chain,
    get_dashboard,
)

router = APIRouter(prefix="/api/v1/internal-deep", tags=["方向2 内网渗透深度做实"])

_smb = get_smb_enumerator()
_ad = get_ad_querier()
_cred = get_cred_extractor()
_move = get_lateral_mover()
_priv = get_privesc_detector()
_chain = get_attack_chain()
_dash = get_dashboard()


def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", obj)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    if isinstance(obj, tuple):
        return [_clean(i) for i in obj]
    return obj


def _ok(data: Any = None) -> Dict[str, Any]:
    return {"success": True, "data": _clean(data), "error": None}


def _err(msg: str) -> Dict[str, Any]:
    return {"success": False, "data": None, "error": msg}


# ---------- 请求模型 ----------
class SMBReq(BaseModel):
    host: str
    user: str = ""
    password: str = ""
    timeout: int = 300


class ADReq(BaseModel):
    dc: str
    user: str = ""
    password: str = ""
    timeout: int = 300


class CredReq(BaseModel):
    target: str
    user: str = ""
    password: str = ""
    timeout: int = 300


class MoveReq(BaseModel):
    target: str
    user: str
    password: str
    command: str = "whoami"
    timeout: int = 300


class ChainReq(BaseModel):
    target: str
    dc: str = ""
    user: str = ""
    password: str = ""
    timeout: int = 300


# ---------- 仪表盘 ----------
@router.get("/dashboard/overview")
def overview():
    return _ok(_dash.overview())


@router.get("/tools-status")
def tools_status():
    return _ok({
        "smb": _smb.tools_status(),
        "ad": _ad.tools_status(),
        "cred": _cred.tools_status(),
        "lateral": _move.tools_status(),
    })


@router.get("/health")
def health():
    return _ok({"package": "internal_deep",
                "chain_history": len(_chain.history())})


# ---------- SMB 枚举 ----------
@router.post("/smb/shares")
def smb_shares(req: SMBReq):
    return _ok(_smb.list_shares(req.host, req.user, req.password, req.timeout))


@router.post("/smb/users")
def smb_users(req: SMBReq):
    return _ok(_smb.list_users(req.host, req.user, req.password, req.timeout))


@router.post("/smb/groups")
def smb_groups(req: SMBReq):
    return _ok(_smb.list_groups(req.host, req.user, req.password, req.timeout))


@router.post("/smb/full-enum")
def smb_full(req: SMBReq):
    return _ok(_smb.full_enum(req.host, req.user, req.password, req.timeout))


# ---------- AD 查询 ----------
@router.post("/ad/users")
def ad_users(req: ADReq):
    return _ok(_ad.query_users(req.dc, req.user, req.password, req.timeout))


@router.post("/ad/groups")
def ad_groups(req: ADReq):
    return _ok(_ad.query_groups(req.dc, req.user, req.password, req.timeout))


@router.post("/ad/computers")
def ad_computers(req: ADReq):
    return _ok(_ad.query_computers(req.dc, req.user, req.password, req.timeout))


@router.post("/ad/ous")
def ad_ous(req: ADReq):
    return _ok(_ad.query_ous(req.dc, req.user, req.password, req.timeout))


@router.post("/ad/full-query")
def ad_full(req: ADReq):
    return _ok(_ad.full_query(req.dc, req.user, req.password, req.timeout))


# ---------- 凭据获取 ----------
@router.post("/cred/hashes")
def cred_hashes(req: CredReq):
    return _ok(_cred.dump_hashes(req.target, req.user, req.password, req.timeout))


@router.post("/cred/passwords")
def cred_passwords(req: CredReq):
    return _ok(_cred.grab_passwords(req.target, req.timeout))


@router.post("/cred/cached")
def cred_cached(req: CredReq):
    return _ok(_cred.cached_creds(req.target, req.user, req.password, req.timeout))


@router.post("/cred/full-extract")
def cred_full(req: CredReq):
    return _ok(_cred.full_extract(req.target, req.user, req.password, req.timeout))


# ---------- 横向移动 ----------
@router.post("/lateral/smb")
def lateral_smb(req: MoveReq):
    return _ok(_move.via_smb(req.target, req.user, req.password,
                             req.command, req.timeout))


@router.post("/lateral/wmi")
def lateral_wmi(req: MoveReq):
    return _ok(_move.via_wmi(req.target, req.user, req.password,
                             req.command, req.timeout))


@router.post("/lateral/winrm")
def lateral_winrm(req: MoveReq):
    return _ok(_move.via_winrm(req.target, req.user, req.password,
                               req.command, req.timeout))


@router.post("/lateral/full-move")
def lateral_full(req: MoveReq):
    return _ok(_move.full_move(req.target, req.user, req.password,
                               req.command, req.timeout))


# ---------- 权限提升 ----------
@router.get("/privesc/cves")
def privesc_cves(timeout: int = 300):
    return _ok(_priv.detect_local_cves(timeout))


@router.get("/privesc/suid")
def privesc_suid(timeout: int = 300):
    return _ok(_priv.check_suid(timeout))


@router.get("/privesc/services")
def privesc_services(timeout: int = 300):
    return _ok(_priv.check_service_misconfig(timeout))


@router.get("/privesc/sudo")
def privesc_sudo(timeout: int = 300):
    return _ok(_priv.check_sudo(timeout))


@router.get("/privesc/full-scan")
def privesc_full(timeout: int = 300):
    return _ok(_priv.full_scan(timeout))


# ---------- 攻击链 ----------
@router.post("/chain/run")
def chain_run(req: ChainReq):
    return _ok(_chain.run(target=req.target, dc=req.dc,
                          user=req.user, password=req.password,
                          timeout=req.timeout))


@router.get("/chain/history")
def chain_history():
    return _ok(_chain.history())


@router.get("/chain/latest")
def chain_latest():
    return _ok(_chain.latest())


@router.get("/chain/stages")
def chain_stages():
    return _ok(["discovery", "enumeration", "credential", "lateral", "privesc"])
