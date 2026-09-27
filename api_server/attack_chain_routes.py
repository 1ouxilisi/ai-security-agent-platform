# -*- coding: utf-8 -*-
"""真实攻击链 API 路由（25+ 端点）。"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from attack_chain_real.chain_dashboard import dashboard


router = APIRouter(prefix="/api/v1/attack-chain", tags=["真实攻击链"])


def ok(data: Any = None, error: Optional[str] = None) -> Dict[str, Any]:
    return {"success": error is None, "data": data, "error": error}


# ---------- 请求模型 ----------
class DomainReq(BaseModel):
    domain: str
    timeout: int = 180


class TargetReq(BaseModel):
    target: str
    ports: Optional[str] = None
    timeout: int = 300


class URLReq(BaseModel):
    url: str
    timeout: int = 300


class NucleiReq(BaseModel):
    url: str
    severity: str = "critical,high,medium"
    timeout: int = 300


class SQLiProbeReq(BaseModel):
    url: str
    data: Optional[str] = None
    cookie: Optional[str] = None
    timeout: int = 300


class SQLiDumpReq(BaseModel):
    url: str
    data: Optional[str] = None
    tables: Optional[List[str]] = None
    timeout: int = 300


class XSSReq(BaseModel):
    url: str
    param: str
    payload: str = "<script>alert(1)</script>"


class LFIReq(BaseModel):
    url_template: str = Field(..., description="含 {path} 占位符")


class RedisReq(BaseModel):
    host: str
    port: int = 6379


class SprayerReq(BaseModel):
    cidr: str
    username: str
    password: str
    timeout: int = 180


class ExecReq(BaseModel):
    target: str
    username: str
    password: str
    command: str = "whoami"


class LDAPReq(BaseModel):
    server: str
    base_dn: str
    username: str = ""
    password: str = ""


class RunReq(BaseModel):
    target: str
    stages: Optional[List[str]] = None


class StageReq(BaseModel):
    run_id: str
    stage: str
    kwargs: Dict[str, Any] = Field(default_factory=dict)


# ---------- 健康 ----------
@router.get("/health")
def health():
    return ok(dashboard.health())


# ---------- 信息收集 ----------
@router.post("/recon/subfinder")
def recon_subfinder(req: DomainReq):
    return ok(dashboard.subfinder(req.domain, timeout=req.timeout))


@router.post("/recon/crt-sh")
def recon_crtsh(req: DomainReq):
    return ok(dashboard.crt_sh(req.domain, timeout=min(req.timeout, 60)))


@router.post("/recon/port-scan")
def recon_port_scan(req: TargetReq):
    ports = req.ports or "--top-ports 1000"
    return ok(dashboard.port_scan(req.target, ports=ports, timeout=req.timeout))


@router.post("/recon/service-detect")
def recon_service(req: TargetReq):
    return ok(dashboard.service_detect(req.target, ports=req.ports, timeout=req.timeout))


@router.post("/recon/fingerprint")
def recon_fp(req: URLReq):
    return ok(dashboard.fingerprint(req.url, timeout=min(req.timeout, 30)))


@router.post("/recon/full")
def recon_full(req: TargetReq):
    return ok(dashboard.recon.run_full(req.target, timeout=req.timeout))


# ---------- 漏洞发现 ----------
@router.post("/discovery/nuclei")
def discovery_nuclei(req: NucleiReq):
    return ok(dashboard.nuclei(req.url, severity=req.severity, timeout=req.timeout))


@router.post("/discovery/sqlmap-probe")
def discovery_sqlmap(req: SQLiProbeReq):
    return ok(dashboard.sqlmap_probe(req.url, data=req.data, timeout=req.timeout))


@router.post("/discovery/nikto")
def discovery_nikto(req: URLReq):
    return ok(dashboard.nikto(req.url, timeout=req.timeout))


@router.post("/discovery/dirbust")
def discovery_dirbust(req: URLReq):
    return ok(dashboard.dirbust(req.url, timeout=req.timeout))


@router.post("/discovery/full")
def discovery_full(req: URLReq):
    return ok(dashboard.discovery.run_full(req.url, timeout=req.timeout))


# ---------- 漏洞利用 ----------
@router.post("/exploit/sqli-dump")
def exploit_sqli(req: SQLiDumpReq):
    return ok(dashboard.sqli_dump(req.url, data=req.data, tables=req.tables, timeout=req.timeout))


@router.post("/exploit/xss-verify")
def exploit_xss(req: XSSReq):
    return ok(dashboard.xss_verify(req.url, req.param, req.payload))


@router.post("/exploit/lfi-read")
def exploit_lfi(req: LFIReq):
    return ok(dashboard.lfi_read(req.url_template))


@router.post("/exploit/redis-unauth")
def exploit_redis(req: RedisReq):
    return ok(dashboard.redis_unauth(req.host, req.port))


@router.post("/exploit/es-unauth")
def exploit_es_unauth(req: RedisReq):
    return ok(dashboard.es_unauth(req.host, req.port))


# ---------- 权限提升 ----------
@router.post("/privesc/enum")
def privesc_enum():
    return ok(dashboard.privesc_enum())


@router.post("/privesc/try")
def privesc_try(vector: str):
    return ok(dashboard.privesc_try(vector))


# ---------- 横向移动 ----------
@router.post("/lateral/smb-spray")
def lateral_spray(req: SprayerReq):
    return ok(dashboard.smb_spray(req.cidr, req.username, req.password, timeout=req.timeout))


@router.post("/lateral/wmiexec")
def lateral_wmi(req: ExecReq):
    return ok(dashboard.wmiexec(req.target, req.username, req.password, req.command))


@router.post("/lateral/winrm")
def lateral_winrm(req: ExecReq):
    return ok(dashboard.winrm_exec(req.target, req.username, req.password, req.command))


@router.post("/lateral/ldap")
def lateral_ldap(req: LDAPReq):
    return ok(dashboard.ldap_enum(req.server, req.base_dn, req.username, req.password))


@router.post("/lateral/pivot")
def lateral_pivot(req: SprayerReq):
    return ok(dashboard.pivot(req.cidr, req.username, req.password))


# ---------- 编排 ----------
@router.post("/run/create")
def run_create(req: RunReq):
    return ok(dashboard.create_run(req.target, req.stages))


@router.get("/run/{run_id}")
def run_get(run_id: str):
    return ok(dashboard.get_run(run_id))


@router.get("/run/list")
def run_list():
    return ok(dashboard.list_runs())


@router.post("/run/stage")
def run_stage(req: StageReq):
    return ok(dashboard.run_stage(req.run_id, req.stage, **req.kwargs))


@router.post("/run/full")
def run_full(req: RunReq):
    return ok(dashboard.run_full_chain(req.target))
