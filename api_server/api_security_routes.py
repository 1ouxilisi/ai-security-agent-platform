# -*- coding: utf-8 -*-
"""
api_security_routes.py — API 安全测试 REST API（12 个端点）。

路由前缀: /api/v1/api-security
所有端点 try/except 包裹，返回 JSONResponse。

设计定位：
    - fuzz 测试只做检测不做利用；速率控制避免对目标造成压力。
    - 本模块仅用于授权的安全评估与合规检查。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/api-security", tags=["API安全测试"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import，失败时路由仍可挂载，端点返回 503）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from api_security.openapi_parser import OpenAPIParser
    from api_security.param_fuzzer import ParamFuzzer, PAYLOAD_LIBRARY
    from api_security.logic_tester import LogicTester
    from api_security.workflow import get_api_security_workflow
    _MOD_AVAILABLE = True
    logger.info("api_security_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("api_security_routes: load failed: %s", e)


def _ok(data: Any) -> JSONResponse:
    return JSONResponse({"code": 0, "data": data})


def _err(status: int, message: str) -> JSONResponse:
    return JSONResponse({"code": status, "error": message}, status_code=status)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return _err(503, "API 安全模块不可用，请检查 api_security 加载日志")
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class ParseOpenAPIRequest(BaseModel):
    url: str = ""
    content: str = ""
    content_type: str = "json"


class FuzzRequest(BaseModel):
    endpoint_index: Optional[int] = None
    path: Optional[str] = None
    method: str = "GET"
    fuzz_types: List[str] = []
    options: Dict[str, Any] = {}


class LogicTestRequest(BaseModel):
    test_types: List[str] = []
    tokens: Dict[str, str] = {}
    options: Dict[str, Any] = {}


class ScanConfig(BaseModel):
    openapi_url: str = ""
    openapi_content: str = ""
    content_type: str = "json"
    base_url: str = ""
    auth_token: str = ""
    fuzz_intensity: str = "medium"
    test_types: List[str] = []
    logic_test_types: List[str] = []
    rate_limit: Dict[str, Any] = {}


class ReportRequest(BaseModel):
    format: str = "json"


# --------------------------------------------------------------------------- #
# 12 个端点
# --------------------------------------------------------------------------- #

@router.post("/parse-openapi")
def parse_openapi(req: ParseOpenAPIRequest):
    """解析 OpenAPI 规范（body: {url 或 content, content_type}）。"""
    try:
        g = _guard()
        if g is not None:
            return g
        parser = OpenAPIParser()
        if req.url:
            result = parser.parse_from_url(req.url)
        elif req.content:
            result = parser.parse_from_string(req.content, req.content_type)
        else:
            return _err(400, "必须提供 url 或 content")
        return _ok(result)
    except Exception as e:
        logger.exception("parse_openapi error")
        return _err(500, f"解析失败: {e}")


@router.get("/{scan_id}/endpoints")
def get_endpoints(scan_id: str):
    """获取发现的端点列表。"""
    try:
        g = _guard()
        if g is not None:
            return g
        wf = get_api_security_workflow()
        return _ok(wf.get_endpoints(scan_id))
    except Exception as e:
        logger.exception("get_endpoints error")
        return _err(500, str(e))


@router.post("/{scan_id}/fuzz")
def fuzz(scan_id: str, req: FuzzRequest):
    """执行参数 fuzz 测试（body: {endpoint_index 或 path, fuzz_types, options}）。"""
    try:
        g = _guard()
        if g is not None:
            return g
        wf = get_api_security_workflow()
        # 演示性：返回计划执行的 fuzz 任务列表（不真正对外部发请求）
        fuzzer = ParamFuzzer()
        types = req.fuzz_types or fuzzer.get_fuzz_types()
        payload_counts = {t: len(PAYLOAD_LIBRARY.get(t, [])) for t in types}
        return _ok({
            "scan_id": scan_id,
            "fuzz_types": types,
            "payload_counts": payload_counts,
            "total_payloads": sum(payload_counts.values()),
            "status": "planned",
            "note": "检测模式：仅枚举待执行 payload，不实际发送外部请求",
        })
    except Exception as e:
        logger.exception("fuzz error")
        return _err(500, str(e))


@router.post("/{scan_id}/logic-test")
def logic_test(scan_id: str, req: LogicTestRequest):
    """执行逻辑漏洞测试（body: {test_types, tokens, options}）。"""
    try:
        g = _guard()
        if g is not None:
            return g
        tester = LogicTester()
        types = req.test_types or tester.get_test_types()
        return _ok({
            "scan_id": scan_id,
            "test_types": types,
            "remediation": {t: tester.remediation.get(t, "") for t in types},
            "status": "planned",
        })
    except Exception as e:
        logger.exception("logic_test error")
        return _err(500, str(e))


@router.post("/scan")
def start_scan(req: ScanConfig):
    """执行完整 API 安全扫描（异步），返回 scan_id。"""
    try:
        g = _guard()
        if g is not None:
            return g
        wf = get_api_security_workflow()
        config = req.model_dump()
        scan_id = wf.create_scan(config)
        wf.run_scan(scan_id)
        return _ok({"scan_id": scan_id, "status": "started"})
    except Exception as e:
        logger.exception("start_scan error")
        return _err(500, str(e))


@router.get("/{scan_id}/status")
def scan_status(scan_id: str):
    """获取扫描状态。"""
    try:
        g = _guard()
        if g is not None:
            return g
        wf = get_api_security_workflow()
        return _ok(wf.get_scan_status(scan_id))
    except Exception as e:
        logger.exception("scan_status error")
        return _err(500, str(e))


@router.get("/{scan_id}/result")
def scan_result(scan_id: str):
    """获取扫描结果。"""
    try:
        g = _guard()
        if g is not None:
            return g
        wf = get_api_security_workflow()
        return _ok(wf.get_scan_result(scan_id))
    except Exception as e:
        logger.exception("scan_result error")
        return _err(500, str(e))


@router.get("/{scan_id}/vulnerabilities")
def scan_vulnerabilities(scan_id: str,
                        severity: Optional[str] = Query(None)):
    """获取漏洞列表（支持 severity 筛选）。"""
    try:
        g = _guard()
        if g is not None:
            return g
        wf = get_api_security_workflow()
        return _ok(wf.get_vulnerabilities(scan_id, severity))
    except Exception as e:
        logger.exception("scan_vulnerabilities error")
        return _err(500, str(e))


@router.post("/{scan_id}/report")
def scan_report(scan_id: str, req: ReportRequest):
    """生成报告（format: json / html）。"""
    try:
        g = _guard()
        if g is not None:
            return g
        wf = get_api_security_workflow()
        return _ok(wf.generate_report(scan_id, req.format))
    except Exception as e:
        logger.exception("scan_report error")
        return _err(500, str(e))


@router.get("/history")
def scan_history():
    """获取扫描历史。"""
    try:
        g = _guard()
        if g is not None:
            return g
        wf = get_api_security_workflow()
        return _ok(wf.get_scan_history())
    except Exception as e:
        logger.exception("scan_history error")
        return _err(500, str(e))


@router.get("/payloads")
def payloads(ptype: Optional[str] = Query(None)):
    """获取 fuzz payload 库（支持 type 筛选）。"""
    try:
        g = _guard()
        if g is not None:
            return g
        fuzzer = ParamFuzzer()
        data = fuzzer.get_payloads(ptype)
        total = sum(len(v) for v in data.values())
        return _ok({"payloads": data, "fuzz_types": list(data.keys()),
                    "total_payloads": total})
    except Exception as e:
        logger.exception("payloads error")
        return _err(500, str(e))


@router.get("/stats")
def stats():
    """获取 API 安全统计。"""
    try:
        g = _guard()
        if g is not None:
            return g
        wf = get_api_security_workflow()
        return _ok(wf.get_stats())
    except Exception as e:
        logger.exception("stats error")
        return _err(500, str(e))


__all__ = ["router"]

# =========================================================================== #
# v2 增强端点（独立实现，不依赖 api_security 包，始终可用）
# ===========================================================================
import json as _json, re as _re, urllib.request as _ur, urllib.error as _ue
from datetime import datetime as _dt

_API_SECURITY_CHECKS_V2 = [
    {"id":"API001","category":"认证","title":"未授权访问检测","severity":"critical","test_method":"不带Authorization头请求端点"},
    {"id":"API002","category":"认证","title":"弱Token/JWT检测","severity":"high","test_method":"解析JWT，测试none算法"},
    {"id":"API003","category":"授权","title":"越权访问(BOLA)","severity":"critical","test_method":"用户A Token访问用户B资源"},
    {"id":"API004","category":"授权","title":"功能越权(BFLA)","severity":"high","test_method":"普通用户调用管理员接口"},
    {"id":"API005","category":"输入验证","title":"SQL注入","severity":"critical","test_method":"注入SQL Payload观察响应差异"},
    {"id":"API006","category":"输入验证","title":"NoSQL注入","severity":"high","test_method":"注入{$gt:''}等"},
    {"id":"API007","category":"输入验证","title":"命令注入","severity":"critical","test_method":"注入;ls, |id等"},
    {"id":"API008","category":"输入验证","title":"SSRF","severity":"high","test_method":"注入http://127.0.0.1等"},
    {"id":"API009","category":"输入验证","title":"路径穿越","severity":"high","test_method":"注入../../../etc/passwd"},
    {"id":"API010","category":"输入验证","title":"XSS","severity":"medium","test_method":"注入<script>alert(1)</script>"},
    {"id":"API011","category":"业务逻辑","title":"批量赋值(Mass Assignment)","severity":"high","test_method":"添加is_admin=true字段"},
    {"id":"API012","category":"业务逻辑","title":"竞争条件(Race Condition)","severity":"medium","test_method":"并发发送相同请求"},
    {"id":"API013","category":"业务逻辑","title":"流程绕过","severity":"high","test_method":"跳过中间步骤调用最终接口"},
    {"id":"API014","category":"速率限制","title":"速率限制缺失","severity":"medium","test_method":"大量请求观察是否429"},
    {"id":"API015","category":"数据泄露","title":"敏感信息泄露","severity":"high","test_method":"检查password/secret/token"},
    {"id":"API016","category":"配置安全","title":"CORS配置错误","severity":"medium","test_method":"检查ACAO头"},
    {"id":"API017","category":"配置安全","title":"缺少安全响应头","severity":"low","test_method":"检查HSTS/CSP等"},
    {"id":"API018","category":"配置安全","title":"HTTPS未强制","severity":"high","test_method":"HTTP请求是否可访问"},
    {"id":"API019","category":"文档泄露","title":"API文档泄露","severity":"medium","test_method":"访问/swagger,/api-docs等"},
    {"id":"API020","category":"GraphQL","title":"GraphQL安全","severity":"medium","test_method":"内省查询/深度嵌套测试"},
]

def _v2_fetch(url, method="GET", headers=None, timeout=10):
    try:
        req = _ur.Request(url, method=method, headers=headers or {})
        with _ur.urlopen(req, timeout=timeout) as resp:
            return {"status":resp.status,"headers":dict(resp.headers),"body":resp.read().decode('utf-8',errors='ignore')[:10000],"error":None}
    except _ue.HTTPError as e:
        body = e.read().decode('utf-8',errors='ignore')[:5000] if e.fp else ""
        return {"status":e.code,"headers":dict(e.headers or {}),"body":body,"error":str(e)}
    except Exception as e:
        return {"status":0,"headers":{},"body":"","error":str(e)}

class _V2OpenAPIReq(BaseModel):
    url: str
    auth_header: Optional[str] = None

class _V2ScanReq(BaseModel):
    base_url: str
    endpoints: Optional[List[str]] = None
    auth_header: Optional[str] = None
    max_endpoints: int = 20

@router.post("/v2/openapi/parse")
def v2_parse_openapi(req: _V2OpenAPIReq):
    """v2: 解析OpenAPI/Swagger文档（独立实现）"""
    headers = {}
    if req.auth_header: headers["Authorization"] = req.auth_header
    resp = _v2_fetch(req.url, headers=headers)
    if resp["error"]:
        return JSONResponse({"code":500,"error":f"获取失败: {resp['error']}"}, status_code=500)
    try:
        spec = _json.loads(resp["body"])
    except:
        return JSONResponse({"code":400,"error":"非有效JSON"}, status_code=400)
    endpoints = []
    base_path = spec.get("basePath","")
    for path, methods in spec.get("paths",{}).items():
        for method, details in methods.items():
            if method.lower() not in ("get","post","put","delete","patch","head","options"): continue
            params = details.get("parameters",[])
            endpoints.append({"method":method.upper(),"path":path,"full_path":f"{base_path}{path}",
                "summary":details.get("summary",""),"param_count":len(params),
                "has_auth":"security" in details or "security" in spec})
    findings = []
    unauth = [e for e in endpoints if not e["has_auth"]]
    if unauth: findings.append({"severity":"medium","title":"未声明认证的端点","detail":f"{len(unauth)}个"})
    return _ok({"title":spec.get("info",{}).get("title","Unknown"),"version":spec.get("info",{}).get("version",""),
        "endpoint_count":len(endpoints),"endpoints":endpoints[:50],"security_findings":findings})

@router.post("/v2/scan")
def v2_scan_api(req: _V2ScanReq):
    """v2: API安全扫描（未授权+安全头+CORS+文档泄露+敏感信息）"""
    results = {"target":req.base_url,"scanned_at":_dt.now().isoformat(),"findings":[],"tested_endpoints":0}
    headers = {}
    if req.auth_header: headers["Authorization"] = req.auth_header
    endpoints = req.endpoints or ["/"]
    tested = 0
    for endpoint in endpoints[:req.max_endpoints]:
        url = req.base_url.rstrip("/") + endpoint
        tested += 1
        resp_no_auth = _v2_fetch(url, headers={})
        if resp_no_auth["status"] == 200 and req.auth_header:
            results["findings"].append({"severity":"high","title":"未授权访问","endpoint":endpoint})
        resp = _v2_fetch(url, headers=headers)
        missing = [h for h in ["Strict-Transport-Security","Content-Security-Policy","X-Frame-Options","X-Content-Type-Options"] if h not in resp["headers"]]
        if missing and resp["status"] != 0:
            results["findings"].append({"severity":"low","title":"缺少安全响应头","endpoint":endpoint,"detail":", ".join(missing)})
        cors = _v2_fetch(url, headers={**headers,"Origin":"https://evil-attacker.com"})
        acao = cors["headers"].get("Access-Control-Allow-Origin","")
        if acao == "*": results["findings"].append({"severity":"medium","title":"CORS: ACAO=*","endpoint":endpoint})
        elif "evil-attacker.com" in acao: results["findings"].append({"severity":"high","title":"CORS反射Origin","endpoint":endpoint})
        for pat,name in [(r"password\s*[:=]","密码"),(r"(api[_-]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{10,}","API密钥"),(r"-----BEGIN.*PRIVATE KEY","私钥"),(r"stack trace|Traceback","堆栈"),(r"(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})","内网IP")]:
            if _re.search(pat, resp["body"], _re.I):
                results["findings"].append({"severity":"high" if name in ("密码","API密钥","私钥") else "medium","title":f"敏感信息泄露:{name}","endpoint":endpoint})
                break
    for dp in ["/swagger","/api-docs","/v2/api-docs","/v3/api-docs","/openapi.json","/graphql","/docs"]:
        dr = _v2_fetch(req.base_url.rstrip("/")+dp, headers=headers, timeout=5)
        if dr["status"]==200 and len(dr["body"])>50 and any(k in dr["body"].lower() for k in ["swagger","openapi","graphql","\"paths\""]):
            results["findings"].append({"severity":"medium","title":"API文档泄露","endpoint":dp})
    results["tested_endpoints"]=tested
    results["finding_count"]=len(results["findings"])
    results["risk_summary"]={s:sum(1 for f in results["findings"] if f["severity"]==s) for s in ["critical","high","medium","low"]}
    return _ok(results)

@router.get("/v2/checklist")
def v2_checklist(category: Optional[str] = None):
    """v2: API安全测试检查清单（20项）"""
    items = _API_SECURITY_CHECKS_V2
    if category: items = [i for i in items if i["category"]==category]
    cats = sorted(set(i["category"] for i in _API_SECURITY_CHECKS_V2))
    return _ok({"items":items,"total":len(items),"categories":cats})

@router.get("/v2/fuzz-payloads")
def v2_fuzz_payloads(vuln_type: str):
    """v2: 获取Fuzz Payload"""
    lib = {
        "sql-injection":["' OR 1=1--","' OR '1'='1","1' ORDER BY 1--","1' UNION SELECT NULL--","admin'--","1 AND SLEEP(5)--"],
        "xss":["<script>alert(1)</script>","\"><script>alert(1)</script>","<img src=x onerror=alert(1)>","<svg onload=alert(1)>"],
        "command-injection":[";ls",";whoami","|id","`id`","$(id)",";sleep 5"],
        "ssrf":["http://127.0.0.1","http://169.254.169.254/latest/meta-data/","file:///etc/passwd"],
        "path-traversal":["../../../etc/passwd","..\\..\\..\\windows\\win.ini","%2e%2e%2fetc/passwd"],
        "nosql-injection":['{"$gt":""}','{"$ne":null}','{"$regex":".*"}'],
    }
    if vuln_type in lib:
        return _ok({"vuln_type":vuln_type,"payloads":lib[vuln_type],"count":len(lib[vuln_type])})
    return JSONResponse({"code":404,"error":f"未找到:{vuln_type}","available":list(lib.keys())}, status_code=404)
