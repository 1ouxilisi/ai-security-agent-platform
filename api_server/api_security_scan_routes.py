"""
v9.5 API安全扫描 - OpenAPI解析+参数fuzz+敏感端点
"""
import os, re, json, asyncio, httpx
from datetime import datetime
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/v9/api-security", tags=["v9-api-security"])


@router.post("/scan")
async def scan_api(request: Request):
    """API安全扫描：解析OpenAPI/Swagger，测试常见漏洞"""
    data = await request.json()
    base_url = data.get("url", "")
    
    if not base_url:
        return JSONResponse(status_code=400, content={"error": "需要url"})
    
    results = {
        "target": base_url,
        "open_api_found": False,
        "endpoints": [],
        "issues": [],
        "scanned_at": datetime.now().isoformat()
    }
    
    # 1. 找OpenAPI/Swagger文档
    openapi_paths = ["/swagger.json", "/openapi.json", "/v1/swagger.json",
                     "/v2/api-docs", "/swagger/v1/swagger.json", "/api-docs",
                     "/swagger.json", "/docs", "/redoc"]
    
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        for p in openapi_paths:
            try:
                r = await client.get(f"{base_url.rstrip('/')}{p}")
                if r.status_code == 200 and len(r.content) > 100:
                    results["open_api_found"] = True
                    results["openapi_path"] = p
                    
                    # 尝试解析
                    try:
                        spec = r.json()
                        paths = spec.get("paths", {})
                        for path, methods in paths.items():
                            for method, info in methods.items():
                                results["endpoints"].append({
                                    "method": method.upper(),
                                    "path": path,
                                    "summary": info.get("summary", "")
                                })
                    except:
                        results["endpoints"].append({"raw": r.text[:500]})
                    break
            except:
                pass
        
        # 2. 测试常见API漏洞
        # 未授权访问
        common_endpoints = ["/api/user", "/api/users", "/api/admin", "/api/config",
                           "/api/v1/user", "/api/v1/admin", "/api/account",
                           "/api/orders", "/api/products", "/api/keys"]
        
        for ep in common_endpoints:
            try:
                r = await client.get(f"{base_url.rstrip('/')}{ep}")
                if r.status_code == 200 and len(r.content) > 50:
                    results["issues"].append({
                        "type": "unauthorized_access",
                        "endpoint": ep,
                        "status": r.status_code,
                        "size": len(r.content),
                        "detail": "可能存在未授权访问"
                    })
            except:
                pass
        
        # 3. 测试SQL注入参数点
        test_params = ["/api/user?id=1", "/api/product?id=1", "/api/search?q=test"]
        for ep in test_params:
            try:
                r = await client.get(f"{base_url.rstrip('/')}{ep}'")
                if r.status_code >= 500 or "sql" in r.text.lower() or "mysql" in r.text.lower():
                    results["issues"].append({
                        "type": "potential_sqli",
                        "endpoint": ep,
                        "status": r.status_code,
                        "detail": "单引号触发错误，可能存在SQL注入"
                    })
            except:
                pass
    
    # 4. 统计
    results["total_endpoints"] = len(results["endpoints"])
    results["total_issues"] = len(results["issues"])
    results["risk_level"] = "high" if results["total_issues"] > 5 else ("medium" if results["total_issues"] > 0 else "low")
    
    return results


@router.post("/fuzz")
async def fuzz_params(request: Request):
    """参数fuzz：测试XSS/SQLi/命令注入"""
    data = await request.json()
    url = data.get("url", "")
    param = data.get("param", "q")
    
    if not url:
        return JSONResponse(status_code=400, content={"error": "需要url"})
    
    payloads = {
        "xss": ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "javascript:alert(1)"],
        "sqli": ["'", "1' OR '1'='1", "1 UNION SELECT NULL--", "1; DROP TABLE users--"],
        "cmdi": ["; cat /etc/passwd", "| whoami", "$(whoami)", "`id`"],
        "ssrf": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8080/admin"],
        "lfi": ["../../etc/passwd", "..\\..\\windows\\system32\\drivers\\etc\\hosts"]
    }
    
    results = []
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        for vuln_type, payload_list in payloads.items():
            for payload in payload_list:
                try:
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}{param}={payload}"
                    r = await client.get(test_url)
                    
                    detected = False
                    detail = ""
                    
                    if vuln_type == "xss" and payload in r.text:
                        detected = True
                        detail = "payload在响应中反射"
                    elif vuln_type == "sqli" and (r.status_code >= 500 or "sql" in r.text.lower() or "mysql" in r.text.lower()):
                        detected = True
                        detail = "数据库错误"
                    elif vuln_type == "cmdi" and ("root:" in r.text or "uid=" in r.text):
                        detected = True
                        detail = "命令执行成功"
                    elif vuln_type == "lfi" and "root:" in r.text:
                        detected = True
                        detail = "文件读取成功"
                    
                    if detected:
                        results.append({
                            "vuln_type": vuln_type,
                            "payload": payload,
                            "status": r.status_code,
                            "detail": detail
                        })
                except:
                    pass
    
    return {
        "url": url,
        "param": param,
        "payloads_tested": sum(len(v) for v in payloads.values()),
        "vulnerabilities_found": len(results),
        "results": results,
        "finished_at": datetime.now().isoformat()
    }
