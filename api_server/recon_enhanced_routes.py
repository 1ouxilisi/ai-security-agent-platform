# -*- coding: utf-8 -*-
"""增强侦察模块 - 子域名枚举+目录爆破+指纹识别+技术栈检测+WHOIS"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime
import socket, ssl, json, re, urllib.request, urllib.error, hashlib

router = APIRouter(prefix="/api/v1/recon-enhanced", tags=["增强侦察"])

# 常见Web技术指纹
TECH_FINGERPRINTS = {
    "nginx": {"headers": ["Server: nginx"], "patterns": [r"nginx/([\d.]+)"], "category": "Web服务器"},
    "apache": {"headers": ["Server: Apache"], "patterns": [r"Apache/([\d.]+)"], "category": "Web服务器"},
    "iis": {"headers": ["Server: Microsoft-IIS"], "patterns": [r"IIS/([\d.]+)"], "category": "Web服务器"},
    "cloudflare": {"headers": ["Server: cloudflare"], "patterns": [r"cloudflare"], "category": "CDN/WAF"},
    "wordpress": {"patterns": [r"wp-content", r"wp-includes", r"WordPress ([\d.]+)"], "category": "CMS"},
    "drupal": {"patterns": [r"Drupal", r"sites/default/files"], "category": "CMS"},
    "joomla": {"patterns": [r"joomla", r"Joomla!"], "category": "CMS"},
    "jquery": {"patterns": [r"jquery[/-]([\d.]+)", r"jQuery v([\d.]+)"], "category": "前端框架"},
    "react": {"patterns": [r"react[/-]([\d.]+)", r"React"], "category": "前端框架"},
    "vue": {"patterns": [r"vue[/-]([\d.]+)", r"Vue.js"], "category": "前端框架"},
    "angular": {"patterns": [r"angular[/-]([\d.]+)", r"Angular"], "category": "前端框架"},
    "bootstrap": {"patterns": [r"bootstrap[/-]([\d.]+)", r"Bootstrap v([\d.]+)"], "category": "CSS框架"},
    "django": {"headers": ["Server: WSGIServer"], "patterns": [r"csrftoken", r"Django"], "category": "后端框架"},
    "flask": {"patterns": [r"Flask"], "category": "后端框架"},
    "spring": {"patterns": [r"spring", r"Spring Boot"], "category": "后端框架"},
    "laravel": {"patterns": [r"laravel", r"Laravel"], "category": "后端框架"},
    "php": {"headers": ["X-Powered-By: PHP"], "patterns": [r"PHP/([\d.]+)"], "category": "编程语言"},
    "asp.net": {"headers": ["X-Powered-By: ASP.NET"], "patterns": [r"ASP.NET"], "category": "编程语言"},
    "node.js": {"headers": ["X-Powered-By: Express"], "patterns": [r"Express"], "category": "编程语言"},
    "mysql": {"patterns": [r"MySQL", r"mysql_error"], "category": "数据库"},
    "postgresql": {"patterns": [r"PostgreSQL", r"pg_"], "category": "数据库"},
    "mongodb": {"patterns": [r"MongoDB", r"mongo"], "category": "数据库"},
    "redis": {"patterns": [r"Redis", r"redis"], "category": "数据库"},
    "google-analytics": {"patterns": [r"googletagmanager", r"GA\(", r"google-analytics"], "category": "第三方服务"},
    "google-tag-manager": {"patterns": [r"googletagmanager"], "category": "第三方服务"},
    "baidu-tongji": {"patterns": [r"hm.baidu.com", r"baidu_tongji"], "category": "第三方服务"},
}

# 常见目录/路径字典
COMMON_PATHS = [
    "/admin", "/login", "/wp-admin", "/administrator", "/phpmyadmin", "/admin.php",
    "/config", "/.git", "/.env", "/backup", "/ backups", "/db", "/database",
    "/api", "/api/v1", "/api/docs", "/swagger", "/swagger-ui.html", "/api-docs",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.htaccess", "/.htpasswd", "/web.config", "/server-status", "/server-info",
    "/phpinfo.php", "/info.php", "/test.php", "/install.php", "/setup.php",
    "/upload", "/uploads", "/files", "/assets", "/static", "/media",
    "/console", "/dashboard", "/manager", "/manage", "/cms",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/heapdump",
    "/graphql", "/graphiql", "/altair", "/playground",
    "/debug", "/_debug", "/dev", "/staging", "/test",
    "/.well-known", "/.DS_Store", "/Thumbs.db",
]

# 常见子域名前缀
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "webdisk", "cpanel", "whm", "autodiscover", "autoconfig", "m", "mobile",
    "api", "api2", "dev", "development", "staging", "test", "testing", "qa",
    "uat", "prod", "production", "demo", "sandbox", "beta", "alpha",
    "admin", "administrator", "manage", "manager", "dashboard", "console",
    "portal", "intranet", "extranet", "vpn", "remote", "rdp", "ssh",
    "git", "github", "gitlab", "bitbucket", "svn", "jenkins", "ci", "cd",
    "docker", "registry", "harbor", "nexus", "artifactory", "sonar",
    "grafana", "kibana", "prometheus", "zabbix", "nagios", "monitor",
    "elastic", "elasticsearch", "logstash", "kibana", "log", "logs",
    "db", "database", "mysql", "postgres", "mongo", "redis", "cache",
    "cdn", "static", "assets", "img", "images", "media", "files", "download",
    "blog", "forum", "bbs", "community", "wiki", "doc", "docs", "help", "support",
    "shop", "store", "cart", "order", "pay", "payment", "billing", "invoice",
    "oauth", "sso", "auth", "login", "register", "signup", "account", "profile",
    "search", "api-docs", "openapi", "swagger", "graphql", "ws", "wss",
]

class ReconReq(BaseModel):
    target: str
    scan_type: str = "all"  # all/subdomain/directory/fingerprint/whois
    max_subdomains: int = 50
    max_directories: int = 50
    timeout: int = 5

def _dns_lookup(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def _fetch_url(url: str, timeout: int = 5) -> Dict:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"status": resp.status, "headers": dict(resp.headers), "body": resp.read().decode('utf-8', errors='ignore')[:20000], "error": None}
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='ignore')[:5000] if e.fp else ""
        return {"status": e.code, "headers": dict(e.headers or {}), "body": body, "error": str(e)}
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}

@router.post("/subdomain/enumerate")
def enumerate_subdomains(req: ReconReq):
    """子域名枚举（DNS字典爆破）"""
    domain = req.target.replace("http://", "").replace("https://", "").split("/")[0]
    results = {"domain": domain, "found": [], "scanned": 0, "started_at": datetime.now().isoformat()}
    for sub in COMMON_SUBDOMAINS[:req.max_subdomains]:
        results["scanned"] += 1
        full = f"{sub}.{domain}"
        ip = _dns_lookup(full)
        if ip:
            results["found"].append({"subdomain": full, "ip": ip, "type": "A"})
    results["count"] = len(results["found"])
    results["completed_at"] = datetime.now().isoformat()
    return {"success": True, "data": results}

@router.post("/directory/brute")
def brute_directories(req: ReconReq):
    """目录/路径爆破"""
    base = req.target if req.target.startswith("http") else f"http://{req.target}"
    results = {"target": base, "found": [], "scanned": 0, "started_at": datetime.now().isoformat()}
    for path in COMMON_PATHS[:req.max_directories]:
        results["scanned"] += 1
        url = base.rstrip("/") + path
        resp = _fetch_url(url, timeout=req.timeout)
        if resp["status"] in (200, 301, 302, 401, 403) and resp["status"] != 0:
            results["found"].append({
                "path": path, "status": resp["status"],
                "content_length": len(resp["body"]),
                "title": re.search(r"<title>(.*?)</title>", resp["body"], re.I).group(1)[:50] if re.search(r"<title>(.*?)</title>", resp["body"], re.I) else "",
            })
    results["count"] = len(results["found"])
    results["completed_at"] = datetime.now().isoformat()
    return {"success": True, "data": results}

@router.post("/fingerprint")
def fingerprint_target(req: ReconReq):
    """Web技术栈指纹识别"""
    url = req.target if req.target.startswith("http") else f"http://{req.target}"
    resp = _fetch_url(url, timeout=req.timeout)
    if resp["error"] and resp["status"] == 0:
        return {"success": False, "error": f"无法访问目标: {resp['error']}"}
    header_text = " ".join(f"{k}: {v}" for k, v in resp["headers"].items())
    body_text = resp["body"]
    detected = []
    for tech, info in TECH_FINGERPRINTS.items():
        found = False
        version = ""
        for h in info.get("headers", []):
            if h.lower() in header_text.lower():
                found = True
                m = re.search(info["patterns"][0], header_text, re.I) if info["patterns"] else None
                if m: version = m.group(1) if m.groups() else ""
        if not found:
            for pat in info.get("patterns", []):
                m = re.search(pat, body_text, re.I)
                if m:
                    found = True
                    version = m.group(1) if m.groups() else ""
                    break
        if found:
            detected.append({"name": tech, "version": version, "category": info["category"]})
    # SSL证书信息
    ssl_info = {}
    try:
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert()
            ssl_info = {"subject": dict(x[0] for x in cert.get("subject", [])), "issuer": dict(x[0] for x in cert.get("issuer", [])), "notAfter": cert.get("notAfter", ""), "notBefore": cert.get("notBefore", "")}
    except: pass
    # 响应头安全分析
    security_headers = {}
    for h in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection", "Referrer-Policy", "Permissions-Policy"]:
        security_headers[h] = resp["headers"].get(h, "未设置")
    return {"success": True, "data": {
        "target": url, "status_code": resp["status"],
        "server": resp["headers"].get("Server", ""),
        "x_powered_by": resp["headers"].get("X-Powered-By", ""),
        "content_type": resp["headers"].get("Content-Type", ""),
        "content_length": len(resp["body"]),
        "technologies": detected,
        "technology_count": len(detected),
        "ssl_certificate": ssl_info,
        "security_headers": security_headers,
        "missing_security_headers": [h for h, v in security_headers.items() if v == "未设置"],
    }}

@router.post("/whois")
def whois_lookup(req: ReconReq):
    """WHOIS信息查询（基础版，通过DNS+HTTP头推断）"""
    domain = req.target.replace("http://", "").replace("https://", "").split("/")[0]
    info = {"domain": domain, "queried_at": datetime.now().isoformat()}
    # DNS信息
    try:
        ip = socket.gethostbyname(domain)
        info["ip"] = ip
        try:
            info["hostname"] = socket.gethostbyaddr(ip)[0]
        except: pass
    except Exception as e:
        info["dns_error"] = str(e)
    # MX记录
    try:
        import socket as _s
        info["mx_records"] = []
        # 简化：尝试常见MX域名
        for mx in ["mail."+domain, "smtp."+domain, "mx."+domain]:
            if _dns_lookup(mx):
                info["mx_records"].append(mx)
    except: pass
    # NS记录（尝试常见NS）
    info["name_servers"] = []
    for ns in ["ns1."+domain, "ns2."+domain, "dns1."+domain]:
        if _dns_lookup(ns):
            info["name_servers"].append(ns)
    # HTTP响应头
    url = f"http://{domain}"
    resp = _fetch_url(url, timeout=req.timeout)
    if resp["status"] != 0:
        info["http_status"] = resp["status"]
        info["server"] = resp["headers"].get("Server", "")
        info["x_powered_by"] = resp["headers"].get("X-Powered-By", "")
    return {"success": True, "data": info}

@router.post("/full")
def full_recon(req: ReconReq):
    """完整侦察（子域名+目录+指纹+WHOIS一站式）"""
    results = {"target": req.target, "started_at": datetime.now().isoformat(), "phases": {}}
    # 1. 指纹识别（最快）
    try:
        fp = fingerprint_target(req)
        results["phases"]["fingerprint"] = fp.get("data", {})
    except Exception as e:
        results["phases"]["fingerprint"] = {"error": str(e)}
    # 2. 子域名枚举
    try:
        sub = enumerate_subdomains(req)
        results["phases"]["subdomains"] = sub.get("data", {})
    except Exception as e:
        results["phases"]["subdomains"] = {"error": str(e)}
    # 3. 目录爆破
    try:
        d = brute_directories(req)
        results["phases"]["directories"] = d.get("data", {})
    except Exception as e:
        results["phases"]["directories"] = {"error": str(e)}
    # 4. WHOIS
    try:
        w = whois_lookup(req)
        results["phases"]["whois"] = w.get("data", {})
    except Exception as e:
        results["phases"]["whois"] = {"error": str(e)}
    # 汇总
    results["summary"] = {
        "technologies_found": len(results["phases"].get("fingerprint", {}).get("technologies", [])),
        "subdomains_found": results["phases"].get("subdomains", {}).get("count", 0),
        "directories_found": results["phases"].get("directories", {}).get("count", 0),
        "ip": results["phases"].get("whois", {}).get("ip", ""),
    }
    results["completed_at"] = datetime.now().isoformat()
    return {"success": True, "data": results}

@router.get("/wordlists")
def get_wordlists():
    """获取字典信息"""
    return {"success": True, "data": {
        "subdomain_prefixes": {"count": len(COMMON_SUBDOMAINS), "sample": COMMON_SUBDOMAINS[:20]},
        "common_paths": {"count": len(COMMON_PATHS), "sample": COMMON_PATHS[:20]},
        "technology_fingerprints": {"count": len(TECH_FINGERPRINTS), "categories": list(set(v["category"] for v in TECH_FINGERPRINTS.values()))},
    }}
