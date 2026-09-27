#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高级安全工具集 - Advanced Security Tools
新增9大高级工具，真正融入项目核心：
1. SSL/TLS安全审计
2. WHOIS域名信息查询
3. CMS指纹识别
4. 安全头审计
5. CORS跨域测试
6. 点击劫持测试
7. SSH安全审计
8. 技术栈检测
9. 一键全面侦察（组合多个工具）
"""
import socket
import ssl
import json
import time
import re
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, Any, List, Optional
from datetime import datetime


# ============================================================
# 1. SSL/TLS安全审计
# ============================================================

def ssl_tls_audit(hostname: str, port: int = 443, timeout: int = 10) -> Dict[str, Any]:
    """SSL/TLS安全审计：检查证书、协议版本、密码套件、漏洞"""
    start_time = time.time()
    result = {
        "tool": "ssl_tls_audit",
        "target": hostname,
        "port": port,
        "status": "success",
        "findings": [],
        "score": 100,
        "details": {}
    }

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # 协议版本
                protocol = ssock.version()
                result["details"]["protocol"] = protocol

                # 密码套件
                cipher = ssock.cipher()
                result["details"]["cipher"] = cipher[0] if cipher else "Unknown"
                result["details"]["cipher_bits"] = cipher[2] if cipher else 0

                # 证书信息
                cert = ssock.getpeercert()
                if cert:
                    result["details"]["subject"] = dict(cert.get("subject", []))
                    result["details"]["issuer"] = dict(cert.get("issuer", []))
                    result["details"]["not_before"] = cert.get("notBefore")
                    result["details"]["not_after"] = cert.get("notAfter")
                    result["details"]["serial_number"] = cert.get("serialNumber")

                    # 证书过期检查
                    if cert.get("notAfter"):
                        try:
                            expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                            days_left = (expiry - datetime.utcnow()).days
                            result["details"]["days_until_expiry"] = days_left
                            if days_left < 0:
                                result["findings"].append({"severity": "critical", "title": "证书已过期", "detail": f"证书已于{abs(days_left)}天前过期"})
                                result["score"] -= 40
                            elif days_left < 30:
                                result["findings"].append({"severity": "high", "title": "证书即将过期", "detail": f"证书将在{days_left}天后过期"})
                                result["score"] -= 20
                        except:
                            pass
                else:
                    result["findings"].append({"severity": "medium", "title": "无法获取证书信息", "detail": "服务器未返回证书"})
                    result["score"] -= 10

                # 协议版本安全检查
                if protocol in ["TLSv1", "TLSv1.1"]:
                    result["findings"].append({"severity": "high", "title": f"使用过时协议{protocol}", "detail": "TLS 1.0/1.1已被弃用，存在安全风险，建议升级到TLS 1.2+"})
                    result["score"] -= 25
                elif protocol == "TLSv1.3":
                    result["findings"].append({"severity": "info", "title": "使用最新TLS 1.3", "detail": "协议版本安全"})

                # 弱密码套件检查
                weak_ciphers = ["RC4", "3DES", "DES", "MD5", "NULL", "EXPORT", "anon"]
                if cipher and any(w in cipher[0].upper() for w in weak_ciphers):
                    result["findings"].append({"severity": "high", "title": "使用弱密码套件", "detail": f"当前密码套件{cipher[0]}存在安全风险"})
                    result["score"] -= 20

    except socket.timeout:
        result["status"] = "failed"
        result["error"] = "连接超时"
        result["score"] = 0
    except ConnectionRefusedError:
        result["status"] = "failed"
        result["error"] = "连接被拒绝"
        result["score"] = 0
    except Exception as e:
        result["status"] = "failed"
        result["error"] = str(e)
        result["score"] = 0

    result["score"] = max(0, result["score"])
    result["duration_ms"] = round((time.time() - start_time) * 1000, 2)
    result["risk_level"] = "critical" if result["score"] < 40 else "high" if result["score"] < 60 else "medium" if result["score"] < 80 else "low"
    return result


# ============================================================
# 2. WHOIS域名信息查询
# ============================================================

def whois_lookup(domain: str, timeout: int = 15) -> Dict[str, Any]:
    """WHOIS查询：获取域名注册信息"""
    start_time = time.time()
    result = {
        "tool": "whois_lookup",
        "domain": domain,
        "status": "success",
        "info": {}
    }

    # 清理域名
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    try:
        # 使用RDAP协议（WHOIS的现代替代）
        rdap_url = f"https://rdap.org/domain/{domain}"
        req = urllib.request.Request(rdap_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))

            result["info"]["ldhName"] = data.get("ldhName", "")
            result["info"]["status"] = data.get("status", [])

            # 注册商
            if "entities" in data:
                for entity in data["entities"]:
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        result["info"]["registrar"] = entity.get("vcardArray", [[]])[1:]
                        break

            # 事件（注册/过期时间）
            if "events" in data:
                for event in data["events"]:
                    if event.get("eventAction") == "registration":
                        result["info"]["registration_date"] = event.get("eventDate")
                    elif event.get("eventAction") == "expiration":
                        result["info"]["expiration_date"] = event.get("eventDate")
                    elif event.get("eventAction") == "last changed":
                        result["info"]["last_updated"] = event.get("eventDate")

            # 名称服务器
            if "nameservers" in data:
                result["info"]["nameservers"] = [ns.get("ldhName", "") for ns in data["nameservers"]]

            # DNSSEC
            result["info"]["dnssec"] = data.get("secureDNS", {}).get("delegationSigned", "unknown")

    except Exception as e:
        # RDAP失败，尝试基本WHOIS
        try:
            whois_server = "whois.iana.org"
            with socket.create_connection((whois_server, 43), timeout=timeout) as sock:
                sock.sendall((domain + "\r\n").encode())
                response = b""
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                result["info"]["raw_whois"] = response.decode("utf-8", errors="ignore")[:2000]
        except Exception as e2:
            result["status"] = "failed"
            result["error"] = f"RDAP: {str(e)}, WHOIS: {str(e2)}"

    result["duration_ms"] = round((time.time() - start_time) * 1000, 2)
    return result


# ============================================================
# 3. CMS指纹识别
# ============================================================

# CMS指纹库
CMS_SIGNATURES = {
    "WordPress": {
        "paths": ["/wp-content/", "/wp-includes/", "/wp-login.php", "/xmlrpc.php"],
        "headers": {},
        "meta": ["WordPress"]
    },
    "Drupal": {
        "paths": ["/sites/default/", "/misc/drupal.js", "/CHANGELOG.txt"],
        "headers": {"X-Generator": "Drupal"},
        "meta": ["Drupal"]
    },
    "Joomla": {
        "paths": ["/administrator/", "/templates/", "/media/system/js/"],
        "headers": {},
        "meta": ["Joomla"]
    },
    "Magento": {
        "paths": ["/magento/", "/skin/frontend/", "/js/mage/"],
        "headers": {},
        "meta": ["Magento"]
    },
    "Shopify": {
        "paths": ["/cdn/shopify/", "/services/"],
        "headers": {},
        "meta": ["shopify"]
    },
    "Discuz": {
        "paths": ["/forum.php", "/source/", "/uc_server/"],
        "headers": {},
        "meta": ["Discuz"]
    },
    "ThinkPHP": {
        "paths": ["/index.php?s=", "/runtime/", "/application/"],
        "headers": {},
        "meta": ["ThinkPHP"]
    },
    "Spring Boot": {
        "paths": ["/actuator", "/actuator/health", "/actuator/env"],
        "headers": {},
        "meta": []
    },
    "Laravel": {
        "paths": ["/favicon.ico", "/public/", "/storage/"],
        "headers": {},
        "meta": ["laravel"]
    },
    "Django": {
        "paths": ["/admin/", "/static/admin/"],
        "headers": {},
        "meta": []
    },
    "Flask": {
        "paths": ["/static/"],
        "headers": {"Server": "Werkzeug"},
        "meta": []
    },
    "Express.js": {
        "paths": ["/public/", "/stylesheets/"],
        "headers": {"X-Powered-By": "Express"},
        "meta": []
    },
    "Nginx": {
        "paths": [],
        "headers": {"Server": "nginx"},
        "meta": []
    },
    "Apache": {
        "paths": [],
        "headers": {"Server": "Apache"},
        "meta": []
    },
    "IIS": {
        "paths": [],
        "headers": {"Server": "Microsoft-IIS"},
        "meta": []
    },
}


def cms_fingerprint(url: str, timeout: int = 10) -> Dict[str, Any]:
    """CMS指纹识别：识别网站使用的CMS系统和技术栈"""
    start_time = time.time()
    result = {
        "tool": "cms_fingerprint",
        "url": url,
        "status": "success",
        "detected_cms": [],
        "tech_stack": [],
        "confidence": "low"
    }

    if not url.startswith("http"):
        url = "http://" + url

    try:
        # 获取首页
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
            headers = dict(resp.headers)

            result["tech_stack"].append(f"HTTP Status: {resp.status}")
            if "Server" in headers:
                result["tech_stack"].append(f"Server: {headers['Server']}")
            if "X-Powered-By" in headers:
                result["tech_stack"].append(f"X-Powered-By: {headers['X-Powered-By']}")

            # 检测CMS
            for cms_name, sig in CMS_SIGNATURES.items():
                matches = 0

                # 路径检测
                for path in sig.get("paths", []):
                    try:
                        path_url = urllib.parse.urljoin(url, path)
                        path_req = urllib.request.Request(path_url, headers={"User-Agent": "Mozilla/5.0"})
                        with urllib.request.urlopen(path_req, timeout=5) as path_resp:
                            if path_resp.status == 200:
                                matches += 1
                    except:
                        pass

                # Header检测
                for header_key, header_val in sig.get("headers", {}).items():
                    if header_key in headers and header_val.lower() in headers[header_key].lower():
                        matches += 1

                # Meta检测
                for meta_val in sig.get("meta", []):
                    if meta_val.lower() in html.lower():
                        matches += 1

                if matches > 0:
                    result["detected_cms"].append({
                        "name": cms_name,
                        "confidence": matches,
                        "match_count": matches
                    })

            # 按置信度排序
            result["detected_cms"].sort(key=lambda x: x["confidence"], reverse=True)

            if result["detected_cms"]:
                top = result["detected_cms"][0]
                result["confidence"] = "high" if top["confidence"] >= 3 else "medium" if top["confidence"] >= 2 else "low"
                result["primary_cms"] = top["name"]

    except Exception as e:
        result["status"] = "failed"
        result["error"] = str(e)

    result["duration_ms"] = round((time.time() - start_time) * 1000, 2)
    return result


# ============================================================
# 4. 安全头审计
# ============================================================

SECURITY_HEADERS_CHECKLIST = {
    "Strict-Transport-Security": {
        "required": True,
        "severity": "high",
        "description": "HSTS - 强制使用HTTPS",
        "recommendation": "max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "required": True,
        "severity": "high",
        "description": "CSP - 内容安全策略，防止XSS",
        "recommendation": "default-src 'self'; script-src 'self'"
    },
    "X-Frame-Options": {
        "required": True,
        "severity": "medium",
        "description": "防止点击劫持",
        "recommendation": "DENY 或 SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "required": True,
        "severity": "medium",
        "description": "防止MIME类型嗅探",
        "recommendation": "nosniff"
    },
    "Referrer-Policy": {
        "required": False,
        "severity": "low",
        "description": "控制Referrer信息泄露",
        "recommendation": "strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "required": False,
        "severity": "low",
        "description": "控制浏览器功能权限",
        "recommendation": "geolocation=(), microphone=(), camera=()"
    },
    "X-XSS-Protection": {
        "required": False,
        "severity": "info",
        "description": "旧版XSS过滤器（已被CSP替代）",
        "recommendation": "1; mode=block"
    },
}


def security_headers_audit(url: str, timeout: int = 10) -> Dict[str, Any]:
    """安全头审计：检查HTTP安全响应头配置"""
    start_time = time.time()
    result = {
        "tool": "security_headers_audit",
        "url": url,
        "status": "success",
        "score": 100,
        "present_headers": {},
        "missing_headers": [],
        "findings": []
    }

    if not url.startswith("http"):
        url = "http://" + url

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in dict(resp.headers).items()}

            for header_name, check in SECURITY_HEADERS_CHECKLIST.items():
                header_lower = header_name.lower()
                if header_lower in headers:
                    result["present_headers"][header_name] = headers[header_lower]
                    result["findings"].append({
                        "severity": "info",
                        "title": f"✓ {header_name} 已配置",
                        "detail": headers[header_lower]
                    })
                else:
                    result["missing_headers"].append(header_name)
                    if check["required"]:
                        result["score"] -= 15
                        result["findings"].append({
                            "severity": check["severity"],
                            "title": f"✗ 缺少 {header_name}",
                            "detail": check["description"],
                            "recommendation": check["recommendation"]
                        })
                    else:
                        result["score"] -= 5
                        result["findings"].append({
                            "severity": "low",
                            "title": f"△ 建议添加 {header_name}",
                            "detail": check["description"],
                            "recommendation": check["recommendation"]
                        })

            # 检查危险头
            dangerous_headers = ["X-Powered-By", "Server", "X-AspNet-Version", "X-Generator"]
            for dh in dangerous_headers:
                if dh.lower() in headers:
                    result["findings"].append({
                        "severity": "info",
                        "title": f"⚠ 信息泄露头: {dh}",
                        "detail": f"{dh}: {headers[dh.lower()]}",
                        "recommendation": "建议移除或模糊化此头信息"
                    })

    except Exception as e:
        result["status"] = "failed"
        result["error"] = str(e)
        result["score"] = 0

    result["score"] = max(0, result["score"])
    result["risk_level"] = "critical" if result["score"] < 40 else "high" if result["score"] < 60 else "medium" if result["score"] < 80 else "low"
    result["duration_ms"] = round((time.time() - start_time) * 1000, 2)
    return result


# ============================================================
# 5. CORS跨域测试
# ============================================================

def cors_test(url: str, timeout: int = 10) -> Dict[str, Any]:
    """CORS跨域测试：检查跨域资源共享配置安全"""
    start_time = time.time()
    result = {
        "tool": "cors_test",
        "url": url,
        "status": "success",
        "findings": [],
        "risk_level": "low"
    }

    if not url.startswith("http"):
        url = "http://" + url

    test_origins = [
        "https://evil.com",
        "null",
        "https://subdomain.evil.com",
    ]

    try:
        for origin in test_origins:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0",
                "Origin": origin
            })
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                if acao == "*":
                    result["findings"].append({
                        "severity": "medium",
                        "title": "CORS配置过于宽松",
                        "detail": "Access-Control-Allow-Origin设置为*，允许任意域访问",
                        "origin_tested": origin
                    })
                elif acao == origin and origin == "https://evil.com":
                    severity = "high" if acac.lower() == "true" else "medium"
                    result["findings"].append({
                        "severity": severity,
                        "title": "CORS反射任意Origin",
                        "detail": f"服务器反射了任意Origin: {acao}" + ("，且允许凭据" if acac.lower() == "true" else ""),
                        "origin_tested": origin
                    })
                elif acao == "null":
                    result["findings"].append({
                        "severity": "high",
                        "title": "CORS允许null Origin",
                        "detail": "null Origin可被沙箱iframe利用",
                        "origin_tested": origin
                    })

        if not result["findings"]:
            result["findings"].append({
                "severity": "info",
                "title": "CORS配置安全",
                "detail": "未发现明显的CORS配置问题"
            })

        high_count = sum(1 for f in result["findings"] if f["severity"] == "high")
        result["risk_level"] = "high" if high_count > 0 else "medium" if any(f["severity"] == "medium" for f in result["findings"]) else "low"

    except Exception as e:
        result["status"] = "failed"
        result["error"] = str(e)

    result["duration_ms"] = round((time.time() - start_time) * 1000, 2)
    return result


# ============================================================
# 6. 点击劫持测试
# ============================================================

def clickjacking_test(url: str, timeout: int = 10) -> Dict[str, Any]:
    """点击劫持测试：检查X-Frame-Options和CSP frame-ancestors"""
    start_time = time.time()
    result = {
        "tool": "clickjacking_test",
        "url": url,
        "status": "success",
        "vulnerable": False,
        "findings": []
    }

    if not url.startswith("http"):
        url = "http://" + url

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in dict(resp.headers).items()}

            xfo = headers.get("x-frame-options", "")
            csp = headers.get("content-security-policy", "")

            if xfo:
                result["findings"].append({
                    "severity": "info",
                    "title": f"X-Frame-Options: {xfo}",
                    "detail": "已配置点击劫持防护"
                })
            elif "frame-ancestors" in csp:
                result["findings"].append({
                    "severity": "info",
                    "title": "CSP frame-ancestors已配置",
                    "detail": csp
                })
            else:
                result["vulnerable"] = True
                result["findings"].append({
                    "severity": "medium",
                    "title": "存在点击劫持风险",
                    "detail": "未设置X-Frame-Options或CSP frame-ancestors",
                    "recommendation": "添加 X-Frame-Options: DENY 或 Content-Security-Policy: frame-ancestors 'none'"
                })

    except Exception as e:
        result["status"] = "failed"
        result["error"] = str(e)

    result["duration_ms"] = round((time.time() - start_time) * 1000, 2)
    return result


# ============================================================
# 7. SSH安全审计
# ============================================================

def ssh_audit(hostname: str, port: int = 22, timeout: int = 10) -> Dict[str, Any]:
    """SSH安全审计：检查SSH服务版本和配置"""
    start_time = time.time()
    result = {
        "tool": "ssh_audit",
        "target": hostname,
        "port": port,
        "status": "success",
        "banner": "",
        "findings": [],
        "risk_level": "low"
    }

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            result["banner"] = banner

            # 分析SSH版本
            if "SSH-2.0-OpenSSH" in banner:
                version = banner.split("OpenSSH_")[1].split()[0] if "OpenSSH_" in banner else "unknown"
                result["ssh_version"] = f"OpenSSH {version}"

                # 已知漏洞版本检查
                vulnerable_versions = {
                    "7.2p2": "CVE-2016-10009/10010/10011/10012",
                    "7.4": "CVE-2017-15906",
                    "7.7": "CVE-2018-15473",
                    "8.1": "CVE-2020-14145",
                    "8.2": "CVE-2020-15778",
                    "8.3": "CVE-2020-16877",
                    "8.4": "CVE-2021-28041",
                    "8.5": "CVE-2021-36368",
                    "8.6": "CVE-2021-41617",
                    "8.7": "CVE-2022-29154",
                    "8.8": "CVE-2023-28531",
                    "8.9": "CVE-2023-38408",
                    "9.0": "CVE-2023-48795 (Terrapin)",
                    "9.1": "CVE-2023-48795 (Terrapin)",
                    "9.2": "CVE-2024-6387 (regreSSHion)",
                    "9.3": "CVE-2024-6387 (regreSSHion)",
                    "9.4": "CVE-2024-6387 (regreSSHion)",
                    "9.5": "CVE-2024-6387 (regreSSHion)",
                    "9.6": "CVE-2024-6387 (regreSSHion)",
                    "9.7": "CVE-2024-6387 (regreSSHion)",
                    "9.8": "CVE-2024-6387 (regreSSHion)",
                }

                for v, cve in vulnerable_versions.items():
                    if version.startswith(v):
                        result["findings"].append({
                            "severity": "high",
                            "title": f"OpenSSH {version} 存在已知漏洞",
                            "detail": cve,
                            "recommendation": "升级到最新版本OpenSSH"
                        })
                        result["risk_level"] = "high"
                        break

                if not result["findings"]:
                    result["findings"].append({
                        "severity": "info",
                        "title": "SSH版本信息",
                        "detail": f"运行 OpenSSH {version}"
                    })

            elif "SSH-1.99" in banner or "SSH-1.5" in banner:
                result["findings"].append({
                    "severity": "critical",
                    "title": "SSH协议版本1已启用",
                    "detail": "SSH v1存在严重安全漏洞，应禁用",
                    "recommendation": "禁用SSH协议1，仅使用SSH v2"
                })
                result["risk_level"] = "critical"

    except socket.timeout:
        result["status"] = "failed"
        result["error"] = "连接超时"
    except ConnectionRefusedError:
        result["status"] = "failed"
        result["error"] = "连接被拒绝（SSH服务可能未运行）"
    except Exception as e:
        result["status"] = "failed"
        result["error"] = str(e)

    result["duration_ms"] = round((time.time() - start_time) * 1000, 2)
    return result


# ============================================================
# 8. 技术栈检测
# ============================================================

def tech_stack_detect(url: str, timeout: int = 10) -> Dict[str, Any]:
    """技术栈检测：综合识别Web服务器、编程语言、框架、数据库、CDN"""
    start_time = time.time()
    result = {
        "tool": "tech_stack_detect",
        "url": url,
        "status": "success",
        "web_server": "",
        "programming_language": "",
        "framework": "",
        "database": "",
        "cdn": "",
        "operating_system": "",
        "all_detected": []
    }

    if not url.startswith("http"):
        url = "http://" + url

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in dict(resp.headers).items()}
            html = resp.read().decode("utf-8", errors="ignore")[:50000]

            # Web服务器
            server = headers.get("server", "")
            if server:
                result["web_server"] = server
                result["all_detected"].append(f"Web服务器: {server}")

            # 编程语言/框架
            x_powered = headers.get("x-powered-by", "")
            if x_powered:
                result["programming_language"] = x_powered
                result["all_detected"].append(f"技术栈: {x_powered}")

            # Cookie检测
            set_cookie = headers.get("set-cookie", "").lower()
            if "phpsessid" in set_cookie:
                result["programming_language"] = "PHP"
                result["all_detected"].append("编程语言: PHP (PHPSESSID)")
            elif "asp.net_sessionid" in set_cookie:
                result["programming_language"] = "ASP.NET"
                result["all_detected"].append("编程语言: ASP.NET")
            elif "jsessionid" in set_cookie:
                result["programming_language"] = "Java"
                result["all_detected"].append("编程语言: Java (JSESSIONID)")
            elif "connect.sid" in set_cookie:
                result["framework"] = "Express.js"
                result["all_detected"].append("框架: Express.js")
            elif "csrftoken" in set_cookie:
                result["framework"] = "Django"
                result["all_detected"].append("框架: Django")

            # HTML特征检测
            if "/wp-content/" in html or "wp-includes" in html:
                result["framework"] = "WordPress"
                result["all_detected"].append("CMS: WordPress")
            if "drupal" in html.lower():
                result["framework"] = "Drupal"
                result["all_detected"].append("CMS: Drupal")
            if "joomla" in html.lower():
                result["framework"] = "Joomla"
                result["all_detected"].append("CMS: Joomla")
            if "laravel" in html.lower():
                result["framework"] = "Laravel"
                result["all_detected"].append("框架: Laravel")
            if "vue.js" in html.lower() or "vuejs" in html.lower():
                result["all_detected"].append("前端框架: Vue.js")
            if "react" in html.lower():
                result["all_detected"].append("前端框架: React")
            if "angular" in html.lower():
                result["all_detected"].append("前端框架: Angular")
            if "jquery" in html.lower():
                result["all_detected"].append("前端库: jQuery")
            if "bootstrap" in html.lower():
                result["all_detected"].append("CSS框架: Bootstrap")

            # CDN检测
            cdn_headers = ["cf-ray", "x-cache", "x-served-by", "x-amz-cf-id"]
            for ch in cdn_headers:
                if ch in headers:
                    result["cdn"] = headers[ch]
                    result["all_detected"].append(f"CDN: {ch}={headers[ch]}")
                    break

            # 操作系统推断
            if "win" in server.lower():
                result["operating_system"] = "Windows"
            elif "ubuntu" in server.lower() or "debian" in server.lower():
                result["operating_system"] = "Linux (Debian/Ubuntu)"
            elif "centos" in server.lower() or "rhel" in server.lower():
                result["operating_system"] = "Linux (RHEL/CentOS)"

    except Exception as e:
        result["status"] = "failed"
        result["error"] = str(e)

    result["duration_ms"] = round((time.time() - start_time) * 1000, 2)
    return result


# ============================================================
# 9. 一键全面侦察（组合多个工具）
# ============================================================

def full_recon(target: str, timeout: int = 30) -> Dict[str, Any]:
    """一键全面侦察：组合端口扫描+DNS+HTTP头+SSL+CMS+安全头+技术栈"""
    start_time = time.time()
    result = {
        "tool": "full_recon",
        "target": target,
        "status": "success",
        "summary": {},
        "details": {}
    }

    # 标准化目标
    host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    url = target if target.startswith("http") else f"http://{host}"

    tasks = [
        ("dns", lambda: __import__("mcp_server.recon_tools", fromlist=["dns_lookup"]).dns_lookup(domain=host)),
        ("http_headers", lambda: __import__("mcp_server.recon_tools", fromlist=["http_headers"]).http_headers(url=url)),
        ("ssl_tls", lambda: ssl_tls_audit(hostname=host)),
        ("cms", lambda: cms_fingerprint(url=url)),
        ("security_headers", lambda: security_headers_audit(url=url)),
        ("tech_stack", lambda: tech_stack_detect(url=url)),
        ("cors", lambda: cors_test(url=url)),
        ("clickjacking", lambda: clickjacking_test(url=url)),
    ]

    findings = []
    for name, task_func in tasks:
        try:
            task_result = task_func()
            result["details"][name] = task_result
            if task_result.get("status") == "success":
                if "findings" in task_result:
                    findings.extend([f for f in task_result["findings"] if f.get("severity") in ["critical", "high", "medium"]])
                if "score" in task_result:
                    result["summary"][f"{name}_score"] = task_result["score"]
        except Exception as e:
            result["details"][name] = {"status": "failed", "error": str(e)}

    # 端口扫描（单独处理，可能耗时较长）
    try:
        from mcp_server.recon_tools import port_scan
        port_result = port_scan(target=host, ports="1-1000", timeout=3)
        result["details"]["port_scan"] = port_result
        if port_result.get("status") == "success":
            result["summary"]["open_ports"] = port_result.get("open_ports", [])
            result["summary"]["services"] = port_result.get("services", {})
    except Exception as e:
        result["details"]["port_scan"] = {"status": "failed", "error": str(e)}

    # 汇总
    result["summary"]["total_findings"] = len(findings)
    result["summary"]["critical_findings"] = sum(1 for f in findings if f.get("severity") == "critical")
    result["summary"]["high_findings"] = sum(1 for f in findings if f.get("severity") == "high")
    result["summary"]["medium_findings"] = sum(1 for f in findings if f.get("severity") == "medium")
    result["findings"] = findings[:20]  # 最多返回20条

    result["duration_ms"] = round((time.time() - start_time) * 1000, 2)
    return result
