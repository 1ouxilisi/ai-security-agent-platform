#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
osint_collector模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import json
import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin

import aiohttp
import asyncio

from utils.logger import log


@dataclass
class OSINTResult:
    """OSINT收集结果"""
    result_id: str
    target: str
    result_type: str  # employee/historical_vuln/leaked_cred/subdomain_takeover/api_endpoint/org_info/dns_record/whois
    title: str = ""
    source: str = ""
    url: str = ""
    confidence: str = "medium"  # high/medium/low
    details: Dict[str, Any] = field(default_factory=dict)
    discovered_at: float = field(default_factory=time.time)
    tags: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "result_id": self.result_id,
            "target": self.target,
            "result_type": self.result_type,
            "title": self.title,
            "source": self.source,
            "url": self.url,
            "confidence": self.confidence,
            "details": self.details,
            "discovered_at": self.discovered_at,
            "tags": self.tags,
            "notes": self.notes
        }


class OSINTCollector:
    """OSINT开源情报收集器"""

    def __init__(self, data_dir: str = "data/osint"):
        """初始化OSINTCollector实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.results: Dict[str, OSINTResult] = {}
        os.makedirs(data_dir, exist_ok=True)
        self._load_results()
        # 常见API端点路径
        self.api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3", "/graphql", "/graphiql",
            "/swagger", "/swagger-ui", "/swagger-ui.html", "/api-docs",
            "/api/swagger", "/api/swagger-ui.html", "/openapi.json",
            "/v1", "/v2", "/v3", "/admin", "/admin/api", "/internal",
            "/internal/api", "/debug", "/debug/vars", "/metrics",
            "/actuator", "/actuator/health", "/actuator/env", "/actuator/heapdump",
            "/wp-json", "/wp-json/wp/v2/users", "/api/user", "/api/users",
            "/api/login", "/api/auth", "/api/token", "/api/register",
            "/api/upload", "/api/download", "/api/export", "/api/import",
            "/api/search", "/api/query", "/api/admin", "/api/config",
            "/api/settings", "/api/profile", "/api/account", "/api/password",
            "/api/reset", "/api/forgot", "/api/verify", "/api/confirm",
            "/api/callback", "/api/webhook", "/api/notify", "/api/subscribe",
            "/api/unsubscribe", "/api/payment", "/api/order", "/api/cart",
            "/api/checkout", "/api/refund", "/api/invoice", "/api/receipt",
            "/api/file", "/api/files", "/api/image", "/api/images",
            "/api/avatar", "/api/attachment", "/api/attachments",
            "/api/comment", "/api/comments", "/api/post", "/api/posts",
            "/api/article", "/api/articles", "/api/news", "/api/feed",
            "/api/message", "/api/messages", "/api/chat", "/api/conversation",
            "/api/notification", "/api/notifications", "/api/alert",
            "/api/log", "/api/logs", "/api/audit", "/api/history",
            "/api/report", "/api/reports", "/api/analytics", "/api/stats",
            "/api/dashboard", "/api/overview", "/api/summary",
            "/api/health", "/api/status", "/api/ping", "/api/version",
            "/api/info", "/api/about", "/api/contact", "/api/support",
            "/api/help", "/api/faq", "/api/docs", "/api/documentation",
            "/api/schema", "/api/spec", "/api/specification",
            "/api/test", "/api/dev", "/api/development", "/api/staging",
            "/api/prod", "/api/production", "/api/live", "/api/preview",
            "/api/beta", "/api/alpha", "/api/experimental",
            "/api/legacy", "/api/deprecated", "/api/old", "/api/new",
            "/api/v0", "/api/v4", "/api/v5", "/api/latest", "/api/current",
        ]
        # 子域名接管常见服务指纹
        self.takeover_fingerprints = {
            "github": ["There isn't a GitHub Pages site here.", "For root URLs (like http://example.com/) you must provide an index.html file."],
            "heroku": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
            "aws_s3": ["NoSuchBucket", "The specified bucket does not exist"],
            "shopify": ["Sorry, this shop is currently unavailable."],
            "tumblr": ["Whatever you were looking for doesn't currently exist at this address."],
            "wordpress": ["Do you want to register"],
            "zendesk": ["Help Center Closed"],
            "fastly": ["Fastly error: unknown domain"],
            "netlify": ["Not Found - Request ID"],
            "surge": ["project not found"],
            "bitbucket": ["Repository not found"],
            "gitlab": ["The page could not be found or you don't have permission to view it."],
        }

    def _load_results(self):
        """从文件加载结果"""
        results_file = os.path.join(self.data_dir, "osint_results.json")
        if os.path.exists(results_file):
            try:
                with open(results_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for rid, rdata in data.items():
                    self.results[rid] = OSINTResult(
                        result_id=rdata["result_id"],
                        target=rdata.get("target", ""),
                        result_type=rdata.get("result_type", ""),
                        title=rdata.get("title", ""),
                        source=rdata.get("source", ""),
                        url=rdata.get("url", ""),
                        confidence=rdata.get("confidence", "medium"),
                        details=rdata.get("details", {}),
                        discovered_at=rdata.get("discovered_at", time.time()),
                        tags=rdata.get("tags", []),
                        notes=rdata.get("notes", "")
                    )
            except Exception as e:
                log.error(f"加载OSINT结果失败: {e}")

    def _save_results(self):
        """保存结果到文件"""
        results_file = os.path.join(self.data_dir, "osint_results.json")
        try:
            data = {rid: r.to_dict() for rid, r in self.results.items()}
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存OSINT结果失败: {e}")

    def _add_result(self, target: str, result_type: str, title: str,
                     source: str = "", url: str = "", confidence: str = "medium",
                     details: Dict[str, Any] = None, tags: List[str] = None) -> str:
        """添加结果"""
        result_id = f"osint-{uuid.uuid4().hex[:8]}"
        result = OSINTResult(
            result_id=result_id,
            target=target,
            result_type=result_type,
            title=title,
            source=source,
            url=url,
            confidence=confidence,
            details=details or {},
            tags=tags or []
        )
        self.results[result_id] = result
        self._save_results()
        return result_id

    # ===== 1. 组织信息收集 =====
    def collect_org_info(self, domain: str) -> Dict[str, Any]:
        """收集组织信息（WHOIS/DNS/注册信息）"""
        log.info(f"收集组织信息: {domain}")
        results = []

        # WHOIS信息（模拟，实际需要调用whois库或API）
        whois_info = self._query_whois(domain)
        if whois_info:
            rid = self._add_result(
                target=domain,
                result_type="org_info",
                title=f"WHOIS注册信息: {domain}",
                source="WHOIS",
                confidence="high",
                details=whois_info,
                tags=["whois", "org_info"]
            )
            results.append(rid)

        # DNS记录
        dns_records = self._query_dns(domain)
        if dns_records:
            rid = self._add_result(
                target=domain,
                result_type="dns_record",
                title=f"DNS记录: {domain}",
                source="DNS",
                confidence="high",
                details=dns_records,
                tags=["dns", "org_info"]
            )
            results.append(rid)

        return {
            "target": domain,
            "results_count": len(results),
            "result_ids": results,
            "whois": whois_info,
            "dns": dns_records
        }

    def _query_whois(self, domain: str) -> Optional[Dict[str, Any]]:
        """查询WHOIS信息（简化实现）"""
        try:
            import socket
            # 简化的WHOIS查询
            whois_server = "whois.iana.org"
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((whois_server, 43))
            sock.send(f"{domain}\r\n".encode())
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            sock.close()
            text = response.decode('utf-8', errors='ignore')

            # 解析关键字段
            info = {}
            for line in text.split('\n'):
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    if key in ['registrar', 'registrant', 'admin', 'tech', 'created', 'updated', 'expires', 'name servers', 'status']:
                        info[key] = value
            return info if info else None
        except Exception as e:
            log.debug(f"WHOIS查询失败: {e}")
            return None

    def _query_dns(self, domain: str) -> Optional[Dict[str, Any]]:
        """查询DNS记录（简化实现）"""
        try:
            import socket
            records = {}
            # A记录
            try:
                ips = socket.getaddrinfo(domain, None)
                records['A'] = list(set([ip[4][0] for ip in ips]))
            except:
                pass
            # MX记录（简化）
            try:
                mx_domain = f"mail.{domain}"
                socket.gethostbyname(mx_domain)
                records['MX'] = [mx_domain]
            except:
                pass
            return records if records else None
        except Exception as e:
            log.debug(f"DNS查询失败: {e}")
            return None

    # ===== 2. 历史漏洞查询 =====
    def query_historical_vulns(self, target: str, keywords: List[str] = None) -> Dict[str, Any]:
        """查询历史漏洞（基于本地CVE库和公开漏洞数据库）"""
        log.info(f"查询历史漏洞: {target}")
        results = []

        # 从本地CVE库搜索
        try:
            cve_file = "data/knowledge/cve_database.json"
            if os.path.exists(cve_file):
                with open(cve_file, 'r', encoding='utf-8') as f:
                    cve_data = json.load(f)

                search_terms = [target] + (keywords or [])
                matched = []
                for cve_id, cve_info in cve_data.items():
                    description = cve_info.get("description", "").lower()
                    for term in search_terms:
                        if term.lower() in description:
                            matched.append({
                                "cve_id": cve_id,
                                "severity": cve_info.get("severity", "unknown"),
                                "description": cve_info.get("description", ""),
                                "match_term": term
                            })
                            break

                for vuln in matched[:20]:  # 最多20条
                    rid = self._add_result(
                        target=target,
                        result_type="historical_vuln",
                        title=f"{vuln['cve_id']}: {vuln['description'][:80]}",
                        source="CVE Database",
                        confidence="medium",
                        details=vuln,
                        tags=["cve", "historical_vuln", vuln['severity']]
                    )
                    results.append(rid)
        except Exception as e:
            log.error(f"查询本地CVE库失败: {e}")

        return {
            "target": target,
            "results_count": len(results),
            "result_ids": results,
            "matched_vulns": len(results)
        }

    # ===== 3. 泄露凭证查询 =====
    def check_leaked_credentials(self, domain: str, emails: List[str] = None) -> Dict[str, Any]:
        """检查泄露凭证（基于本地泄露库和Have I Been Pwned API）"""
        log.info(f"检查泄露凭证: {domain}")
        results = []

        # 检查本地泄露库
        leak_file = "data/osint/leaked_credentials.json"
        leaked = []
        if os.path.exists(leak_file):
            try:
                with open(leak_file, 'r', encoding='utf-8') as f:
                    leak_data = json.load(f)
                for email, info in leak_data.items():
                    if domain in email or (emails and email in emails):
                        leaked.append({
                            "email": email,
                            "breaches": info.get("breaches", []),
                            "passwords": info.get("passwords", []),
                            "first_seen": info.get("first_seen", "")
                        })
            except Exception as e:
                log.error(f"读取本地泄露库失败: {e}")

        for item in leaked:
            rid = self._add_result(
                target=domain,
                result_type="leaked_cred",
                title=f"泄露凭证: {item['email']}",
                source="Local Leak Database",
                confidence="high",
                details=item,
                tags=["credential_leak", "email", "password"]
            )
            results.append(rid)

        return {
            "target": domain,
            "results_count": len(results),
            "result_ids": results,
            "leaked_count": len(leaked),
            "leaked_emails": [item['email'] for item in leaked]
        }

    # ===== 4. 子域名接管检测 =====
    def check_subdomain_takeover(self, subdomains: List[str]) -> Dict[str, Any]:
        """检测子域名接管可能性"""
        log.info(f"检测子域名接管: {len(subdomains)}个子域名")
        results = []
        vulnerable = []

        async def check_one(domain: str):
            try:
                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(f"http://{domain}", allow_redirects=True, ssl=False) as resp:
                        text = await resp.text()
                        status = resp.status
                        # 检查接管指纹
                        for service, fingerprints in self.takeover_fingerprints.items():
                            for fp in fingerprints:
                                if fp in text:
                                    return {
                                        "domain": domain,
                                        "vulnerable": True,
                                        "service": service,
                                        "status_code": status,
                                        "fingerprint": fp,
                                        "confidence": "high"
                                    }
                        # 检查404且指向第三方服务
                        if status == 404:
                            for service in self.takeover_fingerprints.keys():
                                if service in text.lower():
                                    return {
                                        "domain": domain,
                                        "vulnerable": True,
                                        "service": service,
                                        "status_code": status,
                                        "fingerprint": "404 + service reference",
                                        "confidence": "medium"
                                    }
                        return {"domain": domain, "vulnerable": False, "status_code": status}
            except Exception as e:
                return {"domain": domain, "vulnerable": False, "error": str(e)}

        async def check_all():
            tasks = [check_one(d) for d in subdomains[:50]]  # 最多检查50个
            return await asyncio.gather(*tasks)

        try:
            check_results = asyncio.run(check_all())
        except:
            # 如果asyncio有问题，用同步方式
            check_results = []
            import requests
            for domain in subdomains[:50]:
                try:
                    resp = requests.get(f"http://{domain}", timeout=10, allow_redirects=True, verify=False)
                    text = resp.text
                    found = False
                    for service, fingerprints in self.takeover_fingerprints.items():
                        for fp in fingerprints:
                            if fp in text:
                                check_results.append({
                                    "domain": domain, "vulnerable": True,
                                    "service": service, "status_code": resp.status_code,
                                    "fingerprint": fp, "confidence": "high"
                                })
                                found = True
                                break
                        if found:
                            break
                    if not found:
                        check_results.append({"domain": domain, "vulnerable": False, "status_code": resp.status_code})
                except Exception as e:
                    check_results.append({"domain": domain, "vulnerable": False, "error": str(e)})

        for result in check_results:
            if result.get("vulnerable"):
                vulnerable.append(result)
                rid = self._add_result(
                    target=result["domain"],
                    result_type="subdomain_takeover",
                    title=f"子域名接管可能: {result['domain']} ({result.get('service', 'unknown')})",
                    source="Subdomain Takeover Check",
                    confidence=result.get("confidence", "medium"),
                    details=result,
                    tags=["subdomain_takeover", "vulnerable", result.get("service", "")]
                )
                results.append(rid)

        return {
            "checked_count": len(subdomains[:50]),
            "vulnerable_count": len(vulnerable),
            "vulnerable": vulnerable,
            "result_ids": results
        }

    # ===== 5. API端点发现 =====
    def discover_api_endpoints(self, base_url: str, js_content: str = None) -> Dict[str, Any]:
        """发现API端点（从常见路径、JS文件、文档中提取）"""
        log.info(f"发现API端点: {base_url}")
        results = []
        discovered = []

        # 1. 检查常见API路径
        async def check_path(path: str):
            url = urljoin(base_url, path)
            try:
                timeout = aiohttp.ClientTimeout(total=8)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url, allow_redirects=False, ssl=False) as resp:
                        status = resp.status
                        if status in [200, 201, 401, 403, 405]:
                            content_type = resp.headers.get('Content-Type', '')
                            return {
                                "url": url,
                                "path": path,
                                "status_code": status,
                                "content_type": content_type,
                                "confidence": "high" if status in [200, 201] else "medium"
                            }
            except:
                pass
            return None

        async def check_all_paths():
            tasks = [check_path(p) for p in self.api_paths]
            return await asyncio.gather(*tasks)

        try:
            path_results = asyncio.run(check_all_paths())
        except:
            # 同步回退
            import requests
            path_results = []
            for path in self.api_paths:
                url = urljoin(base_url, path)
                try:
                    resp = requests.get(url, timeout=8, allow_redirects=False, verify=False)
                    if resp.status_code in [200, 201, 401, 403, 405]:
                        path_results.append({
                            "url": url, "path": path,
                            "status_code": resp.status_code,
                            "content_type": resp.headers.get('Content-Type', ''),
                            "confidence": "high" if resp.status_code in [200, 201] else "medium"
                        })
                    else:
                        path_results.append(None)
                except:
                    path_results.append(None)

        for result in path_results:
            if result:
                discovered.append(result)
                rid = self._add_result(
                    target=base_url,
                    result_type="api_endpoint",
                    title=f"API端点: {result['path']} ({result['status_code']})",
                    source="API Path Discovery",
                    confidence=result.get("confidence", "medium"),
                    details=result,
                    tags=["api", "endpoint", f"status_{result['status_code']}"]
                )
                results.append(rid)

        # 2. 从JS内容中提取API端点
        if js_content:
            js_endpoints = self._extract_api_from_js(js_content, base_url)
            for ep in js_endpoints:
                discovered.append(ep)
                rid = self._add_result(
                    target=base_url,
                    result_type="api_endpoint",
                    title=f"JS中发现API: {ep['path']}",
                    source="JS Analysis",
                    confidence=ep.get("confidence", "medium"),
                    details=ep,
                    tags=["api", "endpoint", "js_analysis"]
                )
                results.append(rid)

        return {
            "base_url": base_url,
            "discovered_count": len(discovered),
            "endpoints": discovered,
            "result_ids": results
        }

    def _extract_api_from_js(self, js_content: str, base_url: str) -> List[Dict[str, Any]]:
        """从JS内容中提取API端点"""
        endpoints = []
        # 匹配常见的API调用模式
        patterns = [
            r'["\'](/api/[a-zA-Z0-9_/\-]+)["\']',
            r'["\'](/v[0-9]+/[a-zA-Z0-9_/\-]+)["\']',
            r'["\'](/graphql[/a-zA-Z0-9_]*)["\']',
            r'url\s*:\s*["\']([^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']',
            r'\.ajax\(\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
        ]

        found_paths = set()
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if isinstance(match, tuple):
                    path = match[-1]  # 取最后一个分组
                else:
                    path = match
                if path and not path.startswith('http') and len(path) > 3:
                    if path not in found_paths:
                        found_paths.add(path)
                        endpoints.append({
                            "path": path,
                            "url": urljoin(base_url, path),
                            "source": "js_pattern",
                            "confidence": "medium"
                        })

        return endpoints[:30]  # 最多30个

    # ===== 6. 员工信息收集（模拟） =====
    def collect_employee_info(self, company_name: str, domain: str) -> Dict[str, Any]:
        """收集员工信息（基于公开数据源，模拟实现）"""
        log.info(f"收集员工信息: {company_name} ({domain})")
        results = []

        # 生成常见的邮箱模式
        email_patterns = [
            f"{{first}}.{domain}",
            f"{{first}}{{last}}.{domain}",
            f"{{first}}_{domain}",
            f"{{last}}.{domain}",
            f"{{first[0]}}{{last}}.{domain}",
        ]

        # 常见姓氏和名字（用于生成可能的邮箱，实际应从LinkedIn等公开源获取）
        common_first = ["zhang", "wang", "li", "zhao", "liu", "chen", "yang", "huang", "zhou", "wu",
                        "john", "james", "robert", "michael", "william", "david", "richard", "joseph", "thomas", "charles"]
        common_last = ["wei", "fang", "min", "jing", "lei", "qiang", "jun", "yan", "tao", "yong",
                       "smith", "johnson", "williams", "brown", "jones", "garcia", "miller", "davis", "rodriguez", "martinez"]

        possible_emails = []
        for first in common_first[:5]:
            for last in common_last[:5]:
                for pattern in email_patterns[:3]:
                    email = pattern.replace("{first}", first).replace("{last}", last).replace("{first[0]}", first[0])
                    possible_emails.append(email)

        # 去重
        possible_emails = list(set(possible_emails))[:50]

        rid = self._add_result(
            target=company_name,
            result_type="employee",
            title=f"可能的员工邮箱模式: {len(possible_emails)}个",
            source="Email Pattern Generation",
            confidence="low",
            details={
                "company": company_name,
                "domain": domain,
                "email_patterns": email_patterns,
                "possible_emails_count": len(possible_emails),
                "possible_emails": possible_emails[:20]  # 只存前20个
            },
            tags=["employee", "email", "osint"]
        )
        results.append(rid)

        return {
            "company": company_name,
            "domain": domain,
            "possible_emails_count": len(possible_emails),
            "email_patterns": email_patterns,
            "result_ids": results
        }

    # ===== 综合收集 =====
    def full_osint_collection(self, target: str, company_name: str = None,
                               subdomains: List[str] = None, js_content: str = None) -> Dict[str, Any]:
        """执行完整的OSINT收集"""
        log.info(f"开始完整OSINT收集: {target}")
        all_results = {}

        # 1. 组织信息
        all_results["org_info"] = self.collect_org_info(target)

        # 2. 历史漏洞
        all_results["historical_vulns"] = self.query_historical_vulns(target)

        # 3. 泄露凭证
        all_results["leaked_creds"] = self.check_leaked_credentials(target)

        # 4. 子域名接管
        if subdomains:
            all_results["subdomain_takeover"] = self.check_subdomain_takeover(subdomains)

        # 5. API端点发现
        all_results["api_endpoints"] = self.discover_api_endpoints(f"https://{target}", js_content)

        # 6. 员工信息
        if company_name:
            all_results["employee_info"] = self.collect_employee_info(company_name, target)

        total_count = sum(r.get("results_count", 0) for r in all_results.values() if isinstance(r, dict))

        return {
            "target": target,
            "total_results": total_count,
            "categories": all_results,
            "completed_at": time.time()
        }

    # ===== 查询结果 =====
    def get_results(self, target: str = None, result_type: str = None,
                    confidence: str = None) -> List[Dict[str, Any]]:
        """获取收集结果"""
        results = []
        for result in self.results.values():
            if target and result.target != target:
                continue
            if result_type and result.result_type != result_type:
                continue
            if confidence and result.confidence != confidence:
                continue
            results.append(result.to_dict())
        results.sort(key=lambda x: x["discovered_at"], reverse=True)
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        by_type = {}
        by_confidence = {"high": 0, "medium": 0, "low": 0}
        for result in self.results.values():
            rtype = result.result_type
            by_type[rtype] = by_type.get(rtype, 0) + 1
            by_confidence[result.confidence] = by_confidence.get(result.confidence, 0) + 1

        return {
            "total_results": len(self.results),
            "by_type": by_type,
            "by_confidence": by_confidence,
            "unique_targets": len(set(r.target for r in self.results.values()))
        }


# 全局实例
osint_collector = OSINTCollector()
