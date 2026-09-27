"""
subdomain_tools模块，提供相关安全测试功能。

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
import re
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse
from utils.logger import log
from utils.helpers import validate_target


class SubdomainTools:
    """子域名枚举工具集合"""

    # 常见子域名字典（精简版）
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
        "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig",
        "m", "api", "cdn", "static", "assets", "img", "images", "media",
        "download", "files", "docs", "documentation", "wiki", "blog", "news",
        "support", "help", "contact", "about", "admin", "administrator",
        "manage", "management", "dashboard", "panel", "cpanel", "directadmin",
        "test", "testing", "staging", "dev", "development", "prod", "production",
        "demo", "beta", "alpha", "release", "v1", "v2", "v3", "api1", "api2",
        "gateway", "proxy", "reverse-proxy", "loadbalancer", "lb", "cache",
        "redis", "mysql", "db", "database", "mongo", "elasticsearch", "kibana",
        "grafana", "prometheus", "jenkins", "gitlab", "github", "jira", "confluence",
        "vpn", "ssh", "remote", "rdp", "terminal", "console", "shell",
        "status", "health", "monitor", "monitoring", "metrics", "logs", "log",
        "backup", "backups", "archive", "old", "new", "temp", "tmp", "test1",
        "shop", "store", "cart", "checkout", "pay", "payment", "billing",
        "account", "accounts", "user", "users", "profile", "login", "logout",
        "register", "signup", "signin", "auth", "sso", "oauth", "token",
        "search", "query", "explore", "discover", "recommend", "feed",
        "chat", "message", "messages", "notify", "notification", "notifications",
        "upload", "uploads", "import", "export", "convert", "process",
        "mobile", "app", "apps", "ios", "android", "apk", "ipa",
        "cdn1", "cdn2", "cdn3", "img1", "img2", "img3", "static1", "static2",
        "secure", "ssl", "tls", "https", "cert", "certs", "pki",
        "internal", "intranet", "private", "local", "lan", "wan", "vlan",
        "office", "corp", "company", "enterprise", "business", "partner",
        "api-dev", "api-test", "api-staging", "api-prod", "api-beta",
        "web", "websocket", "ws", "wss", "stream", "streaming", "live",
        "push", "fcm", "apns", "gcm", "notification", "notify",
        "s3", "bucket", "storage", "object", "blob", "archive",
        "dns", "nameserver", "ns", "dhcp", "ntp", "time", "clock",
    ]

    def __init__(self):
        """初始化SubdomainTools实例。

        Args:
            self: 类实例。
        """
        self.found_subdomains: Set[str] = set()

    async def dns_bruteforce(self, domain: str, wordlist: Optional[List[str]] = None, max_concurrent: int = 20) -> Dict:
        """
        DNS字典爆破子域名
        通过尝试常见子域名的DNS解析来发现子域名
        """
        if not validate_target(domain):
            return {"error": "目标不在授权白名单内，操作已拒绝"}

        # 提取主域名
        parsed = urlparse(domain)
        base_domain = parsed.hostname or domain
        # 移除www前缀
        if base_domain.startswith("www."):
            base_domain = base_domain[4:]

        log.info(f"子域名DNS爆破: {base_domain}")

        subdomains_to_test = wordlist if wordlist else self.COMMON_SUBDOMAINS[:100]  # 限制数量
        found = []

        semaphore = asyncio.Semaphore(max_concurrent)

        async def check_subdomain(sub: str):
            async with semaphore:
                try:
                    full_domain = f"{sub}.{base_domain}"
                    # DNS解析
                    loop = asyncio.get_event_loop()
                    addrinfo = await loop.getaddrinfo(full_domain, None)
                    ips = list(set([info[4][0] for info in addrinfo]))

                    if ips:
                        found.append({
                            "subdomain": full_domain,
                            "ip_addresses": ips,
                            "source": "dns_bruteforce",
                        })
                        log.debug(f"发现子域名: {full_domain} -> {ips}")
                except Exception:
                    pass

        tasks = [check_subdomain(sub) for sub in subdomains_to_test]
        await asyncio.gather(*tasks)

        # 去重
        unique_found = []
        seen = set()
        for item in found:
            if item["subdomain"] not in seen:
                seen.add(item["subdomain"])
                unique_found.append(item)
                self.found_subdomains.add(item["subdomain"])

        result = {
            "domain": base_domain,
            "method": "dns_bruteforce",
            "tested_count": len(subdomains_to_test),
            "found_count": len(unique_found),
            "subdomains": sorted(unique_found, key=lambda x: x["subdomain"]),
        }
        log.info(f"子域名DNS爆破完成: {base_domain}, 发现 {len(unique_found)} 个")
        return result

    async def certificate_transparency(self, domain: str) -> Dict:
        """
        证书透明度查询
        通过查询证书透明度日志发现子域名
        """
        if not validate_target(domain):
            return {"error": "目标不在授权白名单内，操作已拒绝"}

        parsed = urlparse(domain)
        base_domain = parsed.hostname or domain
        if base_domain.startswith("www."):
            base_domain = base_domain[4:]

        log.info(f"证书透明度查询: {base_domain}")

        found = []
        try:
            import aiohttp
            # 使用crt.sh的证书透明度API
            url = f"https://crt.sh/?q=%25.{base_domain}&output=json"

            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()

                        for cert in data:
                            # 提取通用名称和主题备用名称
                            common_name = cert.get("common_name", "")
                            name_value = cert.get("name_value", "")

                            # 解析所有域名
                            all_names = set()
                            if common_name:
                                all_names.add(common_name)
                            if name_value:
                                for name in name_value.split("\n"):
                                    name = name.strip()
                                    if name and not name.startswith("*"):
                                        all_names.add(name)

                            for name in all_names:
                                if name.endswith(base_domain) and name != base_domain:
                                    found.append({
                                        "subdomain": name,
                                        "issuer": cert.get("issuer_name", ""),
                                        "valid_from": cert.get("not_before", ""),
                                        "valid_to": cert.get("not_after", ""),
                                        "source": "certificate_transparency",
                                    })
                                    self.found_subdomains.add(name)
        except Exception as e:
            log.error(f"证书透明度查询异常: {e}")
            return {"domain": base_domain, "error": str(e), "subdomains": []}

        # 去重
        unique_found = []
        seen = set()
        for item in found:
            if item["subdomain"] not in seen:
                seen.add(item["subdomain"])
                unique_found.append(item)

        result = {
            "domain": base_domain,
            "method": "certificate_transparency",
            "found_count": len(unique_found),
            "subdomains": sorted(unique_found, key=lambda x: x["subdomain"]),
        }
        log.info(f"证书透明度查询完成: {base_domain}, 发现 {len(unique_found)} 个")
        return result

    async def enumerate_all(self, domain: str, methods: Optional[List[str]] = None) -> Dict:
        """
        全方法子域名枚举
        组合多种方法发现子域名
        """
        log.info(f"全方法子域名枚举: {domain}")

        methods = methods or ["dns_bruteforce", "certificate_transparency"]
        all_results = {}

        if "dns_bruteforce" in methods:
            result = await self.dns_bruteforce(domain)
            all_results["dns_bruteforce"] = result

        if "certificate_transparency" in methods:
            result = await self.certificate_transparency(domain)
            all_results["certificate_transparency"] = result

        # 合并所有发现
        all_subdomains = {}
        for method_result in all_results.values():
            for sub in method_result.get("subdomains", []):
                name = sub["subdomain"]
                if name not in all_subdomains:
                    all_subdomains[name] = sub

        merged_list = sorted(all_subdomains.values(), key=lambda x: x["subdomain"])

        result = {
            "domain": domain,
            "methods_used": methods,
            "total_found": len(merged_list),
            "breakdown": {k: v.get("found_count", 0) for k, v in all_results.items()},
            "subdomains": merged_list,
        }
        log.info(f"全方法子域名枚举完成: {domain}, 共发现 {len(merged_list)} 个")
        return result

    def get_found_subdomains(self) -> List[str]:
        """获取所有已发现的子域名"""
        return sorted(list(self.found_subdomains))

    def clear_cache(self):
        """清空发现缓存"""
        self.found_subdomains.clear()
        log.info("子域名发现缓存已清空")


# 全局实例
subdomain_tools = SubdomainTools()
