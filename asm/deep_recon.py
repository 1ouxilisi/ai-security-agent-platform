"""
ASM深度侦察模块
- 子域名爆破
- 目录扫描
- API端点发现
- 技术栈深度识别
"""

import socket
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional
import ipaddress
import re


class DeepRecon:
    """深度侦察引擎"""

    # 常见子域名前缀（Top 100）
    SUBDOMAIN_WORDLIST = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
        "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig",
        "m", "imap", "test", "ns", "blog", "pop3", "dev", "www2",
        "admin", "forum", "news", "vpn", "ns3", "mail2", "new", "mysql",
        "old", "lists", "apps", "support", "shop", "db", "stage", "staging",
        "static", "docs", "beta", "swift", "monitor", "gateway", "hermes",
        "dns1", "dns2", "secure", "demo", "cp", "calendar", "wiki", "web",
        "media", "email", "images", "img", "cdn", "api", "cms", "crm",
        "erp", "hr", "finance", "accounting", "billing", "payment", "pay",
        "oauth", "sso", "login", "auth", "register", "signup", "portal",
        "dashboard", "panel", "console", "manager", "admin", "backend",
        "frontend", "mobile", "app", "download", "upload", "files", "data"
    ]

    # 常见目录路径（Top 100）
    DIRECTORY_WORDLIST = [
        "admin", "login", "wp-admin", "administrator", "admin.php", "login.php",
        "config", "config.php", "backup", "bak", "old", "test", "dev", "staging",
        "api", "api/v1", "api/v2", "graphql", "swagger", "swagger-ui", "docs",
        "documentation", "readme", "README.md", "CHANGELOG", ".git", ".env",
        ".htaccess", "robots.txt", "sitemap.xml", "crossdomain.xml", "phpinfo.php",
        "info.php", "server-status", "server-info", "wp-login.php", "wp-content",
        "wp-includes", "xmlrpc.php", "wp-cron.php", "wp-json", "wp-json/wp/v2",
        "user", "users", "account", "accounts", "profile", "register", "signup",
        "logout", "forgot", "reset", "password", "change-password", "settings",
        "dashboard", "panel", "console", "manager", "moderator", "editor",
        "upload", "download", "files", "file", "media", "images", "assets",
        "static", "public", "private", "internal", "external", "secure", "ssl",
        "health", "healthcheck", "status", "ping", "metrics", "actuator",
        "debug", "trace", "log", "logs", "error", "errors", "exception",
        "cache", "tmp", "temp", "session", "sessions", "cookie", "cookies"
    ]

    # 常见API端点路径
    API_ENDPOINTS = [
        "api/users", "api/user", "api/admin", "api/auth", "api/login",
        "api/register", "api/logout", "api/refresh", "api/token",
        "api/profile", "api/account", "api/settings", "api/password",
        "api/v1/users", "api/v1/user", "api/v1/admin", "api/v1/auth",
        "api/v2/users", "api/v2/user", "api/v2/admin", "api/v2/auth",
        "api/products", "api/product", "api/orders", "api/order",
        "api/payments", "api/payment", "api/invoices", "api/invoice",
        "api/files", "api/file", "api/upload", "api/download",
        "api/search", "api/query", "api/filter", "api/sort",
        "api/stats", "api/statistics", "api/metrics", "api/reports",
        "api/config", "api/configuration", "api/system", "api/health",
        "api/status", "api/info", "api/version", "api/about",
        "api/swagger", "api/docs", "api/documentation", "api/spec",
        "api/graphql", "api/subscriptions", "api/webhooks", "api/hooks",
        "api/roles", "api/permissions", "api/groups", "api/teams",
        "api/projects", "api/project", "api/tasks", "api/task",
        "api/notifications", "api/messages", "api/chat", "api/comments",
        "api/reviews", "api/ratings", "api/likes", "api/follows",
        "api/sessions", "api/session", "api/cookies", "api/cache",
        "api/logs", "api/audit", "api/history", "api/activity"
    ]

    def __init__(self, target: str, timeout: int = 3, max_threads: int = 50):
        self.target = target
        self.timeout = timeout
        self.max_threads = max_threads
        self.results = {
            "subdomains": [],
            "directories": [],
            "api_endpoints": [],
            "tech_stack": {},
            "summary": {}
        }

    def run_all(self) -> Dict[str, Any]:
        """执行全部深度侦察"""
        start_time = time.time()

        # 1. 子域名爆破（仅对域名执行）
        if not self._is_ip(self.target):
            self._subdomain_bruteforce()

        # 2. 目录扫描
        self._directory_scan()

        # 3. API端点发现
        self._api_endpoint_discovery()

        # 4. 技术栈深度识别
        self._deep_tech_stack_detect()

        # 汇总
        self.results["summary"] = {
            "subdomains_found": len(self.results["subdomains"]),
            "directories_found": len(self.results["directories"]),
            "api_endpoints_found": len(self.results["api_endpoints"]),
            "tech_stack_detected": len(self.results["tech_stack"]),
            "duration_seconds": round(time.time() - start_time, 2)
        }

        return self.results

    def _is_ip(self, target: str) -> bool:
        """判断是否为IP地址"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    def _subdomain_bruteforce(self) -> List[Dict]:
        """子域名爆破"""
        domain = self.target
        found = []

        def check_subdomain(sub: str):
            hostname = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(hostname)
                return {"subdomain": hostname, "ip": ip, "status": "resolved"}
            except socket.gaierror:
                return None

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in self.SUBDOMAIN_WORDLIST]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        found.append(result)
                except Exception:
                    pass

        self.results["subdomains"] = found
        return found

    def _directory_scan(self) -> List[Dict]:
        """目录扫描"""
        base_url = f"http://{self.target}"
        found = []

        def check_directory(path: str):
            url = f"{base_url}/{path}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    status = resp.status
                    size = len(resp.read())
                    if status in (200, 301, 302, 401, 403):
                        return {"path": f"/{path}", "status": status, "size": size}
            except urllib.error.HTTPError as e:
                if e.code in (200, 301, 302, 401, 403):
                    return {"path": f"/{path}", "status": e.code, "size": 0}
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(check_directory, d) for d in self.DIRECTORY_WORDLIST]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        found.append(result)
                except Exception:
                    pass

        # 按状态码排序
        found.sort(key=lambda x: x["status"])
        self.results["directories"] = found
        return found

    def _api_endpoint_discovery(self) -> List[Dict]:
        """API端点发现"""
        base_url = f"http://{self.target}"
        found = []

        def check_api(path: str):
            url = f"{base_url}/{path}"
            try:
                req = urllib.request.Request(url, headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "application/json"
                })
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    status = resp.status
                    content_type = resp.headers.get("Content-Type", "")
                    body = resp.read().decode("utf-8", errors="ignore")[:500]
                    is_json = "json" in content_type.lower() or body.strip().startswith(("{", "["))
                    if status in (200, 401, 403):
                        return {
                            "endpoint": f"/{path}",
                            "status": status,
                            "is_json": is_json,
                            "content_type": content_type
                        }
            except urllib.error.HTTPError as e:
                if e.code in (200, 401, 403):
                    return {"endpoint": f"/{path}", "status": e.code, "is_json": False, "content_type": ""}
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(check_api, p) for p in self.API_ENDPOINTS]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        found.append(result)
                except Exception:
                    pass

        found.sort(key=lambda x: x["status"])
        self.results["api_endpoints"] = found
        return found

    def _deep_tech_stack_detect(self) -> Dict[str, Any]:
        """技术栈深度识别"""
        url = f"http://{self.target}"
        tech = {
            "web_server": "",
            "programming_language": "",
            "framework": "",
            "database": "",
            "frontend_framework": "",
            "cdn": "",
            "operating_system": "",
            "security_headers": {},
            "all_detected": []
        }

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                headers = {k.lower(): v for k, v in dict(resp.headers).items()}
                html = resp.read().decode("utf-8", errors="ignore")[:50000]

                # Web服务器
                server = headers.get("server", "")
                if server:
                    tech["web_server"] = server
                    tech["all_detected"].append(f"Web服务器: {server}")

                # X-Powered-By
                x_powered = headers.get("x-powered-by", "")
                if x_powered:
                    tech["programming_language"] = x_powered
                    tech["all_detected"].append(f"技术栈: {x_powered}")

                # Cookie检测
                set_cookie = headers.get("set-cookie", "").lower()
                cookie_map = {
                    "phpsessid": ("PHP", "编程语言: PHP"),
                    "asp.net_sessionid": ("ASP.NET", "编程语言: ASP.NET"),
                    "jsessionid": ("Java", "编程语言: Java"),
                    "connect.sid": ("Express.js", "框架: Express.js"),
                    "csrftoken": ("Django", "框架: Django"),
                    "laravel_session": ("Laravel", "框架: Laravel"),
                    "symfony": ("Symfony", "框架: Symfony"),
                    "node": ("Node.js", "运行时: Node.js")
                }
                for key, (lang, desc) in cookie_map.items():
                    if key in set_cookie:
                        if "语言" in desc:
                            tech["programming_language"] = lang
                        else:
                            tech["framework"] = lang
                        tech["all_detected"].append(desc)
                        break

                # HTML特征检测
                html_features = [
                    ("/wp-content/", "WordPress", "CMS: WordPress"),
                    ("wp-includes", "WordPress", "CMS: WordPress"),
                    ("drupal", "Drupal", "CMS: Drupal"),
                    ("joomla", "Joomla", "CMS: Joomla"),
                    ("laravel", "Laravel", "框架: Laravel"),
                    ("vue.js", "Vue.js", "前端框架: Vue.js"),
                    ("vuejs", "Vue.js", "前端框架: Vue.js"),
                    ("react", "React", "前端框架: React"),
                    ("angular", "Angular", "前端框架: Angular"),
                    ("jquery", "jQuery", "前端库: jQuery"),
                    ("bootstrap", "Bootstrap", "CSS框架: Bootstrap"),
                    ("next.js", "Next.js", "前端框架: Next.js"),
                    ("nuxt", "Nuxt.js", "前端框架: Nuxt.js"),
                    ("svelte", "Svelte", "前端框架: Svelte"),
                    ("tailwind", "Tailwind CSS", "CSS框架: Tailwind CSS")
                ]
                for pattern, name, desc in html_features:
                    if pattern.lower() in html.lower():
                        if "CMS" in desc or "框架" in desc:
                            if "前端" in desc:
                                tech["frontend_framework"] = name
                            elif "CMS" in desc:
                                tech["framework"] = name
                            else:
                                tech["framework"] = name
                        tech["all_detected"].append(desc)

                # 安全头检测
                security_headers = [
                    "x-frame-options", "x-content-type-options", "x-xss-protection",
                    "strict-transport-security", "content-security-policy",
                    "referrer-policy", "permissions-policy", "x-permitted-cross-domain-policies"
                ]
                for sh in security_headers:
                    if sh in headers:
                        tech["security_headers"][sh] = headers[sh]
                        tech["all_detected"].append(f"安全头: {sh}")

                # CDN检测
                cdn_headers = ["cf-ray", "x-cache", "x-served-by", "x-amz-cf-id", "x-azure-ref"]
                for ch in cdn_headers:
                    if ch in headers:
                        tech["cdn"] = headers[ch]
                        tech["all_detected"].append(f"CDN: {ch}={headers[ch]}")
                        break

                # 操作系统推断
                if "win" in server.lower():
                    tech["operating_system"] = "Windows"
                elif "ubuntu" in server.lower() or "debian" in server.lower():
                    tech["operating_system"] = "Linux (Debian/Ubuntu)"
                elif "centos" in server.lower() or "rhel" in server.lower():
                    tech["operating_system"] = "Linux (RHEL/CentOS)"
                elif "nginx" in server.lower() or "apache" in server.lower():
                    tech["operating_system"] = "Linux (推测)"

        except Exception as e:
            tech["error"] = str(e)

        self.results["tech_stack"] = tech
        return tech
