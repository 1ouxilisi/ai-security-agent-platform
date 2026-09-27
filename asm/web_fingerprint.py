"""
Web服务指纹识别器 + 目录扫描器 - 第五轮升级
- 识别Web服务器、框架、CMS、编程语言、CDN
- 常见Web路径枚举
"""
import urllib.request
import urllib.error
import re
import time
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


# Web服务器指纹
SERVER_FINGERPRINTS = {
    "nginx": r"nginx[/\-]([\d.]+)?",
    "apache": r"Apache[/\-]([\d.]+)?",
    "iis": r"Microsoft-IIS[/\-]([\d.]+)?",
    "lighttpd": r"lighttpd[/\-]([\d.]+)?",
    "caddy": r"caddy[/\-]([\d.]+)?",
    "tomcat": r"Apache-Coyote|Tomcat",
}

# 框架/CMS指纹
FRAMEWORK_FINGERPRINTS = [
    (r"wp-content|wp-includes|wordpress", "WordPress"),
    (r"Drupal\.settings|drupal", "Drupal"),
    (r"Joomla!|com_content", "Joomla"),
    (r"laravel|Laravel", "Laravel"),
    (r"X-Powered-By.*Express|express", "Express.js"),
    (r"X-Powered-By.*PHP", "PHP"),
    (r"Set-Cookie.*ASP\.NET|ASP\.NET", "ASP.NET"),
    (r"X-Powered-By.*Nest", "NestJS"),
    (r"X-Powered-By.*Next\.js|_next/static", "Next.js"),
    (r"__NEXT_DATA__", "Next.js"),
    (r"csrf-token.*meta", "CSRF保护"),
    (r"csrf-token", "CSRF保护"),
    (r"XSRF-TOKEN", "CSRF保护"),
    (r"generator.*Django", "Django"),
    (r"X-Frame-Options", "安全头:X-Frame-Options"),
    (r"Content-Security-Policy", "安全头:CSP"),
    (r"Strict-Transport-Security", "安全头:HSTS"),
    (r"X-XSS-Protection", "安全头:XSS"),
    (r"X-Content-Type-Options", "安全头:X-Content-Type"),
]

# 常见目录/文件路径
COMMON_PATHS = [
    "/admin", "/login", "/administrator", "/wp-admin", "/wp-login.php",
    "/.env", "/.git/config", "/.git/HEAD", "/config.php", "/config.json",
    "/robots.txt", "/sitemap.xml", "/.htaccess", "/web.config",
    "/api", "/api/v1", "/api/docs", "/docs", "/swagger", "/swagger-ui",
    "/swagger.json", "/openapi.json", "/graphql", "/graphiql",
    "/phpinfo.php", "/info.php", "/test.php", "/debug",
    "/backup", "/backup.sql", "/dump.sql", "/db.sql",
    "/readme", "/README.md", "/CHANGELOG.md", "/LICENSE",
    "/server-status", "/server-info", "/.well-known/security.txt",
    "/actuator", "/actuator/health", "/actuator/env", "/metrics",
    "/console", "/management", "/druid", "/nacos",
    "/static", "/public", "/uploads", "/files",
    "/js", "/css", "/images", "/assets",
    "/favicon.ico", "/crossdomain.xml",
    "/user", "/users", "/register", "/signup",
    "/logout", "/forgot", "/reset",
    "/upload", "/download", "/file",
    "/health", "/status", "/ping",
    "/.svn/entries", "/.hg/store", "/CVS/Root",
    "/composer.json", "/package.json", "/Gemfile",
    "/Dockerfile", "/docker-compose.yml",
    "/.npmrc", "/.pypirc", "/.gitignore",
]


class WebFingerprinter:
    """Web服务指纹识别器"""

    def __init__(self, target: str, timeout: int = 5):
        self.target = target if target.startswith("http") else f"http://{target}"
        self.timeout = timeout
        self.result = {}

    def fingerprint(self) -> Dict[str, Any]:
        """执行完整指纹识别"""
        start = time.time()
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityScanner/1.0"
        }

        # 获取首页响应
        try:
            req = urllib.request.Request(self.target, headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.status
                resp_headers = dict(resp.headers)
                body = resp.read().decode("utf-8", errors="ignore")[:50000]
        except urllib.error.HTTPError as e:
            status = e.code
            resp_headers = dict(e.headers) if e.headers else {}
            try:
                body = e.read().decode("utf-8", errors="ignore")[:50000]
            except:
                body = ""
        except Exception as e:
            return {"error": str(e), "target": self.target}

        # 分析服务器
        server = resp_headers.get("Server", "")
        x_powered_by = resp_headers.get("X-Powered-By", "")

        # 识别Web服务器
        web_server = "unknown"
        for name, pattern in SERVER_FINGERPRINTS.items():
            if re.search(pattern, server, re.IGNORECASE):
                web_server = name
                break

        # 识别框架/CMS
        tech_stack = []
        combined = (server + " " + x_powered_by + " " + body + " " + str(resp_headers)).lower()
        for pattern, name in FRAMEWORK_FINGERPRINTS:
            if re.search(pattern, combined, re.IGNORECASE):
                tech_stack.append(name)

        # 检查安全头
        security_headers = []
        for h in ["X-Frame-Options", "X-XSS-Protection", "X-Content-Type-Options",
                  "Strict-Transport-Security", "Content-Security-Policy"]:
            if h in resp_headers:
                security_headers.append({"header": h, "value": resp_headers[h][:100]})

        # Cookie分析
        cookies = resp_headers.get("Set-Cookie", "")
        cookie_names = re.findall(r'(\w+)=', cookies) if cookies else []

        self.result = {
            "target": self.target,
            "status_code": status,
            "web_server": web_server,
            "server_header": server,
            "x_powered_by": x_powered_by,
            "tech_stack": list(set(tech_stack)),
            "security_headers": security_headers,
            "cookies": cookie_names[:10],
            "page_title": self._extract_title(body),
            "content_length": len(body),
            "fingerprint_time": round(time.time() - start, 2)
        }
        return self.result

    def _extract_title(self, body: str) -> str:
        m = re.search(r'<title[^>]*>([^<]+)</title>', body, re.IGNORECASE)
        return m.group(1).strip() if m else ""


class DirectoryScanner:
    """Web目录/路径枚举扫描器"""

    def __init__(self, target: str, timeout: int = 3, max_threads: int = 20):
        self.target = target if target.startswith("http") else f"http://{target}"
        self.timeout = timeout
        self.max_threads = max_threads
        self.found = []

    def _check_path(self, path: str) -> Optional[Dict]:
        """检查单个路径"""
        url = self.target.rstrip("/") + path
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)"
            })
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                length = len(resp.read())
                return {
                    "path": path,
                    "status": resp.status,
                    "length": length,
                    "url": url
                }
        except urllib.error.HTTPError as e:
            # 401/403也说明路径存在
            if e.code in (401, 403):
                return {
                    "path": path,
                    "status": e.code,
                    "length": 0,
                    "url": url
                }
            return None
        except:
            return None

    def scan(self, paths: List[str] = None) -> Dict[str, Any]:
        """执行目录扫描"""
        if paths is None:
            paths = COMMON_PATHS

        start = time.time()
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._check_path, p): p for p in paths}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.found.append(result)

        self.found.sort(key=lambda x: (x["status"], -x["length"]))

        return {
            "target": self.target,
            "paths_scanned": len(paths),
            "paths_found": len(self.found),
            "results": self.found,
            "scan_duration": round(time.time() - start, 2)
        }


if __name__ == "__main__":
    # 测试
    fp = WebFingerprinter("http://127.0.0.1:8000", timeout=3)
    r = fp.fingerprint()
    print("指纹识别:")
    for k, v in r.items():
        print(f"  {k}: {v}")

    print("\n目录扫描:")
    ds = DirectoryScanner("http://127.0.0.1:8000", timeout=2, max_threads=20)
    dr = ds.scan()
    print(f"  扫描{dr['paths_scanned']}路径，发现{dr['paths_found']}个")
    for p in dr["results"][:10]:
        print(f"    [{p['status']}] {p['path']} ({p['length']}B)")
