#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recon_workflow妯″潡锛屾彁渚涚浉鍏冲畨鍏ㄦ祴璇曞姛鑳姐€?

妯″潡鍔熻兘锛?
    - 鎻愪緵鐩稿叧瀹夊叏娴嬭瘯鍔熻兘
    - 鏀寔API璋冪敤鍜屽懡浠よ浣跨敤
    - 涓庡叾浠栨ā鍧楅泦鎴愬崗浣?

娉ㄦ剰浜嬮」锛?
    - 鏈ā鍧椾粎鐢ㄤ簬鎺堟潈鐨勫畨鍏ㄦ祴璇?
    - 璇峰嬁鐢ㄤ簬闈炴硶鐢ㄩ€?
    - 浣跨敤鍓嶈纭繚宸茶幏寰楃浉鍏虫巿鏉?
"""
import asyncio
import json
import os
import time
import uuid
import re
import socket
import urllib.request
import urllib.parse
import urllib.error
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.logger import log


@dataclass
class ReconResult:
    """渚﹀療缁撴灉"""
    subdomains: List[str] = field(default_factory=list)
    alive_urls: List[Dict[str, Any]] = field(default_factory=list)
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    directories: List[Dict[str, Any]] = field(default_factory=list)
    js_files: List[Dict[str, Any]] = field(default_factory=list)
    secrets: List[Dict[str, Any]] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    interesting_files: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """鎵ц鐩稿叧鎿嶄綔銆?

            Returns:
            鎿嶄綔缁撴灉銆?
        """
        return {
            "subdomains_count": len(self.subdomains),
            "subdomains": self.subdomains,
            "alive_urls_count": len(self.alive_urls),
            "alive_urls": self.alive_urls,
            "open_ports_count": len(self.open_ports),
            "open_ports": self.open_ports,
            "endpoints_count": len(self.endpoints),
            "endpoints": self.endpoints[:100],  # 闄愬埗杩斿洖鏁伴噺
            "directories_count": len(self.directories),
            "directories": self.directories[:50],
            "js_files_count": len(self.js_files),
            "js_files": self.js_files,
            "secrets_count": len(self.secrets),
            "secrets": self.secrets,
            "technologies": self.technologies,
            "interesting_files": self.interesting_files,
            "errors": self.errors,
            "duration_seconds": round((self.completed_at or time.time()) - self.started_at, 2)
        }


class SRCReconWorkflow:
    """SRC渚﹀療宸ヤ綔娴?""

    def __init__(self):
        """鍒濆鍖朣RCReconWorkflow瀹炰緥銆?

            Args:
            self: 绫诲疄渚嬨€?
        """
        self.timeout = 10
        self.max_threads = 20
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
                            1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9000, 9090, 9200, 11211, 27017]
        self.common_dirs = ["admin", "administrator", "login", "wp-admin", "phpmyadmin", "admin.php",
                            "config", "backup", "bak", ".git", ".env", "api", "swagger", "docs",
                            "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
                            "server-status", "phpinfo.php", "test", "debug", "console", "cpanel",
                            "web.config", ".htaccess", "install", "setup", "upgrade", "readme.html",
                            "license.txt", "changelog.txt", "status", "health", "metrics", "actuator"]
        self.secret_patterns = {
            "aws_access_key": r"AKIA[0-9A-Z]{16}",
            "aws_secret_key": r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]",
            "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",
            "github_token": r"gh[pousr]_[0-9a-zA-Z]{36}",
            "slack_token": r"xox[baprs]-[0-9a-zA-Z-]{10,}",
            "stripe_key": r"sk_live_[0-9a-zA-Z]{24}",
            "private_key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "jwt_token": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            "basic_auth": r"(?i)basic\s+[a-z0-9+/=]{4,}",
            "api_key_generic": r"(?i)(api[_-]?key|apikey|secret[_-]?key|token)['\"\s:=]+['\"]?[a-zA-Z0-9_\-]{20,}['\"]?"
        }

    async def run_full_recon(self, domain: str, options: Dict[str, Any] = None) -> ReconResult:
        """
        杩愯瀹屾暣渚﹀療娴佺▼
        :param domain: 鐩爣鍩熷悕锛堝 example.com 鎴?*.example.com锛?
        :param options: 閫夐」锛堝惎鐢?绂佺敤鍚勬楠わ級
        """
        opts = options or {}
        result = ReconResult()
        target_domain = domain.replace("*.", "")

        log.info(f"寮€濮嬪畬鏁翠睛瀵? {domain}")

        try:
            # 姝ラ1锛氬瓙鍩熷悕鏋氫妇
            if opts.get("subdomain_enum", True):
                log.info("姝ラ1/6: 瀛愬煙鍚嶆灇涓?..")
                result.subdomains = await self._enumerate_subdomains(target_domain)
                log.info(f"  鍙戠幇 {len(result.subdomains)} 涓瓙鍩熷悕")

            # 姝ラ2锛氱鍙ｆ壂鎻?
            if opts.get("port_scan", True):
                log.info("姝ラ2/6: 绔彛鎵弿...")
                all_hosts = [target_domain] + result.subdomains
                result.open_ports = await self._scan_ports(all_hosts)
                log.info(f"  鍙戠幇 {len(result.open_ports)} 涓紑鏀剧鍙?)

            # 姝ラ3锛欻TTP鎺㈡祴
            if opts.get("http_probe", True):
                log.info("姝ラ3/6: HTTP瀛樻椿鎺㈡祴...")
                all_hosts = [target_domain] + result.subdomains
                result.alive_urls = await self._probe_http(all_hosts)
                log.info(f"  鍙戠幇 {len(result.alive_urls)} 涓瓨娲籙RL")

            # 姝ラ4锛歐eb鐖櫕
            if opts.get("web_crawl", True) and result.alive_urls:
                log.info("姝ラ4/6: Web鐖櫕...")
                result.endpoints, result.technologies = await self._crawl_web(result.alive_urls)
                log.info(f"  鍙戠幇 {len(result.endpoints)} 涓鐐?)

            # 姝ラ5锛氱洰褰曠垎鐮?
            if opts.get("dir_bruteforce", True) and result.alive_urls:
                log.info("姝ラ5/6: 鐩綍鐖嗙牬...")
                result.directories, result.interesting_files = await self._bruteforce_dirs(result.alive_urls)
                log.info(f"  鍙戠幇 {len(result.directories)} 涓洰褰?鏂囦欢")

            # 姝ラ6锛欽S鏂囦欢鍒嗘瀽
            if opts.get("js_analysis", True) and result.alive_urls:
                log.info("姝ラ6/6: JS鏂囦欢鍒嗘瀽...")
                result.js_files, result.secrets = await self._analyze_js(result.alive_urls)
                log.info(f"  鍙戠幇 {len(result.js_files)} 涓狫S鏂囦欢, {len(result.secrets)} 涓瘑閽?)

        except Exception as e:
            result.errors.append(f"渚﹀療娴佺▼寮傚父: {str(e)}")
            log.error(f"渚﹀療娴佺▼寮傚父: {e}")

        result.completed_at = time.time()
        log.info(f"渚﹀療瀹屾垚: 鑰楁椂 {result.completed_at - result.started_at:.1f}绉?)
        return result

    async def _enumerate_subdomains(self, domain: str) -> List[str]:
        """瀛愬煙鍚嶆灇涓撅紙閫氳繃DNS瑙ｆ瀽甯歌瀛愬煙鍚嶏級"""
        subdomains = set()
        common_subs = ["www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
                       "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m",
                       "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum",
                       "news", "vpn", "ns3", "mail2", "new", "mysql", "old", "lists", "apps",
                       "support", "shop", "db", "api", "cdn", "static", "assets", "img", "images",
                       "upload", "download", "files", "docs", "wiki", "git", "svn", "jenkins",
                       "ci", "staging", "prod", "production", "dev", "development", "test", "testing",
                       "uat", "qa", "demo", "beta", "alpha", "sandbox", "lab", "local", "internal",
                       "intranet", "extranet", "portal", "dashboard", "app", "apps", "mobile",
                       "ios", "android", "api", "graphql", "rest", "v1", "v2", "v3"]

        def check_sub(sub: str) -> Optional[str]:
            """妫€鏌ョ浉鍏崇姸鎬併€?

                Args:
                sub: 鐩稿叧鍙傛暟銆?

                Returns:
                鎿嶄綔缁撴灉銆?
            """
            try:
                full = f"{sub}.{domain}"
                socket.gethostbyname(full)
                return full
            except (socket.gaierror, socket.timeout):
                return None

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(check_sub, sub): sub for sub in common_subs}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomains.add(result)

        return sorted(list(subdomains))

    async def _scan_ports(self, hosts: List[str]) -> List[Dict[str, Any]]:
        """绔彛鎵弿"""
        open_ports = []

        def scan_host_port(host: str, port: int) -> Optional[Dict[str, Any]]:
            """鎵ц鎵弿鎿嶄綔銆?

                Args:
                host: 鐩稿叧鍙傛暟銆?
                port: 鐩稿叧鍙傛暟銆?

                Returns:
                鎿嶄綔缁撴灉銆?
            """
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    service = self._get_service_name(port)
                    return {"host": host, "port": port, "service": service, "status": "open"}
            except Exception:
                pass
            return None

        tasks = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            for host in hosts[:20]:  # 闄愬埗鎵弿涓绘満鏁?
                for port in self.common_ports:
                    tasks.append(executor.submit(scan_host_port, host, port))
            for future in as_completed(tasks):
                result = future.result()
                if result:
                    open_ports.append(result)

        return open_ports

    def _get_service_name(self, port: int) -> str:
        """鑾峰彇绔彛瀵瑰簲鐨勬湇鍔″悕"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9000: "PHP-FPM", 9200: "Elasticsearch",
            27017: "MongoDB", 11211: "Memcached", 1433: "MSSQL", 1521: "Oracle"
        }
        return services.get(port, "Unknown")

    async def _probe_http(self, hosts: List[str]) -> List[Dict[str, Any]]:
        """HTTP瀛樻椿鎺㈡祴"""
        alive_urls = []

        def probe_host(host: str) -> List[Dict[str, Any]]:
            """鎵ц鐩稿叧鎿嶄綔銆?

                Args:
                host: 鐩稿叧鍙傛暟銆?

                Returns:
                鎿嶄綔缁撴灉銆?
            """
            results = []
            for scheme in ["https", "http"]:
                url = f"{scheme}://{host}"
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
                    with urllib.request.urlopen(req, timeout=self.timeout) as response:
                        body = response.read().decode("utf-8", errors="replace")[:5000]
                        title = self._extract_title(body)
                        tech = self._detect_technologies(response.headers, body)
                        results.append({
                            "url": url,
                            "status_code": response.status,
                            "title": title,
                            "technologies": tech,
                            "content_length": len(body),
                            "server": response.headers.get("Server", ""),
                            "redirect_url": response.url if response.url != url else ""
                        })
                except urllib.error.HTTPError as e:
                    if e.code in [200, 301, 302, 401, 403, 500]:
                        results.append({
                            "url": url,
                            "status_code": e.code,
                            "title": "",
                            "technologies": [],
                            "server": e.headers.get("Server", "") if e.headers else ""
                        })
                except Exception:
                    pass
            return results

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(probe_host, host): host for host in hosts[:30]}
            for future in as_completed(futures):
                results = future.result()
                alive_urls.extend(results)

        return alive_urls

    def _extract_title(self, html: str) -> str:
        """鎻愬彇HTML鏍囬"""
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()[:100]
        return ""

    def _detect_technologies(self, headers: Dict, body: str) -> List[str]:
        """妫€娴嬫妧鏈爤"""
        techs = set()
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body.lower()

        # Web鏈嶅姟鍣?
        if "server" in headers_lower:
            server = headers_lower["server"]
            if "nginx" in server:
                techs.add("Nginx")
            if "apache" in server:
                techs.add("Apache")
            if "iis" in server:
                techs.add("IIS")
            if "cloudflare" in server:
                techs.add("Cloudflare")

        # 缂栫▼璇█
        if "x-powered-by" in headers_lower:
            powered = headers_lower["x-powered-by"]
            if "php" in powered:
                techs.add("PHP")
            if "asp.net" in powered:
                techs.add("ASP.NET")
            if "express" in powered:
                techs.add("Node.js/Express")

        # CMS
        if "wp-content" in body_lower or "wp-includes" in body_lower:
            techs.add("WordPress")
        if "drupal" in body_lower or "sites/default" in body_lower:
            techs.add("Drupal")
        if "joomla" in body_lower or "index.php?option=" in body_lower:
            techs.add("Joomla")

        # 妗嗘灦
        if "laravel" in body_lower or "_token" in body_lower:
            techs.add("Laravel")
        if "django" in body_lower or "csrftoken" in headers_lower:
            techs.add("Django")
        if "react" in body_lower or "react-root" in body_lower:
            techs.add("React")
        if "vue" in body_lower or "__vue" in body_lower:
            techs.add("Vue.js")

        return sorted(list(techs))

    async def _crawl_web(self, alive_urls: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
        """Web鐖櫕锛堟彁鍙栭摼鎺ュ拰绔偣锛?""
        endpoints = set()
        all_techs = set()

        for url_info in alive_urls[:10]:  # 闄愬埗鐖彇鏁伴噺
            url = url_info["url"]
            try:
                req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    body = response.read().decode("utf-8", errors="replace")

                    # 鎻愬彇閾炬帴
                    links = re.findall(r'href=["\']([^"\']+)["\']', body)
                    for link in links:
                        if link.startswith("http"):
                            endpoints.add(link)
                        elif link.startswith("/"):
                            base = "/".join(url.split("/")[:3])
                            endpoints.add(base + link)

                    # 鎻愬彇src
                    srcs = re.findall(r'src=["\']([^"\']+)["\']', body)
                    for src in srcs:
                        if src.startswith("/"):
                            base = "/".join(url.split("/")[:3])
                            endpoints.add(base + src)

                    # 鎻愬彇API绔偣锛堜粠JS涓級
                    api_patterns = re.findall(r'["\'](/api/[a-zA-Z0-9_/\-]+)["\']', body)
                    for api in api_patterns:
                        base = "/".join(url.split("/")[:3])
                        endpoints.add(base + api)

                    # 鎶€鏈爤
                    techs = self._detect_technologies(response.headers, body)
                    all_techs.update(techs)

            except Exception:
                pass

        return sorted(list(endpoints)), sorted(list(all_techs))

    async def _bruteforce_dirs(self, alive_urls: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """鐩綍鐖嗙牬"""
        directories = []
        interesting_files = []

        def check_url(url: str) -> Optional[Dict[str, Any]]:
            """妫€鏌ョ浉鍏崇姸鎬併€?

                Args:
                url: 鐩稿叧鍙傛暟銆?

                Returns:
                鎿嶄綔缁撴灉銆?
            """
            try:
                req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    if response.status == 200:
                        return {"url": url, "status_code": 200, "size": len(response.read())}
            except urllib.error.HTTPError as e:
                if e.code in [200, 401, 403, 500]:
                    return {"url": url, "status_code": e.code, "size": 0}
            except Exception:
                pass
            return None

        # 鍙鍓?涓猆RL杩涜鐩綍鐖嗙牬
        for url_info in alive_urls[:5]:
            base_url = url_info["url"].rstrip("/")
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = {executor.submit(check_url, f"{base_url}/{d}"): d for d in self.common_dirs}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        directories.append(result)
                        # 鏍囪鏈夎叮鐨勬枃浠?
                        path = result["url"].split("/")[-1].lower()
                        if any(x in path for x in [".git", ".env", "config", "backup", "phpinfo", "admin", "swagger", "api-docs"]):
                            interesting_files.append(result)

        return directories, interesting_files

    async def _analyze_js(self, alive_urls: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """JS鏂囦欢鍒嗘瀽锛堟彁鍙栧瘑閽ュ拰API绔偣锛?""
        js_files = []
        secrets = []

        # 鏀堕泦JS鏂囦欢URL
        js_urls = set()
        for url_info in alive_urls[:10]:
            url = url_info["url"]
            try:
                req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    body = response.read().decode("utf-8", errors="replace")
                    # 鎻愬彇JS鏂囦欢
                    js_links = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body)
                    for js in js_links:
                        if js.startswith("http"):
                            js_urls.add(js)
                        elif js.startswith("/"):
                            base = "/".join(url.split("/")[:3])
                            js_urls.add(base + js)
            except Exception:
                pass

        # 鍒嗘瀽姣忎釜JS鏂囦欢
        for js_url in list(js_urls)[:20]:
            try:
                req = urllib.request.Request(js_url, headers={"User-Agent": self.user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    content = response.read().decode("utf-8", errors="replace")

                    js_files.append({
                        "url": js_url,
                        "size": len(content),
                        "status_code": response.status
                    })

                    # 妫€娴嬪瘑閽?
                    for secret_type, pattern in self.secret_patterns.items():
                        matches = re.findall(pattern, content)
                        for match in matches[:3]:  # 姣忎釜绫诲瀷鏈€澶?涓?
                            secrets.append({
                                "type": secret_type,
                                "value": str(match)[:100],
                                "source": js_url,
                                "confidence": "high" if secret_type in ["aws_access_key", "google_api_key", "github_token", "private_key"] else "medium"
                            })

                    # 鎻愬彇API绔偣
                    api_endpoints = re.findall(r'["\'](/api/[a-zA-Z0-9_/\-{}.]+)["\']', content)
                    # 锛堢鐐瑰凡鍦ㄧ埇铏樁娈垫敹闆嗭紝杩欓噷涓嶉噸澶嶏級

            except Exception:
                pass

        return js_files, secrets

    def get_workflow_summary(self, result: ReconResult) -> Dict[str, Any]:
        """鑾峰彇宸ヤ綔娴佹憳瑕?""
        return {
            "status": "completed" if result.completed_at else "running",
            "duration_seconds": round((result.completed_at or time.time()) - result.started_at, 2),
            "subdomains_found": len(result.subdomains),
            "alive_urls": len(result.alive_urls),
            "open_ports": len(result.open_ports),
            "endpoints_found": len(result.endpoints),
            "directories_found": len(result.directories),
            "js_files_analyzed": len(result.js_files),
            "secrets_found": len(result.secrets),
            "technologies": result.technologies,
            "high_value_targets": [
                u for u in result.alive_urls
                if any(t in u.get("technologies", []) for t in ["WordPress", "Drupal", "Joomla", "PHP", "Laravel"])
                or u.get("status_code") in [401, 403]
            ],
            "errors": result.errors
        }


# 鍏ㄥ眬瀹炰緥
src_recon = SRCReconWorkflow()
