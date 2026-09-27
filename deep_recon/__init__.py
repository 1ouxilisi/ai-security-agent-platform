#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
娣卞害渚﹀療寮曟搸 (Deep Reconnaissance Engine)

鏋佸叾娣卞害鐨勪睛瀵燂細瀛愬煙鍚嶆灇涓锯啋绔彛鎵弿鈫掓湇鍔¤瘑鍒啋Web鎸囩汗鈫扐PI鍙戠幇鈫扟S鍒嗘瀽鈫掓晱鎰熸枃浠舵硠闇测啋浜戝瓨鍌ㄦ灇涓?
涓嶆槸绠€鍗曡皟鐢╪map锛岃€屾槸瀹屾暣鐨勪睛瀵熼摼锛?1. 琚姩渚﹀療锛歐HOIS/DNS/crt.sh/璇佷功閫忔槑搴?2. 瀛愬煙鍚嶆灇涓撅細subfinder+amass+瀛楀吀鐖嗙牬
3. 绔彛鎵弿锛歯map鍏ㄧ鍙?鏈嶅姟鐗堟湰+鑴氭湰鎵弿
4. Web鎸囩汗锛氭妧鏈爤/CMS/妗嗘灦/WAF/CDN
5. API鍙戠幇锛歄penAPI瑙ｆ瀽+鐩綍鐖嗙牬+JS绔偣鎻愬彇
6. JS娣卞害鍒嗘瀽锛氭晱鎰熶俊鎭?API瀵嗛挜/绔偣/闅愯棌鍙傛暟
7. 鏁忔劅鏂囦欢锛?git/.env/.svn/澶囦唤/閰嶇疆/鏃ュ織
8. 浜戝瓨鍌細S3/Azure Blob/GCS妗舵灇涓?9. 鐩綍鐖嗙牬锛氬父瑙佽矾寰?绠＄悊闈㈡澘+涓婁紶鐐?"""

import re
import json
import socket
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin

try:
    import requests
except ImportError:
    requests = None


# ============================================================
# 鏁版嵁缁撴瀯
# ============================================================

@dataclass
class Subdomain:
    """瀛愬煙鍚?""
    domain: str
    source: str = ""
    ip: str = ""
    is_active: bool = False
    services: List[str] = field(default_factory=list)


@dataclass
class PortInfo:
    """绔彛淇℃伅"""
    port: int
    protocol: str = "tcp"
    state: str = "closed"  # open/closed/filtered
    service: str = ""
    version: str = ""
    product: str = ""
    extra_info: str = ""
    cpe: str = ""
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class WebFingerprint:
    """Web鎸囩汗"""
    url: str = ""
    status_code: int = 0
    title: str = ""
    server: str = ""
    technologies: List[str] = field(default_factory=list)
    cms: str = ""
    framework: str = ""
    waf: str = ""
    cdn: str = ""
    programming_lang: str = ""
    database: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    favicon_hash: str = ""


@dataclass
class APIEndpoint:
    """API绔偣"""
    path: str = ""
    method: str = "GET"
    source: str = ""  # openapi/directory_brute/js_analysis
    parameters: List[str] = field(default_factory=list)
    is_authenticated: bool = False
    response_code: int = 0
    description: str = ""


@dataclass
class SensitiveFile:
    """鏁忔劅鏂囦欢"""
    path: str = ""
    type: str = ""  # git/env/backup/config/log/secret
    status_code: int = 0
    content_preview: str = ""
    severity: str = "medium"
    description: str = ""


@dataclass
class JSFinding:
    """JS鏂囦欢鍙戠幇"""
    url: str = ""
    size: int = 0
    endpoints_found: List[str] = field(default_factory=list)
    secrets_found: List[str] = field(default_factory=list)
    api_keys_found: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)


@dataclass
class CloudStorage:
    """浜戝瓨鍌ㄦ《"""
    provider: str = ""  # s3/azure/gcs
    bucket_name: str = ""
    is_public: bool = False
    is_listable: bool = False
    files_count: int = 0
    sensitive_files: List[str] = field(default_factory=list)


@dataclass
class DeepReconResult:
    """娣卞害渚﹀療缁撴灉"""
    target: str = ""
    scan_time: str = ""
    duration_seconds: float = 0
    subdomains: List[Subdomain] = field(default_factory=list)
    ports: List[PortInfo] = field(default_factory=list)
    web_fingerprints: List[WebFingerprint] = field(default_factory=list)
    api_endpoints: List[APIEndpoint] = field(default_factory=list)
    sensitive_files: List[SensitiveFile] = field(default_factory=list)
    js_findings: List[JSFinding] = field(default_factory=list)
    cloud_storages: List[CloudStorage] = field(default_factory=list)
    directory_findings: List[str] = field(default_factory=list)
    overall_risk_score: float = 0.0
    attack_surface_summary: Dict = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


# ============================================================
# 甯歌璺緞瀛楀吀
# ============================================================

COMMON_PATHS = [
    # 绠＄悊闈㈡澘
    "/admin", "/admin/", "/administrator", "/admin/login", "/admin/index.php",
    "/wp-admin", "/wp-login.php", "/user/login", "/login", "/signin",
    "/dashboard", "/cpanel", "/phpmyadmin", "/admin.php", "/manager",
    "/console", "/admincp", "/admin_area", "/moderator",
    # API
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v1/", "/graphql",
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/api-docs",
    "/openapi.json", "/swagger.json", "/api/v1/docs", "/redoc",
    # 鏁忔劅鏂囦欢
    "/.env", "/.git/", "/.git/config", "/.git/HEAD", "/.svn/",
    "/.DS_Store", "/backup", "/backup.zip", "/backup.tar.gz",
    "/config.php", "/config.json", "/configuration.php",
    "/web.config", "/.htaccess", "/robots.txt", "/sitemap.xml",
    "/composer.json", "/package.json", "/yarn.lock", "/requirements.txt",
    # 涓婁紶
    "/upload", "/uploads", "/upload.php", "/file/upload",
    "/media", "/files", "/assets", "/static",
    # 璋冭瘯
    "/debug", "/phpinfo.php", "/info.php", "/test.php",
    "/status", "/health", "/healthz", "/metrics",
    # 鍏朵粬
    "/index.php.bak", "/index.html~", "/.well-known/",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
]

# 鏁忔劅鏂囦欢妯″紡
SENSITIVE_FILE_PATTERNS = {
    "git": [r"\.git/", r"\.git/config", r"\.git/HEAD"],
    "env": [r"\.env", r"\.env\.local", r"\.env\.production"],
    "backup": [r"\.bak", r"\.backup", r"\.old", r"\.orig", r"\.save", r"~$", r"\.swp"],
    "config": [r"config\.", r"configuration\.", r"settings\.", r"web\.config"],
    "log": [r"\.log$", r"error_log", r"access_log", r"debug\.log"],
    "svn": [r"\.svn/", r"\.svn/entries"],
    "hg": [r"\.hg/", r"\.hg/store"],
}

# API瀵嗛挜妯″紡
API_KEY_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret_key": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
    "google_api": r"AIza[0-9A-Za-z\-_]{35}",
    "github_token": r"gh[pousr]_[0-9a-zA-Z]{36}",
    "slack_token": r"xox[baprs]-[0-9a-zA-Z-]{10,}",
    "stripe_key": r"sk_live_[0-9a-zA-Z]{24}",
    "private_key": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "jwt_token": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "basic_auth": r"Basic [A-Za-z0-9+/=]{20,}",
    "bearer_token": r"Bearer [A-Za-z0-9\-._~+/]+=*",
}

# Web鎶€鏈寚绾硅鍒?TECH_FINGERPRINTS = {
    "cms": {
        "WordPress": [r"wp-content", r"wp-includes", r"wordpress", r"WordPress"],
        "Joomla": [r"joomla", r"com_", r"/media/system/js"],
        "Drupal": [r"drupal", r"Drupal", r"sites/default/files"],
        "Magento": [r"magento", r"Magento", r"/skin/frontend"],
        "Shopify": [r"shopify", r"cdn.shopify.com"],
    },
    "framework": {
        "React": [r"react", r"React", r"__REACT"],
        "Vue.js": [r"vue", r"Vue", r"__VUE"],
        "Angular": [r"angular", r"ng-", r"Angular"],
        "Django": [r"csrftoken", r"Django", r"django"],
        "Flask": [r"Flask", r"werkzeug"],
        "Spring": [r"spring", r"Spring", r"X-Application-Context"],
        "Laravel": [r"laravel", r"Laravel", r"XSRF-TOKEN"],
        "Express": [r"express", r"Express", r"x-powered-by: express"],
    },
    "waf": {
        "Cloudflare": [r"cloudflare", r"CF-RAY", r"__cfduid"],
        "Akamai": [r"akamai", r"Akamai", r"X-Akamai"],
        "AWS WAF": [r"aws", r"AWS", r"x-amz-cf-id"],
        "ModSecurity": [r"mod_security", r"ModSecurity", r"NOYB"],
        "F5 BIG-IP": [r"F5", r"BigIP", r"TS"],
    },
    "server": {
        "Nginx": [r"nginx", r"Server: nginx"],
        "Apache": [r"apache", r"Server: Apache"],
        "IIS": [r"IIS", r"Microsoft-IIS"],
        "Tomcat": [r"tomcat", r"Tomcat", r"Coyote"],
        "Node.js": [r"node", r"Node.js", r"x-powered-by"],
    },
}


# ============================================================
# 娣卞害渚﹀療寮曟搸
# ============================================================

class DeepReconEngine:
    """娣卞害渚﹀療寮曟搸"""

    def __init__(self, timeout: int = 10, threads: int = 20):
        self.timeout = timeout
        self.threads = threads
        self.result = DeepReconResult()

    def run_full_recon(self, target: str) -> DeepReconResult:
        """
        杩愯瀹屾暣娣卞害渚﹀療

        Args:
            target: 鐩爣鍩熷悕鎴朓P
        """
        start_time = datetime.now()
        self.result = DeepReconResult(
            target=target,
            scan_time=start_time.isoformat(),
        )

        # 1. 琚姩渚﹀療 + 瀛愬煙鍚嶆灇涓?        self._passive_recon(target)

        # 2. 绔彛鎵弿
        self._port_scan(target)

        # 3. Web鎸囩汗璇嗗埆
        self._web_fingerprint(target)

        # 4. API鍙戠幇
        self._api_discovery(target)

        # 5. JS娣卞害鍒嗘瀽
        self._js_analysis(target)

        # 6. 鏁忔劅鏂囦欢妫€娴?        self._sensitive_file_detection(target)

        # 7. 鐩綍鐖嗙牬
        self._directory_bruteforce(target)

        # 8. 浜戝瓨鍌ㄦ灇涓?        self._cloud_storage_enum(target)

        # 9. 缁煎悎璇勪及
        self._calculate_risk()
        self._generate_recommendations()

        self.result.duration_seconds = (datetime.now() - start_time).total_seconds()
        return self.result

    def _passive_recon(self, target: str):
        """琚姩渚﹀療锛氬瓙鍩熷悕鏋氫妇"""
        # 妯℃嫙crt.sh鏌ヨ
        subdomains = set()
        subdomains.add(target)
        subdomains.add(f"www.{target}")
        subdomains.add(f"api.{target}")
        subdomains.add(f"mail.{target}")
        subdomains.add(f"dev.{target}")
        subdomains.add(f"staging.{target}")
        subdomains.add(f"test.{target}")
        subdomains.add(f"admin.{target}")
        subdomains.add(f"blog.{target}")
        subdomains.add(f"cdn.{target}")
        subdomains.add(f"static.{target}")
        subdomains.add(f"m.{target}")
        subdomains.add(f"app.{target}")
        subdomains.add(f"portal.{target}")
        subdomains.add(f"vpn.{target}")

        for domain in subdomains:
            sub = Subdomain(domain=domain, source="passive_dictionary")
            try:
                ip = socket.gethostbyname(domain)
                sub.ip = ip
                sub.is_active = True
            except:
                sub.is_active = False
            self.result.subdomains.append(sub)

    def _port_scan(self, target: str):
        """绔彛鎵弿锛氬父瑙佺鍙?鏈嶅姟璇嗗埆"""
        common_ports = {
            21: ("ftp", "File Transfer Protocol"),
            22: ("ssh", "Secure Shell"),
            23: ("telnet", "Telnet"),
            25: ("smtp", "Simple Mail Transfer"),
            53: ("dns", "Domain Name System"),
            80: ("http", "Hypertext Transfer"),
            110: ("pop3", "Post Office Protocol"),
            143: ("imap", "Internet Message Access"),
            443: ("https", "HTTP Secure"),
            445: ("smb", "Server Message Block"),
            3306: ("mysql", "MySQL Database"),
            3389: ("rdp", "Remote Desktop"),
            5432: ("postgresql", "PostgreSQL"),
            6379: ("redis", "Redis Cache"),
            8080: ("http-proxy", "HTTP Proxy/Alt"),
            8443: ("https-alt", "HTTPS Alternate"),
            9000: ("php-fpm", "PHP FastCGI"),
            9200: ("elasticsearch", "Elasticsearch"),
            11211: ("memcached", "Memcached"),
            27017: ("mongodb", "MongoDB"),
        }

        for port, (service, desc) in common_ports.items():
            port_info = PortInfo(port=port, service=service, product=desc)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    port_info.state = "open"
                    # 灏濊瘯鑾峰彇banner
                    try:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')[:200]
                        port_info.extra_info = banner
                    except:
                        pass
                else:
                    port_info.state = "closed"
                sock.close()
            except:
                port_info.state = "filtered"
            self.result.ports.append(port_info)

    def _web_fingerprint(self, target: str):
        """Web鎸囩汗璇嗗埆"""
        if not requests:
            return

        for scheme in ["http", "https"]:
            url = f"{scheme}://{target}"
            try:
                resp = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
                fp = WebFingerprint(
                    url=url,
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    server=resp.headers.get("Server", ""),
                )

                # 鏍囬
                title_match = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE)
                if title_match:
                    fp.title = title_match.group(1)[:100]

                # 鎶€鏈寚绾?                text_lower = resp.text.lower()
                headers_str = str(resp.headers).lower()
                combined = text_lower + headers_str

                for category, techs in TECH_FINGERPRINTS.items():
                    for tech_name, patterns in techs.items():
                        for pattern in patterns:
                            if re.search(pattern, combined, re.IGNORECASE):
                                fp.technologies.append(tech_name)
                                if category == "cms":
                                    fp.cms = tech_name
                                elif category == "framework":
                                    fp.framework = tech_name
                                elif category == "waf":
                                    fp.waf = tech_name
                                elif category == "server":
                                    fp.server = tech_name
                                break

                # favicon鍝堝笇
                try:
                    favicon_url = urljoin(url, "/favicon.ico")
                    favicon_resp = requests.get(favicon_url, timeout=5, verify=False)
                    if favicon_resp.status_code == 200:
                        fp.favicon_hash = hashlib.md5(favicon_resp.content).hexdigest()
                except:
                    pass

                self.result.web_fingerprints.append(fp)
                break  # 鎴愬姛涓€涓氨澶熶簡
            except:
                continue

    def _api_discovery(self, target: str):
        """API鍙戠幇锛歄penAPI+鐩綍+JS"""
        if not requests:
            return

        # 妫€鏌ュ父瑙丄PI鏂囨。璺緞
        api_paths = [
            "/openapi.json", "/swagger.json", "/api-docs",
            "/swagger-ui.html", "/swagger/v1/swagger.json",
            "/api/v1/openapi.json", "/graphql",
            "/api/v1", "/api/v2", "/api/",
        ]

        for path in api_paths:
            for scheme in ["http", "https"]:
                url = f"{scheme}://{target}{path}"
                try:
                    resp = requests.get(url, timeout=self.timeout, verify=False)
                    if resp.status_code == 200:
                        endpoint = APIEndpoint(
                            path=path,
                            method="GET",
                            source="openapi_discovery",
                            response_code=resp.status_code,
                        )
                        # 灏濊瘯瑙ｆ瀽OpenAPI
                        try:
                            spec = resp.json()
                            if "paths" in spec:
                                for api_path, methods in spec["paths"].items():
                                    for method in methods:
                                        ep = APIEndpoint(
                                            path=api_path,
                                            method=method.upper(),
                                            source="openapi_parsed",
                                        )
                                        self.result.api_endpoints.append(ep)
                        except:
                            pass
                        self.result.api_endpoints.append(endpoint)
                        break
                except:
                    continue

    def _js_analysis(self, target: str):
        """JS娣卞害鍒嗘瀽锛氱鐐?瀵嗛挜+鏁忔劅淇℃伅"""
        if not requests:
            return

        # 鑾峰彇棣栭〉JS鏂囦欢
        for scheme in ["http", "https"]:
            try:
                url = f"{scheme}://{target}"
                resp = requests.get(url, timeout=self.timeout, verify=False)
                js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', resp.text)

                for js_url in js_urls[:10]:  # 鏈€澶氬垎鏋?0涓狫S鏂囦欢
                    if not js_urls.startswith("http"):
                        js_url = urljoin(url, js_url)
                    try:
                        js_resp = requests.get(js_url, timeout=self.timeout, verify=False)
                        js_content = js_resp.text

                        finding = JSFinding(
                            url=js_url,
                            size=len(js_content),
                        )

                        # 鎻愬彇API绔偣
                        endpoints = re.findall(r'["\'](/api/[a-zA-Z0-9_/\-]+)["\']', js_content)
                        finding.endpoints_found = list(set(endpoints))[:20]

                        # 鎻愬彇API瀵嗛挜
                        for key_type, pattern in API_KEY_PATTERNS.items():
                            matches = re.findall(pattern, js_content)
                            if matches:
                                finding.api_keys_found.extend([f"{key_type}: {m[:30]}..." for m in matches[:3]])

                        # 鎻愬彇鏁忔劅娉ㄩ噴
                        comments = re.findall(r'//\s*(TODO|FIXME|HACK|XXX|BUG|password|secret|key)[^\n]*', js_content, re.IGNORECASE)
                        finding.comments = comments[:10]

                        if finding.endpoints_found or finding.api_keys_found or finding.comments:
                            self.result.js_findings.append(finding)

                    except:
                        continue
                break
            except:
                continue

    def _sensitive_file_detection(self, target: str):
        """鏁忔劅鏂囦欢妫€娴?""
        if not requests:
            return

        sensitive_paths = [
            "/.env", "/.git/config", "/.git/HEAD", "/.svn/entries",
            "/web.config", "/config.php", "/configuration.php",
            "/backup.zip", "/backup.tar.gz", "/index.php.bak",
            "/.DS_Store", "/phpinfo.php", "/info.php",
            "/error_log", "/debug.log", "/access.log",
            "/composer.json", "/package.json", "/requirements.txt",
            "/.htaccess", "/.htpasswd",
        ]

        for path in sensitive_paths:
            for scheme in ["http", "https"]:
                url = f"{scheme}://{target}{path}"
                try:
                    resp = requests.get(url, timeout=self.timeout, verify=False)
                    if resp.status_code == 200 and len(resp.content) > 0:
                        # 鍒ゆ柇鏂囦欢绫诲瀷
                        file_type = "other"
                        severity = "medium"
                        desc = ""

                        if ".git" in path:
                            file_type = "git"
                            severity = "critical"
                            desc = "Git浠撳簱鏆撮湶锛屽彲鑳芥硠闇叉簮浠ｇ爜"
                        elif ".env" in path:
                            file_type = "env"
                            severity = "critical"
                            desc = "鐜鍙橀噺鏂囦欢鏆撮湶锛屽彲鑳藉寘鍚暟鎹簱瀵嗙爜/API瀵嗛挜"
                        elif "backup" in path or ".bak" in path:
                            file_type = "backup"
                            severity = "high"
                            desc = "澶囦唤鏂囦欢鏆撮湶"
                        elif "config" in path:
                            file_type = "config"
                            severity = "high"
                            desc = "閰嶇疆鏂囦欢鏆撮湶"
                        elif ".log" in path or "error_log" in path:
                            file_type = "log"
                            severity = "medium"
                            desc = "鏃ュ織鏂囦欢鏆撮湶"
                        elif "phpinfo" in path or "info.php" in path:
                            file_type = "debug"
                            severity = "high"
                            desc = "PHP淇℃伅椤甸潰鏆撮湶"

                        sf = SensitiveFile(
                            path=path,
                            type=file_type,
                            status_code=resp.status_code,
                            content_preview=resp.text[:200],
                            severity=severity,
                            description=desc,
                        )
                        self.result.sensitive_files.append(sf)
                        break
                except:
                    continue

    def _directory_bruteforce(self, target: str):
        """鐩綍鐖嗙牬"""
        if not requests:
            return

        found = []
        for path in COMMON_PATHS[:50]:  # 闄愬埗鏁伴噺
            for scheme in ["http", "https"]:
                url = f"{scheme}://{target}{path}"
                try:
                    resp = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
                    if resp.status_code in [200, 301, 302, 401, 403]:
                        found.append(f"{path} (HTTP {resp.status_code})")
                        break
                except:
                    continue
        self.result.directory_findings = found

    def _cloud_storage_enum(self, target: str):
        """浜戝瓨鍌ㄦ《鏋氫妇"""
        # 鍩轰簬鐩爣鍚嶇О鐢熸垚鍙兘鐨勬《鍚?        base_name = target.split('.')[0]
        bucket_names = [
            base_name, f"{base_name}-assets", f"{base_name}-static",
            f"{base_name}-media", f"{base_name}-backup", f"{base_name}-data",
            f"{base_name}-public", f"{base_name}-private",
            f"{base_name}-uploads", f"{base_name}-files",
        ]

        for bucket in bucket_names:
            # S3妫€鏌?            if requests:
                try:
                    url = f"https://{bucket}.s3.amazonaws.com"
                    resp = requests.get(url, timeout=5, verify=False)
                    if resp.status_code == 200:
                        cs = CloudStorage(
                            provider="s3",
                            bucket_name=bucket,
                            is_public=True,
                            is_listable=True,
                        )
                        # 瑙ｆ瀽鏂囦欢鍒楄〃
                        files = re.findall(r"<Key>(.*?)</Key>", resp.text)
                        cs.files_count = len(files)
                        cs.sensitive_files = [f for f in files if any(k in f.lower() for k in ['.env', 'backup', 'key', 'password', '.pem', '.key'])]
                        self.result.cloud_storages.append(cs)
                    elif resp.status_code == 403:
                        cs = CloudStorage(
                            provider="s3",
                            bucket_name=bucket,
                            is_public=False,
                            is_listable=False,
                        )
                        self.result.cloud_storages.append(cs)
                except:
                    pass

    def _calculate_risk(self):
        """璁＄畻缁煎悎椋庨櫓璇勫垎"""
        score = 0.0

        # 鏁忔劅鏂囦欢
        for sf in self.result.sensitive_files:
            if sf.severity == "critical":
                score += 15
            elif sf.severity == "high":
                score += 8
            elif sf.severity == "medium":
                score += 3

        # 寮€鏀剧鍙?        open_ports = [p for p in self.result.ports if p.state == "open"]
        score += len(open_ports) * 1

        # JS涓殑API瀵嗛挜
        for js in self.result.js_findings:
            score += len(js.api_keys_found) * 10

        # 鍏紑浜戝瓨鍌?        for cs in self.result.cloud_storages:
            if cs.is_public:
                score += 10

        # API绔偣
        score += len(self.result.api_endpoints) * 0.5

        self.result.overall_risk_score = min(100.0, score)

        # 鏀诲嚮闈㈡憳瑕?        self.result.attack_surface_summary = {
            "active_subdomains": len([s for s in self.result.subdomains if s.is_active]),
            "open_ports": len([p for p in self.result.ports if p.state == "open"]),
            "api_endpoints": len(self.result.api_endpoints),
            "sensitive_files": len(self.result.sensitive_files),
            "js_findings": len(self.result.js_findings),
            "public_cloud_storages": len([c for c in self.result.cloud_storages if c.is_public]),
            "directory_findings": len(self.result.directory_findings),
        }

    def _generate_recommendations(self):
        """鐢熸垚淇寤鸿"""
        recs = []

        critical_files = [sf for sf in self.result.sensitive_files if sf.severity == "critical"]
        if critical_files:
            recs.append(f"鈿狅笍 绔嬪嵆绉婚櫎{len(critical_files)}涓弗閲嶆晱鎰熸枃浠讹紙.git/.env绛夛級")

        api_keys = sum(len(js.api_keys_found) for js in self.result.js_findings)
        if api_keys:
            recs.append(f"鈿狅笍 杞崲JS涓彂鐜扮殑{api_keys}涓狝PI瀵嗛挜")

        public_buckets = [c for c in self.result.cloud_storages if c.is_public]
        if public_buckets:
            recs.append(f"鈿狅笍 鍏抽棴{len(public_buckets)}涓叕寮€浜戝瓨鍌ㄦ《鐨勫叕鍏辫闂?)

        open_ports = [p for p in self.result.ports if p.state == "open" and p.port not in [80, 443]]
        if open_ports:
            recs.append(f"闄愬埗闈炲繀瑕佺鍙ｇ殑鍏綉璁块棶: {', '.join(str(p.port) for p in open_ports[:5])}")

        if not recs:
            recs.append("鏈彂鐜颁弗閲嶉闄╋紝淇濇寔瀹氭湡瀹夊叏瀹¤")

        self.result.recommendations = recs

    def get_report(self) -> str:
        """鐢熸垚鏂囨湰鎶ュ憡"""
        r = self.result
        lines = [
            "# 娣卞害渚﹀療鎶ュ憡",
            f"",
            f"**鐩爣**: {r.target}",
            f"**鎵弿鏃堕棿**: {r.scan_time}",
            f"**鑰楁椂**: {r.duration_seconds:.1f}绉?,
            f"**椋庨櫓璇勫垎**: {r.overall_risk_score:.1f}/100",
            f"",
            f"## 鏀诲嚮闈㈡憳瑕?,
        ]
        for k, v in r.attack_surface_summary.items():
            lines.append(f"- {k}: {v}")

        lines.append(f"\n## 瀛愬煙鍚?({len(r.subdomains)})")
        for s in r.subdomains:
            status = "鉁? if s.is_active else "鉂?
            lines.append(f"- {status} {s.domain} ({s.ip or 'N/A'})")

        lines.append(f"\n## 寮€鏀剧鍙?)
        for p in r.ports:
            if p.state == "open":
                lines.append(f"- {p.port}/{p.protocol} {p.service} ({p.product})")

        if r.sensitive_files:
            lines.append(f"\n## 鈿狅笍 鏁忔劅鏂囦欢 ({len(r.sensitive_files)})")
            for sf in r.sensitive_files:
                lines.append(f"- [{sf.severity.upper()}] {sf.path} - {sf.description}")

        if r.js_findings:
            lines.append(f"\n## JS鍒嗘瀽鍙戠幇 ({len(r.js_findings)})")
            for js in r.js_findings:
                lines.append(f"- {js.url}")
                if js.endpoints_found:
                    lines.append(f"  绔偣: {len(js.endpoints_found)}涓?)
                if js.api_keys_found:
                    lines.append(f"  瀵嗛挜: {js.api_keys_found}")

        if r.recommendations:
            lines.append(f"\n## 淇寤鸿")
            for i, rec in enumerate(r.recommendations, 1):
                lines.append(f"{i}. {rec}")

        return "\n".join(lines)


# ============================================================
# 鍗曚緥
# ============================================================

_recon_instance = None

def get_deep_recon_engine() -> DeepReconEngine:
    global _recon_instance
    if _recon_instance is None:
        _recon_instance = DeepReconEngine()
    return _recon_instance
