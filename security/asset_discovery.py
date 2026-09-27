# -*- coding: utf-8 -*-
"""
资产发现与管理模块

提供主动/被动资产发现与资产全生命周期管理：
    - 主动发现：ICMP ping 存活探测、TCP 端口扫描、服务识别
    - 被动发现：子域名字典爆破解析
    - 资产管理：CRUD / 分组标签 / 负责人 / 重要性 / 指纹 / 变更检测 / 风险评分

注意：本模块仅用于授权资产清点与防御评估，禁止对未授权目标扫描。
"""
import os
import json
import time
import socket
import subprocess
import ipaddress
import uuid
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import log

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data", "assets")

# 常见端口 -> 默认服务名映射
COMMON_PORTS: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 27017: "mongodb", 9200: "elasticsearch",
}

# 子域名爆破字典（50+ 常见前缀）
SUBDOMAIN_WORDS: List[str] = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "admin", "blog", "test", "dev", "stage", "staging", "api", "app", "m",
    "mobile", "portal", "vpn", "git", "gitlab", "jenkins", "ci", "cd", "docs",
    "wiki", "status", "monitor", "grafana", "prometheus", "zabbix", "db",
    "database", "redis", "mysql", "backup", "cdn", "static", "img", "images",
    "assets", "download", "upload", "store", "shop", "pay", "payment",
    "auth", "sso", "oauth", "login", "crm", "erp", "oa", "mail2",
]

# CMS 指纹规则：响应头/页面内容关键词 -> CMS 名称
CMS_RULES: List[Tuple[str, str]] = [
    (r"wp-content", "WordPress"),
    (r"wp-includes", "WordPress"),
    (r"Drupal", "Drupal"),
    (r"X-Drupal-Cache", "Drupal"),
    (r"Joomla", "Joomla"),
    (r"XSRF-TOKEN.*laravel", "Laravel"),
    (r"csrf-token.*metronic", "Metronic"),
    (r"Discuz", "Discuz"),
    (r"phpwind", "PHPWind"),
    (r"ThinkPHP", "ThinkPHP"),
    (r"X-Powered-CMS", "自定义"),
]


class AssetDiscovery:
    """资产发现与管理器"""

    def __init__(self, data_dir: Optional[str] = None):
        self.data_dir = data_dir or DATA_DIR
        os.makedirs(self.data_dir, exist_ok=True)
        self.assets_file = os.path.join(self.data_dir, "assets.json")
        self.assets: Dict[str, Dict[str, Any]] = {}
        self._load()
        log.info("资产发现管理器初始化，共 %d 个资产" % len(self.assets))

    # ------------------------------------------------------------------ #
    # 持久化
    # ------------------------------------------------------------------ #
    def _load(self) -> None:
        try:
            if os.path.exists(self.assets_file):
                with open(self.assets_file, "r", encoding="utf-8") as f:
                    self.assets = json.load(f)
        except Exception as e:  # pragma: no cover
            log.warning("加载资产数据失败: %s" % e)
            self.assets = {}

    def _save(self) -> None:
        try:
            with open(self.assets_file, "w", encoding="utf-8") as f:
                json.dump(self.assets, f, ensure_ascii=False, indent=2)
        except Exception as e:  # pragma: no cover
            log.error("保存资产数据失败: %s" % e)

    # ------------------------------------------------------------------ #
    # 主动发现
    # ------------------------------------------------------------------ #
    @staticmethod
    def _expand_cidr(cidr: str) -> List[str]:
        """将 CIDR/IP 段展开为 IP 列表。"""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            # 限制单次扫描规模，避免误扫过大网段
            hosts = [str(ip) for ip in net.hosts()]
            if len(hosts) > 256:
                hosts = hosts[:256]
            return hosts
        except Exception:
            # 非 CIDR 格式，视为单个 IP
            return [cidr]

    def ip_scan(self, cidr: str, timeout: int = 1000) -> List[str]:
        """ICMP ping 扫描，返回存活 IP 列表（Windows: ping -n 1 -w timeout）。"""
        alive: List[str] = []
        for ip in self._expand_cidr(cidr):
            try:
                param = "-n" if os.name == "nt" else "-c"
                wparam = "-w" if os.name == "nt" else "-W"
                cmd = ["ping", param, "1", wparam, str(timeout // 1000), ip]
                result = subprocess.run(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=5, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                out = result.stdout.decode("gbk", errors="ignore")
                # Windows 下 "TTL=" 出现表示主机存活
                if result.returncode == 0 or "TTL=" in out or "ttl=" in out:
                    alive.append(ip)
            except Exception:
                continue
        log.info("IP 段 %s 存活主机 %d 台" % (cidr, len(alive)))
        return alive

    def port_scan(self, ip: str, ports: Optional[List[int]] = None,
                  timeout: float = 1.0) -> List[int]:
        """TCP connect 扫描常用端口，返回开放端口列表。"""
        ports = ports or list(COMMON_PORTS.keys())
        open_ports: List[int] = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
            except Exception:
                continue
        log.info("主机 %s 开放端口 %s" % (ip, open_ports))
        return open_ports

    def service_identify(self, ip: str, port: int) -> Dict[str, Any]:
        """根据端口与 banner 识别服务。"""
        service = COMMON_PORTS.get(port, "unknown")
        banner = ""
        software = ""
        cms = ""
        try:
            if port in (80, 8080, 8000):
                banner, software, cms = self._probe_http(ip, port, use_ssl=False)
            elif port in (443, 8443):
                banner, software, cms = self._probe_http(ip, port, use_ssl=True)
            else:
                # 其他端口尝试抓取 banner
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.5)
                    s.connect((ip, port))
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(256).decode("utf-8", errors="ignore").strip()
        except Exception:
            pass
        return {
            "ip": ip, "port": port, "service": service,
            "banner": banner, "software_version": software, "cms": cms,
        }

    def _probe_http(self, ip: str, port: int, use_ssl: bool) -> Tuple[str, str, str]:
        """HTTP 探测：获取 Server 头与页面内容，识别服务/CMS。"""
        import urllib.request
        scheme = "https" if use_ssl else "http"
        url = "%s://%s:%d/" % (scheme, ip, port)
        ctx = None
        if use_ssl:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AssetScanner/1.0"})
            with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:
                server = resp.headers.get("Server", "")
                body = resp.read(2048).decode("utf-8", errors="ignore")
            cms = self.cms_identify(body, dict(resp.headers))
            return (server, server, cms)
        except Exception:
            return ("", "", "")

    @staticmethod
    def cms_identify(body: str, headers: Dict[str, str]) -> str:
        """基于 HTTP 响应头与页面内容匹配常见 CMS。"""
        blob = body + " " + " ".join("%s:%s" % (k, v) for k, v in headers.items())
        for pattern, name in CMS_RULES:
            if pattern.replace(r"\\", "") in blob:
                return name
        return ""

    def subdomain_enumerate(self, domain: str,
                            wordlist: Optional[List[str]] = None) -> List[Dict[str, str]]:
        """字典爆破子域名并解析，返回解析成功的子域名列表。"""
        words = wordlist or SUBDOMAIN_WORDS
        found: List[Dict[str, str]] = []
        domain = domain.strip().lower()
        for word in words:
            sub = "%s.%s" % (word, domain)
            try:
                ip = socket.gethostbyname(sub)
                found.append({"subdomain": sub, "ip": ip})
            except Exception:
                continue
        log.info("域名 %s 解析到 %d 个子域名" % (domain, len(found)))
        return found

    # ------------------------------------------------------------------ #
    # 资产管理 CRUD
    # ------------------------------------------------------------------ #
    def add_asset(self, ip: str, domain: Optional[str] = None,
                  asset_type: Optional[str] = None,
                  importance: str = "medium",
                  owner: Optional[str] = None,
                  groups: Optional[List[str]] = None,
                  tags: Optional[List[str]] = None) -> Dict[str, Any]:
        """登记一个新资产。"""
        asset_id = "asset-%s" % uuid.uuid4().hex[:10]
        asset = {
            "id": asset_id,
            "ip": ip,
            "domain": domain,
            "asset_type": asset_type or "unknown",
            "importance": importance,       # critical/high/medium/low
            "owner": owner,
            "groups": groups or [],
            "tags": tags or [],
            "open_ports": [],
            "running_services": [],
            "software_versions": {},
            "os_fingerprint": "",
            "cms": "",
            "last_scan": None,
            "first_seen": time.time(),
            "updated_at": time.time(),
        }
        self.assets[asset_id] = asset
        self._save()
        return asset

    def list_assets(self) -> List[Dict[str, Any]]:
        """列出全部资产。"""
        return list(self.assets.values())

    def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """按 ID 获取资产。"""
        return self.assets.get(asset_id)

    def update_asset(self, asset_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """更新资产字段。"""
        if asset_id not in self.assets:
            return None
        allowed = {"domain", "asset_type", "importance", "owner",
                   "groups", "tags", "open_ports", "running_services",
                   "software_versions", "os_fingerprint", "cms"}
        for k, v in updates.items():
            if k in allowed:
                self.assets[asset_id][k] = v
        self.assets[asset_id]["updated_at"] = time.time()
        self._save()
        return self.assets[asset_id]

    def delete_asset(self, asset_id: str) -> bool:
        """删除资产。"""
        if asset_id in self.assets:
            del self.assets[asset_id]
            self._save()
            return True
        return False

    # ------------------------------------------------------------------ #
    # 指纹 / 变更 / 风险
    # ------------------------------------------------------------------ #
    @staticmethod
    def os_fingerprint(open_ports: List[int]) -> str:
        """基于开放端口粗略推断操作系统家族。"""
        s = set(open_ports)
        if 3389 in s or 445 in s or 139 in s:
            return "Windows"
        if 22 in s and 80 in s:
            return "Linux/Unix"
        if 22 in s:
            return "Linux/Unix"
        if 548 in s or 631 in s:
            return "macOS"
        return "Unknown"

    def detect_changes(self, asset_id: str) -> Dict[str, Any]:
        """对比上次扫描结果，检测端口/服务/指纹变化并生成告警。"""
        asset = self.assets.get(asset_id)
        if not asset:
            raise KeyError("资产不存在: %s" % asset_id)
        prev_ports = set(asset.get("open_ports", []))
        # 重新扫描该资产
        new_ports = set(self.port_scan(asset["ip"]))
        new_services = [self.service_identify(asset["ip"], p) for p in sorted(new_ports)]
        added = sorted(new_ports - prev_ports)
        removed = sorted(prev_ports - new_ports)
        changes = []
        if added:
            changes.append("新增开放端口: %s" % added)
        if removed:
            changes.append("关闭端口: %s" % removed)
        old_os = asset.get("os_fingerprint", "")
        new_os = self.os_fingerprint(list(new_ports))
        if old_os and old_os != new_os:
            changes.append("操作系统指纹变化: %s -> %s" % (old_os, new_os))
        # 更新资产指纹
        asset["open_ports"] = sorted(new_ports)
        asset["running_services"] = [s["service"] for s in new_services]
        asset["os_fingerprint"] = new_os or old_os
        asset["software_versions"] = {str(s["port"]): s["software_version"]
                                      for s in new_services if s["software_version"]}
        asset["cms"] = next((s["cms"] for s in new_services if s["cms"]), asset.get("cms", ""))
        asset["last_scan"] = time.time()
        asset["updated_at"] = time.time()
        self._save()
        alert = {
            "asset_id": asset_id,
            "ip": asset["ip"],
            "has_change": bool(changes),
            "added_ports": added,
            "removed_ports": removed,
            "changes": changes,
            "alert": "资产 %s 发生变更: %s" % (asset["ip"], "; ".join(changes)) if changes else "",
            "scanned_at": time.time(),
        }
        return alert

    def calculate_risk(self, asset_id: str) -> Dict[str, Any]:
        """基于开放端口数量/重要性计算 0-100 风险分。"""
        asset = self.assets.get(asset_id)
        if not asset:
            raise KeyError("资产不存在: %s" % asset_id)
        score = 0
        reasons: List[str] = []
        # 1) 开放端口数量
        port_count = len(asset.get("open_ports", []))
        score += min(port_count * 3, 30)
        if port_count > 10:
            reasons.append("暴露端口过多(%d)" % port_count)
        # 2) 高危服务加权
        high_risk_ports = {21: 5, 23: 8, 3389: 8, 445: 6, 6379: 6, 27017: 7, 9200: 6, 3306: 4}
        hr = [p for p in asset.get("open_ports", []) if p in high_risk_ports]
        score += sum(high_risk_ports[p] for p in hr)
        if hr:
            reasons.append("存在高危服务端口: %s" % hr)
        # 3) 重要性加权
        importance_bonus = {"critical": 30, "high": 18, "medium": 8, "low": 0}
        score += importance_bonus.get(asset.get("importance", "medium"), 8)
        # 4) 已知漏洞（外部传入，资产记录 extra 字段）
        known_vulns = asset.get("known_vulns", 0)
        score += min(known_vulns * 4, 20)
        if known_vulns:
            reasons.append("已知漏洞 %d 个" % known_vulns)
        score = max(0, min(100, score))
        level = "高" if score >= 70 else ("中" if score >= 40 else "低")
        return {
            "asset_id": asset_id,
            "risk_score": score,
            "risk_level": level,
            "reasons": reasons,
        }


# 全局单例
_discovery: Optional[AssetDiscovery] = None


def get_discovery() -> AssetDiscovery:
    """获取全局资产发现管理器单例。"""
    global _discovery
    if _discovery is None:
        _discovery = AssetDiscovery()
    return _discovery
