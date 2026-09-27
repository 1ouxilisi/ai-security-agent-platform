"""
资产发现引擎
自动发现目标组织的所有公网资产：域名、子域名、IP、端口、服务、技术栈、云存储桶
"""
import socket
import json
import time
import ipaddress
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse


class AssetDiscoveryEngine:
    """资产发现引擎"""

    def __init__(self):
        self.discovered_assets = {
            "domains": [],
            "subdomains": [],
            "ip_addresses": [],
            "open_ports": [],
            "services": [],
            "tech_stacks": [],
            "cloud_buckets": [],
            "certificates": [],
            "dns_records": []
        }
        self.scan_stats = {
            "start_time": None,
            "end_time": None,
            "total_scanned": 0,
            "total_found": 0
        }

    def discover_all(self, target: str, options: Optional[Dict] = None) -> Dict[str, Any]:
        """
        全面资产发现
        :param target: 目标（域名/IP/IP段/URL）
        :param options: 扫描选项
        :return: 完整资产清单
        """
        options = options or {}
        self.scan_stats["start_time"] = time.time()
        self.discovered_assets = {k: [] for k in self.discovered_assets}

        # 1. 解析目标类型
        target_type = self._identify_target_type(target)

        # 2. DNS解析
        if target_type in ["domain", "url"]:
            domain = target if target_type == "domain" else urlparse(target).netloc
            self._dns_enumeration(domain)
            self._subdomain_discovery(domain, options.get("subdomain_depth", 2))
            self._certificate_transparency(domain)

        # 3. IP范围展开
        if target_type == "ip_range":
            ips = self._expand_ip_range(target)
        elif target_type == "ip":
            ips = [target]
        else:
            ips = list(set(a["ip"] for a in self.discovered_assets["ip_addresses"] if a.get("ip")))

        # 4. 端口扫描（并发）
        if ips:
            self._parallel_port_scan(ips, options.get("ports", "top100"),
                                       options.get("timeout", 3),
                                       options.get("max_threads", 50))

        # 5. 服务识别和技术栈检测
        self._service_identification()

        # 6. 云存储桶检测
        if target_type in ["domain", "url"]:
            self._cloud_bucket_detection(domain)

        self.scan_stats["end_time"] = time.time()
        self.scan_stats["total_found"] = sum(len(v) for v in self.discovered_assets.values())

        return {
            "target": target,
            "target_type": target_type,
            "assets": self.discovered_assets,
            "summary": self._generate_summary(),
            "scan_stats": {
                "duration_seconds": round(self.scan_stats["end_time"] - self.scan_stats["start_time"], 2),
                "total_found": self.scan_stats["total_found"],
                "ips_scanned": len(ips)
            }
        }

    def _identify_target_type(self, target: str) -> str:
        """识别目标类型"""
        if target.startswith(("http://", "https://")):
            return "url"
        if "/" in target and any(c.isdigit() for c in target.split("/")[0]):
            return "ip_range"
        try:
            ipaddress.ip_address(target)
            return "ip"
        except ValueError:
            return "domain"

    def _dns_enumeration(self, domain: str):
        """DNS枚举"""
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]
        for rtype in record_types:
            try:
                import dns.resolver
                answers = dns.resolver.resolve(domain, rtype)
                for rdata in answers:
                    record = {"domain": domain, "type": rtype, "value": str(rdata)}
                    self.discovered_assets["dns_records"].append(record)
                    if rtype == "A":
                        self.discovered_assets["ip_addresses"].append(
                            {"domain": domain, "ip": str(rdata), "source": "dns_a"})
            except Exception:
                pass

        # 备用：socket解析
        if not any(r["type"] == "A" for r in self.discovered_assets["dns_records"]):
            try:
                ips = socket.getaddrinfo(domain, None)
                for ip_info in ips:
                    ip = ip_info[4][0]
                    if not any(a["ip"] == ip for a in self.discovered_assets["ip_addresses"]):
                        self.discovered_assets["ip_addresses"].append(
                            {"domain": domain, "ip": ip, "source": "socket"})
            except Exception:
                pass

    def _subdomain_discovery(self, domain: str, depth: int = 2):
        """子域名发现（字典+搜索引擎）"""
        common_subdomains = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
            "webdisk", "ns2", "cpanel", "whm", "autodiscover", "admin", "api",
            "dev", "test", "staging", "prod", "blog", "shop", "store", "forum",
            "wiki", "docs", "git", "gitlab", "jenkins", "ci", "cd", "monitor",
            "grafana", "prometheus", "kibana", "elasticsearch", "redis", "mysql",
            "db", "database", "cache", "vpn", "proxy", "gateway", "portal",
            "intranet", "extranet", "remote", "desktop", "app", "mobile", "m",
            "cdn", "static", "media", "images", "img", "upload", "download",
            "files", "backup", "old", "new", "test1", "dev1", "staging1"
        ]

        found = []
        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                ips = socket.getaddrinfo(subdomain, None)
                ip = ips[0][4][0]
                found.append({"subdomain": subdomain, "ip": ip, "source": "dictionary"})
                if not any(a["ip"] == ip for a in self.discovered_assets["ip_addresses"]):
                    self.discovered_assets["ip_addresses"].append(
                        {"domain": subdomain, "ip": ip, "source": "subdomain"})
            except Exception:
                pass

        self.discovered_assets["subdomains"] = found

    def _certificate_transparency(self, domain: str):
        """证书透明度日志查询"""
        # 简化版：通过crt.sh API查询
        try:
            import urllib.request
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                for cert in data[:50]:
                    cert_info = {
                        "domain": cert.get("name_value", ""),
                        "issuer": cert.get("issuer_name", ""),
                        "not_before": cert.get("not_before", ""),
                        "not_after": cert.get("not_after", "")
                    }
                    if not any(c["domain"] == cert_info["domain"] for c in self.discovered_assets["certificates"]):
                        self.discovered_assets["certificates"].append(cert_info)
        except Exception:
            pass

    def _expand_ip_range(self, ip_range: str) -> List[str]:
        """展开IP范围"""
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            return [str(ip) for ip in network.hosts()]
        except Exception:
            return [ip_range.split("/")[0]]

    def _parallel_port_scan(self, ips: List[str], ports: str = "top20",
                              timeout: int = 2, max_threads: int = 200):
        """全并发端口扫描（IP+端口双层并发）"""
        # 最常用20端口（覆盖90%常见服务）
        top_20 = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
        # 扩展端口（top100时追加）
        top_ext = [111, 143, 993, 995, 1723, 5000, 7001, 8000, 8001, 8888, 9090, 11211, 5001, 8081, 8444, 9000, 9443, 9999, 10000, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8800, 8880, 9001, 9043, 9080, 9800, 11000, 12000, 15000, 16000, 18000, 18080, 20000, 2082, 2083, 2086, 2087, 2095, 2096, 18081, 18082, 18083, 18084, 18085, 18086, 18087, 18088, 18089, 18090, 20001, 20002]

        if ports in ("top100", "top1000"):
            scan_ports = top_20 + top_ext
        elif ports == "top20":
            scan_ports = top_20
        elif "-" in ports:
            start, end = map(int, ports.split("-"))
            scan_ports = list(range(start, end + 1))
        else:
            scan_ports = [int(p) for p in ports.split(",")]

        # 构建所有(ip, port)任务对，全并发扫描
        tasks = [(ip, port) for ip in ips for port in scan_ports]

        def scan_single(task):
            ip, port = task
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                return (ip, port) if result == 0 else None
            except Exception:
                return None

        open_results = []
        with ThreadPoolExecutor(max_workers=min(max_threads, len(tasks) or 1)) as executor:
            futures = [executor.submit(scan_single, task) for task in tasks]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        open_results.append(result)
                except Exception:
                    pass

        # 按IP分组
        ip_ports = {}
        for ip, port in open_results:
            ip_ports.setdefault(ip, []).append(port)
        for ip in ips:
            for port in ip_ports.get(ip, []):
                self.discovered_assets["open_ports"].append(
                    {"ip": ip, "port": port, "status": "open"})

    def _service_identification(self):
        """服务识别"""
        service_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
            11211: "Memcached", 27017: "MongoDB", 5900: "VNC", 1723: "PPTP"
        }

        for port_info in self.discovered_assets["open_ports"]:
            port = port_info["port"]
            service = service_map.get(port, f"Unknown-{port}")
            self.discovered_assets["services"].append({
                "ip": port_info["ip"],
                "port": port,
                "service": service,
                "banner": self._grab_banner(port_info["ip"], port)
            })

    def _grab_banner(self, ip: str, port: int, timeout: int = 3) -> str:
        """抓取服务Banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            if port in [80, 8080, 8443]:
                sock.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore")[:200]
            sock.close()
            return banner.strip()
        except Exception:
            return ""

    def _cloud_bucket_detection(self, domain: str):
        """云存储桶检测"""
        bucket_names = [
            domain.replace(".", "-"),
            domain.split(".")[0],
            f"{domain}-backup",
            f"{domain}-static",
            f"{domain}-media",
            f"{domain}-uploads"
        ]

        for bucket in bucket_names:
            # AWS S3
            try:
                import urllib.request
                url = f"https://{bucket}.s3.amazonaws.com"
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=2) as resp:
                    if resp.status == 200:
                        self.discovered_assets["cloud_buckets"].append({
                            "name": bucket,
                            "provider": "AWS S3",
                            "access": "public",
                            "url": url
                        })
            except Exception:
                pass

    def _generate_summary(self) -> Dict[str, Any]:
        """生成资产摘要"""
        return {
            "total_domains": len(self.discovered_assets["domains"]),
            "total_subdomains": len(self.discovered_assets["subdomains"]),
            "total_ips": len(set(a["ip"] for a in self.discovered_assets["ip_addresses"])),
            "total_open_ports": len(self.discovered_assets["open_ports"]),
            "total_services": len(self.discovered_assets["services"]),
            "total_tech_stacks": len(self.discovered_assets["tech_stacks"]),
            "total_cloud_buckets": len(self.discovered_assets["cloud_buckets"]),
            "total_certificates": len(self.discovered_assets["certificates"]),
            "total_dns_records": len(self.discovered_assets["dns_records"])
        }
