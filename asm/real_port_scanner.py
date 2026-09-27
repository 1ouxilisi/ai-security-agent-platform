"""
真实端口扫描器 - 第四轮升级P0
支持TCP连接扫描、服务指纹识别、常见端口快速扫描
"""
import socket
import time
import re
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


# 常见端口映射表
COMMON_PORTS = {
    21: {"service": "ftp", "name": "FTP"},
    22: {"service": "ssh", "name": "SSH"},
    23: {"service": "telnet", "name": "Telnet"},
    25: {"service": "smtp", "name": "SMTP"},
    53: {"service": "dns", "name": "DNS"},
    80: {"service": "http", "name": "HTTP"},
    110: {"service": "pop3", "name": "POP3"},
    111: {"service": "rpcbind", "name": "RPC"},
    135: {"service": "msrpc", "name": "MSRPC"},
    139: {"service": "netbios", "name": "NetBIOS"},
    143: {"service": "imap", "name": "IMAP"},
    443: {"service": "https", "name": "HTTPS"},
    445: {"service": "smb", "name": "SMB"},
    993: {"service": "imaps", "name": "IMAPS"},
    995: {"service": "pop3s", "name": "POP3S"},
    1433: {"service": "mssql", "name": "MSSQL"},
    1521: {"service": "oracle", "name": "Oracle"},
    1723: {"service": "pptp", "name": "PPTP VPN"},
    2049: {"service": "nfs", "name": "NFS"},
    2375: {"service": "docker", "name": "Docker API"},
    2376: {"service": "docker-tls", "name": "Docker TLS"},
    3000: {"service": "nodejs", "name": "Node.js应用"},
    3306: {"service": "mysql", "name": "MySQL"},
    3389: {"service": "rdp", "name": "RDP远程桌面"},
    5432: {"service": "postgresql", "name": "PostgreSQL"},
    5900: {"service": "vnc", "name": "VNC"},
    5984: {"service": "couchdb", "name": "CouchDB"},
    6379: {"service": "redis", "name": "Redis"},
    7001: {"service": "weblogic", "name": "WebLogic"},
    8000: {"service": "http-alt", "name": "HTTP Alternate"},
    8080: {"service": "http-proxy", "name": "HTTP Proxy"},
    8443: {"service": "https-alt", "name": "HTTPS Alternate"},
    8888: {"service": "http-alt2", "name": "HTTP 8888"},
    9000: {"service": "php-fpm", "name": "PHP-FPM"},
    9200: {"service": "elasticsearch", "name": "Elasticsearch"},
    9300: {"service": "es-transport", "name": "ES Transport"},
    11211: {"service": "memcached", "name": "Memcached"},
    27017: {"service": "mongodb", "name": "MongoDB"},
    50070: {"service": "hadoop", "name": "Hadoop NameNode"},
}

# 服务指纹匹配
SERVICE_FINGERPRINTS = [
    (r"SSH-\d+\.\d+", "ssh"),
    (r"^220.*FTP", "ftp"),
    (r"^220.*SMTP", "smtp"),
    (r"HTTP/\d+\.\d+", "http"),
    (r"MySQL", "mysql"),
    (r"Redis", "redis"),
    (r"MongoDB", "mongodb"),
    (r"Elasticsearch", "elasticsearch"),
    (r"WebLogic", "weblogic"),
    (r"Apache", "http"),
    (r"Nginx", "http"),
    (r"Microsoft-IIS", "http"),
]


class RealPortScanner:
    """真实TCP端口扫描器"""

    def __init__(self, target: str, timeout: float = 2.0, max_threads: int = 50):
        self.target = self._extract_host(target)
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports = []
        self.scan_duration = 0

    def _extract_host(self, target: str) -> str:
        """从URL中提取主机名"""
        if target.startswith("http"):
            return target.split("://")[1].split("/")[0].split(":")[0]
        return target

    def _scan_port(self, port: int) -> Optional[Dict]:
        """扫描单个端口"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                # 端口开放，尝试获取banner
                banner = ""
                service = COMMON_PORTS.get(port, {}).get("service", "unknown")
                service_name = COMMON_PORTS.get(port, {}).get("name", str(port))
                
                # 对特定端口尝试获取banner
                if port in (21, 22, 25, 110, 143):
                    try:
                        sock.settimeout(2)
                        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    except:
                        pass
                elif port in (80, 443, 8080, 8443, 3000):
                    try:
                        request = f"HEAD / HTTP/1.0\r\nHost: {self.target}\r\n\r\n"
                        sock.send(request.encode())
                        sock.settimeout(2)
                        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()[:200]
                    except:
                        pass
                
                # 指纹识别
                if banner:
                    for pattern, svc in SERVICE_FINGERPRINTS:
                        if re.search(pattern, banner, re.IGNORECASE):
                            service = svc
                            break
                
                sock.close()
                return {
                    "port": port,
                    "service": service,
                    "name": service_name,
                    "state": "open",
                    "banner": banner[:200]
                }
            sock.close()
        except:
            pass
        return None

    def scan_common_ports(self) -> Dict[str, Any]:
        """扫描常见端口（约40个）"""
        start_time = time.time()
        ports = list(COMMON_PORTS.keys())
        
        print(f"开始扫描 {self.target} 的 {len(ports)} 个常见端口...")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._scan_port, p): p for p in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.open_ports.append(result)
                    print(f"  发现开放端口: {result['port']}/tcp ({result['service']})")
        
        self.open_ports.sort(key=lambda x: x["port"])
        self.scan_duration = time.time() - start_time
        
        return {
            "target": self.target,
            "scan_type": "common_ports",
            "total_ports_scanned": len(ports),
            "open_ports_count": len(self.open_ports),
            "open_ports": self.open_ports,
            "scan_duration_seconds": round(self.scan_duration, 2)
        }

    def scan_full(self) -> Dict[str, Any]:
        """快速扫描1-1000端口"""
        start_time = time.time()
        ports = list(range(1, 1001))
        
        print(f"开始全端口扫描 {self.target} (1-1000)...")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._scan_port, p): p for p in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.open_ports.append(result)
                    print(f"  发现开放端口: {result['port']}/tcp ({result['service']})")
        
        self.open_ports.sort(key=lambda x: x["port"])
        self.scan_duration = time.time() - start_time
        
        return {
            "target": self.target,
            "scan_type": "full_1000",
            "total_ports_scanned": len(ports),
            "open_ports_count": len(self.open_ports),
            "open_ports": self.open_ports,
            "scan_duration_seconds": round(self.scan_duration, 2)
        }


# 快速测试
if __name__ == "__main__":
    scanner = RealPortScanner("127.0.0.1", timeout=1.0, max_threads=100)
    result = scanner.scan_common_ports()
    print(f"\n扫描完成: {result['open_ports_count']}个开放端口, 耗时{result['scan_duration_seconds']}秒")
    for p in result["open_ports"]:
        print(f"  {p['port']}/tcp {p['service']:15s} {p['banner'][:50]}")
