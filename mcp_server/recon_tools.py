"""
recon_tools模块，提供相关安全测试功能。

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
import socket
from typing import Dict, List, Optional
from utils.logger import log
from utils.helpers import validate_target, rate_limit


class ReconTools:
    """侦察工具集合"""

    def __init__(self):
        """初始化ReconTools实例。

        Args:
            self: 类实例。
        """
        self.results = {}
        self._nmap_available = None

    def _check_nmap(self) -> bool:
        """检测nmap是否可用"""
        if self._nmap_available is not None:
            return self._nmap_available
        try:
            import shutil
            self._nmap_available = shutil.which("nmap") is not None
        except:
            self._nmap_available = False
        return self._nmap_available

    @rate_limit()
    async def port_scan(self, target: str, ports: Optional[str] = None, timeout: float = 2.0) -> Dict:
        """
        端口扫描 - 扫描目标主机开放端口
        优先使用真实nmap扫描，不可用时回退到Python socket模拟
        仅允许扫描授权白名单内的目标
        """
        if not validate_target(target):
            return {"error": "目标不在授权白名单内，操作已拒绝"}

        # 如果nmap可用，使用真实nmap扫描
        if self._check_nmap():
            log.info(f"使用真实nmap扫描: {target}")
            try:
                # 构造nmap命令
                nmap_args = ["nmap", "-T4", "-Pn"]
                if ports:
                    nmap_args.extend(["-p", ports])
                else:
                    nmap_args.extend(["-p", "1-1000"])
                nmap_args.extend(["-oX", "-", target])

                proc = await asyncio.create_subprocess_exec(
                    *nmap_args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
                nmap_xml = stdout.decode("utf-8", errors="ignore")

                # 解析nmap XML输出
                import xml.etree.ElementTree as ET
                open_ports = []
                services = {}
                root = ET.fromstring(nmap_xml)
                for host in root.findall(".//host"):
                    for port in host.findall(".//port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            port_id = int(port.get("portid"))
                            open_ports.append(port_id)
                            service = port.find("service")
                            if service is not None:
                                services[port_id] = service.get("name", "Unknown")

                result = {
                    "target": target,
                    "scan_type": "nmap_real",
                    "scanner": "nmap",
                    "total_ports_scanned": len(ports.split("-")[-1]) if ports and "-" in ports else 1000,
                    "open_ports": sorted(open_ports),
                    "open_port_count": len(open_ports),
                    "services": services if services else {p: "Unknown" for p in sorted(open_ports)},
                }
                log.info(f"nmap扫描完成: {target}, 开放端口: {result['open_ports']}")
                return result
            except Exception as e:
                log.warning(f"nmap扫描失败，回退到模拟模式: {e}")

        # 回退到Python socket模拟模式
        log.info(f"使用Python socket模拟扫描: {target}")

        # 解析端口范围
        if ports is None:
            port_list = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]
        elif "-" in ports:
            start, end = map(int, ports.split("-"))
            port_list = range(start, end + 1)
        else:
            port_list = [int(p.strip()) for p in ports.split(",")]

        log.info(f"开始端口扫描: {target}, 端口数: {len(list(port_list))}")

        open_ports = []
        closed_ports = []
        filtered_ports = []

        async def check_port(port: int):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=timeout
                )
                writer.close()
                await writer.wait_closed()
                open_ports.append(port)
                log.debug(f"端口 {port} 开放")
            except asyncio.TimeoutError:
                filtered_ports.append(port)
            except (ConnectionRefusedError, OSError):
                closed_ports.append(port)
            except Exception as e:
                log.debug(f"端口 {port} 检查异常: {e}")

        # 并发扫描，限制并发数
        semaphore = asyncio.Semaphore(50)

        async def bounded_check(port):
            async with semaphore:
                await check_port(port)

        tasks = [bounded_check(p) for p in port_list]
        await asyncio.gather(*tasks)

        result = {
            "target": target,
            "scan_type": "tcp_connect_simulated",
            "scanner": "python_socket",
            "note": "使用Python socket模拟扫描，建议安装nmap获取更准确的结果",
            "total_ports_scanned": len(port_list),
            "open_ports": sorted(open_ports),
            "closed_ports_count": len(closed_ports),
            "filtered_ports_count": len(filtered_ports),
            "open_port_count": len(open_ports),
        }

        # 常见端口服务识别
        service_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
        }
        result["services"] = {p: service_map.get(p, "Unknown") for p in sorted(open_ports)}

        log.info(f"端口扫描完成: {target}, 开放端口: {result['open_ports']}")
        return result

    async def dns_lookup(self, domain: str) -> Dict:
        """DNS解析 - 解析域名对应的IP地址"""
        try:
            log.info(f"DNS解析: {domain}")
            # 提取主机名
            from urllib.parse import urlparse
            parsed = urlparse(domain)
            host = parsed.hostname or domain

            ip_addresses = []
            try:
                addrinfo = await asyncio.get_event_loop().getaddrinfo(host, None)
                ip_addresses = list(set([info[4][0] for info in addrinfo]))
            except socket.gaierror as e:
                return {"domain": domain, "error": f"DNS解析失败: {e}"}

            result = {
                "domain": host,
                "ip_addresses": ip_addresses,
                "record_count": len(ip_addresses),
            }
            log.info(f"DNS解析完成: {host} -> {ip_addresses}")
            return result
        except Exception as e:
            log.error(f"DNS解析异常: {e}")
            return {"domain": domain, "error": str(e)}

    async def whois_lookup(self, domain: str) -> Dict:
        """
        WHOIS查询 - 域名注册信息
        注意：需要系统安装whois命令，否则返回模拟信息
        """
        try:
            log.info(f"WHOIS查询: {domain}")
            from urllib.parse import urlparse
            parsed = urlparse(domain)
            host = parsed.hostname or domain

            # 尝试调用系统whois命令
            try:
                proc = await asyncio.create_subprocess_exec(
                    "whois", host,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
                whois_data = stdout.decode("utf-8", errors="ignore")
                return {"domain": host, "whois_data": whois_data[:5000]}
            except (FileNotFoundError, asyncio.TimeoutError):
                # whois命令不可用，返回基础信息
                return {
                    "domain": host,
                    "note": "系统未安装whois命令，仅返回基础信息",
                    "tip": "Linux: apt install whois | Windows: 安装whois客户端"
                }
        except Exception as e:
            log.error(f"WHOIS查询异常: {e}")
            return {"domain": domain, "error": str(e)}

    async def http_headers(self, url: str) -> Dict:
        """获取HTTP响应头 - 识别服务器、技术栈"""
        if not validate_target(url):
            return {"error": "目标不在授权白名单内，操作已拒绝"}

        try:
            import aiohttp
            log.info(f"获取HTTP头: {url}")

            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as resp:
                    headers = dict(resp.headers)
                    result = {
                        "url": str(resp.url),
                        "status_code": resp.status,
                        "status_text": resp.reason,
                        "headers": headers,
                        "server": headers.get("Server", "Unknown"),
                        "powered_by": headers.get("X-Powered-By", "Unknown"),
                        "content_type": headers.get("Content-Type", "Unknown"),
                    }

                    # 技术栈识别
                    tech = []
                    server = headers.get("Server", "").lower()
                    if "nginx" in server: tech.append("Nginx")
                    if "apache" in server: tech.append("Apache")
                    if "iis" in server: tech.append("IIS")
                    if "cloudflare" in server: tech.append("Cloudflare")

                    powered = headers.get("X-Powered-By", "").lower()
                    if "php" in powered: tech.append("PHP")
                    if "asp.net" in powered: tech.append("ASP.NET")
                    if "express" in powered: tech.append("Node.js/Express")

                    result["detected_tech"] = tech if tech else ["Unknown"]
                    return result
        except Exception as e:
            log.error(f"HTTP头获取异常: {e}")
            return {"url": url, "error": str(e)}


# 全局实例
recon_tools = ReconTools()
