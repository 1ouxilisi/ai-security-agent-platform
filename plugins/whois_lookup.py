"""
whois_lookup模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import socket
from typing import Dict, Any, List, Optional
from datetime import datetime
from utils.plugin_system import Plugin


class WHOISPlugin(Plugin):
    """WHOIS域名查询插件"""

    name = "whois_lookup"
    version = "1.0.0"
    description = "WHOIS域名查询工具，查询域名注册信息、注册商、有效期、域名服务器等"
    author = "AI Hacking Agent"
    category = "recon"
    tags = ["whois", "domain", "recon", "dns"]

    # WHOIS服务器映射（常见顶级域名）
    WHOIS_SERVERS = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "info": "whois.afilias.net",
        "biz": "whois.biz",
        "io": "whois.nic.io",
        "co": "whois.nic.co",
        "me": "whois.nic.me",
        "tv": "whois.nic.tv",
        "cc": "whois.nic.cc",
        "cn": "whois.cnnic.cn",
        "top": "whois.nic.top",
        "xyz": "whois.nic.xyz",
        "site": "whois.nic.site",
        "online": "whois.nic.online",
        "store": "whois.nic.store",
        "tech": "whois.nic.tech",
        "space": "whois.nic.space",
        "fun": "whois.nic.fun",
        "club": "whois.nic.club",
        "shop": "whois.nic.shop",
        "site": "whois.nic.site",
    }

    # 默认WHOIS服务器
    DEFAULT_WHOIS_SERVER = "whois.iana.org"

    def get_parameters(self) -> Dict[str, Any]:
        """获取相关数据。

        Returns:
            操作结果。
        """
        return {
            "domain": {
                "type": "string",
                "description": "要查询的域名（如 example.com）",
                "required": True,
            },
            "whois_server": {
                "type": "string",
                "description": "指定WHOIS服务器（可选，自动检测）",
                "required": False,
            },
            "timeout": {
                "type": "integer",
                "description": "查询超时时间（秒）",
                "required": False,
                "default": 15,
            },
        }

    def execute(self, domain: str = "", whois_server: str = None,
                timeout: int = 15, **kwargs) -> Dict[str, Any]:
        """执行WHOIS查询"""
        if not domain:
            return {"success": False, "error": "域名不能为空"}

        # 清理域名
        domain = domain.strip().lower()
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        if domain.startswith("www."):
            domain = domain[4:]

        try:
            # 确定WHOIS服务器
            if not whois_server:
                whois_server = self._get_whois_server(domain)

            # 查询WHOIS
            raw_data = self._query_whois(domain, whois_server, timeout)
            if not raw_data:
                return {"success": False, "error": "WHOIS查询失败，无返回数据"}

            # 解析WHOIS数据
            parsed = self._parse_whois(raw_data, domain)

            return {
                "success": True,
                "result": {
                    "domain": domain,
                    "whois_server": whois_server,
                    "raw_data": raw_data[:5000],  # 限制原始数据长度
                    "parsed": parsed,
                },
            }

        except socket.timeout:
            return {"success": False, "error": f"WHOIS查询超时: {whois_server}"}
        except Exception as e:
            return {"success": False, "error": f"WHOIS查询失败: {e}"}

    def _get_whois_server(self, domain: str) -> str:
        """根据域名后缀获取WHOIS服务器"""
        parts = domain.split(".")
        if len(parts) < 2:
            return self.DEFAULT_WHOIS_SERVER

        tld = parts[-1]
        return self.WHOIS_SERVERS.get(tld, self.DEFAULT_WHOIS_SERVER)

    def _query_whois(self, domain: str, server: str, timeout: int) -> Optional[str]:
        """执行WHOIS查询"""
        try:
            with socket.create_connection((server, 43), timeout=timeout) as sock:
                sock.sendall(f"{domain}\r\n".encode())
                response = b""
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                return response.decode("utf-8", errors="replace")
        except Exception:
            return None

    def _parse_whois(self, raw_data: str, domain: str) -> Dict[str, Any]:
        """解析WHOIS数据"""
        parsed = {
            "domain_name": None,
            "registrar": None,
            "whois_server": None,
            "referral_url": None,
            "updated_date": None,
            "creation_date": None,
            "expiration_date": None,
            "name_servers": [],
            "status": [],
            "registrant": {},
            "admin": {},
            "tech": {},
            "dnssec": None,
        }

        # 按行解析
        lines = raw_data.split("\n")
        current_section = None

        for line in lines:
            line = line.strip()
            if not line or line.startswith("%") or line.startswith(">>>"):
                continue

            # 检查是否是section header（如 "Registrant:"）
            if line.endswith(":") and not line.startswith(" "):
                section_name = line[:-1].strip().lower()
                if section_name in ["registrant", "admin", "administrator", "tech", "technical"]:
                    current_section = section_name
                    continue

            # 解析 key: value 格式
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower()
                value = value.strip()

                if not value:
                    continue

                # 域名信息
                if key in ["domain name", "domain"]:
                    parsed["domain_name"] = value
                elif key in ["registrar", "sponsoring registrar", "registrar name"]:
                    parsed["registrar"] = value
                elif key in ["whois server", "registrar whois server"]:
                    parsed["whois_server"] = value
                elif key in ["referral url", "registrar url"]:
                    parsed["referral_url"] = value
                elif key in ["updated date", "last updated", "updated"]:
                    parsed["updated_date"] = value
                elif key in ["creation date", "created", "registered on"]:
                    parsed["creation_date"] = value
                elif key in ["expiration date", "expires", "expiry date", "paid-till"]:
                    parsed["expiration_date"] = value
                elif key in ["name server", "nameserver", "nserver"]:
                    if value and value not in parsed["name_servers"]:
                        parsed["name_servers"].append(value)
                elif key in ["status", "domain status"]:
                    if value and value not in parsed["status"]:
                        parsed["status"].append(value)
                elif key in ["dnssec", "dnssec signed"]:
                    parsed["dnssec"] = value

                # section-specific fields
                elif current_section:
                    if current_section not in parsed:
                        parsed[current_section] = {}
                    parsed[current_section][key] = value

        # 计算域名年龄
        try:
            if parsed["creation_date"]:
                # 尝试解析日期
                for date_fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S",
                                  "%d-%b-%Y", "%Y-%m-%d", "%Y.%m.%d"]:
                    try:
                        created = datetime.strptime(parsed["creation_date"].split("T")[0].strip(), date_fmt.split("T")[0])
                        now = datetime.now()
                        age_days = (now - created).days
                        parsed["domain_age_days"] = age_days
                        parsed["domain_age_years"] = round(age_days / 365, 1)
                        break
                    except ValueError:
                        continue
        except Exception:
            pass

        # 检查域名是否即将过期
        try:
            if parsed["expiration_date"]:
                for date_fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S",
                                  "%d-%b-%Y", "%Y-%m-%d"]:
                    try:
                        expires = datetime.strptime(parsed["expiration_date"].split("T")[0].strip(), date_fmt.split("T")[0])
                        now = datetime.now()
                        days_until_expiry = (expires - now).days
                        parsed["days_until_expiry"] = days_until_expiry
                        if days_until_expiry < 0:
                            parsed["expired"] = True
                        elif days_until_expiry < 30:
                            parsed["expiring_soon"] = True
                        break
                    except ValueError:
                        continue
        except Exception:
            pass

        return parsed

    def is_available(self) -> bool:
        """检查插件是否可用（socket是Python标准库，总是可用）"""
        return True
