"""
dns_lookup模块，提供相关安全测试功能。

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
from typing import Dict, Any
from utils.plugin_system import Plugin


class DNSLookupPlugin(Plugin):
    """DNS查询插件 - 解析域名的IP地址"""

    name = "dns_lookup"
    version = "1.0.0"
    description = "DNS域名解析工具，支持A记录、AAAA记录、CNAME记录查询"
    author = "AI Hacking Agent"
    category = "recon"
    tags = ["dns", "recon", "domain"]

    def get_parameters(self) -> Dict[str, Any]:
        """获取相关数据。

        Returns:
            操作结果。
        """
        return {
            "domain": {
                "type": "string",
                "description": "要查询的域名",
                "required": True,
            },
            "record_type": {
                "type": "string",
                "description": "记录类型 (A, AAAA, CNAME, MX, TXT)",
                "required": False,
                "default": "A",
            },
        }

    def execute(self, domain: str = "", record_type: str = "A", **kwargs) -> Dict[str, Any]:
        """执行DNS查询"""
        if not domain:
            return {"success": False, "error": "域名不能为空"}

        try:
            results = []

            if record_type.upper() == "A":
                # A记录查询
                addr_info = socket.getaddrinfo(domain, None, socket.AF_INET)
                for info in addr_info:
                    ip = info[4][0]
                    if ip not in [r["value"] for r in results]:
                        results.append({"type": "A", "value": ip})

            elif record_type.upper() == "AAAA":
                # AAAA记录查询
                addr_info = socket.getaddrinfo(domain, None, socket.AF_INET6)
                for info in addr_info:
                    ip = info[4][0]
                    if ip not in [r["value"] for r in results]:
                        results.append({"type": "AAAA", "value": ip})

            elif record_type.upper() == "CNAME":
                # CNAME查询（通过gethostbyname_ex）
                try:
                    hostname, aliases, addresses = socket.gethostbyname_ex(domain)
                    for alias in aliases:
                        results.append({"type": "CNAME", "value": alias})
                except Exception:
                    pass

            else:
                return {
                    "success": False,
                    "error": f"不支持的记录类型: {record_type}，支持: A, AAAA, CNAME",
                }

            return {
                "success": True,
                "result": {
                    "domain": domain,
                    "record_type": record_type,
                    "records": results,
                    "count": len(results),
                },
            }

        except socket.gaierror as e:
            return {"success": False, "error": f"DNS解析失败: {e}"}
        except Exception as e:
            return {"success": False, "error": f"查询失败: {e}"}

    def is_available(self) -> bool:
        """检查插件是否可用（DNS功能总是可用）"""
        return True
