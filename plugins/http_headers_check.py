"""
http_headers_check模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import ssl
import socket
from typing import Dict, Any, List
from urllib.parse import urlparse
import aiohttp
from utils.plugin_system import Plugin


class HTTPHeadersPlugin(Plugin):
    """HTTP安全头检测插件"""

    name = "http_headers_check"
    version = "1.0.0"
    description = "HTTP安全响应头检测工具，检查CSP/HSTS/X-Frame-Options等安全头配置"
    author = "AI Hacking Agent"
    category = "recon"
    tags = ["http", "headers", "security", "recon"]

    # 安全头定义
    SECURITY_HEADERS = {
        "Content-Security-Policy": {
            "description": "内容安全策略，防止XSS和数据注入",
            "severity": "high",
            "recommendation": "配置严格的CSP策略，限制脚本和资源来源",
        },
        "Strict-Transport-Security": {
            "description": "强制使用HTTPS，防止SSL剥离攻击",
            "severity": "high",
            "recommendation": "配置max-age至少31536000秒，并包含includeSubDomains",
        },
        "X-Content-Type-Options": {
            "description": "防止MIME类型嗅探",
            "severity": "medium",
            "recommendation": "设置为 nosniff",
        },
        "X-Frame-Options": {
            "description": "防止点击劫持攻击",
            "severity": "medium",
            "recommendation": "设置为 DENY 或 SAMEORIGIN",
        },
        "X-XSS-Protection": {
            "description": "启用浏览器内置XSS过滤器",
            "severity": "low",
            "recommendation": "设置为 1; mode=block（注意：现代浏览器已弃用）",
        },
        "Referrer-Policy": {
            "description": "控制Referer头信息泄露",
            "severity": "low",
            "recommendation": "设置为 strict-origin-when-cross-origin 或 no-referrer",
        },
        "Permissions-Policy": {
            "description": "控制浏览器功能权限（摄像头/麦克风/地理位置等）",
            "severity": "low",
            "recommendation": "禁用不需要的功能，如 geolocation=(), microphone=()",
        },
        "Cross-Origin-Opener-Policy": {
            "description": "防止跨源窗口攻击",
            "severity": "medium",
            "recommendation": "设置为 same-origin",
        },
        "Cross-Origin-Resource-Policy": {
            "description": "防止跨源资源读取",
            "severity": "medium",
            "recommendation": "设置为 same-origin 或 same-site",
        },
    }

    def get_parameters(self) -> Dict[str, Any]:
        """获取相关数据。

        Returns:
            操作结果。
        """
        return {
            "url": {
                "type": "string",
                "description": "目标URL（如 https://example.com）",
                "required": True,
            },
            "timeout": {
                "type": "integer",
                "description": "请求超时时间（秒）",
                "required": False,
                "default": 10,
            },
        }

    def execute(self, url: str = "", timeout: int = 10, **kwargs) -> Dict[str, Any]:
        """执行HTTP安全头检测"""
        if not url:
            return {"success": False, "error": "URL不能为空"}

        # 确保URL有协议
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            import asyncio
            result = asyncio.run(self._check_headers_async(url, timeout))
            return result
        except Exception as e:
            return {"success": False, "error": f"检测失败: {e}"}

    async def _check_headers_async(self, url: str, timeout: int) -> Dict[str, Any]:
        """异步检测HTTP头"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                                       allow_redirects=True, ssl=False) as response:
                    headers = dict(response.headers)
                    status_code = response.status
                    final_url = str(response.url)

                    # 分析安全头
                    present = []
                    missing = []
                    misconfigured = []
                    findings = []

                    for header_name, header_info in self.SECURITY_HEADERS.items():
                        header_value = headers.get(header_name) or headers.get(header_name.lower())

                        if header_value:
                            present.append({
                                "name": header_name,
                                "value": header_value,
                                "description": header_info["description"],
                            })

                            # 检查常见配置错误
                            issues = self._check_header_config(header_name, header_value)
                            if issues:
                                misconfigured.append({
                                    "name": header_name,
                                    "value": header_value,
                                    "issues": issues,
                                })
                                findings.append({
                                    "type": "misconfigured_header",
                                    "severity": header_info["severity"],
                                    "title": f"{header_name} 配置不当",
                                    "description": f"{header_name} 头存在但配置不当",
                                    "issues": issues,
                                    "recommendation": header_info["recommendation"],
                                })
                        else:
                            missing.append({
                                "name": header_name,
                                "description": header_info["description"],
                                "severity": header_info["severity"],
                                "recommendation": header_info["recommendation"],
                            })
                            findings.append({
                                "type": "missing_header",
                                "severity": header_info["severity"],
                                "title": f"缺少 {header_name} 头",
                                "description": f"未设置 {header_name} 安全响应头",
                                "recommendation": header_info["recommendation"],
                            })

                    # 计算安全评分
                    total_headers = len(self.SECURITY_HEADERS)
                    score = int((len(present) / total_headers) * 100)

                    # 风险等级
                    if score >= 80:
                        risk_level = "low"
                    elif score >= 60:
                        risk_level = "medium"
                    elif score >= 40:
                        risk_level = "high"
                    else:
                        risk_level = "critical"

                    return {
                        "success": True,
                        "result": {
                            "url": url,
                            "final_url": final_url,
                            "status_code": status_code,
                            "security_score": score,
                            "risk_level": risk_level,
                            "headers_present": len(present),
                            "headers_missing": len(missing),
                            "headers_misconfigured": len(misconfigured),
                            "present": present,
                            "missing": missing,
                            "misconfigured": misconfigured,
                            "findings": findings,
                            "all_headers": {k: v for k, v in headers.items()},
                        },
                    }

        except aiohttp.ClientError as e:
            return {"success": False, "error": f"HTTP请求失败: {e}"}
        except Exception as e:
            return {"success": False, "error": f"检测异常: {e}"}

    def _check_header_config(self, header_name: str, header_value: str) -> List[str]:
        """检查头配置是否正确"""
        issues = []

        if header_name == "Content-Security-Policy":
            if "unsafe-inline" in header_value:
                issues.append("包含 unsafe-inline，降低了XSS防护效果")
            if "unsafe-eval" in header_value:
                issues.append("包含 unsafe-eval，存在代码注入风险")
            if "*" in header_value and "default-src" in header_value:
                issues.append("default-src 使用通配符 *，过于宽松")

        elif header_name == "Strict-Transport-Security":
            if "max-age=0" in header_value:
                issues.append("max-age=0 会禁用HSTS")
            if "includeSubDomains" not in header_value:
                issues.append("未包含 includeSubDomains，子域名不受保护")

        elif header_name == "X-Frame-Options":
            if header_value.upper() not in ["DENY", "SAMEORIGIN"]:
                issues.append(f"无效的值: {header_value}，应为 DENY 或 SAMEORIGIN")

        elif header_name == "X-Content-Type-Options":
            if header_value.lower() != "nosniff":
                issues.append(f"无效的值: {header_value}，应为 nosniff")

        elif header_name == "Referrer-Policy":
            if header_value.lower() in ["unsafe-url", "no-referrer-when-downgrade"]:
                issues.append(f"策略 {header_value} 可能泄露敏感信息")

        return issues

    def is_available(self) -> bool:
        """检查插件是否可用（aiohttp是项目依赖，总是可用）"""
        return True
