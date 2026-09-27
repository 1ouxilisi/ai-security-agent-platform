"""
ssl_certificate_check模块，提供相关安全测试功能。

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
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from utils.plugin_system import Plugin


class SSLCertificatePlugin(Plugin):
    """SSL/TLS证书检测插件"""

    name = "ssl_certificate_check"
    version = "1.0.0"
    description = "SSL/TLS证书检测工具，检查证书有效期、颁发者、密钥强度、TLS版本等"
    author = "AI Hacking Agent"
    category = "recon"
    tags = ["ssl", "tls", "certificate", "security", "recon"]

    # 弱签名算法
    WEAK_SIGNATURE_ALGORITHMS = [
        "md5", "sha1", "md2", "md4",
    ]

    # 弱密钥长度
    WEAK_KEY_LENGTHS = {
        "RSA": 2048,  # 小于2048位视为弱
        "EC": 256,    # 小于256位视为弱
    }

    # TLS版本评级
    TLS_VERSION_RATINGS = {
        "TLSv1.3": "excellent",
        "TLSv1.2": "good",
        "TLSv1.1": "weak",
        "TLSv1.0": "insecure",
        "SSLv3": "insecure",
        "SSLv2": "insecure",
    }

    def get_parameters(self) -> Dict[str, Any]:
        """获取相关数据。

        Returns:
            操作结果。
        """
        return {
            "host": {
                "type": "string",
                "description": "目标域名（如 example.com）",
                "required": True,
            },
            "port": {
                "type": "integer",
                "description": "SSL端口",
                "required": False,
                "default": 443,
            },
            "timeout": {
                "type": "integer",
                "description": "连接超时时间（秒）",
                "required": False,
                "default": 10,
            },
        }

    def execute(self, host: str = "", port: int = 443, timeout: int = 10, **kwargs) -> Dict[str, Any]:
        """执行SSL证书检测"""
        if not host:
            return {"success": False, "error": "主机名不能为空"}

        # 移除协议前缀
        host = host.replace("https://", "").replace("http://", "").split("/")[0]

        try:
            cert_info = self._get_certificate_info(host, port, timeout)
            if not cert_info:
                return {"success": False, "error": "无法获取证书信息"}

            analysis = self._analyze_certificate(cert_info)

            return {
                "success": True,
                "result": {
                    "host": host,
                    "port": port,
                    "certificate": cert_info,
                    "analysis": analysis,
                },
            }

        except socket.timeout:
            return {"success": False, "error": f"连接超时: {host}:{port}"}
        except ssl.SSLError as e:
            return {"success": False, "error": f"SSL错误: {e}"}
        except Exception as e:
            return {"success": False, "error": f"检测失败: {e}"}

    def _get_certificate_info(self, host: str, port: int, timeout: int) -> Optional[Dict[str, Any]]:
        """获取证书信息"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # 获取证书
                    cert = ssock.getpeercert()
                    if not cert:
                        return None

                    # 获取TLS版本
                    tls_version = ssock.version()

                    # 获取证书二进制数据用于额外分析
                    der_cert = ssock.getpeercert(binary_form=True)

                    cert_info = {
                        "subject": self._parse_name(cert.get("subject", [])),
                        "issuer": self._parse_name(cert.get("issuer", [])),
                        "version": cert.get("version"),
                        "serial_number": cert.get("serialNumber"),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "subject_alt_names": self._parse_san(cert.get("subjectAltName", [])),
                        "tls_version": tls_version,
                        "cipher": ssock.cipher(),
                    }

                    return cert_info

        except Exception as e:
            return None

    def _parse_name(self, name_fields: List) -> Dict[str, str]:
        """解析证书名称字段"""
        result = {}
        for field in name_fields:
            if isinstance(field, tuple) and len(field) > 0:
                for item in field:
                    if isinstance(item, tuple) and len(item) == 2:
                        key, value = item
                        result[key] = value
        return result

    def _parse_san(self, san_fields: List) -> List[str]:
        """解析Subject Alternative Names"""
        result = []
        for field in san_fields:
            if isinstance(field, tuple) and len(field) == 2:
                result.append(f"{field[0]}:{field[1]}")
        return result

    def _analyze_certificate(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """分析证书安全性"""
        findings = []
        score = 100
        risk_level = "low"

        # 1. 检查证书有效期
        try:
            not_after = datetime.strptime(cert_info["not_after"], "%b %d %H:%M:%S %Y %Z")
            not_after = not_after.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_remaining = (not_after - now).days

            if days_remaining < 0:
                findings.append({
                    "type": "cert_expired",
                    "severity": "critical",
                    "title": "证书已过期",
                    "description": f"证书已于 {cert_info['not_after']} 过期",
                    "recommendation": "立即更新证书",
                })
                score -= 50
            elif days_remaining < 7:
                findings.append({
                    "type": "cert_expiring_soon",
                    "severity": "high",
                    "title": "证书即将过期",
                    "description": f"证书将在 {days_remaining} 天后过期",
                    "recommendation": "尽快更新证书",
                })
                score -= 20
            elif days_remaining < 30:
                findings.append({
                    "type": "cert_expiring",
                    "severity": "medium",
                    "title": "证书将在30天内过期",
                    "description": f"证书将在 {days_remaining} 天后过期",
                    "recommendation": "安排证书更新",
                })
                score -= 10
        except Exception:
            pass

        # 2. 检查TLS版本
        tls_version = cert_info.get("tls_version", "")
        tls_rating = self.TLS_VERSION_RATINGS.get(tls_version, "unknown")

        if tls_rating == "insecure":
            findings.append({
                "type": "weak_tls_version",
                "severity": "critical",
                "title": f"使用不安全的TLS版本: {tls_version}",
                "description": f"{tls_version} 存在已知安全漏洞",
                "recommendation": "升级到 TLS 1.2 或更高版本",
            })
            score -= 40
        elif tls_rating == "weak":
            findings.append({
                "type": "weak_tls_version",
                "severity": "high",
                "title": f"使用较弱的TLS版本: {tls_version}",
                "description": f"{tls_version} 已被弃用，存在安全风险",
                "recommendation": "升级到 TLS 1.2 或更高版本",
            })
            score -= 20

        # 3. 检查证书颁发者
        issuer = cert_info.get("issuer", {})
        issuer_org = issuer.get("organizationName", "")

        # 4. 检查通配符证书
        subject_cn = cert_info.get("subject", {}).get("commonName", "")
        if subject_cn.startswith("*."):
            findings.append({
                "type": "wildcard_certificate",
                "severity": "low",
                "title": "使用通配符证书",
                "description": f"证书通配符: {subject_cn}",
                "recommendation": "考虑使用特定域名证书以减少攻击面",
            })
            score -= 5

        # 5. 检查SAN数量
        san_count = len(cert_info.get("subject_alt_names", []))
        if san_count > 50:
            findings.append({
                "type": "too_many_san",
                "severity": "low",
                "title": "证书包含过多SAN",
                "description": f"证书包含 {san_count} 个Subject Alternative Names",
                "recommendation": "考虑拆分证书以减少单个证书的影响范围",
            })
            score -= 5

        # 计算最终风险等级
        score = max(0, min(100, score))
        if score >= 80:
            risk_level = "low"
        elif score >= 60:
            risk_level = "medium"
        elif score >= 40:
            risk_level = "high"
        else:
            risk_level = "critical"

        return {
            "security_score": score,
            "risk_level": risk_level,
            "tls_version": tls_version,
            "tls_rating": tls_rating,
            "findings": findings,
            "issuer": issuer,
            "subject_cn": subject_cn,
            "san_count": san_count,
        }

    def is_available(self) -> bool:
        """检查插件是否可用（ssl和socket是Python标准库，总是可用）"""
        return True
