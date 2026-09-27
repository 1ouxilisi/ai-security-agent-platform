"""
SSL/TLS安全检测器 + 专业报告生成器 - 第六轮升级
"""
import ssl
import socket
import datetime
import json
import os
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse


class SSLTLSDetector:
    """SSL/TLS安全配置检测器"""

    # 弱加密套件
    WEAK_CIPHERS = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]
    # 不安全协议版本
    INSECURE_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]

    def __init__(self, target: str, port: int = 443, timeout: int = 10):
        if target.startswith("http"):
            parsed = urlparse(target)
            self.host = parsed.hostname
            self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        else:
            self.host = target
            self.port = port
        self.timeout = timeout

    def detect(self) -> Dict[str, Any]:
        """执行SSL/TLS检测"""
        result = {
            "host": self.host,
            "port": self.port,
            "ssl_enabled": False,
            "certificate": {},
            "protocol_versions": [],
            "vulnerabilities": [],
            "risk_score": 0
        }

        # 获取证书
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    result["ssl_enabled"] = True
                    result["protocol_versions"].append(version)

                    # 证书信息
                    if cert:
                        subject = dict(x[0] for x in cert.get("subject", []))
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        not_after = cert.get("notAfter", "")
                        try:
                            expire_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days_left = (expire_date - datetime.datetime.now()).days
                        except:
                            days_left = None

                        result["certificate"] = {
                            "subject": subject.get("commonName", ""),
                            "issuer": issuer.get("organizationName", issuer.get("commonName", "")),
                            "valid_from": cert.get("notBefore", ""),
                            "valid_to": not_after,
                            "days_until_expiry": days_left,
                            "serial_number": cert.get("serialNumber", ""),
                            "version": cert.get("version", ""),
                            "san": [x for x in cert.get("subjectAltName", [])]
                        }

                        # 证书过期检查
                        if days_left is not None and days_left < 0:
                            result["vulnerabilities"].append({
                                "type": "cert_expired",
                                "severity": "high",
                                "description": f"证书已过期{abs(days_left)}天"
                            })
                            result["risk_score"] += 30
                        elif days_left is not None and days_left < 30:
                            result["vulnerabilities"].append({
                                "type": "cert_expiring",
                                "severity": "medium",
                                "description": f"证书将在{days_left}天后过期"
                            })
                            result["risk_score"] += 15

                    # 加密套件检查
                    if cipher:
                        cipher_name = cipher[0]
                        result["cipher_suite"] = cipher_name
                        for weak in self.WEAK_CIPHERS:
                            if weak.lower() in cipher_name.lower():
                                result["vulnerabilities"].append({
                                    "type": "weak_cipher",
                                    "severity": "high",
                                    "description": f"使用弱加密套件: {cipher_name}"
                                })
                                result["risk_score"] += 25
                                break

                    # 协议版本检查
                    if version in ("SSLv2", "SSLv3"):
                        result["vulnerabilities"].append({
                            "type": "insecure_protocol",
                            "severity": "critical",
                            "description": f"使用不安全协议: {version}"
                        })
                        result["risk_score"] += 40
                    elif version in ("TLSv1", "TLSv1.1"):
                        result["vulnerabilities"].append({
                            "type": "insecure_protocol",
                            "severity": "high",
                            "description": f"使用过时协议: {version}，建议TLSv1.2+"
                        })
                        result["risk_score"] += 20

        except ssl.SSLError as e:
            result["ssl_enabled"] = False
            result["error"] = f"SSL错误: {str(e)[:200]}"
            result["vulnerabilities"].append({
                "type": "ssl_error",
                "severity": "medium",
                "description": f"SSL连接失败: {str(e)[:100]}"
            })
        except socket.timeout:
            result["error"] = "连接超时"
        except Exception as e:
            result["error"] = str(e)[:200]

        # 风险等级
        score = result["risk_score"]
        if score >= 50:
            result["overall_risk"] = "high"
        elif score >= 25:
            result["overall_risk"] = "medium"
        elif score > 0:
            result["overall_risk"] = "low"
        else:
            result["overall_risk"] = "secure"

        return result


class ReportGenerator:
    """专业渗透测试报告生成器"""

    @staticmethod
    def generate_html(target: str, scan_data: Dict[str, Any]) -> str:
        """生成HTML格式的专业渗透测试报告"""

        risk = scan_data.get("summary", {})
        risk_score = risk.get("risk_score", 0)
        risk_level = risk.get("overall_risk", "unknown")
        risk_colors = {
            "critical": "#dc2626", "high": "#ea580c",
            "medium": "#ca8a04", "low": "#16a34a", "secure": "#16a34a"
        }
        color = risk_colors.get(risk_level, "#6b7280")

        # 漏洞统计
        phases = scan_data.get("phases", {})
        vuln_data = phases.get("vuln_scan", {})
        vulns = vuln_data.get("vulnerabilities", [])
        port_data = phases.get("port_scan", {})
        open_ports = port_data.get("open_ports", [])
        fp_data = phases.get("web_fingerprint", {})

        vuln_sections = ""
        for i, v in enumerate(vulns[:20]):
            sev = v.get("severity", "medium")
            sev_color = risk_colors.get(sev, "#6b7280")
            vuln_sections += f"""
            <tr>
                <td style="padding:8px;border:1px solid #374151;"><span style="background:{sev_color};color:white;padding:2px 8px;border-radius:3px;font-size:11px;">{sev.upper()}</span></td>
                <td style="padding:8px;border:1px solid #374151;">{v.get('name','')}</td>
                <td style="padding:8px;border:1px solid #374151;font-size:12px;">{v.get('category','')}</td>
                <td style="padding:8px;border:1px solid #374151;font-size:11px;">{v.get('request',{}).get('path','')}</td>
            </tr>"""

        port_rows = ""
        for p in open_ports:
            port_rows += f"""
            <tr>
                <td style="padding:6px;border:1px solid #374151;">{p.get('port','')}/tcp</td>
                <td style="padding:6px;border:1px solid #374151;">{p.get('name','')}</td>
                <td style="padding:6px;border:1px solid #374151;color:#16a34a;">{p.get('state','')}</td>
                <td style="padding:6px;border:1px solid #374151;font-size:11px;">{p.get('banner','')[:80]}</td>
            </tr>"""

        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>安全评估报告 - {target}</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 20px; }}
.container {{ max-width: 900px; margin: 0 auto; }}
.header {{ text-align: center; padding: 30px; background: #1e293b; border-radius: 10px; margin-bottom: 20px; }}
.header h1 {{ color: #f8fafc; margin: 0; }}
.risk-badge {{ display: inline-block; padding: 8px 24px; border-radius: 20px; color: white; font-weight: bold; margin-top: 10px; background: {color}; }}
.section {{ background: #1e293b; border-radius: 10px; padding: 20px; margin-bottom: 15px; }}
.section h2 {{ color: #38bdf8; margin-top: 0; }}
table {{ width: 100%; border-collapse: collapse; }}
th {{ background: #0f172a; padding: 10px; text-align: left; color: #94a3b8; border: 1px solid #374151; }}
.meta {{ color: #64748b; font-size: 12px; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>AI全栈安全评估报告</h1>
        <p>目标: {target}</p>
        <p class="meta">生成时间: {now}</p>
        <div class="risk-badge">风险等级: {risk_level.upper()} (评分: {risk_score}/100)</div>
    </div>

    <div class="section">
        <h2>端口扫描结果</h2>
        <table><tr><th>端口</th><th>服务</th><th>状态</th><th>Banner</th></tr>{port_rows}</table>
    </div>

    <div class="section">
        <h2>Web指纹信息</h2>
        <p>页面标题: {fp_data.get('page_title', 'N/A')}</p>
        <p>技术栈: {', '.join(fp_data.get('tech_stack', [])) or 'N/A'}</p>
    </div>

    <div class="section">
        <h2>发现的漏洞 ({len(vulns)}个)</h2>
        <table><tr><th>严重度</th><th>漏洞名称</th><th>类别</th><th>路径</th></tr>{vuln_sections}</table>
    </div>

    <div class="section">
        <h2>修复建议</h2>
        <ul>
            <li>及时更新所有软件和服务到最新版本</li>
            <li>关闭不必要的开放端口和服务</li>
            <li>配置正确的安全响应头(CSP/HSTS/X-Frame-Options)</li>
            <li>定期进行安全扫描和渗透测试</li>
        </ul>
    </div>

    <p class="meta">本报告由AI全栈安全平台自动生成，仅供授权安全评估使用。</p>
</div>
</body>
</html>"""
        return html

    @staticmethod
    def generate_markdown(target: str, scan_data: Dict[str, Any]) -> str:
        """生成Markdown格式报告"""
        risk = scan_data.get("summary", {})
        lines = [
            f"# 安全评估报告 - {target}",
            f"",
            f"**生成时间**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**风险等级**: {risk.get('overall_risk', 'unknown')}",
            f"**风险评分**: {risk.get('risk_score', 0)}/100",
            f"",
            f"## 扫描概要",
            f"- 开放端口: {len(scan_data.get('phases',{}).get('port_scan',{}).get('open_ports',[]))}个",
            f"- 发现漏洞: {len(scan_data.get('phases',{}).get('vuln_scan',{}).get('vulnerabilities',[]))}个",
            f"- 完成阶段: {', '.join(risk.get('phases_completed', []))}",
            f"",
            f"## 风险因素",
        ]
        for factor in risk.get("risk_factors", []):
            lines.append(f"- {factor}")
        return "\n".join(lines)


if __name__ == "__main__":
    # 测试SSL检测
    det = SSLTLSDetector("baidu.com", 443, timeout=5)
    r = det.detect()
    print("SSL检测结果:")
    for k, v in r.items():
        print(f"  {k}: {v}")
