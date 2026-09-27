"""一键式安全评估引擎。

输入目标IP/域名，自动完成：端口扫描→漏洞扫描→Web检测→风险评级→报告生成。
这是项目的核心工作流，用户只需输入目标，一键得到完整评估报告。

注意：本模块仅用于授权的安全测试，使用前请确保已获得相关授权。
"""
import os
import re
import json
import time
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from utils.logger import log


@dataclass
class PortInfo:
    """端口信息"""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""


@dataclass
class VulnInfo:
    """漏洞信息"""
    name: str
    severity: str = "info"  # critical/high/medium/low/info
    description: str = ""
    target: str = ""
    evidence: str = ""
    reference: str = ""


@dataclass
class AssessmentResult:
    """安全评估结果"""
    target: str
    start_time: str = ""
    end_time: str = ""
    duration: float = 0
    status: str = "running"  # running/completed/failed
    ports: List[PortInfo] = field(default_factory=list)
    vulnerabilities: List[VulnInfo] = field(default_factory=list)
    web_findings: List[Dict] = field(default_factory=list)
    risk_score: int = 0  # 0-100
    risk_level: str = "未知"  # 严重/高危/中危/低危/安全
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    report_path: str = ""


class QuickAssessmentEngine:
    """一键式安全评估引擎"""

    # 常见Web敏感路径
    COMMON_WEB_PATHS = [
        "/admin", "/login", "/wp-admin", "/phpmyadmin",
        "/.git/config", "/.env", "/backup", "/config.php",
        "/robots.txt", "/sitemap.xml", "/.htaccess",
        "/server-status", "/info.php", "/test.php",
    ]

    def __init__(self, output_dir: str = "scan_results"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self._nmap_path = self._find_tool("nmap")
        self._nuclei_path = self._find_tool("nuclei")

    def _find_tool(self, tool_name: str) -> Optional[str]:
        """查找工具路径"""
        from shutil import which
        path = which(tool_name)
        if path:
            return path
        # 检查常见安装路径
        common_paths = {
            "nmap": [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"],
            "nuclei": [os.path.expandvars(r"%USERPROFILE%\tools\nuclei.exe")],
        }
        for p in common_paths.get(tool_name, []):
            if os.path.exists(p):
                return p
        return None

    def run_assessment(self, target: str, scan_type: str = "full") -> AssessmentResult:
        """执行一键安全评估

        Args:
            target: 目标IP或域名
            scan_type: quick(快速)/full(完整)/deep(深度)
        """
        result = AssessmentResult(
            target=target,
            start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        start_ts = time.time()

        log.info(f"开始安全评估: {target}, 类型: {scan_type}")

        try:
            # 步骤1: 端口扫描
            self._scan_ports(target, result, scan_type)

            # 步骤2: 漏洞扫描
            self._scan_vulnerabilities(target, result, scan_type)

            # 步骤3: Web安全检测
            if self._has_web_service(result):
                self._web_security_check(target, result)

            # 步骤4: 风险评级
            self._calculate_risk(result)

            # 步骤5: 生成建议
            self._generate_recommendations(result)

            # 步骤6: 生成报告
            report_path = self._generate_report(result)
            result.report_path = report_path

            result.status = "completed"
            result.summary = f"发现 {len(result.ports)} 个开放端口，{len(result.vulnerabilities)} 个漏洞，风险等级: {result.risk_level}"

        except Exception as e:
            result.status = "failed"
            result.errors.append(f"评估过程出错: {str(e)}")
            log.error(f"安全评估失败: {e}")

        result.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        result.duration = round(time.time() - start_ts, 2)

        # 保存JSON结果
        self._save_json_result(result)

        log.info(f"安全评估完成: {target}, 耗时: {result.duration}秒, 状态: {result.status}")
        return result

    def _scan_ports(self, target: str, result: AssessmentResult, scan_type: str):
        """端口扫描"""
        if not self._nmap_path:
            result.errors.append("nmap未安装，跳过端口扫描")
            return

        result.tools_used.append("nmap")
        log.info(f"执行nmap端口扫描: {target}")

        try:
            # 根据扫描类型选择参数
            if scan_type == "quick":
                args = ["-sV", "-T4", "-F", "--open", target]
            elif scan_type == "deep":
                args = ["-sV", "-sC", "-T4", "-p-", "--open", target]
            else:  # full
                args = ["-sV", "-T4", "-p", "1-10000", "--open", target]

            # 添加XML输出
            xml_output = os.path.join(self.output_dir, f"nmap_{self._safe_name(target)}.xml")
            args.extend(["-oX", xml_output])

            process = subprocess.run(
                [self._nmap_path] + args,
                capture_output=True, text=True, timeout=300
            )

            # 解析XML结果
            if os.path.exists(xml_output):
                ports = self._parse_nmap_xml(xml_output)
                result.ports.extend(ports)
                log.info(f"nmap发现 {len(ports)} 个开放端口")
            else:
                # 尝试从stdout解析
                ports = self._parse_nmap_output(process.stdout)
                result.ports.extend(ports)

        except subprocess.TimeoutExpired:
            result.errors.append("nmap扫描超时")
            log.warning("nmap扫描超时")
        except Exception as e:
            result.errors.append(f"nmap扫描出错: {str(e)}")
            log.error(f"nmap扫描出错: {e}")

    def _parse_nmap_xml(self, xml_path: str) -> List[PortInfo]:
        """解析nmap XML输出"""
        ports = []
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            for host in root.findall(".//host"):
                for port in host.findall(".//port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        service = port.find("service")
                        port_info = PortInfo(
                            port=int(port.get("portid", 0)),
                            protocol=port.get("protocol", "tcp"),
                            state="open",
                            service=service.get("name", "") if service is not None else "",
                            version=service.get("version", "") if service is not None else ""
                        )
                        ports.append(port_info)
        except Exception as e:
            log.error(f"解析nmap XML失败: {e}")
        return ports

    def _parse_nmap_output(self, output: str) -> List[PortInfo]:
        """从nmap文本输出解析端口"""
        ports = []
        for line in output.split("\n"):
            match = re.match(r"^(\d+)/(\w+)\s+(\w+)\s+(.+)$", line.strip())
            if match:
                port, proto, state, service = match.groups()
                if state == "open":
                    ports.append(PortInfo(
                        port=int(port), protocol=proto, state=state, service=service
                    ))
        return ports

    def _scan_vulnerabilities(self, target: str, result: AssessmentResult, scan_type: str):
        """漏洞扫描（nuclei）"""
        if not self._nuclei_path:
            result.errors.append("nuclei未安装，跳过漏洞扫描")
            return

        result.tools_used.append("nuclei")
        log.info(f"执行nuclei漏洞扫描: {target}")

        try:
            json_output = os.path.join(self.output_dir, f"nuclei_{self._safe_name(target)}.json")

            args = ["-u", f"http://{target}", "-jsonl", "-silent", "-severity", "critical,high,medium,low"]
            if scan_type == "quick":
                args.extend(["-t", "cves/"])
            elif scan_type == "deep":
                args.extend(["-as"])  # 自动扫描

            with open(json_output, "w", encoding="utf-8") as f:
                process = subprocess.run(
                    [self._nuclei_path] + args,
                    stdout=f, stderr=subprocess.PIPE, text=True, timeout=300
                )

            # 解析JSONL结果
            if os.path.exists(json_output):
                vulns = self._parse_nuclei_output(json_output)
                result.vulnerabilities.extend(vulns)
                log.info(f"nuclei发现 {len(vulns)} 个漏洞")

        except subprocess.TimeoutExpired:
            result.errors.append("nuclei扫描超时")
        except Exception as e:
            result.errors.append(f"nuclei扫描出错: {str(e)}")
            log.error(f"nuclei扫描出错: {e}")

    def _parse_nuclei_output(self, jsonl_path: str) -> List[VulnInfo]:
        """解析nuclei JSONL输出"""
        vulns = []
        try:
            with open(jsonl_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        vuln = VulnInfo(
                            name=data.get("info", {}).get("name", data.get("template-id", "未知")),
                            severity=data.get("info", {}).get("severity", "info"),
                            description=data.get("info", {}).get("description", ""),
                            target=data.get("matched-at", ""),
                            evidence=str(data.get("extracted-results", ""))[:200],
                            reference=", ".join(data.get("info", {}).get("reference", []))
                        )
                        vulns.append(vuln)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            log.error(f"解析nuclei输出失败: {e}")
        return vulns

    def _has_web_service(self, result: AssessmentResult) -> bool:
        """检查是否有Web服务"""
        web_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000}
        for port in result.ports:
            if port.port in web_ports or "http" in port.service.lower():
                return True
        # 如果没有端口信息，也尝试Web检测
        return len(result.ports) == 0

    def _web_security_check(self, target: str, result: AssessmentResult):
        """Web安全基础检测"""
        result.tools_used.append("web_check")
        log.info(f"执行Web安全检测: {target}")

        try:
            import urllib.request
            import ssl

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            base_url = f"http://{target}"

            # 检测常见敏感路径
            for path in self.COMMON_WEB_PATHS[:15]:  # 限制数量避免太慢
                try:
                    url = base_url + path
                    req = urllib.request.Request(url, method="HEAD")
                    resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                    if resp.status == 200:
                        finding = {
                            "url": url,
                            "status_code": resp.status,
                            "type": "敏感路径发现",
                            "severity": "medium" if any(k in path for k in [".git", ".env", "admin", "phpmyadmin"]) else "low",
                            "description": f"发现可访问的敏感路径: {path}"
                        }
                        result.web_findings.append(finding)
                except Exception:
                    continue

            # 检查HTTP安全头
            try:
                req = urllib.request.Request(base_url, method="HEAD")
                resp = urllib.request.urlopen(req, timeout=10, context=ctx)
                headers = dict(resp.headers)
                security_headers = ["X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection",
                                    "Content-Security-Policy", "Strict-Transport-Security", "Referrer-Policy"]
                missing = [h for h in security_headers if h not in headers]
                if missing:
                    result.web_findings.append({
                        "url": base_url,
                        "type": "安全头缺失",
                        "severity": "low",
                        "description": f"缺少以下安全响应头: {', '.join(missing)}"
                    })
            except Exception:
                pass

            log.info(f"Web检测发现 {len(result.web_findings)} 个问题")

        except Exception as e:
            result.errors.append(f"Web检测出错: {str(e)}")

    def _calculate_risk(self, result: AssessmentResult):
        """计算风险评分和等级"""
        score = 0

        # 漏洞权重
        severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
        for vuln in result.vulnerabilities:
            score += severity_weights.get(vuln.severity.lower(), 1)

        # Web发现权重
        for finding in result.web_findings:
            sev = finding.get("severity", "low")
            score += {"critical": 20, "high": 12, "medium": 6, "low": 2}.get(sev, 1)

        # 端口数量（开放端口越多风险越大）
        if len(result.ports) > 20:
            score += 10
        elif len(result.ports) > 10:
            score += 5
        elif len(result.ports) > 5:
            score += 2

        # 限制在0-100
        result.risk_score = min(score, 100)

        # 风险等级
        if result.risk_score >= 75:
            result.risk_level = "严重"
        elif result.risk_score >= 50:
            result.risk_level = "高危"
        elif result.risk_score >= 25:
            result.risk_level = "中危"
        elif result.risk_score >= 10:
            result.risk_level = "低危"
        else:
            result.risk_level = "安全"

    def _generate_recommendations(self, result: AssessmentResult):
        """生成修复建议"""
        recs = []

        # 按漏洞类型生成建议
        high_vulns = [v for v in result.vulnerabilities if v.severity in ("critical", "high")]
        if high_vulns:
            recs.append(f"⚠️ 存在 {len(high_vulns)} 个高危/严重漏洞，建议立即修复并排查是否已被利用")

        # 敏感路径
        sensitive = [f for f in result.web_findings if "敏感路径" in f.get("type", "")]
        if sensitive:
            recs.append("🔒 发现可访问的敏感路径，建议限制访问权限或删除不必要的文件")

        # 安全头
        headers = [f for f in result.web_findings if "安全头" in f.get("type", "")]
        if headers:
            recs.append("📋 建议配置HTTP安全响应头（CSP/HSTS/X-Frame-Options等）")

        # 端口
        if len(result.ports) > 10:
            recs.append("🚪 开放端口较多，建议关闭不必要的服务，最小化攻击面")

        # 通用建议
        recs.append("🔄 建议定期进行安全扫描，建立持续安全监测机制")
        recs.append("📚 建议对开发人员进行安全编码培训，从源头减少漏洞")

        result.recommendations = recs

    def _generate_report(self, result: AssessmentResult) -> str:
        """生成HTML评估报告"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"report_{self._safe_name(result.target)}_{timestamp}.html"
        report_path = os.path.join(self.output_dir, report_filename)

        # 风险等级颜色
        risk_colors = {
            "严重": "#dc3545", "高危": "#fd7e14", "中危": "#ffc107",
            "低危": "#20c997", "安全": "#28a745", "未知": "#6c757d"
        }
        risk_color = risk_colors.get(result.risk_level, "#6c757d")

        # 漏洞统计
        vuln_stats = {}
        for v in result.vulnerabilities:
            vuln_stats[v.severity] = vuln_stats.get(v.severity, 0) + 1

        # 生成HTML
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全评估报告 - {result.target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #333; line-height: 1.6; }}
        .container {{ max-width: 1100px; margin: 0 auto; padding: 30px 20px; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 40px; border-radius: 12px; margin-bottom: 30px; }}
        .header h1 {{ font-size: 28px; margin-bottom: 10px; }}
        .header .meta {{ opacity: 0.8; font-size: 14px; }}
        .risk-banner {{ background: {risk_color}; color: white; padding: 25px 40px; border-radius: 12px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }}
        .risk-banner .score {{ font-size: 48px; font-weight: bold; }}
        .risk-banner .level {{ font-size: 24px; }}
        .card {{ background: white; border-radius: 12px; padding: 25px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
        .card h2 {{ font-size: 20px; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #e9ecef; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; }}
        .stat-item {{ text-align: center; padding: 20px; background: #f8f9fa; border-radius: 8px; }}
        .stat-item .num {{ font-size: 32px; font-weight: bold; color: #1a1a2e; }}
        .stat-item .label {{ font-size: 13px; color: #666; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e9ecef; }}
        th {{ background: #f8f9fa; font-weight: 600; font-size: 13px; color: #555; }}
        .severity {{ padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; }}
        .sev-critical {{ background: #f8d7da; color: #721c24; }}
        .sev-high {{ background: #ffe5d0; color: #8a4500; }}
        .sev-medium {{ background: #fff3cd; color: #856404; }}
        .sev-low {{ background: #d4edda; color: #155724; }}
        .sev-info {{ background: #d1ecf1; color: #0c5460; }}
        .rec-list {{ list-style: none; }}
        .rec-list li {{ padding: 10px 0; border-bottom: 1px solid #f0f0f0; }}
        .rec-list li:last-child {{ border-bottom: none; }}
        .footer {{ text-align: center; padding: 30px; color: #999; font-size: 13px; }}
        .error-box {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin-bottom: 15px; border-radius: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 安全评估报告</h1>
            <div class="meta">
                目标: <strong>{result.target}</strong> |
                开始时间: {result.start_time} |
                结束时间: {result.end_time} |
                耗时: {result.duration}秒
            </div>
        </div>

        <div class="risk-banner">
            <div>
                <div class="level">风险等级: {result.risk_level}</div>
                <div style="margin-top:5px;opacity:0.9;">{result.summary}</div>
            </div>
            <div class="score">{result.risk_score}<span style="font-size:18px;">/100</span></div>
        </div>

        {"".join(f'<div class="error-box">⚠️ {err}</div>' for err in result.errors) if result.errors else ""}

        <div class="card">
            <h2>📊 评估概览</h2>
            <div class="stats-grid">
                <div class="stat-item"><div class="num">{len(result.ports)}</div><div class="label">开放端口</div></div>
                <div class="stat-item"><div class="num">{len(result.vulnerabilities)}</div><div class="label">发现漏洞</div></div>
                <div class="stat-item"><div class="num">{len(result.web_findings)}</div><div class="label">Web问题</div></div>
                <div class="stat-item"><div class="num">{len(result.tools_used)}</div><div class="label">使用工具</div></div>
            </div>
            {"".join(f'<div class="stats-grid" style="margin-top:15px;"><div class="stat-item"><div class="num" style="color:#dc3545;">{vuln_stats.get(k,0)}</div><div class="label">{k}</div></div></div>' if False else '')}
        </div>

        <div class="card">
            <h2>🔌 开放端口列表</h2>
            {"".join(f'''
            <table>
                <thead><tr><th>端口</th><th>协议</th><th>状态</th><th>服务</th><th>版本</th></tr></thead>
                <tbody>
                    {"".join(f"<tr><td>{p.port}</td><td>{p.protocol}</td><td>{p.state}</td><td>{p.service}</td><td>{p.version}</td></tr>" for p in result.ports)}
                </tbody>
            </table>
            ''' if result.ports else '<p style="color:#999;">未发现开放端口（或nmap未安装/扫描超时）</p>')}
        </div>

        <div class="card">
            <h2>🐛 漏洞列表</h2>
            {"".join(f'''
            <table>
                <thead><tr><th>漏洞名称</th><th>严重程度</th><th>目标</th><th>描述</th></tr></thead>
                <tbody>
                    {"".join(f'''<tr>
                        <td>{v.name}</td>
                        <td><span class="severity sev-{v.severity}">{v.severity}</span></td>
                        <td style="font-size:12px;word-break:break-all;">{v.target}</td>
                        <td style="font-size:13px;">{v.description[:100]}</td>
                    </tr>''' for v in result.vulnerabilities)}
                </tbody>
            </table>
            ''' if result.vulnerabilities else '<p style="color:#28a745;">✅ 未发现已知漏洞</p>')}
        </div>

        <div class="card">
            <h2>🌐 Web安全检测</h2>
            {"".join(f'''
            <table>
                <thead><tr><th>类型</th><th>严重程度</th><th>URL</th><th>描述</th></tr></thead>
                <tbody>
                    {"".join(f'''<tr>
                        <td>{f.get("type","")}</td>
                        <td><span class="severity sev-{f.get("severity","info")}">{f.get("severity","info")}</span></td>
                        <td style="font-size:12px;word-break:break-all;">{f.get("url","")}</td>
                        <td style="font-size:13px;">{f.get("description","")}</td>
                    </tr>''' for f in result.web_findings)}
                </tbody>
            </table>
            ''' if result.web_findings else '<p style="color:#999;">未进行Web检测或未发现问题</p>')}
        </div>

        <div class="card">
            <h2>💡 修复建议</h2>
            <ul class="rec-list">
                {"".join(f"<li>{r}</li>" for r in result.recommendations)}
            </ul>
        </div>

        <div class="card">
            <h2>🔧 使用工具</h2>
            <p>{", ".join(result.tools_used) if result.tools_used else "无"}</p>
        </div>

        <div class="footer">
            <p>本报告由 AI Hacking Agent 自动生成 | 仅供授权安全测试使用</p>
            <p>生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>
</body>
</html>"""

        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(html)
            log.info(f"报告已生成: {report_path}")
        except Exception as e:
            log.error(f"生成报告失败: {e}")
            report_path = ""

        return report_path

    def _save_json_result(self, result: AssessmentResult):
        """保存JSON格式结果"""
        try:
            json_path = os.path.join(self.output_dir, f"result_{self._safe_name(result.target)}.json")
            data = {
                "target": result.target,
                "start_time": result.start_time,
                "end_time": result.end_time,
                "duration": result.duration,
                "status": result.status,
                "risk_score": result.risk_score,
                "risk_level": result.risk_level,
                "summary": result.summary,
                "ports": [{"port": p.port, "service": p.service, "version": p.version} for p in result.ports],
                "vulnerabilities": [{"name": v.name, "severity": v.severity, "target": v.target} for v in result.vulnerabilities],
                "web_findings": result.web_findings,
                "recommendations": result.recommendations,
                "tools_used": result.tools_used,
                "errors": result.errors,
                "report_path": result.report_path
            }
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            log.error(f"保存JSON结果失败: {e}")

    @staticmethod
    def _safe_name(name: str) -> str:
        """生成安全的文件名"""
        return re.sub(r'[^\w\-\.]', '_', name)[:50]


# 全局引擎实例
assessment_engine = QuickAssessmentEngine()
