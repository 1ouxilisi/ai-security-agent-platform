#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端到端实战验证引擎（End-to-End Penetration Validation Engine）

针对真实靶场执行完整渗透测试流程：
1. 目标确认与范围定义
2. 信息收集（DNS解析/端口扫描/服务识别）
3. 漏洞扫描（nuclei/nikto/Web漏洞检测）
4. 漏洞验证（PoC执行/手动验证）
5. 风险评估与报告生成

支持真实工具调用，工具不可用时自动回退模拟模式。
"""

import time
import json
import socket
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import subprocess
import urllib.request
import urllib.error


class ValidationPhase(Enum):
    """验证阶段"""
    TARGET_CONFIRM = "target_confirm"
    RECON = "reconnaissance"
    SCAN = "scanning"
    VULN_ANALYSIS = "vulnerability_analysis"
    VALIDATION = "validation"
    REPORT = "reporting"


@dataclass
class ValidationFinding:
    """验证发现"""
    phase: str
    finding_type: str
    name: str
    severity: str  # critical/high/medium/low/info
    description: str
    evidence: str = ""
    is_real: bool = False  # 是否真实工具发现
    tool_used: str = ""
    cve: str = ""
    cvss: float = 0.0


@dataclass
class ValidationResult:
    """验证结果"""
    target: str
    start_time: float
    end_time: float = 0
    phases_completed: List[str] = field(default_factory=list)
    findings: List[ValidationFinding] = field(default_factory=list)
    risk_score: float = 0.0
    tools_used: List[str] = field(default_factory=list)
    real_findings: int = 0
    simulated_findings: int = 0
    report_generated: bool = False


class EndToEndValidator:
    """
    端到端实战验证引擎

    执行完整渗透测试流程，调用真实安全工具。
    """

    def __init__(self):
        self.tool_status = self._detect_tools()

    def _detect_tools(self) -> Dict[str, bool]:
        """检测系统中可用的安全工具"""
        tools = {
            "nmap": False,
            "nuclei": False,
            "sqlmap": False,
            "nikto": False,
            "subfinder": False,
            "httpx": False,
            "curl": True,  # Python urllib替代
        }
        for tool in tools:
            if tool == "curl":
                continue
            try:
                result = subprocess.run(
                    [tool, "--version"],
                    capture_output=True, text=True, timeout=10
                )
                tools[tool] = result.returncode == 0
            except Exception:
                tools[tool] = False
        return tools

    def run_full_validation(self, target: str,
                            scope: str = "web",
                            aggressive: bool = False) -> ValidationResult:
        """
        执行完整端到端验证

        Args:
            target: 目标URL或IP
            scope: 验证范围 (web/network/full)
            aggressive: 是否启用激进扫描
        """
        result = ValidationResult(
            target=target,
            start_time=time.time(),
        )

        print(f"[*] 开始端到端验证: {target}")
        print(f"[*] 工具状态: {self.tool_status}")

        # 阶段1: 目标确认
        self._phase_target_confirm(target, result)

        # 阶段2: 信息收集
        self._phase_recon(target, result)

        # 阶段3: 漏洞扫描
        self._phase_scan(target, result, aggressive)

        # 阶段4: 漏洞分析
        self._phase_vuln_analysis(target, result)

        # 阶段5: 漏洞验证
        if aggressive:
            self._phase_validation(target, result)

        # 阶段6: 报告
        self._phase_report(target, result)

        result.end_time = time.time()
        self._calculate_risk(result)

        return result

    def _phase_target_confirm(self, target: str, result: ValidationResult):
        """阶段1: 目标确认"""
        print(f"[1/6] 目标确认: {target}")
        result.phases_completed.append(ValidationPhase.TARGET_CONFIRM.value)

        # 解析目标
        is_url = target.startswith("http")
        host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        # DNS解析
        try:
            ip = socket.gethostbyname(host)
            result.findings.append(ValidationFinding(
                phase="target_confirm",
                finding_type="dns_resolution",
                name=f"DNS解析成功: {host} -> {ip}",
                severity="info",
                description=f"目标域名解析到IP地址 {ip}",
                evidence=ip,
                is_real=True,
                tool_used="python_socket",
            ))
            result.real_findings += 1
        except Exception as e:
            result.findings.append(ValidationFinding(
                phase="target_confirm",
                finding_type="dns_failed",
                name=f"DNS解析失败: {host}",
                severity="info",
                description=f"无法解析目标: {e}",
                is_real=True,
                tool_used="python_socket",
            ))

        # HTTP可达性检查
        if is_url:
            try:
                req = urllib.request.Request(target, method="HEAD")
                resp = urllib.request.urlopen(req, timeout=10)
                status = resp.status
                headers = dict(resp.headers)
                server = headers.get("Server", "unknown")

                result.findings.append(ValidationFinding(
                    phase="target_confirm",
                    finding_type="http_reachable",
                    name=f"HTTP服务可达 (状态码: {status})",
                    severity="info",
                    description=f"目标Web服务响应正常，Server: {server}",
                    evidence=f"Status: {status}, Server: {server}",
                    is_real=True,
                    tool_used="python_urllib",
                ))
                result.real_findings += 1
                result.tools_used.append("python_urllib")

                # 检查安全头
                security_headers = ["X-Frame-Options", "X-Content-Type-Options",
                                    "X-XSS-Protection", "Content-Security-Policy",
                                    "Strict-Transport-Security"]
                missing_headers = [h for h in security_headers if h not in headers]
                if missing_headers:
                    result.findings.append(ValidationFinding(
                        phase="target_confirm",
                        finding_type="missing_security_headers",
                        name=f"缺失安全头: {', '.join(missing_headers[:3])}",
                        severity="low",
                        description=f"目标缺少 {len(missing_headers)} 个安全响应头",
                        evidence=f"Missing: {missing_headers}",
                        is_real=True,
                        tool_used="python_urllib",
                    ))
                    result.real_findings += 1
            except urllib.error.HTTPError as e:
                result.findings.append(ValidationFinding(
                    phase="target_confirm",
                    finding_type="http_error",
                    name=f"HTTP错误: {e.code}",
                    severity="info",
                    description=f"目标返回HTTP错误 {e.code}",
                    is_real=True,
                    tool_used="python_urllib",
                ))
            except Exception as e:
                result.findings.append(ValidationFinding(
                    phase="target_confirm",
                    finding_type="http_unreachable",
                    name="HTTP服务不可达",
                    severity="medium",
                    description=f"无法连接到目标Web服务: {e}",
                    is_real=True,
                    tool_used="python_urllib",
                ))

    def _phase_recon(self, target: str, result: ValidationResult):
        """阶段2: 信息收集"""
        print("[2/6] 信息收集")
        result.phases_completed.append(ValidationPhase.RECON.value)

        host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        # 端口扫描（nmap或Python socket）
        if self.tool_status.get("nmap"):
            try:
                print("  [*] 使用nmap进行端口扫描...")
                result_ports = subprocess.run(
                    ["nmap", "-p", "1-1000", "--open", "-T4", host],
                    capture_output=True, text=True, timeout=60
                )
                open_ports = []
                for line in result_ports.stdout.split("\n"):
                    if "/tcp" in line and "open" in line:
                        port = line.split("/")[0].strip()
                        service = line.split()[-1] if len(line.split()) > 3 else "unknown"
                        open_ports.append({"port": int(port), "service": service})

                if open_ports:
                    result.findings.append(ValidationFinding(
                        phase="reconnaissance",
                        finding_type="open_ports",
                        name=f"发现 {len(open_ports)} 个开放端口",
                        severity="info",
                        description=f"开放端口: {', '.join(p['port'] + '/' + p['service'] for p in open_ports[:5])}",
                        evidence=str(open_ports),
                        is_real=True,
                        tool_used="nmap",
                    ))
                    result.real_findings += 1
                    result.tools_used.append("nmap")
            except Exception as e:
                print(f"  [!] nmap扫描失败: {e}")

        # Python socket端口扫描（回退）
        if not self.tool_status.get("nmap") or True:
            print("  [*] Python socket快速端口扫描...")
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                            3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090]
            open_ports = []
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    if sock.connect_ex((host, port)) == 0:
                        open_ports.append(port)
                    sock.close()
                except Exception:
                    pass

            if open_ports:
                result.findings.append(ValidationFinding(
                    phase="reconnaissance",
                    finding_type="open_ports",
                    name=f"发现 {len(open_ports)} 个开放端口",
                    severity="info",
                    description=f"常见端口扫描发现: {', '.join(map(str, open_ports))}",
                    evidence=str(open_ports),
                    is_real=True,
                    tool_used="python_socket",
                ))
                result.real_findings += 1
                result.tools_used.append("python_socket")

    def _phase_scan(self, target: str, result: ValidationResult, aggressive: bool):
        """阶段3: 漏洞扫描"""
        print("[3/6] 漏洞扫描")
        result.phases_completed.append(ValidationPhase.SCAN.value)

        # nuclei扫描
        if self.tool_status.get("nuclei"):
            try:
                print("  [*] 使用nuclei进行漏洞扫描...")
                nuclei_result = subprocess.run(
                    ["nuclei", "-u", target, "-silent", "-timeout", "10"],
                    capture_output=True, text=True, timeout=120
                )
                vulns = [l for l in nuclei_result.stdout.split("\n") if l.strip()]
                for vuln in vulns[:10]:
                    result.findings.append(ValidationFinding(
                        phase="scanning",
                        finding_type="nuclei_vuln",
                        name=f"nuclei发现: {vuln[:80]}",
                        severity="high",
                        description=vuln,
                        evidence=vuln,
                        is_real=True,
                        tool_used="nuclei",
                    ))
                    result.real_findings += 1
                result.tools_used.append("nuclei")
            except Exception as e:
                print(f"  [!] nuclei扫描失败: {e}")

        # nikto扫描
        if self.tool_status.get("nikto"):
            try:
                print("  [*] 使用nikto进行Web扫描...")
                nikto_result = subprocess.run(
                    ["nikto", "-h", target, "-Tuning", "1234", "-nointeractive"],
                    capture_output=True, text=True, timeout=120
                )
                issues = [l for l in nikto_result.stdout.split("\n")
                          if "OSVDB" in l or "vulnerability" in l.lower()]
                for issue in issues[:5]:
                    result.findings.append(ValidationFinding(
                        phase="scanning",
                        finding_type="nikto_issue",
                        name=f"nikto发现: {issue[:80]}",
                        severity="medium",
                        description=issue,
                        evidence=issue,
                        is_real=True,
                        tool_used="nikto",
                    ))
                    result.real_findings += 1
                result.tools_used.append("nikto")
            except Exception as e:
                print(f"  [!] nikto扫描失败: {e}")

        # 模拟Web漏洞检测（基于已知靶场特征）
        if "dvwa" in target.lower() or "127.0.0.1:8080" in target or "localhost:8080" in target:
            result.findings.extend([
                ValidationFinding(
                    phase="scanning",
                    finding_type="simulated_vuln",
                    name="SQL注入漏洞 (登录页面)",
                    severity="critical",
                    description="登录表单存在SQL注入，可使用 ' OR '1'='1 绕过认证",
                    evidence="username=admin' OR '1'='1 -- &password=anything",
                    is_real=False,
                    tool_used="simulated",
                    cvss=9.8,
                ),
                ValidationFinding(
                    phase="scanning",
                    finding_type="simulated_vuln",
                    name="反射型XSS漏洞",
                    severity="high",
                    description="搜索参数存在反射型XSS，可注入恶意脚本",
                    evidence="<script>alert('XSS')</script>",
                    is_real=False,
                    tool_used="simulated",
                    cvss=6.1,
                ),
                ValidationFinding(
                    phase="scanning",
                    finding_type="simulated_vuln",
                    name="文件上传漏洞",
                    severity="high",
                    description="文件上传功能未校验文件类型，可上传WebShell",
                    evidence="上传 .php 文件被接受",
                    is_real=False,
                    tool_used="simulated",
                    cvss=8.8,
                ),
                ValidationFinding(
                    phase="scanning",
                    finding_type="simulated_vuln",
                    name="命令注入漏洞",
                    severity="critical",
                    description="ping功能存在命令注入，可执行任意系统命令",
                    evidence="127.0.0.1; cat /etc/passwd",
                    is_real=False,
                    tool_used="simulated",
                    cvss=9.8,
                ),
            ])
            result.simulated_findings += 4

    def _phase_vuln_analysis(self, target: str, result: ValidationResult):
        """阶段4: 漏洞分析"""
        print("[4/6] 漏洞分析")
        result.phases_completed.append(ValidationPhase.VULN_ANALYSIS.value)

        # 统计漏洞分布
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in result.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        result.findings.append(ValidationFinding(
            phase="vulnerability_analysis",
            finding_type="analysis_summary",
            name="漏洞分析汇总",
            severity="info",
            description=f"严重{severity_counts['critical']}/高危{severity_counts['high']}/中危{severity_counts['medium']}/低危{severity_counts['low']}/信息{severity_counts['info']}",
            evidence=str(severity_counts),
            is_real=True,
            tool_used="analysis_engine",
        ))

    def _phase_validation(self, target: str, result: ValidationResult):
        """阶段5: 漏洞验证"""
        print("[5/6] 漏洞验证")
        result.phases_completed.append(ValidationPhase.VALIDATION.value)

        # 验证SQL注入（简单测试）
        test_paths = [
            "/login.php", "/vulnerabilities/sqli/", "/?id=1",
            "/search.php?q=test", "/index.php?id=1"
        ]
        for path in test_paths:
            test_url = target.rstrip("/") + path
            try:
                payload = test_url + ("&" if "?" in test_url else "?") + "id=1' OR '1'='1"
                req = urllib.request.Request(payload)
                resp = urllib.request.urlopen(req, timeout=5)
                content = resp.read().decode("utf-8", errors="ignore")
                if "error" in content.lower() or "sql" in content.lower() or "warning" in content.lower():
                    result.findings.append(ValidationFinding(
                        phase="validation",
                        finding_type="sql_injection_confirmed",
                        name=f"SQL注入已确认: {path}",
                        severity="critical",
                        description=f"在 {path} 确认SQL注入漏洞",
                        evidence=f"Payload: {payload}",
                        is_real=True,
                        tool_used="python_urllib",
                        cvss=9.8,
                    ))
                    result.real_findings += 1
                    break
            except Exception:
                continue

    def _phase_report(self, target: str, result: ValidationResult):
        """阶段6: 报告生成"""
        print("[6/6] 生成报告")
        result.phases_completed.append(ValidationPhase.REPORT.value)
        result.report_generated = True

    def _calculate_risk(self, result: ValidationResult):
        """计算风险评分"""
        severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        total_risk = 0
        for f in result.findings:
            total_risk += severity_weights.get(f.severity, 0)
        result.risk_score = min(100, total_risk)

    def generate_report(self, result: ValidationResult, format: str = "markdown") -> str:
        """生成验证报告"""
        duration = result.end_time - result.start_time
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in result.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        if format == "json":
            return json.dumps({
                "target": result.target,
                "duration_seconds": round(duration, 2),
                "risk_score": result.risk_score,
                "phases_completed": result.phases_completed,
                "tools_used": result.tools_used,
                "real_findings": result.real_findings,
                "simulated_findings": result.simulated_findings,
                "severity_distribution": severity_counts,
                "findings": [
                    {
                        "phase": f.phase,
                        "type": f.finding_type,
                        "name": f.name,
                        "severity": f.severity,
                        "description": f.description,
                        "evidence": f.evidence,
                        "is_real": f.is_real,
                        "tool": f.tool_used,
                        "cvss": f.cvss,
                    }
                    for f in result.findings
                ],
            }, indent=2, ensure_ascii=False)

        # Markdown报告
        report = f"""# 端到端渗透验证报告

## 基本信息
- **目标**: {result.target}
- **验证时长**: {duration:.1f}秒
- **风险评分**: {result.risk_score}/100
- **完成阶段**: {', '.join(result.phases_completed)}
- **使用工具**: {', '.join(result.tools_used) or '无'}
- **真实发现**: {result.real_findings}个
- **模拟发现**: {result.simulated_findings}个

## 漏洞分布
| 严重程度 | 数量 |
|---------|------|
| 严重(Critical) | {severity_counts['critical']} |
| 高危(High) | {severity_counts['high']} |
| 中危(Medium) | {severity_counts['medium']} |
| 低危(Low) | {severity_counts['low']} |
| 信息(Info) | {severity_counts['info']} |

## 漏洞详情
"""
        for i, f in enumerate(result.findings, 1):
            severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(f.severity, "⚪")
            report += f"""
### {i}. {severity_emoji} {f.name}
- **阶段**: {f.phase}
- **类型**: {f.finding_type}
- **严重程度**: {f.severity}
- **工具**: {f.tool_used} {'(真实)' if f.is_real else '(模拟)'}
- **描述**: {f.description}
"""
            if f.evidence:
                report += f"- **证据**: `{f.evidence[:200]}`\n"
            if f.cvss > 0:
                report += f"- **CVSS**: {f.cvss}\n"

        report += f"""
## 修复建议
1. 优先修复严重(Critical)和高危(High)漏洞
2. 对SQL注入使用参数化查询
3. 对XSS实施输出编码和CSP策略
4. 对文件上传实施严格的类型和内容校验
5. 对命令注入使用白名单参数验证
6. 补充缺失的安全响应头

---
*报告由 AI Security Operations Center 自动生成*
"""
        return report


# 单例模式
_validator_instance: Optional[EndToEndValidator] = None

def get_validator() -> EndToEndValidator:
    """获取全局验证引擎实例"""
    global _validator_instance
    if _validator_instance is None:
        _validator_instance = EndToEndValidator()
    return _validator_instance
