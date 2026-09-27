"""
result_analyzer智能体模块，提供相关AI驱动的安全分析和决策功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import re
import json
import time
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from utils.logger import log


@dataclass
class VulnerabilityFinding:
    """漏洞发现"""
    id: str = ""
    type: str = ""  # sqli / xss / ssrf / idor / command_injection / file_upload / xxe / info_disclosure / ...
    severity: str = "low"  # critical / high / medium / low / info
    title: str = ""
    description: str = ""
    target: str = ""
    tool: str = ""
    evidence: str = ""
    confidence: float = 0.0  # 0.0 - 1.0
    false_positive_risk: float = 0.0  # 误报风险 0.0 - 1.0
    related_vulnerabilities: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    cve_references: List[str] = field(default_factory=list)
    discovered_at: float = field(default_factory=time.time)
    status: str = "new"  # new / confirmed / false_positive / remediated

    def to_dict(self) -> Dict:
        """执行相关操作。

            Returns:
            操作结果。
        """
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "target": self.target,
            "tool": self.tool,
            "evidence": self.evidence[:500] if self.evidence else "",
            "confidence": self.confidence,
            "false_positive_risk": self.false_positive_risk,
            "related_vulnerabilities": self.related_vulnerabilities,
            "recommendations": self.recommendations,
            "cve_references": self.cve_references,
            "discovered_at": self.discovered_at,
            "status": self.status,
        }


class ResultAnalyzer:
    """智能结果分析器"""

    # 漏洞类型识别规则
    VULNERABILITY_PATTERNS = {
        "sqli": {
            "keywords": ["sql", "syntax", "mysql", "oracle", "postgresql", "sqlite", "sqlstate", "unclosed quotation"],
            "error_patterns": [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"ORA-\d+",
                r"PostgreSQL.*ERROR",
                r"SQLite/JDBCDriver",
                r"Microsoft SQL Server.*Driver",
                r"unclosed quotation mark",
            ],
            "default_severity": "high",
        },
        "xss": {
            "keywords": ["<script>", "alert(", "onerror", "onload", "javascript:", "xss"],
            "error_patterns": [
                r"<script[^>]*>.*?</script>",
                r"onerror\s*=",
                r"onload\s*=",
                r"javascript\s*:",
            ],
            "default_severity": "medium",
        },
        "ssrf": {
            "keywords": ["ssrf", "127.0.0.1", "localhost", "169.254.169.254", "file://", "gopher://", "dict://"],
            "error_patterns": [
                r"root:x:0:0",
                r"ami-id",
                r"computeMetadata",
                r"redis_version",
            ],
            "default_severity": "high",
        },
        "command_injection": {
            "keywords": ["command", "injection", "uid=", "gid=", "root:", "/bin/bash", "/bin/sh"],
            "error_patterns": [
                r"uid=\d+\([^)]+\)",
                r"Linux\s+\S+\s+\d+\.\d+\.\d+",
                r"root:x:0:0:root",
            ],
            "default_severity": "critical",
        },
        "file_upload": {
            "keywords": ["upload", "file", ".php", ".asp", ".jsp", "webshell"],
            "error_patterns": [
                r"upload.*success",
                r"file.*uploaded",
            ],
            "default_severity": "high",
        },
        "info_disclosure": {
            "keywords": ["phpinfo", "git", ".env", "config", "backup", "sql", "dump", "password", "secret", "api_key", "token"],
            "error_patterns": [
                r"phpinfo\(\)",
                r"DB_PASSWORD",
                r"API_KEY",
                r"SECRET_KEY",
                r"-----BEGIN",
            ],
            "default_severity": "medium",
        },
    }

    # 误报特征
    FALSE_POSITIVE_INDICATORS = [
        "waf", "firewall", "blocked", "forbidden", "403", "404",
        "not found", "no such", "invalid", "error", "exception",
        "rate limit", "too many requests",
    ]

    def __init__(self):
        """初始化ResultAnalyzer实例。

            Args:
            self: 类实例。
        """
        self.findings: List[VulnerabilityFinding] = []
        log.info("智能结果分析器初始化")

    def analyze_result(self, tool_name: str, target: str, result: Any) -> List[VulnerabilityFinding]:
        """
            分析工具执行结果，提取漏洞
            返回: 发现的漏洞列表
        """
        log.debug(f"分析工具结果: {tool_name}, 目标: {target}")

        findings = []

        # 将结果转为文本
        result_text = self._result_to_text(result)

        # 1. 基于规则的漏洞识别
        rule_findings = self._rule_based_detection(tool_name, target, result_text)
        findings.extend(rule_findings)

        # 2. 基于工具特定结果的分析
        tool_findings = self._tool_specific_analysis(tool_name, target, result)
        findings.extend(tool_findings)

        # 3. 置信度评估
        for finding in findings:
            self._evaluate_confidence(finding, result_text)

        # 4. 误报过滤
        findings = [f for f in findings if f.false_positive_risk < 0.7]

        # 5. 生成修复建议
        for finding in findings:
            finding.recommendations = self._generate_recommendations(finding)

        # 6. 关联CVE
        for finding in findings:
            finding.cve_references = self._link_cves(finding)

        # 添加到全局发现列表
        self.findings.extend(findings)

        log.info(f"分析完成，发现 {len(findings)} 个潜在漏洞 (工具: {tool_name})")
        return findings

    def _result_to_text(self, result: Any) -> str:
        """将结果转为文本"""
        if isinstance(result, str):
            return result
        if isinstance(result, dict):
            return json.dumps(result, ensure_ascii=False, indent=2)
        return str(result)

    def _rule_based_detection(self, tool_name: str, target: str, result_text: str) -> List[VulnerabilityFinding]:
        """基于规则的漏洞识别"""
        findings = []
        result_lower = result_text.lower()

        for vuln_type, patterns in self.VULNERABILITY_PATTERNS.items():
            # 检查关键词
            keyword_matches = [kw for kw in patterns["keywords"] if kw.lower() in result_lower]

            # 检查错误模式
            error_matches = []
            for pattern in patterns["error_patterns"]:
                if re.search(pattern, result_text, re.IGNORECASE):
                    error_matches.append(pattern)

            if keyword_matches or error_matches:
                finding = VulnerabilityFinding(
                    id=f"vuln_{int(time.time() * 1000)}_{len(self.findings) + len(findings)}",
                    type=vuln_type,
                    severity=patterns["default_severity"],
                    title=f"潜在{vuln_type.upper()}漏洞",
                    description=f"在目标 {target} 的响应中检测到 {vuln_type} 相关特征",
                    target=target,
                    tool=tool_name,
                    evidence=f"关键词匹配: {keyword_matches}\n错误模式匹配: {error_matches}\n响应片段: {result_text[:300]}",
                )
                findings.append(finding)

        return findings

    def _tool_specific_analysis(self, tool_name: str, target: str, result: Any) -> List[VulnerabilityFinding]:
        """工具特定的结果分析"""
        findings = []

        if not isinstance(result, dict):
            return findings

        # SQL注入测试结果
        if tool_name == "sql_injection_test" and result.get("is_vulnerable"):
            for vuln in result.get("vulnerabilities", []):
                findings.append(VulnerabilityFinding(
                    id=f"sqli_{int(time.time() * 1000)}_{len(findings)}",
                    type="sqli",
                    severity=vuln.get("confidence", "high").lower(),
                    title=f"SQL注入漏洞 - 参数: {result.get('param')}",
                    description=f"目标URL存在SQL注入漏洞，测试Payload: {vuln.get('payload')}",
                    target=result.get("url", target),
                    tool=tool_name,
                    evidence=vuln.get("payload", ""),
                ))

        # XSS测试结果
        elif tool_name == "xss_test" and result.get("is_vulnerable"):
            for vuln in result.get("vulnerabilities", []):
                findings.append(VulnerabilityFinding(
                    id=f"xss_{int(time.time() * 1000)}_{len(findings)}",
                    type="xss",
                    severity=vuln.get("confidence", "medium").lower(),
                    title=f"XSS跨站脚本漏洞 - 参数: {result.get('param')}",
                    description=f"目标URL存在XSS漏洞，测试Payload: {vuln.get('payload')}",
                    target=result.get("url", target),
                    tool=tool_name,
                    evidence=vuln.get("payload", ""),
                ))

        # SSRF测试结果
        elif tool_name == "ssrf_test" and result.get("is_vulnerable"):
            for vuln in result.get("vulnerabilities", []):
                findings.append(VulnerabilityFinding(
                    id=f"ssrf_{int(time.time() * 1000)}_{len(findings)}",
                    type="ssrf",
                    severity=vuln.get("confidence", "high").lower(),
                    title=f"SSRF服务端请求伪造漏洞 - 参数: {result.get('param')}",
                    description=f"目标URL存在SSRF漏洞，测试Payload: {vuln.get('payload')}",
                    target=result.get("url", target),
                    tool=tool_name,
                    evidence=vuln.get("payload", ""),
                ))

        # 命令注入测试结果
        elif tool_name == "command_injection_test" and result.get("is_vulnerable"):
            for vuln in result.get("vulnerabilities", []):
                findings.append(VulnerabilityFinding(
                    id=f"cmdi_{int(time.time() * 1000)}_{len(findings)}",
                    type="command_injection",
                    severity="critical",
                    title=f"命令注入漏洞 - 参数: {result.get('param')}",
                    description=f"目标URL存在命令注入漏洞，测试Payload: {vuln.get('payload')}",
                    target=result.get("url", target),
                    tool=tool_name,
                    evidence=vuln.get("payload", ""),
                ))

        # 目录扫描结果 - 敏感文件
        elif tool_name == "directory_scan":
            sensitive_paths = ["/.env", "/.git/config", "/backup", "/db.sql", "/phpinfo.php", "/config.php"]
            for item in result.get("found_items", []):
                path = item.get("path", "")
                if any(s in path for s in sensitive_paths):
                    findings.append(VulnerabilityFinding(
                        id=f"info_{int(time.time() * 1000)}_{len(findings)}",
                        type="info_disclosure",
                        severity="high",
                        title=f"敏感文件/目录暴露: {path}",
                        description=f"发现敏感路径可访问: {path}, 状态码: {item.get('status_code')}",
                        target=result.get("url", target),
                        tool=tool_name,
                        evidence=path,
                    ))

        # 端口扫描结果 - 高危端口
        elif tool_name == "port_scan":
            high_risk_ports = {21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP", 6379: "Redis", 27017: "MongoDB"}
            for port in result.get("open_ports", []):
                if port in high_risk_ports:
                    findings.append(VulnerabilityFinding(
                        id=f"port_{int(time.time() * 1000)}_{len(findings)}",
                        type="insecure_service",
                        severity="medium",
                        title=f"高危端口开放: {port} ({high_risk_ports[port]})",
                        description=f"目标开放了高危端口 {port} ({high_risk_ports[port]})，该服务通常不应暴露在公网",
                        target=result.get("target", target),
                        tool=tool_name,
                        evidence=f"端口 {port} 开放",
                    ))

        return findings

    def _evaluate_confidence(self, finding: VulnerabilityFinding, result_text: str):
        """评估漏洞置信度"""
        score = 0.5  # 基础分

        # 有明确的错误信息 +0.2
        if any(indicator in result_text.lower() for indicator in ["error", "exception", "warning", "syntax"]):
            score += 0.2

        # 有明确的Payload反射 +0.2
        if finding.evidence and finding.evidence[:20] in result_text:
            score += 0.2

        # 工具特定验证结果 +0.1
        if finding.tool in ["sql_injection_test", "xss_test", "ssrf_test", "command_injection_test"]:
            score += 0.1

        # 误报风险评估
        fp_risk = 0.0
        result_lower = result_text.lower()
        for indicator in self.FALSE_POSITIVE_INDICATORS:
            if indicator in result_lower:
                fp_risk += 0.1

        finding.confidence = min(1.0, score)
        finding.false_positive_risk = min(1.0, fp_risk)

    def _generate_recommendations(self, finding: VulnerabilityFinding) -> List[str]:
        """生成修复建议"""
        recommendations_map = {
            "sqli": [
                "使用参数化查询/预编译语句（Prepared Statements）",
                "使用ORM框架（SQLAlchemy、Django ORM）",
                "对用户输入进行白名单校验",
                "数据库账户使用最小权限原则",
            ],
            "xss": [
                "对输出进行HTML实体编码",
                "使用Content Security Policy (CSP)",
                "设置HttpOnly Cookie标志",
                "使用现代前端框架的自动转义功能",
            ],
            "ssrf": [
                "禁用不必要的协议（file://, gopher://, dict://）",
                "限制可访问的IP范围（禁止内网IP）",
                "使用URL白名单机制",
                "禁用HTTP重定向跟随",
            ],
            "command_injection": [
                "避免直接调用系统命令",
                "使用安全的API替代系统调用",
                "对输入进行严格白名单校验",
                "以最小权限运行应用",
            ],
            "file_upload": [
                "限制允许上传的文件类型（白名单）",
                "重命名上传文件，避免路径遍历",
                "上传文件存储在Web根目录之外",
                "设置上传目录不可执行",
            ],
            "info_disclosure": [
                "移除或限制访问敏感文件",
                "配置Web服务器禁止访问敏感路径",
                "生产环境关闭调试模式",
                "敏感信息加密存储",
            ],
            "insecure_service": [
                "限制高危端口的访问来源（防火墙规则）",
                "使用VPN或跳板机访问管理服务",
                "为服务启用强认证和加密",
                "定期更新服务补丁",
            ],
        }

        return recommendations_map.get(finding.type, ["建议参考OWASP指南进行修复"])

    def _link_cves(self, finding: VulnerabilityFinding) -> List[str]:
        """关联CVE"""
        cve_map = {
            "sqli": ["CWE-89"],
            "xss": ["CWE-79"],
            "ssrf": ["CWE-918"],
            "command_injection": ["CWE-78"],
            "file_upload": ["CWE-434"],
            "info_disclosure": ["CWE-200"],
        }
        return cve_map.get(finding.type, [])

    def analyze_vulnerability_chain(self) -> List[List[VulnerabilityFinding]]:
        """
            漏洞链分析
            识别可以组合利用的漏洞链
        """
        chains = []

        # 简单的漏洞链识别：信息泄露 + 认证绕过 + 远程代码执行
        info_findings = [f for f in self.findings if f.type == "info_disclosure"]
        high_severity = [f for f in self.findings if f.severity in ["critical", "high"]]

        if info_findings and high_severity:
            chain = info_findings[:1] + high_severity[:2]
            if len(chain) >= 2:
                chains.append(chain)

        return chains

    def get_prioritized_findings(self) -> List[VulnerabilityFinding]:
        """获取按优先级排序的漏洞列表"""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        def priority_key(finding: VulnerabilityFinding) -> tuple:
            """或...。

                Args:
                finding: 相关参数。

                Returns:
                操作结果。
            """
            return (
                severity_order.get(finding.severity, 99),
                -finding.confidence,  # 置信度高的排前面
                finding.false_positive_risk,  # 误报风险低的排前面
            )

        return sorted(self.findings, key=priority_key)

    def get_statistics(self) -> Dict:
        """获取分析统计"""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        type_counts = {}
        avg_confidence = 0.0

        for finding in self.findings:
            if finding.severity in severity_counts:
                severity_counts[finding.severity] += 1
            type_counts[finding.type] = type_counts.get(finding.type, 0) + 1
            avg_confidence += finding.confidence

        if self.findings:
            avg_confidence /= len(self.findings)

        return {
            "total_findings": len(self.findings),
            "by_severity": severity_counts,
            "by_type": type_counts,
            "average_confidence": round(avg_confidence, 2),
            "vulnerability_chains": len(self.analyze_vulnerability_chain()),
        }

    def export_findings(self, filepath: str):
        """导出漏洞发现到JSON文件"""
        data = {
            "exported_at": time.time(),
            "statistics": self.get_statistics(),
            "findings": [f.to_dict() for f in self.get_prioritized_findings()],
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        log.info(f"漏洞发现已导出: {filepath}")


# 全局结果分析器实例
result_analyzer = ResultAnalyzer()
