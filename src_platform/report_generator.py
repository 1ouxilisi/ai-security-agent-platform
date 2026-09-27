#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
report_generator模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import json
import os
import time
import uuid
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from utils.logger import log


class ReportSeverity(str, Enum):
    """报告严重程度（HackerOne标准）"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class ReportStatus(str, Enum):
    """报告状态"""
    DRAFT = "draft"
    SUBMITTED = "submitted"
    TRIAGED = "triaged"
    RESOLVED = "resolved"
    DISPUTED = "disputed"
    CLOSED = "closed"
    DUPLICATE = "duplicate"
    NOT_APPLICABLE = "not_applicable"
    INFORMATIVE = "informative"
    SPAM = "spam"


@dataclass
class VulnerabilityReport:
    """漏洞报告"""
    report_id: str
    title: str
    severity: ReportSeverity
    weakness: str = ""  # CWE编号
    url: str = ""
    parameter: str = ""
    description: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    proof_of_concept: str = ""
    impact: str = ""
    remediation: str = ""
    affected_assets: List[str] = field(default_factory=list)
    screenshots: List[str] = field(default_factory=list)
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    cvss_score: float = 0.0
    cvss_vector: str = ""
    target_platform: str = "hackerone"  # hackerone/bugcrowd/intigriti/yeswehack
    status: ReportStatus = ReportStatus.DRAFT
    bounty_amount: float = 0.0
    currency: str = "USD"
    submitted_at: Optional[float] = None
    resolved_at: Optional[float] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    notes: str = ""
    duplicate_of: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "report_id": self.report_id,
            "title": self.title,
            "severity": self.severity.value,
            "weakness": self.weakness,
            "url": self.url,
            "parameter": self.parameter,
            "description": self.description,
            "reproduction_steps": self.reproduction_steps,
            "proof_of_concept": self.proof_of_concept,
            "impact": self.impact,
            "remediation": self.remediation,
            "affected_assets": self.affected_assets,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "target_platform": self.target_platform,
            "status": self.status.value,
            "bounty_amount": self.bounty_amount,
            "currency": self.currency,
            "submitted_at": self.submitted_at,
            "resolved_at": self.resolved_at,
            "created_at": self.created_at,
            "notes": self.notes
        }


class SRCReportGenerator:
    """SRC报告生成器"""

    def __init__(self, data_dir: str = "data/src_platform/reports"):
        """初始化SRCReportGenerator实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.reports: Dict[str, VulnerabilityReport] = {}
        os.makedirs(data_dir, exist_ok=True)
        self._load_data()

    def _load_data(self):
        """从文件加载报告"""
        reports_file = os.path.join(self.data_dir, "reports.json")
        if os.path.exists(reports_file):
            try:
                with open(reports_file, 'r', encoding='utf-8') as f:
                    reports_data = json.load(f)
                for report_id, data in reports_data.items():
                    self.reports[report_id] = VulnerabilityReport(
                        report_id=data["report_id"],
                        title=data.get("title", ""),
                        severity=ReportSeverity(data.get("severity", "medium")),
                        weakness=data.get("weakness", ""),
                        url=data.get("url", ""),
                        parameter=data.get("parameter", ""),
                        description=data.get("description", ""),
                        reproduction_steps=data.get("reproduction_steps", []),
                        proof_of_concept=data.get("proof_of_concept", ""),
                        impact=data.get("impact", ""),
                        remediation=data.get("remediation", ""),
                        affected_assets=data.get("affected_assets", []),
                        cvss_score=data.get("cvss_score", 0),
                        cvss_vector=data.get("cvss_vector", ""),
                        target_platform=data.get("target_platform", "hackerone"),
                        status=ReportStatus(data.get("status", "draft")),
                        bounty_amount=data.get("bounty_amount", 0),
                        currency=data.get("currency", "USD"),
                        submitted_at=data.get("submitted_at"),
                        resolved_at=data.get("resolved_at"),
                        created_at=data.get("created_at", time.time()),
                        notes=data.get("notes", "")
                    )
            except Exception as e:
                log.error(f"加载报告失败: {e}")

    def _save_data(self):
        """保存报告到文件"""
        reports_file = os.path.join(self.data_dir, "reports.json")
        try:
            reports_data = {rid: r.to_dict() for rid, r in self.reports.items()}
            with open(reports_file, 'w', encoding='utf-8') as f:
                json.dump(reports_data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存报告失败: {e}")

    def generate_report(self, vulnerability: Dict[str, Any],
                        verification: Dict[str, Any] = None,
                        platform: str = "hackerone") -> VulnerabilityReport:
        """
        从漏洞和验证结果生成报告
        """
        report_id = f"report-{uuid.uuid4().hex[:8]}"

        # 根据漏洞类型生成标题
        title = self._generate_title(vulnerability)

        # 根据漏洞类型生成描述
        description = self._generate_description(vulnerability)

        # 生成复现步骤
        reproduction_steps = verification.get("reproduction_steps", []) if verification else []
        if not reproduction_steps:
            reproduction_steps = self._generate_reproduction_steps(vulnerability)

        # 生成影响分析
        impact = self._generate_impact(vulnerability)

        # 生成修复建议
        remediation = self._generate_remediation(vulnerability)

        # 生成POC
        poc = verification.get("poc", "") if verification else ""

        # 确定严重程度
        severity = vulnerability.get("severity", "medium")

        # 确定CWE
        cwe = vulnerability.get("cwe_id", "")

        report = VulnerabilityReport(
            report_id=report_id,
            title=title,
            severity=ReportSeverity(severity),
            weakness=cwe,
            url=vulnerability.get("url", ""),
            parameter=vulnerability.get("parameter", ""),
            description=description,
            reproduction_steps=reproduction_steps,
            proof_of_concept=poc,
            impact=impact,
            remediation=remediation,
            affected_assets=[vulnerability.get("url", "")],
            cvss_score=vulnerability.get("cvss_score", 0),
            target_platform=platform,
            status=ReportStatus.DRAFT
        )

        self.reports[report_id] = report
        self._save_data()
        log.info(f"生成报告: {title} ({report_id})")
        return report

    def _generate_title(self, vuln: Dict[str, Any]) -> str:
        """生成漏洞标题"""
        category = vuln.get("category", "")
        url = vuln.get("url", "")
        param = vuln.get("parameter", "")

        # 从URL提取域名
        domain = url.split("/")[2] if "://" in url else url.split("/")[0]

        title_templates = {
            "sqli": f"SQL Injection on {domain} via {param} parameter",
            "xss": f"Cross-Site Scripting (XSS) on {domain} via {param} parameter",
            "command_injection": f"OS Command Injection on {domain} via {param} parameter",
            "ssrf": f"Server-Side Request Forgery (SSRF) on {domain} via {param} parameter",
            "lfi": f"Local File Inclusion (LFI) on {domain} via {param} parameter",
            "open_redirect": f"Open Redirect on {domain} via {param} parameter",
            "cors": f"CORS Misconfiguration on {domain}",
            "info_disclosure": f"Sensitive Information Disclosure on {domain}",
            "idor": f"Insecure Direct Object Reference (IDOR) on {domain}",
            "directory_listing": f"Directory Listing Enabled on {domain}",
            "security_headers": f"Missing Security Headers on {domain}",
        }

        return title_templates.get(category, vuln.get("name", f"Vulnerability on {domain}"))

    def _generate_description(self, vuln: Dict[str, Any]) -> str:
        """生成漏洞描述"""
        category = vuln.get("category", "")
        description = vuln.get("description", "")
        evidence = vuln.get("evidence", "")

        descriptions = {
            "sqli": f"""## Summary
The application is vulnerable to SQL Injection attacks. The `{vuln.get('parameter', '')}` parameter is not properly sanitized before being used in SQL queries, allowing an attacker to manipulate the query and extract sensitive data from the database.

## Vulnerable Endpoint
{vuln.get('url', '')}

## Vulnerable Parameter
`{vuln.get('parameter', '')}`

## Evidence
{evidence}
""",
            "xss": f"""## Summary
The application is vulnerable to Cross-Site Scripting (XSS) attacks. The `{vuln.get('parameter', '')}` parameter is not properly sanitized before being rendered in the HTML response, allowing an attacker to execute arbitrary JavaScript in the victim's browser.

## Vulnerable Endpoint
{vuln.get('url', '')}

## Vulnerable Parameter
`{vuln.get('parameter', '')}`

## Evidence
{evidence}
""",
            "command_injection": f"""## Summary
The application is vulnerable to OS Command Injection. The `{vuln.get('parameter', '')}` parameter is directly concatenated into system commands without proper sanitization, allowing an attacker to execute arbitrary commands on the server.

## Vulnerable Endpoint
{vuln.get('url', '')}

## Vulnerable Parameter
`{vuln.get('parameter', '')}`

## Evidence
{evidence}
""",
            "ssrf": f"""## Summary
The application is vulnerable to Server-Side Request Forgery (SSRF). The `{vuln.get('parameter', '')}` parameter allows user-controlled URLs to be fetched by the server, enabling an attacker to access internal services, cloud metadata, and local files.

## Vulnerable Endpoint
{vuln.get('url', '')}

## Vulnerable Parameter
`{vuln.get('parameter', '')}`

## Evidence
{evidence}
""",
        }

        return descriptions.get(category, f"""## Summary
{description}

## Vulnerable Endpoint
{vuln.get('url', '')}

## Evidence
{evidence}
""")

    def _generate_reproduction_steps(self, vuln: Dict[str, Any]) -> List[str]:
        """生成复现步骤"""
        category = vuln.get("category", "")
        url = vuln.get("url", "")
        param = vuln.get("parameter", "")
        payload = vuln.get("payload", "")

        steps = [
            f"1. Navigate to the vulnerable endpoint: {url.split('?')[0]}",
        ]

        if param and payload:
            steps.append(f"2. Intercept the request using a proxy tool (e.g., Burp Suite)")
            steps.append(f"3. Modify the `{param}` parameter to: `{payload}`")
            steps.append(f"4. The full request URL becomes: `{url.split('?')[0]}?{param}={payload}`")
            steps.append("5. Send the request and observe the response")
        else:
            steps.append(f"2. Send a request to: `{url}`")
            steps.append("3. Observe the response")

        if category == "sqli":
            steps.append("6. Confirm SQL errors or extracted data in the response")
            steps.append("7. Further exploitation can be done using sqlmap")
        elif category == "xss":
            steps.append("6. Confirm the JavaScript payload is executed in the browser")
            steps.append("7. Check the page source to verify the payload is not sanitized")
        elif category == "command_injection":
            steps.append("6. Confirm the command output is reflected in the response")
            steps.append("7. Try `; id` or `| whoami` to further verify")
        elif category == "ssrf":
            steps.append("6. Confirm access to internal services or local files")
            steps.append("7. Try accessing `http://169.254.169.254` for cloud metadata")

        steps.append("8. Take screenshots of the request and response as evidence")

        return steps

    def _generate_impact(self, vuln: Dict[str, Any]) -> str:
        """生成影响分析"""
        category = vuln.get("category", "")

        impacts = {
            "sqli": """## Impact
An attacker can exploit this SQL Injection vulnerability to:

- **Extract sensitive data**: Read usernames, passwords, email addresses, and other confidential information from the database
- **Modify data**: Insert, update, or delete database records
- **Bypass authentication**: Log in as any user without credentials
- **Gain server access**: In some configurations, execute system commands or upload files
- **Cause denial of service**: Drop tables or corrupt data

This vulnerability poses a **critical risk** to the confidentiality, integrity, and availability of the application and its data.
""",
            "xss": """## Impact
An attacker can exploit this XSS vulnerability to:

- **Steal user sessions**: Hijack authenticated user sessions by stealing cookies
- **Perform actions on behalf of users**: Change passwords, make purchases, send messages
- **Redirect users**: Send victims to phishing sites or malware downloads
- **Deface the website**: Modify page content to display misleading information
- **Keylogging**: Record user keystrokes
- **Browser exploitation**: Combine with browser vulnerabilities to compromise the victim's machine

This vulnerability poses a **high risk** to user accounts and application integrity.
""",
            "command_injection": """## Impact
An attacker can exploit this Command Injection vulnerability to:

- **Execute arbitrary commands**: Run any system command on the server
- **Read sensitive files**: Access `/etc/passwd`, configuration files, private keys
- **Gain reverse shell**: Establish an interactive shell on the server
- **Pivot to internal network**: Use the server as a jump host to access internal systems
- **Install malware**: Deploy backdoors, cryptominers, or other malicious software
- **Cause denial of service**: Shut down services or delete critical files
- **Exfiltrate data**: Steal database contents, user data, and intellectual property

This vulnerability poses a **critical risk** as it provides full server compromise.
""",
            "ssrf": """## Impact
An attacker can exploit this SSRF vulnerability to:

- **Access internal services**: Scan and connect to services on the internal network (databases, caches, APIs)
- **Read local files**: Use `file://` protocol to read sensitive files on the server
- **Access cloud metadata**: Retrieve temporary cloud credentials from `169.254.169.254` (AWS/GCP/Azure)
- **Bypass firewalls**: Access services that are not directly reachable from the internet
- **Perform port scanning**: Map the internal network topology
- **Attack internal applications**: Exploit vulnerabilities in internal services

This vulnerability poses a **high to critical risk** depending on the environment and accessible services.
""",
            "lfi": """## Impact
An attacker can exploit this Local File Inclusion vulnerability to:

- **Read sensitive files**: Access configuration files, source code, private keys, `/etc/passwd`, `/etc/shadow`
- **Gain information disclosure**: Learn about the application structure, database credentials, API keys
- **Remote code execution**: In some cases, combine with file upload or log poisoning to execute code
- **Bypass authentication**: Read session files or authentication tokens

This vulnerability poses a **high risk** to application confidentiality and can lead to full server compromise.
""",
            "open_redirect": """## Impact
An attacker can exploit this Open Redirect vulnerability to:

- **Phishing attacks**: Redirect users to malicious login pages that look identical to the legitimate site
- **Malware distribution**: Redirect users to sites that automatically download malware
- **Bypass URL validation**: Use the trusted domain to bypass security filters and email scanners
- **Social engineering**: Increase the credibility of phishing campaigns by using the trusted domain

This vulnerability poses a **medium risk** and is often used as a stepping stone for more sophisticated attacks.
""",
            "cors": """## Impact
An attacker can exploit this CORS misconfiguration to:

- **Steal user data**: Make authenticated cross-origin requests and read sensitive user data
- **Perform actions on behalf of users**: Change account settings, make transactions, send messages
- **Bypass same-origin policy**: Access API endpoints that should be protected
- **Session hijacking**: If credentials are allowed, steal session tokens and user data

This vulnerability poses a **high risk** when combined with `Access-Control-Allow-Credentials: true`.
""",
            "info_disclosure": """## Impact
An attacker can exploit this information disclosure to:

- **Gain intelligence**: Learn about the application structure, technologies, and versions
- **Find credentials**: Discover API keys, database passwords, and other secrets in exposed files
- **Plan further attacks**: Use the disclosed information to craft more targeted exploits
- **Bypass security**: Find hidden endpoints, backup files, or debug interfaces

The risk depends on the sensitivity of the disclosed information.
""",
        }

        return impacts.get(category, """## Impact
This vulnerability may allow an attacker to compromise the security of the application. The specific impact depends on the vulnerability type and the affected functionality.
""")

    def _generate_remediation(self, vuln: Dict[str, Any]) -> str:
        """生成修复建议"""
        category = vuln.get("category", "")

        remediations = {
            "sqli": """## Remediation
To fix this SQL Injection vulnerability:

1. **Use parameterized queries**: Replace string concatenation with prepared statements or parameterized queries
   ```python
   # Vulnerable
   cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
   
   # Secure
   cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
   ```

2. **Use an ORM**: Use a modern ORM (SQLAlchemy, Django ORM, Hibernate) that automatically parameterizes queries

3. **Input validation**: Implement strict whitelist validation for all user inputs

4. **Least privilege**: Use a database account with minimal permissions

5. **Disable error messages**: Do not display detailed SQL errors to users

6. **Deploy a WAF**: Use a Web Application Firewall as an additional layer of protection
""",
            "xss": """## Remediation
To fix this XSS vulnerability:

1. **Output encoding**: HTML-encode all user-supplied data before rendering it in the browser
   ```python
   from markupsafe import escape
   output = escape(user_input)
   ```

2. **Use framework protections**: Use modern frameworks (React, Vue, Angular) that automatically escape output

3. **Content Security Policy (CSP)**: Implement a strict CSP header to prevent unauthorized script execution
   ```
   Content-Security-Policy: default-src 'self'; script-src 'self'
   ```

4. **HttpOnly cookies**: Set the `HttpOnly` flag on session cookies to prevent JavaScript access

5. **Input validation**: Validate and sanitize all user inputs

6. **Use DOMPurify**: For rich text content, use a trusted sanitization library
""",
            "command_injection": """## Remediation
To fix this Command Injection vulnerability:

1. **Avoid system calls**: Use programming language APIs instead of executing system commands
   ```python
   # Vulnerable
   os.system(f"ping {host}")
   
   # Secure
   subprocess.run(["ping", "-c", "1", host], check=True)
   ```

2. **Use parameterized functions**: Pass arguments as a list, not as a concatenated string

3. **Input validation**: Implement strict whitelist validation for all inputs used in commands

4. **Escape shell metacharacters**: Use `escapeshellarg()` or equivalent functions

5. **Least privilege**: Run the application with minimal system permissions

6. **Disable dangerous functions**: Disable `eval()`, `exec()`, and similar functions if not needed
""",
            "ssrf": """## Remediation
To fix this SSRF vulnerability:

1. **Whitelist allowed domains**: Only allow requests to pre-approved domains or IP ranges

2. **Block internal IP ranges**: Reject requests to private IP addresses (10.x, 172.16-31.x, 192.168.x, 127.x)

3. **Block cloud metadata**: Explicitly block `169.254.169.254` and similar metadata endpoints

4. **Restrict protocols**: Only allow `http://` and `https://`, disable `file://`, `gopher://`, `dict://`

5. **Disable redirects**: Do not follow HTTP redirects in server-side requests

6. **Use a proxy**: Route all outbound requests through a proxy with strict access controls

7. **DNS rebinding protection**: Implement DNS pinning or resolve and verify the IP before connecting
""",
            "lfi": """## Remediation
To fix this Local File Inclusion vulnerability:

1. **Normalize file paths**: Use `realpath()` or equivalent to resolve and canonicalize file paths

2. **Whitelist allowed directories**: Only allow file access within specific, pre-approved directories

3. **Remove path traversal characters**: Strip `../`, `..\\`, and URL-encoded variants

4. **Use a file ID mapping**: Map user input to file identifiers rather than directly using file paths

5. **Disable allow_url_include**: In PHP, disable `allow_url_include` and `allow_url_fopen`

6. **Run with minimal permissions**: Ensure the application process cannot read sensitive system files
""",
            "open_redirect": """## Remediation
To fix this Open Redirect vulnerability:

1. **Whitelist allowed URLs**: Only allow redirects to pre-approved domains or paths

2. **Use relative URLs**: Prefer relative paths over absolute URLs for redirects

3. **Validate redirect URLs**: Check that the redirect URL belongs to your domain

4. **Use a redirect mapping**: Map user input to predefined redirect destinations

5. **Warn users**: When redirecting to external sites, show a warning page

6. **Avoid user-controlled redirects**: Do not use user input directly in `Location` headers
""",
            "cors": """## Remediation
To fix this CORS misconfiguration:

1. **Do not use wildcard with credentials**: Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`

2. **Whitelist allowed origins**: Explicitly list trusted domains instead of using `*`

3. **Do not reflect arbitrary origins**: Validate the `Origin` header against a whitelist

4. **Limit allowed methods**: Only allow necessary HTTP methods

5. **Limit allowed headers**: Restrict the headers that can be used in cross-origin requests

6. **Use short-lived preflight cache**: Set appropriate `Access-Control-Max-Age` values
""",
            "info_disclosure": """## Remediation
To fix this information disclosure:

1. **Remove sensitive files**: Delete `.env`, `.git`, backup files, and other sensitive files from web-accessible directories

2. **Restrict file access**: Configure the web server to deny access to sensitive file types

3. **Disable directory listing**: Turn off directory listing in the web server configuration

4. **Custom error pages**: Replace default error pages with generic, non-revealing pages

5. **Remove version headers**: Do not disclose server software versions in HTTP headers

6. **Secure configuration files**: Store configuration files outside the web root

7. **Regular audits**: Periodically scan for accidentally exposed sensitive files
""",
        }

        return remediations.get(category, """## Remediation
Please review the vulnerability and implement appropriate security measures to prevent exploitation.
""")

    def format_for_platform(self, report: VulnerabilityReport, platform: str = None) -> str:
        """格式化为特定平台的报告文本"""
        plat = platform or report.target_platform

        if plat == "hackerone":
            return self._format_hackerone(report)
        elif plat == "bugcrowd":
            return self._format_bugcrowd(report)
        elif plat == "intigriti":
            return self._format_intigriti(report)
        else:
            return self._format_generic(report)

    def _format_hackerone(self, report: VulnerabilityReport) -> str:
        """格式化为HackerOne报告"""
        lines = []
        lines.append(f"# {report.title}")
        lines.append("")
        lines.append(report.description)
        lines.append("")
        lines.append("## Reproduction Steps")
        lines.append("")
        for i, step in enumerate(report.reproduction_steps, 1):
            lines.append(f"{step}")
        lines.append("")
        if report.proof_of_concept:
            lines.append("## Proof of Concept")
            lines.append("")
            lines.append(report.proof_of_concept)
            lines.append("")
        lines.append(report.impact)
        lines.append("")
        lines.append(report.remediation)
        lines.append("")
        if report.references:
            lines.append("## References")
            lines.append("")
            for ref in report.references:
                lines.append(f"- {ref}")
            lines.append("")
        return "\n".join(lines)

    def _format_bugcrowd(self, report: VulnerabilityReport) -> str:
        """格式化为Bugcrowd报告"""
        lines = []
        lines.append(f"**Title:** {report.title}")
        lines.append("")
        lines.append(f"**Severity:** {report.severity.value}")
        lines.append("")
        lines.append(f"**URL:** {report.url}")
        lines.append("")
        lines.append("## Description")
        lines.append(report.description)
        lines.append("")
        lines.append("## Steps to Reproduce")
        for step in report.reproduction_steps:
            lines.append(step)
        lines.append("")
        lines.append("## Impact")
        lines.append(report.impact)
        lines.append("")
        lines.append("## Remediation")
        lines.append(report.remediation)
        return "\n".join(lines)

    def _format_intigriti(self, report: VulnerabilityReport) -> str:
        """格式化为Intigriti报告"""
        return self._format_hackerone(report)  # Intigriti使用类似格式

    def _format_generic(self, report: VulnerabilityReport) -> str:
        """格式化为通用报告"""
        return self._format_hackerone(report)

    def submit_report(self, report_id: str) -> bool:
        """标记报告为已提交"""
        report = self.reports.get(report_id)
        if not report:
            return False
        report.status = ReportStatus.SUBMITTED
        report.submitted_at = time.time()
        report.updated_at = time.time()
        self._save_data()
        log.info(f"报告已提交: {report.title} ({report_id})")
        return True

    def update_report_status(self, report_id: str, status: str,
                              bounty_amount: float = 0, notes: str = "") -> bool:
        """更新报告状态"""
        report = self.reports.get(report_id)
        if not report:
            return False
        report.status = ReportStatus(status)
        if bounty_amount:
            report.bounty_amount = bounty_amount
        if notes:
            report.notes = notes
        if status == "resolved":
            report.resolved_at = time.time()
        report.updated_at = time.time()
        self._save_data()
        return True

    def get_reports(self, status: str = None, severity: str = None,
                    platform: str = None) -> List[Dict[str, Any]]:
        """获取报告列表"""
        results = []
        for report in self.reports.values():
            if status and report.status.value != status:
                continue
            if severity and report.severity.value != severity:
                continue
            if platform and report.target_platform != platform:
                continue
            results.append(report.to_dict())
        results.sort(key=lambda x: x["created_at"], reverse=True)
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        total = len(self.reports)
        submitted = sum(1 for r in self.reports.values() if r.status.value in ["submitted", "triaged", "resolved"])
        resolved = sum(1 for r in self.reports.values() if r.status.value == "resolved")
        duplicates = sum(1 for r in self.reports.values() if r.status.value == "duplicate")
        total_bounty = sum(r.bounty_amount for r in self.reports.values())

        by_severity = {
            "critical": sum(1 for r in self.reports.values() if r.severity.value == "critical"),
            "high": sum(1 for r in self.reports.values() if r.severity.value == "high"),
            "medium": sum(1 for r in self.reports.values() if r.severity.value == "medium"),
            "low": sum(1 for r in self.reports.values() if r.severity.value == "low"),
        }

        by_platform = {}
        for report in self.reports.values():
            p = report.target_platform
            by_platform[p] = by_platform.get(p, 0) + 1

        return {
            "total_reports": total,
            "submitted": submitted,
            "resolved": resolved,
            "duplicates": duplicates,
            "total_bounty_earned": total_bounty,
            "by_severity": by_severity,
            "by_platform": by_platform,
            "resolution_rate": round(resolved / submitted * 100, 2) if submitted > 0 else 0,
            "duplicate_rate": round(duplicates / submitted * 100, 2) if submitted > 0 else 0,
            "average_bounty": round(total_bounty / resolved, 2) if resolved > 0 else 0
        }


# 全局实例
src_report_generator = SRCReportGenerator()
