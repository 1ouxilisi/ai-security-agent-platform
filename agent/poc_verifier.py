"""
poc_verifier智能体模块，提供相关AI驱动的安全分析和决策功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import asyncio
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse

from utils.logger import log


class POCVerifier:
    """漏洞POC验证器"""

    def __init__(self):
        """初始化POCVerifier实例。

        Args:
            self: 类实例。
        """
        self.verified_findings = []
        self.false_positives = []
        self._payload_lib = None

    def _get_payload_lib(self):
        """获取Payload库（懒加载）"""
        if self._payload_lib is None:
            try:
                from tools.payload_library import payload_library
                self._payload_lib = payload_library
                log.info("✅ POC验证器集成Payload库成功")
            except Exception as e:
                log.warning(f"⚠️ POC验证器集成Payload库失败: {e}")
        return self._payload_lib

    # 支持的漏洞类型（12种）
    SUPPORTED_TYPES = [
        "sql_injection", "xss", "ssrf", "command_injection",
        "path_traversal", "open_redirect", "ldap_injection",
        "xpath_injection", "template_injection", "xxe",
        "csrf", "insecure_deserialization",
    ]

    async def verify_finding(self, finding: Dict) -> Dict:
        """验证单个漏洞发现"""
        vuln_type = finding.get("type", finding.get("vulnerability_type", "unknown")).lower()
        target = finding.get("url", finding.get("target", ""))
        param = finding.get("parameter", finding.get("param", ""))

        log.info(f"开始验证漏洞: {vuln_type} at {target}")

        verification_result = {
            "finding": finding,
            "verified": False,
            "confidence": "low",
            "verification_method": "none",
            "evidence": "",
            "false_positive": False,
        }

        try:
            if "sql" in vuln_type or "sqli" in vuln_type:
                result = await self._verify_sql_injection(target, param)
                verification_result.update(result)
            elif "xss" in vuln_type or "cross_site" in vuln_type:
                result = await self._verify_xss(target, param)
                verification_result.update(result)
            elif "ssrf" in vuln_type:
                result = await self._verify_ssrf(target, param)
                verification_result.update(result)
            elif "command" in vuln_type or "rce" in vuln_type or "code_execution" in vuln_type:
                result = await self._verify_command_injection(target, param)
                verification_result.update(result)
            elif "path_traversal" in vuln_type or "directory_traversal" in vuln_type:
                result = await self._verify_path_traversal(target, param)
                verification_result.update(result)
            elif "open_redirect" in vuln_type:
                result = await self._verify_open_redirect(target, param)
                verification_result.update(result)
            elif "ldap" in vuln_type:
                result = await self._verify_ldap_injection(target, param)
                verification_result.update(result)
            elif "xpath" in vuln_type:
                result = await self._verify_xpath_injection(target, param)
                verification_result.update(result)
            elif "template" in vuln_type or "ssti" in vuln_type:
                result = await self._verify_template_injection(target, param)
                verification_result.update(result)
            elif "xxe" in vuln_type or "xml" in vuln_type:
                result = await self._verify_xxe(target, param)
                verification_result.update(result)
            elif "csrf" in vuln_type:
                result = self._verify_csrf(finding)
                verification_result.update(result)
            elif "deserialization" in vuln_type or "deser" in vuln_type:
                result = self._verify_deserialization(finding)
                verification_result.update(result)
            else:
                verification_result["verification_method"] = "manual_required"
                verification_result["evidence"] = "此漏洞类型需要人工验证"

            if verification_result["verified"]:
                self.verified_findings.append(verification_result)
                log.info(f"漏洞验证通过: {vuln_type} (置信度: {verification_result['confidence']})")
            elif verification_result["false_positive"]:
                self.false_positives.append(verification_result)
                log.info(f"误报排除: {vuln_type}")
            else:
                log.info(f"漏洞未确认: {vuln_type} (需要人工验证)")

        except Exception as e:
            log.error(f"POC验证失败: {e}")
            verification_result["error"] = str(e)

        return verification_result

    async def verify_batch(self, findings: List[Dict]) -> Dict:
        """批量验证漏洞"""
        log.info(f"开始批量验证 {len(findings)} 个漏洞")

        results = []
        for finding in findings:
            result = await self.verify_finding(finding)
            results.append(result)

        verified = [r for r in results if r["verified"]]
        false_positives = [r for r in results if r["false_positive"]]
        unconfirmed = [r for r in results if not r["verified"] and not r["false_positive"]]

        summary = {
            "total": len(findings),
            "verified": len(verified),
            "false_positives": len(false_positives),
            "unconfirmed": len(unconfirmed),
            "verification_rate": f"{len(verified)/len(findings)*100:.1f}%" if findings else "0%",
            "results": results,
        }

        log.info(f"批量验证完成: 验证通过 {len(verified)}, 误报 {len(false_positives)}, 未确认 {len(unconfirmed)}")
        return summary

    async def _verify_sql_injection(self, url: str, param: str) -> Dict:
        """验证SQL注入（基于响应差异的布尔盲注检测）"""
        if not url or not param:
            return {"verified": False, "confidence": "low", "verification_method": "insufficient_data"}

        try:
            import aiohttp

            # 测试payload
            payloads = [
                ("' AND '1'='1", "' AND '1'='2"),
                ("1 AND 1=1", "1 AND 1=2"),
            ]

            async with aiohttp.ClientSession() as session:
                for true_payload, false_payload in payloads:
                    # 构造测试URL
                    true_url = self._inject_param(url, param, true_payload)
                    false_url = self._inject_param(url, param, false_payload)

                    # 发送请求
                    async with session.get(true_url, timeout=10) as true_resp:
                        true_content = await true_resp.text()
                        true_length = len(true_content)
                        true_status = true_resp.status

                    async with session.get(false_url, timeout=10) as false_resp:
                        false_content = await false_resp.text()
                        false_length = len(false_content)
                        false_status = false_resp.status

                    # 分析响应差异
                    length_diff = abs(true_length - false_length)
                    status_diff = true_status != false_status

                    if length_diff > 50 or status_diff:
                        return {
                            "verified": True,
                            "confidence": "medium",
                            "verification_method": "boolean_based_blind",
                            "evidence": f"响应长度差异: {true_length} vs {false_length} (差异: {length_diff}), 状态码差异: {status_diff}",
                            "false_positive": False,
                            "payload_used": true_payload,
                        }

            return {
                "verified": False,
                "confidence": "low",
                "verification_method": "boolean_based_blind",
                "evidence": "未检测到显著的响应差异，可能不存在SQL注入或需要更复杂的测试",
                "false_positive": True,
            }

        except ImportError:
            return {"verified": False, "confidence": "low", "verification_method": "aiohttp_not_installed"}
        except Exception as e:
            return {"verified": False, "confidence": "low", "verification_method": "error", "error": str(e)}

    async def _verify_xss(self, url: str, param: str) -> Dict:
        """验证XSS（检查payload是否在响应中原样输出）"""
        if not url or not param:
            return {"verified": False, "confidence": "low", "verification_method": "insufficient_data"}

        try:
            import aiohttp

            xss_payload = "<script>alert('POC_VERIFICATION_XSS')</script>"
            test_url = self._inject_param(url, param, xss_payload)

            async with aiohttp.ClientSession() as session:
                async with session.get(test_url, timeout=10) as resp:
                    content = await resp.text()

            if xss_payload in content:
                # 检查是否在HTML上下文中（不在属性或脚本标签内）
                context = self._check_xss_context(content, xss_payload)
                return {
                    "verified": True,
                    "confidence": "high" if context == "html_body" else "medium",
                    "verification_method": "reflected_payload_check",
                    "evidence": f"XSS payload在响应中原样输出，上下文: {context}",
                    "false_positive": False,
                    "payload_used": xss_payload,
                    "xss_context": context,
                }
            else:
                return {
                    "verified": False,
                    "confidence": "low",
                    "verification_method": "reflected_payload_check",
                    "evidence": "XSS payload未在响应中输出，可能已被过滤或编码",
                    "false_positive": True,
                }

        except ImportError:
            return {"verified": False, "confidence": "low", "verification_method": "aiohttp_not_installed"}
        except Exception as e:
            return {"verified": False, "confidence": "low", "verification_method": "error", "error": str(e)}

    async def _verify_ssrf(self, url: str, param: str) -> Dict:
        """验证SSRF（检查是否能访问内部地址）"""
        if not url or not param:
            return {"verified": False, "confidence": "low", "verification_method": "insufficient_data"}

        # SSRF验证需要一个外部回调服务器，这里只做基础检测
        return {
            "verified": False,
            "confidence": "medium",
            "verification_method": "manual_required",
            "evidence": "SSRF需要外部回调服务器（如Burp Collaborator、interactsh）进行验证，建议人工验证",
            "false_positive": False,
            "recommendation": "使用Burp Collaborator或interactsh进行SSRF验证",
        }

    async def _verify_command_injection(self, url: str, param: str) -> Dict:
        """验证命令注入（基于时间延迟的检测）"""
        if not url or not param:
            return {"verified": False, "confidence": "low", "verification_method": "insufficient_data"}

        try:
            import aiohttp
            import time

            # 时间延迟payload
            payload = "; sleep 5 #"
            test_url = self._inject_param(url, param, payload)

            async with aiohttp.ClientSession() as session:
                start_time = time.time()
                async with session.get(test_url, timeout=15) as resp:
                    await resp.text()
                elapsed = time.time() - start_time

            if elapsed >= 4.5:  # 考虑网络延迟，阈值设为4.5秒
                return {
                    "verified": True,
                    "confidence": "high",
                    "verification_method": "time_based_blind",
                    "evidence": f"命令执行导致响应延迟: {elapsed:.2f}秒（预期5秒）",
                    "false_positive": False,
                    "payload_used": payload,
                }
            else:
                return {
                    "verified": False,
                    "confidence": "low",
                    "verification_method": "time_based_blind",
                    "evidence": f"未检测到显著延迟: {elapsed:.2f}秒",
                    "false_positive": True,
                }

        except ImportError:
            return {"verified": False, "confidence": "low", "verification_method": "aiohttp_not_installed"}
        except Exception as e:
            return {"verified": False, "confidence": "low", "verification_method": "error", "error": str(e)}

    async def _verify_path_traversal(self, url: str, param: str) -> Dict:
        """验证路径遍历（检查是否能读取系统文件）"""
        if not url or not param:
            return {"verified": False, "confidence": "low", "verification_method": "insufficient_data"}

        try:
            import aiohttp

            # 路径遍历payload（Windows和Linux）
            payloads = [
                "../../../../etc/passwd",
                "..\\..\\..\\..\\windows\\win.ini",
                "/etc/passwd",
                "C:\\windows\\win.ini",
            ]

            async with aiohttp.ClientSession() as session:
                for payload in payloads:
                    test_url = self._inject_param(url, param, payload)
                    try:
                        async with session.get(test_url, timeout=10) as resp:
                            content = await resp.text()

                        # 检查是否包含系统文件特征
                        if "root:x:" in content or "[extensions]" in content or "root:" in content:
                            return {
                                "verified": True,
                                "confidence": "high",
                                "verification_method": "file_read_check",
                                "evidence": f"成功读取系统文件，payload: {payload}",
                                "false_positive": False,
                                "payload_used": payload,
                            }
                    except:
                        continue

            return {
                "verified": False,
                "confidence": "low",
                "verification_method": "file_read_check",
                "evidence": "未能读取系统文件，可能不存在路径遍历或已被防护",
                "false_positive": True,
            }

        except ImportError:
            return {"verified": False, "confidence": "low", "verification_method": "aiohttp_not_installed"}
        except Exception as e:
            return {"verified": False, "confidence": "low", "verification_method": "error", "error": str(e)}

    async def _verify_open_redirect(self, url: str, param: str) -> Dict:
        """验证开放重定向（检查是否跳转到外部URL）"""
        if not url or not param:
            return {"verified": False, "confidence": "low", "verification_method": "insufficient_data"}

        try:
            import aiohttp

            redirect_url = "https://example.com/poc_verification"
            test_url = self._inject_param(url, param, redirect_url)

            async with aiohttp.ClientSession() as session:
                async with session.get(test_url, timeout=10, allow_redirects=False) as resp:
                    location = resp.headers.get("Location", "")
                    status = resp.status

            if status in (301, 302, 303, 307, 308) and "example.com" in location:
                return {
                    "verified": True,
                    "confidence": "high",
                    "verification_method": "redirect_check",
                    "evidence": f"检测到重定向到外部URL: {location} (状态码: {status})",
                    "false_positive": False,
                    "payload_used": redirect_url,
                }
            else:
                return {
                    "verified": False,
                    "confidence": "low",
                    "verification_method": "redirect_check",
                    "evidence": f"未检测到外部重定向 (状态码: {status}, Location: {location})",
                    "false_positive": True,
                }

        except ImportError:
            return {"verified": False, "confidence": "low", "verification_method": "aiohttp_not_installed"}
        except Exception as e:
            return {"verified": False, "confidence": "low", "verification_method": "error", "error": str(e)}

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        """在URL参数中注入payload"""
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            query_params[param] = [value]
            new_query = urlencode(query_params, doseq=True)
            return urlunparse(parsed._replace(query=new_query))
        except:
            # 如果解析失败，简单拼接
            separator = "&" if "?" in url else "?"
            return f"{url}{separator}{param}={value}"

    @staticmethod
    def _check_xss_context(content: str, payload: str) -> str:
        """检查XSS payload在HTML中的上下文"""
        try:
            idx = content.index(payload)
            before = content[max(0, idx - 50):idx]

            if "<script" in before.lower():
                return "script_tag"
            elif "javascript:" in before.lower():
                return "javascript_uri"
            elif "=" in before and ("'" in before or '"' in before):
                return "attribute_value"
            else:
                return "html_body"
        except:
            return "unknown"

    async def _verify_ldap_injection(self, url: str, param: str) -> Dict:
        """验证LDAP注入（使用Payload库中的payload）"""
        if not url or not param:
            return {"verified": False, "confidence": "low", "verification_method": "insufficient_data"}

        try:
            import aiohttp
            payload_lib = self._get_payload_lib()
            payloads = payload_lib.get_payloads("ldap_injection", limit=3) if payload_lib else [{"payload": "*"}]

            async with aiohttp.ClientSession() as session:
                for p in payloads:
                    test_url = self._inject_param(url, param, p["payload"])
                    try:
                        async with session.get(test_url, timeout=10) as resp:
                            content = await resp.text()
                            # 检测LDAP错误或异常响应
                            if any(kw in content.lower() for kw in ["ldap", "directory", "search error", "invalid filter"]):
                                return {
                                    "verified": True,
                                    "confidence": "medium",
                                    "verification_method": "ldap_error_check",
                                    "evidence": f"检测到LDAP相关错误响应，payload: {p['payload']}",
                                    "false_positive": False,
                                    "payload_used": p["payload"],
                                }
                    except:
                        continue

            return {"verified": False, "confidence": "low", "verification_method": "ldap_check",
                    "evidence": "未检测到LDAP注入特征", "false_positive": True}
        except ImportError:
            return {"verified": False, "confidence": "low", "verification_method": "aiohttp_not_installed"}
        except Exception as e:
            return {"verified": False, "confidence": "low", "verification_method": "error", "error": str(e)}

    async def _verify_xpath_injection(self, url: str, param: str) -> Dict:
        """验证XPath注入"""
        if not url or not param:
            return {"verified": False, "confidence": "low", "verification_method": "insufficient_data"}

        try:
            import aiohttp
            payload_lib = self._get_payload_lib()
            payloads = payload_lib.get_payloads("xpath_injection", limit=3) if payload_lib else [{"payload": "' or '1'='1"}]

            async with aiohttp.ClientSession() as session:
                for p in payloads:
                    test_url = self._inject_param(url, param, p["payload"])
                    try:
                        async with session.get(test_url, timeout=10) as resp:
                            content = await resp.text()
                            if any(kw in content.lower() for kw in ["xpath", "xml", "parser", "syntax error"]):
                                return {
                                    "verified": True,
                                    "confidence": "medium",
                                    "verification_method": "xpath_error_check",
                                    "evidence": f"检测到XPath/XML相关错误，payload: {p['payload']}",
                                    "false_positive": False,
                                    "payload_used": p["payload"],
                                }
                    except:
                        continue

            return {"verified": False, "confidence": "low", "verification_method": "xpath_check",
                    "evidence": "未检测到XPath注入特征", "false_positive": True}
        except ImportError:
            return {"verified": False, "confidence": "low", "verification_method": "aiohttp_not_installed"}
        except Exception as e:
            return {"verified": False, "confidence": "low", "verification_method": "error", "error": str(e)}

    async def _verify_template_injection(self, url: str, param: str) -> Dict:
        """验证模板注入（SSTI）"""
        if not url or not param:
            return {"verified": False, "confidence": "low", "verification_method": "insufficient_data"}

        try:
            import aiohttp
            # 数学运算检测：{{7*7}} 应该返回49
            test_payloads = ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"]

            async with aiohttp.ClientSession() as session:
                for payload in test_payloads:
                    test_url = self._inject_param(url, param, payload)
                    try:
                        async with session.get(test_url, timeout=10) as resp:
                            content = await resp.text()
                            if "49" in content:
                                return {
                                    "verified": True,
                                    "confidence": "high",
                                    "verification_method": "math_operation_check",
                                    "evidence": f"检测到模板注入，数学运算 {{7*7}} 被执行返回49，payload: {payload}",
                                    "false_positive": False,
                                    "payload_used": payload,
                                }
                    except:
                        continue

            return {"verified": False, "confidence": "low", "verification_method": "ssti_check",
                    "evidence": "未检测到模板注入特征（数学运算未被执行）", "false_positive": True}
        except ImportError:
            return {"verified": False, "confidence": "low", "verification_method": "aiohttp_not_installed"}
        except Exception as e:
            return {"verified": False, "confidence": "low", "verification_method": "error", "error": str(e)}

    async def _verify_xxe(self, url: str, param: str) -> Dict:
        """验证XXE（XML外部实体注入）"""
        if not url:
            return {"verified": False, "confidence": "low", "verification_method": "insufficient_data"}

        try:
            import aiohttp
            payload_lib = self._get_payload_lib()
            payloads = payload_lib.get_payloads("xxe", limit=2) if payload_lib else [
                {"payload": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'}
            ]

            async with aiohttp.ClientSession() as session:
                for p in payloads:
                    try:
                        async with session.post(url, data=p["payload"],
                                                headers={"Content-Type": "application/xml"},
                                                timeout=10) as resp:
                            content = await resp.text()
                            if "root:x:0:0" in content or "root:" in content:
                                return {
                                    "verified": True,
                                    "confidence": "high",
                                    "verification_method": "xxe_file_read",
                                    "evidence": "检测到XXE，成功读取/etc/passwd文件内容",
                                    "false_positive": False,
                                    "payload_used": p["payload"][:100],
                                }
                    except:
                        continue

            return {"verified": False, "confidence": "low", "verification_method": "xxe_check",
                    "evidence": "未检测到XXE特征", "false_positive": True}
        except ImportError:
            return {"verified": False, "confidence": "low", "verification_method": "aiohttp_not_installed"}
        except Exception as e:
            return {"verified": False, "confidence": "low", "verification_method": "error", "error": str(e)}

    def _verify_csrf(self, finding: Dict) -> Dict:
        """验证CSRF（检查是否缺少CSRF令牌）"""
        url = finding.get("url", "")
        method = finding.get("method", "POST").upper()

        if method not in ["POST", "PUT", "DELETE", "PATCH"]:
            return {"verified": False, "confidence": "low", "verification_method": "method_check",
                    "evidence": f"{method}方法通常不需要CSRF保护", "false_positive": True}

        # 检查请求中是否包含CSRF令牌
        request_headers = finding.get("request_headers", {})
        request_data = finding.get("request_data", {})
        has_csrf_token = any(
            "csrf" in k.lower() or "xsrf" in k.lower() or "token" in k.lower()
            for k in {**request_headers, **request_data}.keys()
        )

        if not has_csrf_token:
            return {
                "verified": True,
                "confidence": "medium",
                "verification_method": "csrf_token_check",
                "evidence": f"{method}请求中未检测到CSRF令牌，可能存在CSRF漏洞",
                "false_positive": False,
                "note": "需人工确认是否使用其他CSRF防护机制（如SameSite Cookie、自定义Header）",
            }
        else:
            return {"verified": False, "confidence": "medium", "verification_method": "csrf_token_check",
                    "evidence": "请求中包含CSRF令牌，可能不存在CSRF漏洞", "false_positive": True}

    def _verify_deserialization(self, finding: Dict) -> Dict:
        """验证不安全反序列化"""
        content_type = finding.get("content_type", "").lower()
        request_data = finding.get("request_data", "")

        # 检测序列化数据特征
        serialized_indicators = [
            ("java", ["rO0AB", "aced0005", "java.io"]),
            ("python", ["gASV", "cPickle", "pickle", "__reduce__"]),
            ("php", ["O:", "a:", "C:", "php_serialize"]),
            (".net", ["System.Configuration", "TypeName", "$type"]),
        ]

        detected_type = None
        for stype, indicators in serialized_indicators:
            if any(ind in str(request_data) for ind in indicators):
                detected_type = stype
                break

        if detected_type:
            return {
                "verified": True,
                "confidence": "medium",
                "verification_method": "serialized_data_check",
                "evidence": f"检测到{detected_type}序列化数据，可能存在不安全反序列化漏洞",
                "false_positive": False,
                "serialization_type": detected_type,
                "note": "需人工确认反序列化数据是否被安全处理",
            }
        else:
            return {"verified": False, "confidence": "low", "verification_method": "deserialization_check",
                    "evidence": "未检测到序列化数据特征", "false_positive": True}


# 单例
poc_verifier = POCVerifier()
