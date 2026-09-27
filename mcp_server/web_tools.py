"""
web_tools模块，提供相关安全测试功能。

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
from urllib.parse import urljoin, urlparse
from utils.logger import log
from utils.helpers import validate_target, rate_limit


class WebTools:
    """Web安全测试工具集合"""

    # 常见目录字典（精简版）
    COMMON_PATHS = [
        "/admin", "/login", "/wp-admin", "/wp-login.php",
        "/phpmyadmin", "/admin.php", "/config.php", "/.git/config",
        "/.env", "/backup", "/backup.zip", "/db.sql", "/database.sql",
        "/api", "/api/v1", "/api/docs", "/swagger", "/swagger-ui.html",
        "/robots.txt", "/sitemap.xml", "/.htaccess", "/server-status",
        "/phpinfo.php", "/info.php", "/test.php", "/debug",
        "/uploads", "/files", "/download", "/static", "/media",
        "/console", "/actuator", "/actuator/health", "/actuator/env",
    ]

    # SQL注入测试Payload
    SQLI_PAYLOADS = [
        "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
        "' OR 1=1--", "\" OR 1=1--",
        "1' ORDER BY 1--", "1' UNION SELECT NULL--",
        "admin'--", "admin' #",
    ]

    # XSS测试Payload
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
    ]

    def __init__(self):
        """初始化WebTools实例。

        Args:
            self: 类实例。
        """
        self.vulnerabilities = []

    @rate_limit()
    async def directory_scan(self, url: str, wordlist: Optional[List[str]] = None) -> Dict:
        """
        目录扫描 - 发现隐藏目录和文件
        仅允许扫描授权白名单内的目标
        """
        if not validate_target(url):
            return {"error": "目标不在授权白名单内，操作已拒绝"}

        paths = wordlist if wordlist else self.COMMON_PATHS
        log.info(f"开始目录扫描: {url}, 字典大小: {len(paths)}")

        found = []
        import aiohttp

        semaphore = asyncio.Semaphore(10)

        async def check_path(path: str):
            target_url = urljoin(url, path)
            async with semaphore:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            target_url,
                            timeout=aiohttp.ClientTimeout(total=5),
                            allow_redirects=False,
                            headers={"User-Agent": "Mozilla/5.0 (Security Research Bot)"}
                        ) as resp:
                            if resp.status in [200, 301, 302, 401, 403]:
                                size = len(await resp.read())
                                found.append({
                                    "path": path,
                                    "url": target_url,
                                    "status_code": resp.status,
                                    "size": size,
                                    "content_type": resp.headers.get("Content-Type", "Unknown")
                                })
                                log.debug(f"发现: {path} [{resp.status}]")
                except Exception:
                    pass

        tasks = [check_path(p) for p in paths]
        await asyncio.gather(*tasks)

        result = {
            "target": url,
            "total_paths_scanned": len(paths),
            "found_count": len(found),
            "found_items": sorted(found, key=lambda x: x["status_code"]),
        }
        log.info(f"目录扫描完成: {url}, 发现 {len(found)} 个路径")
        return result

    async def sql_injection_test(self, url: str, param: str) -> Dict:
        """
        SQL注入测试 - 测试URL参数是否存在SQL注入
        仅允许测试授权白名单内的目标
        """
        if not validate_target(url):
            return {"error": "目标不在授权白名单内，操作已拒绝"}

        log.info(f"SQL注入测试: {url}, 参数: {param}")
        import aiohttp

        vulnerabilities = []
        base_response = None

        # 获取基线响应
        try:
            async with aiohttp.ClientSession() as session:
                parsed = urlparse(url)
                from urllib.parse import parse_qs, urlencode
                query_params = parse_qs(parsed.query)
                query_params[param] = ["1"]
                test_url = parsed._replace(query=urlencode(query_params, doseq=True)).geturl()

                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    base_response = {
                        "status": resp.status,
                        "length": len(await resp.read()),
                        "body_preview": (await resp.text())[:500]
                    }
        except Exception as e:
            return {"url": url, "param": param, "error": f"基线请求失败: {e}"}

        # 测试各个Payload
        for payload in self.SQLI_PAYLOADS[:5]:  # 限制测试数量
            try:
                parsed = urlparse(url)
                from urllib.parse import parse_qs, urlencode
                query_params = parse_qs(parsed.query)
                query_params[param] = [payload]
                test_url = parsed._replace(query=urlencode(query_params, doseq=True)).geturl()

                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        body = await resp.text()
                        current_length = len(body)

                        # 检测SQL错误信息
                        sql_errors = [
                            "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL",
                            "sqlite3", "SQLSTATE", "unclosed quotation",
                            "Warning: mysql", "Microsoft SQL Server",
                        ]
                        has_error = any(err.lower() in body.lower() for err in sql_errors)

                        # 检测响应异常变化
                        length_diff = abs(current_length - base_response["length"])
                        abnormal_length = length_diff > base_response["length"] * 0.5

                        if has_error or abnormal_length:
                            vulnerabilities.append({
                                "payload": payload,
                                "status_code": resp.status,
                                "response_length": current_length,
                                "length_diff": length_diff,
                                "has_sql_error": has_error,
                                "confidence": "High" if has_error else "Medium"
                            })
                            log.warning(f"疑似SQL注入: {payload}")

                await asyncio.sleep(0.5)  # 速率限制
            except Exception as e:
                log.debug(f"Payload测试异常: {payload}, {e}")

        result = {
            "url": url,
            "param": param,
            "tested_payloads": len(self.SQLI_PAYLOADS[:5]),
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "is_vulnerable": len(vulnerabilities) > 0,
            "baseline": base_response,
        }
        log.info(f"SQL注入测试完成: {url}, 发现 {len(vulnerabilities)} 个疑似漏洞")
        return result

    async def xss_test(self, url: str, param: str) -> Dict:
        """
        XSS测试 - 测试URL参数是否存在跨站脚本漏洞
        仅允许测试授权白名单内的目标
        """
        if not validate_target(url):
            return {"error": "目标不在授权白名单内，操作已拒绝"}

        log.info(f"XSS测试: {url}, 参数: {param}")
        import aiohttp

        vulnerabilities = []

        for payload in self.XSS_PAYLOADS[:4]:
            try:
                parsed = urlparse(url)
                from urllib.parse import parse_qs, urlencode
                query_params = parse_qs(parsed.query)
                query_params[param] = [payload]
                test_url = parsed._replace(query=urlencode(query_params, doseq=True)).geturl()

                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        body = await resp.text()
                        # 检测Payload是否被原样反射
                        if payload in body:
                            vulnerabilities.append({
                                "payload": payload,
                                "reflected": True,
                                "confidence": "High",
                                "note": "Payload被原样反射到页面，可能存在XSS"
                            })
                            log.warning(f"疑似XSS: {payload}")
                        # 检测部分反射（过滤了部分字符）
                        elif "<script>" not in body and "alert" in body:
                            vulnerabilities.append({
                                "payload": payload,
                                "reflected": "partial",
                                "confidence": "Medium",
                                "note": "Payload被部分过滤，可能存在绕过空间"
                            })

                await asyncio.sleep(0.5)
            except Exception as e:
                log.debug(f"XSS测试异常: {e}")

        result = {
            "url": url,
            "param": param,
            "tested_payloads": len(self.XSS_PAYLOADS[:4]),
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "is_vulnerable": len(vulnerabilities) > 0,
        }
        log.info(f"XSS测试完成: {url}, 发现 {len(vulnerabilities)} 个疑似漏洞")
        return result

    async def ssl_certificate_check(self, host: str, port: int = 443) -> Dict:
        """SSL证书检测 - 检查HTTPS证书有效性"""
        try:
            log.info(f"SSL证书检测: {host}:{port}")
            import ssl
            import socket
            from datetime import datetime

            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()

                    # 解析证书信息
                    subject = dict(x[0] for x in cert["subject"])
                    issuer = dict(x[0] for x in cert["issuer"])
                    not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")

                    result = {
                        "host": host,
                        "port": port,
                        "subject": subject.get("commonName", "Unknown"),
                        "issuer": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
                        "valid_from": not_before.isoformat(),
                        "valid_to": not_after.isoformat(),
                        "days_until_expiry": (not_after - datetime.utcnow()).days,
                        "is_expired": datetime.utcnow() > not_after,
                        "serial_number": cert.get("serialNumber", "Unknown"),
                        "version": cert.get("version", "Unknown"),
                        "san": [x[1] for x in cert.get("subjectAltName", [])],
                    }
                    log.info(f"SSL证书检测完成: {host}, 剩余 {result['days_until_expiry']} 天")
                    return result
        except ssl.SSLCertVerificationError as e:
            return {"host": host, "port": port, "error": "SSL证书验证失败", "detail": str(e)}
        except Exception as e:
            log.error(f"SSL检测异常: {e}")
            return {"host": host, "port": port, "error": str(e)}


# 全局实例
web_tools = WebTools()
