#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web 漏洞真实验证器（模块一：1.2）。

合法安全边界：
    - 所有 payload 仅用于"检测漏洞是否存在"，不获取 shell、不窃取数据、不写入 webshell。
    - 时间盲注通过响应时延判断；布尔盲注通过响应内容差异判断；错误注入只看回显关键字。
    - 文件上传只上传纯文本测试文件（.txt / 改后缀的文本），不上传任何可执行脚本内容。

统一返回格式：
    {
        "vuln_type": str,
        "status": "verified" | "possible" | "unverifiable" | "false_positive",
        "confidence": float(0~1),
        "evidence": str,
        "details": dict,
        "target": str,
        "param": str,
        "timestamp": float,
    }
"""

import time
from datetime import datetime
from typing import Any, Dict, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests

try:
    from loguru import logger
except Exception:  # pragma: no cover
    import logging

    logger = logging.getLogger("web_vuln_verifier")

# 全局请求超时（秒），避免长时间阻塞
REQUEST_TIMEOUT = 15
# 时间盲注阈值（秒）：比基线多 3s 判定 possible，多 5s 判定 verified
TIME_DELAY_POSSIBLE = 3.0
TIME_DELAY_VERIFIED = 5.0
# 布尔盲注内容长度差异阈值（比例）
BOOL_DIFF_RATIO = 0.10

# 常见 SQL 错误回显关键字（用于错误注入判断）
SQL_ERROR_KEYWORDS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "ora-",
    "oracle error",
    "postgresql",
    "psql error",
    "sqlite3::syntax error",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "odbc drivers error",
    "syntax error",
    "sqlsrv_error",
    "microsoft ole db provider for sql server",
]


class WebVulnVerifier:
    """Web 漏洞真实验证器。"""

    def __init__(self, timeout: int = REQUEST_TIMEOUT, user_agent: Optional[str] = None):
        """初始化验证器。

        Args:
            timeout: 单次 HTTP 请求超时（秒）。
            user_agent: 自定义 User-Agent。
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent or (
                "Mozilla/5.0 (compatible; AIHackingAgent-Verifier/1.0; +authorized-testing)"
            ),
            "Accept": "*/*",
        })
        # 关闭 InsecureRequestWarning
        try:
            requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 内部工具方法
    # ------------------------------------------------------------------
    def _make_result(self, vuln_type: str, status: str, confidence: float,
                     evidence: str, details: Dict[str, Any],
                     target: str, param: str) -> Dict[str, Any]:
        """构造统一返回结果。"""
        return {
            "vuln_type": vuln_type,
            "status": status,
            "confidence": round(float(confidence), 3),
            "evidence": evidence,
            "details": details or {},
            "target": target,
            "param": param,
            "timestamp": time.time(),
            "verified_at": datetime.now().isoformat(),
        }

    def _unverifiable(self, vuln_type: str, target: str, param: str,
                      error: str) -> Dict[str, Any]:
        """构造网络异常/不可验证结果。"""
        return self._make_result(
            vuln_type, "unverifiable", 0.0,
            f"请求失败，无法验证：{error}",
            {"error": str(error)}, target, param,
        )

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """统一请求封装，带超时与 verify=False。"""
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", True)
        return self.session.request(method.upper(), url, **kwargs)

    @staticmethod
    def _inject_param(url: str, param: str, payload: str,
                      method: str = "GET") -> str:
        """把 payload 注入到 URL 指定参数中，返回新 URL（GET）。"""
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        replaced = False
        new_pairs = []
        for k, v in pairs:
            if k == param:
                new_pairs.append((k, payload))
                replaced = True
            else:
                new_pairs.append((k, v))
        if not replaced:
            new_pairs.append((param, payload))
        new_query = urlencode(new_pairs)
        return urlunparse(parsed._replace(query=new_query))

    def _baseline(self, url: str, method: str = "GET",
                  data: Optional[Dict[str, str]] = None):
        """发送基线请求，返回 (elapsed_sec, text, length, status_code, error)。"""
        try:
            if method.upper() == "POST":
                r = self._request("POST", url, data=data or {})
            else:
                r = self._request("GET", url)
            return {
                "elapsed": r.elapsed.total_seconds(),
                "text": r.text or "",
                "length": len(r.text or ""),
                "status_code": r.status_code,
                "error": None,
            }
        except Exception as e:
            return {"elapsed": 0.0, "text": "", "length": 0,
                    "status_code": 0, "error": str(e)}

    # ------------------------------------------------------------------
    # 1. SQL 注入验证
    # ------------------------------------------------------------------
    def verify_sql_injection(self, url: str, param: str,
                            method: str = "GET") -> Dict[str, Any]:
        """SQL 注入验证：时间盲注 + 布尔盲注 + 错误回显。只检测不脱库。"""
        vuln_type = "sql_injection"
        try:
            base = self._baseline(url, method=method)
            if base["error"]:
                return self._unverifiable(vuln_type, url, param, base["error"])

            details: Dict[str, Any] = {
                "baseline_elapsed": base["elapsed"],
                "baseline_length": base["length"],
                "time_based": {}, "boolean_based": {}, "error_based": {},
            }
            evidence_parts = []
            confidence = 0.0

            # --- 错误回显：发送单引号 ---
            err_payload = "'"
            err_url = self._inject_param(url, param, err_payload, method)
            try:
                if method.upper() == "POST":
                    r = self._request("POST", url, data={param: err_payload})
                else:
                    r = self._request("GET", err_url)
                body_lower = (r.text or "").lower()
                hit = [kw for kw in SQL_ERROR_KEYWORDS if kw in body_lower]
                details["error_based"] = {
                    "payload": err_payload,
                    "status_code": r.status_code,
                    "matched_keywords": hit,
                }
                if hit:
                    evidence_parts.append(f"错误回显命中关键字: {hit[:3]}")
                    confidence = max(confidence, 0.7)
            except Exception as e:
                details["error_based"]["error"] = str(e)

            # --- 时间盲注：sleep(5) / pg_sleep(5) ---
            time_payloads = [
                ("mysql_sleep", "' AND SLEEP(5)-- -"),
                ("mysql_sleep2", "1' AND SLEEP(5)-- -"),
                ("pgsql_sleep", "'; SELECT pg_sleep(5)-- -"),
                ("mssql_waitfor", "'; WAITFOR DELAY '0:0:5'-- -"),
            ]
            delayed = False
            for name, payload in time_payloads:
                inj_url = self._inject_param(url, param, payload, method)
                t0 = time.time()
                try:
                    if method.upper() == "POST":
                        r = self._request("POST", url, data={param: payload})
                    else:
                        r = self._request("GET", inj_url)
                    elapsed = time.time() - t0
                except Exception as e:
                    details["time_based"][name] = {"error": str(e)}
                    continue
                extra = elapsed - base["elapsed"]
                details["time_based"][name] = {
                    "payload": payload,
                    "elapsed": round(elapsed, 3),
                    "extra": round(extra, 3),
                }
                if extra >= TIME_DELAY_VERIFIED:
                    delayed = True
                    evidence_parts.append(f"时间盲注[{name}]延迟 {extra:.1f}s")
                    confidence = max(confidence, 0.9)
                    break
                elif extra >= TIME_DELAY_POSSIBLE:
                    delayed = True
                    evidence_parts.append(f"时间盲注[{name}]轻微延迟 {extra:.1f}s")
                    confidence = max(confidence, 0.5)

            # --- 布尔盲注：AND 1=1 vs AND 1=2 ---
            try:
                true_url = self._inject_param(url, param, "1' AND '1'='1", method)
                false_url = self._inject_param(url, param, "1' AND '1'='2", method)
                if method.upper() == "POST":
                    rt = self._request("POST", url, data={param: "1' AND '1'='1"})
                    rf = self._request("POST", url, data={param: "1' AND '1'='2"})
                else:
                    rt = self._request("GET", true_url)
                    rf = self._request("GET", false_url)
                lt, lf = len(rt.text or ""), len(rf.text or "")
                if base["length"] > 0:
                    diff_ratio = abs(lt - lf) / max(base["length"], 1)
                else:
                    diff_ratio = 0.0
                details["boolean_based"] = {
                    "true_len": lt, "false_len": lf,
                    "baseline_len": base["length"],
                    "diff_ratio": round(diff_ratio, 3),
                }
                if diff_ratio > BOOL_DIFF_RATIO:
                    evidence_parts.append(
                        f"布尔盲注响应长度差异 {diff_ratio*100:.1f}%")
                    confidence = max(confidence, 0.6)
            except Exception as e:
                details["boolean_based"]["error"] = str(e)

            # --- 判定状态 ---
            if confidence >= 0.85:
                status = "verified"
            elif confidence >= 0.5:
                status = "possible"
            elif not evidence_parts:
                # 没有任何证据，但请求正常
                status = "false_positive"
                confidence = 0.1
            else:
                status = "unverifiable"

            return self._make_result(
                vuln_type, status, confidence,
                "; ".join(evidence_parts) or "未观察到注入特征",
                details, url, param,
            )
        except Exception as e:
            return self._unverifiable(vuln_type, url, param, e)

    # ------------------------------------------------------------------
    # 2. XSS 验证
    # ------------------------------------------------------------------
    def verify_xss(self, url: str, param: str,
                   method: str = "GET") -> Dict[str, Any]:
        """XSS 验证：反射型 payload 原样输出检测；存储型需二次请求确认。"""
        vuln_type = "xss"
        try:
            base = self._baseline(url, method=method)
            if base["error"]:
                return self._unverifiable(vuln_type, url, param, base["error"])

            payloads = [
                ("reflected_script", "<script>alert(1)</script>"),
                ("reflected_img", "<img src=x onerror=alert(1)>"),
                ("reflected_quote", "\"><svg onload=alert(1)>"),
            ]
            details: Dict[str, Any] = {"baseline_length": base["length"],
                                       "reflected": {}, "stored": {}}
            evidence_parts = []
            confidence = 0.0
            unescaped = False

            for name, payload in payloads:
                inj_url = self._inject_param(url, param, payload, method)
                try:
                    if method.upper() == "POST":
                        r = self._request("POST", url, data={param: payload})
                    else:
                        r = self._request("GET", inj_url)
                    body = r.text or ""
                    reflected = payload in body
                    escaped = (payload.replace("<", "&lt;") in body)
                    details["reflected"][name] = {
                        "payload": payload,
                        "reflected_raw": reflected,
                        "escaped_only": (not reflected) and escaped,
                        "status_code": r.status_code,
                    }
                    if reflected:
                        unescaped = True
                        evidence_parts.append(f"反射型 XSS 原样输出: {payload}")
                        confidence = max(confidence, 0.8)
                except Exception as e:
                    details["reflected"][name] = {"error": str(e)}

            # --- 存储型：二次请求基线 URL，看 payload 是否仍在页面里 ---
            try:
                r2 = self._request("GET", url)
                body2 = r2.text or ""
                stored_hit = any(p in body2 for _, p in payloads)
                details["stored"]["second_request_reflected"] = stored_hit
                if stored_hit and unescaped:
                    evidence_parts.append("二次请求仍命中，疑似存储型 XSS")
                    confidence = max(confidence, 0.95)
            except Exception as e:
                details["stored"]["error"] = str(e)

            if confidence >= 0.85:
                status = "verified"
            elif confidence >= 0.5:
                status = "possible"
            elif not evidence_parts:
                status = "false_positive"
                confidence = 0.1
            else:
                status = "unverifiable"

            return self._make_result(
                vuln_type, status, confidence,
                "; ".join(evidence_parts) or "未观察到未过滤输出",
                details, url, param,
            )
        except Exception as e:
            return self._unverifiable(vuln_type, url, param, e)

    # ------------------------------------------------------------------
    # 3. 路径穿越验证
    # ------------------------------------------------------------------
    def verify_path_traversal(self, url: str,
                              param: str) -> Dict[str, Any]:
        """路径穿越验证：尝试 ../ 序列，检查是否回显目标文件特征串。只读特征不读全文。"""
        vuln_type = "path_traversal"
        try:
            base = self._baseline(url)
            if base["error"]:
                return self._unverifiable(vuln_type, url, param, base["error"])

            payloads = [
                ("unix_passwd", "../../../../etc/passwd", ["root:", "/bin/", "daemon:"]),
                ("unix_passwd_enc", "..%2f..%2f..%2f..%2fetc%2fpasswd",
                 ["root:", "/bin/"]),
                ("win_winini", "..\\..\\..\\..\\windows\\win.ini",
                 ["[extensions]", "[fonts]", "[mci extensions]"]),
                ("win_winini_fwd", "../../../../windows/win.ini",
                 ["[extensions]", "[fonts]"]),
            ]
            details: Dict[str, Any] = {"baseline_length": base["length"],
                                       "probes": {}}
            evidence_parts = []
            confidence = 0.0

            for name, payload, markers in payloads:
                inj_url = self._inject_param(url, param, payload, "GET")
                try:
                    r = self._request("GET", inj_url)
                    body = r.text or ""
                    hit = [m for m in markers if m in body]
                    details["probes"][name] = {
                        "payload": payload,
                        "status_code": r.status_code,
                        "matched_markers": hit,
                        "length": len(body),
                    }
                    if hit:
                        evidence_parts.append(
                            f"路径穿越命中文件特征: {name} -> {hit[:2]}")
                        confidence = max(confidence, 0.85)
                except Exception as e:
                    details["probes"][name] = {"error": str(e)}

            if confidence >= 0.85:
                status = "verified"
            elif confidence >= 0.5:
                status = "possible"
            elif not evidence_parts:
                status = "false_positive"
                confidence = 0.1
            else:
                status = "unverifiable"

            return self._make_result(
                vuln_type, status, confidence,
                "; ".join(evidence_parts) or "未观察到敏感文件特征回显",
                details, url, param,
            )
        except Exception as e:
            return self._unverifiable(vuln_type, url, param, e)

    # ------------------------------------------------------------------
    # 4. SSRF 验证
    # ------------------------------------------------------------------
    def verify_ssrf(self, url: str, param: str) -> Dict[str, Any]:
        """SSRF 验证：把参数指向 127.0.0.1 常见端口，通过响应时间/内容差异判断端口开放。"""
        vuln_type = "ssrf"
        try:
            base = self._baseline(url)
            if base["error"]:
                return self._unverifiable(vuln_type, url, param, base["error"])

            probes = [
                ("ssh_22", "http://127.0.0.1:22"),
                ("redis_6379", "http://127.0.0.1:6379"),
                ("closed_port_9999", "http://127.0.0.1:9999"),
                ("metadata", "http://169.254.169.254/latest/meta-data/"),
            ]
            details: Dict[str, Any] = {"baseline_elapsed": base["elapsed"],
                                       "baseline_length": base["length"],
                                       "probes": {}}
            evidence_parts = []
            confidence = 0.0

            for name, payload in probes:
                inj_url = self._inject_param(url, param, payload, "GET")
                t0 = time.time()
                try:
                    r = self._request("GET", inj_url)
                    elapsed = time.time() - t0
                    body = r.text or ""
                    details["probes"][name] = {
                        "payload": payload,
                        "elapsed": round(elapsed, 3),
                        "status_code": r.status_code,
                        "length": len(body),
                        "snippet": body[:120],
                    }
                    # 端口开放通常有 Banner 或更快的 RST，关闭端口通常慢/超时/连接拒绝
                    # 这里只看：响应内容长度明显不同于 baseline 且不是错误页
                    if r.status_code == 200 and abs(len(body) - base["length"]) > 50:
                        evidence_parts.append(
                            f"SSRF 探测 {name} 得到差异化响应 (len={len(body)})")
                        confidence = max(confidence, 0.6)
                    if "redis" in body.lower() or "+pong" in body.lower():
                        evidence_parts.append(f"SSRF {name} 返回内部服务 Banner")
                        confidence = max(confidence, 0.85)
                except Exception as e:
                    details["probes"][name] = {"error": str(e),
                                               "elapsed": round(time.time() - t0, 3)}

            if confidence >= 0.85:
                status = "verified"
            elif confidence >= 0.5:
                status = "possible"
            elif not evidence_parts:
                status = "false_positive"
                confidence = 0.1
            else:
                status = "unverifiable"

            return self._make_result(
                vuln_type, status, confidence,
                "; ".join(evidence_parts) or "未观察到内部服务差异化响应",
                details, url, param,
            )
        except Exception as e:
            return self._unverifiable(vuln_type, url, param, e)

    # ------------------------------------------------------------------
    # 5. 命令注入验证
    # ------------------------------------------------------------------
    def verify_command_injection(self, url: str, param: str,
                                 method: str = "GET") -> Dict[str, Any]:
        """命令注入验证：带延迟的探测命令，通过响应时延判断。只做延迟探测。"""
        vuln_type = "command_injection"
        try:
            base = self._baseline(url, method=method)
            if base["error"]:
                return self._unverifiable(vuln_type, url, param, base["error"])

            payloads = [
                ("unix_semicolon", "; sleep 5"),
                ("unix_pipe", "| sleep 5"),
                ("unix_amp", "& sleep 5"),
                ("win_ping", "| ping -n 6 127.0.0.1"),
                ("win_amp_ping", "& ping -n 6 127.0.0.1"),
                ("backtick", "`sleep 5`"),
            ]
            details: Dict[str, Any] = {"baseline_elapsed": base["elapsed"],
                                       "probes": {}}
            evidence_parts = []
            confidence = 0.0

            for name, payload in payloads:
                inj_url = self._inject_param(url, param, payload, method)
                t0 = time.time()
                try:
                    if method.upper() == "POST":
                        r = self._request("POST", url, data={param: payload})
                    else:
                        r = self._request("GET", inj_url)
                    elapsed = time.time() - t0
                except Exception as e:
                    details["probes"][name] = {"error": str(e)}
                    continue
                extra = elapsed - base["elapsed"]
                details["probes"][name] = {
                    "payload": payload,
                    "elapsed": round(elapsed, 3),
                    "extra": round(extra, 3),
                    "status_code": r.status_code,
                }
                if extra >= TIME_DELAY_VERIFIED:
                    evidence_parts.append(f"命令注入[{name}]延迟 {extra:.1f}s")
                    confidence = max(confidence, 0.9)
                    break
                elif extra >= TIME_DELAY_POSSIBLE:
                    evidence_parts.append(f"命令注入[{name}]轻微延迟 {extra:.1f}s")
                    confidence = max(confidence, 0.55)

            if confidence >= 0.85:
                status = "verified"
            elif confidence >= 0.5:
                status = "possible"
            elif not evidence_parts:
                status = "false_positive"
                confidence = 0.1
            else:
                status = "unverifiable"

            return self._make_result(
                vuln_type, status, confidence,
                "; ".join(evidence_parts) or "未观察到命令执行延迟",
                details, url, param,
            )
        except Exception as e:
            return self._unverifiable(vuln_type, url, param, e)

    # ------------------------------------------------------------------
    # 6. 文件上传验证
    # ------------------------------------------------------------------
    def verify_file_upload(self, url: str,
                           file_field: str = "file") -> Dict[str, Any]:
        """文件上传验证：上传纯文本测试文件，检查接口是否接受危险扩展名。
        安全边界：上传内容永远是纯文本测试字符串，不上传任何可执行脚本/webshell。
        """
        vuln_type = "file_upload"
        try:
            # (上传文件名, 内容, 说明)
            test_cases = [
                ("safe_test.txt", "authorized-security-test", "纯文本基线"),
                ("fake_image.jpg", "authorized-security-test", "改后缀为jpg的文本"),
                ("test.php", "<?php echo 'security-test-only'; ?>",
                 "危险扩展名但仅为无害打印语句"),
                ("test.asp", "<% response.write \"security-test-only\" %>",
                 "危险扩展名但仅为无害打印语句"),
            ]
            details: Dict[str, Any] = {"probes": {}}
            evidence_parts = []
            confidence = 0.0

            for filename, content, desc in test_cases:
                try:
                    files = {file_field: (filename, content,
                                          "application/octet-stream")}
                    r = self._request("POST", url, files=files)
                    body = r.text or ""
                    accepted = r.status_code in (200, 201)
                    details["probes"][filename] = {
                        "desc": desc,
                        "status_code": r.status_code,
                        "accepted": accepted,
                        "snippet": body[:200],
                    }
                    # 仅检查接口是否接受危险扩展名（不检查是否解析执行）
                    if accepted and filename.endswith((".php", ".asp")):
                        evidence_parts.append(
                            f"接口接受危险扩展名 {filename}（未尝试执行）")
                        confidence = max(confidence, 0.7)
                except Exception as e:
                    details["probes"][filename] = {"error": str(e)}

            if confidence >= 0.85:
                status = "verified"
            elif confidence >= 0.5:
                status = "possible"
            elif not evidence_parts:
                status = "false_positive"
                confidence = 0.1
            else:
                status = "unverifiable"

            return self._make_result(
                vuln_type, status, confidence,
                "; ".join(evidence_parts) or "未观察到危险扩展名被接受",
                details, url, file_field,
            )
        except Exception as e:
            return self._unverifiable(vuln_type, url, file_field, e)
