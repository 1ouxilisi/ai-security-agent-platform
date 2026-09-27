#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fuzz_engine.py — API Fuzz 测试引擎（专业级深化）。

覆盖：
    - 参数 Fuzz：基于类型生成 Payload（字符串/数字/布尔/数组/对象/文件）
    - 边界值：最小值/最大值/空值/超长/特殊字符/Unicode/编码绕过
    - 变异 Fuzz：基于样本变异/位翻转/算术变异/字典替换
    - 异常检测：500 错误/堆栈/响应时间异常/资源消耗
    - 内置 300+ Fuzz Payload

设计定位：仅生成 Fuzz 用例与异常检测规则，不主动对真实目标发起高并发请求。
"""

from __future__ import annotations

import random
import time
from typing import Any, Dict, List, Optional


# ====================================================================== #
# Fuzz Payload 库（300+）
# ====================================================================== #
FUZZ_PAYLOAD_LIBRARY: Dict[str, List[str]] = {
    # 字符串边界
    "string_empty": ["", " ", "  ", "\t", "\n", "\r\n", "\x00", "\x00\x00", " ", "　"],
    "string_long": [
        "A" * 100, "A" * 1000, "A" * 5000, "A" * 10000, "A" * 100000,
        "A" * 500000, "啊" * 1000, "🎉" * 500, "a" * 255, "a" * 65535,
    ],
    "string_special": [
        "'", '"', "\\", "`", ";", "|", "&", "$", "#", "@", "!", "?",
        "(", ")", "{", "}", "[", "]", "<", ">", "=", "+", "-", "*", "/", "%", "^", "~",
        ":", ":", ",", ".", "_", "-", " ", " ", "	",
        "‘", "’", "“", "”", "…", "—", "·", "•", "©", "®", "™",
    ],
    "string_unicode": [
        "ñ", "中文", "🎉", "\u0000", "\uFFFF", "𝕳𝖊𝖑𝖑𝖔",
        "ＩＤＥＮＴＩＦＩＥＲ", "Ťëŝť", "🧪", "\x00\x01\x02",
        "𝒉𝒆𝒍𝒍𝒐", "🟢🔴🟡", "\u200b\u200c\u200d", "\ufeff",
        "äöüÄÖÜß", "ЁЂЃЄ", "ΑΒΓΔ", "אֶבֶן", "العربية",
        "\uD83D\uDE00", "\u00e9\u00e8\u00ea", "\u3042\u3044\u3046",
    ],
    "string_encoding": [
        "%00", "%20", "%22", "%27", "%2e%2e%2f", "%e4%b8%ad%e6%96%87",
        "&#0;", "&lt;", "&gt;", "&amp;", "\\u0000", "\\x00",
        "%252e%252e%252f", "%u002e%u002e%u002f", "%c0%ae%c0%ae%c0%af",
        "%u002F", "%%32%65", "%00%00", "%ff%fe",
    ],
    "string_xss": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>", "javascript:alert(1)",
        "\"><script>alert(1)</script>", "'><script>alert(1)</script>",
        "<body onload=alert(1)>", "<iframe src=javascript:alert(1)>",
        "<script/src=data:,alert(1)>", "<svg><script>alert(1)</script></svg>",
        "<details open ontoggle=alert(1)>", "<marquee onstart=alert(1)>",
    ],
    # 数字边界
    "number_int": [
        "0", "1", "-1", "999999999", "-999999999", "2147483647", "-2147483648",
        "9223372036854775807", "0.1", "-0.0", "1e10", "NaN", "Infinity",
        "0xdeadbeef", "0b1010", "1_000_000", "+1", " 1 ",
        "2147483648", "-2147483649", "00", "-0", "1.7976931348623157e308",
        "-9223372036854775808", "3.4028235e38", "-3.4028235e38",
    ],
    "number_float": [
        "0.0", "-0.0", "0.0000001", "99999999.99", "1.7976931348623157e308",
        "5e-324", "1,000.00", ".1", "1.", "1e",
        "0.1+0.2", "0.1+0.2==0.3", "1e999", "-1e999", "0x1p-1074",
    ],
    # 布尔/空
    "boolean": [
        "true", "false", "True", "False", "TRUE", "FALSE", "1", "0",
        "null", "NULL", "None", "undefined", "yes", "no", "on", "off",
    ],
    "null_values": [
        "null", "None", "NULL", "", "nil", "NaN", "0", "false", "[]", "{}",
        "void", "undef", "NIL", "Null", "~", "-", "0x0",
    ],
    # 数组
    "array": [
        "[]", "[1]", "[1,2,3]", "[\"a\",\"b\"]", "[null]", "[{}]",
        "[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]",
        "[\"" + "A" * 1000 + "\"]",
        "[[]]", "[[[[[[]]]]]]", "[1,\"a\",null,{},[]]",
        "[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20]",
    ],
    # 对象
    "object": [
        "{}", "{\"a\":1}", "{\"a\":\"" + "B" * 500 + "\"}",
        "{\"__proto__\":{\"polluted\":true}}", "{\"constructor\":{\"prototype\":{}}}",
        "{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":1}}}}}",
        "{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":1}}}}}}",
        "{\"__proto__\":{\"isAdmin\":true}}",
    ],
    # 文件
    "file": [
        "filename.exe", "filename.php", "filename.jsp", "filename.html",
        "filename.svg", "filename.phtml", "file.php.jpg",
        "../../../etc/passwd", "....//....//etc/passwd",
        "A" * 10000 + ".txt", "",
        "shell.php%00.jpg", "file.php%00.png", "..\\..\\..\\windows\\system32\\",
        ".htaccess", ".git/config", "web.config",
    ],
    # 路径
    "path_traversal": [
        "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
        "....//....//etc/passwd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/etc/passwd", "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "file:///etc/passwd", "..%252f..%252fetc%252fpasswd",
        "....\\....\\....\\windows\\win.ini", "/proc/self/cmdline",
        "/root/.bash_history", "C:/boot.ini",
    ],
    # 命令注入
    "command": [
        "; id", "| id", "&& id", "`id`", "$(id)", "; ls", "| cat /etc/passwd",
        "%0aid", "%0aid%0a", "& whoami", "|| whoami",
        "; ping -c 3 127.0.0.1", "| nc 127.0.0.1 443",
    ],
    # SQL 片段
    "sql": [
        "'", "\"", "' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--",
        "1; DROP TABLE users--", "' AND SLEEP(3)--", "admin'--",
        "' OR '1'='1' --", "\" OR \"\"=\"", "') OR ('1'='1",
    ],
    # SSRF
    "ssrf": [
        "http://127.0.0.1", "http://localhost", "http://169.254.169.254/",
        "file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO",
        "http://[::1]", "http://0.0.0.0",
        "http://[::ffff:127.0.0.1]/", "dict://127.0.0.1:6379/INFO",
    ],
    # CRLF
    "crlf": [
        "%0d%0a", "%0a", "\r\n", "%0d%0aSet-Cookie:hijacked=1",
        "%0d%0aLocation:%20http://evil.com",
        "%0d%0aX-Injected:%20true", "%0d%0a%0d%0a<script>alert(1)</script>",
        "%0d%0aRefresh:%200;url=http://evil.com", "%0d%0aProxy-Authorization:%20Basic%20YWRt",
    ],
    # 类型混淆
    "type_confusion": [
        "{\"id\": \"1\"}", "{\"id\": 1}", "{\"id\": [1]}", "{\"id\": {\"$gt\": 0}}",
        "{\"amount\": -1}", "{\"amount\": \"1e10\"}", "{\"role\": \"admin\"}",
        "{\"is_admin\": true}", "{\"verified\": 1}",
        "{\"id\": null}", "{\"id\": true}", "{\"id\": \"1,2,3\"}",
        "{\"limit\": -1}", "{\"limit\": 99999}", "{\"sort\": \"id; DROP TABLE\"}",
    ],
}


def _count_fuzz() -> int:
    return sum(len(v) for v in FUZZ_PAYLOAD_LIBRARY.values())


TOTAL_FUZZ_PAYLOADS = _count_fuzz()


# 变异字典
_MUTATION_DICTIONARY = [
    "admin", "root", "test", "user", "guest", "null", "undefined",
    "123456", "password", "secret", "true", "false", "0", "1",
]


class FuzzEngine:
    """API Fuzz 测试引擎。"""

    def __init__(self) -> None:
        self.findings: List[Dict[str, Any]] = []
        self.cases: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # 入口
    # ------------------------------------------------------------------ #
    def run(
        self,
        parameters: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """生成 Fuzz 用例并模拟异常检测。"""
        options = options or {}
        self.findings = []
        self.cases = []
        parameters = parameters or self._default_parameters()

        for p in parameters:
            self._gen_for_parameter(p)

        # 基于样本变异
        samples = options.get("samples", [])
        for s in samples:
            self._mutate_sample(s)

        # 模拟异常检测（基于用例数量与类型推断风险）
        self._detect_anomalies(options)

        return {
            "total_cases": len(self.cases),
            "total_findings": len(self.findings),
            "by_category": self._category_breakdown(),
            "cases": self.cases[:200],  # 限量返回
            "findings": self.findings,
            "payload_library_size": TOTAL_FUZZ_PAYLOADS,
            "summary": self._summary(),
        }

    @staticmethod
    def _default_parameters() -> List[Dict[str, Any]]:
        return [
            {"name": "id", "in": "path", "type": "integer", "path": "/api/v1/items/{id}"},
            {"name": "q", "in": "query", "type": "string", "path": "/api/v1/search"},
            {"name": "page", "in": "query", "type": "integer", "path": "/api/v1/list"},
            {"name": "name", "in": "body", "type": "string", "path": "/api/v1/users"},
            {"name": "active", "in": "body", "type": "boolean", "path": "/api/v1/users"},
        ]

    # ------------------------------------------------------------------ #
    # 用例生成
    # ------------------------------------------------------------------ #
    def _gen_for_parameter(self, p: Dict[str, Any]) -> None:
        ptype = (p.get("type") or "string").lower()
        name = p.get("name", "param")
        loc = p.get("in", "query")
        path = p.get("path", "/")

        buckets: List[str] = []
        if ptype in ("string", "text", None):
            buckets = ["string_empty", "string_long", "string_special",
                       "string_unicode", "string_encoding", "string_xss"]
        elif ptype in ("integer", "number", "float"):
            buckets = ["number_int", "number_float", "null_values"]
        elif ptype in ("boolean",):
            buckets = ["boolean", "null_values"]
        elif ptype in ("array",):
            buckets = ["array", "type_confusion"]
        elif ptype in ("object",):
            buckets = ["object", "type_confusion"]
        elif ptype in ("file",):
            buckets = ["file", "path_traversal"]
        else:
            buckets = ["string_empty", "string_special", "null_values"]

        for b in buckets:
            for payload in FUZZ_PAYLOAD_LIBRARY.get(b, []):
                self.cases.append({
                    "parameter": name, "in": loc, "path": path,
                    "type": ptype, "category": b, "payload": payload,
                    "expected": "观察是否 500/堆栈/超时/异常行为",
                })

    # ------------------------------------------------------------------ #
    # 变异
    # ------------------------------------------------------------------ #
    def _mutate_sample(self, sample: Any) -> None:
        if isinstance(sample, str):
            # 位翻转（字符级别）
            for i in range(min(3, len(sample))):
                chars = list(sample)
                chars[i] = chr(ord(chars[i]) ^ 0xFF) if chars[i] else "X"
                self.cases.append({
                    "parameter": "sample_mutation", "in": "body",
                    "path": "<sample>", "type": "string",
                    "category": "bit_flip", "payload": "".join(chars),
                    "expected": "观察反序列化/解析异常",
                })
            # 字典替换
            for word in _MUTATION_DICTIONARY:
                self.cases.append({
                    "parameter": "sample_mutation", "in": "body",
                    "path": "<sample>", "type": "string",
                    "category": "dict_replace", "payload": word,
                    "expected": "观察逻辑分支变化",
                })
        elif isinstance(sample, (int, float)):
            for delta in (-1, 1, 0, -100, 100):
                self.cases.append({
                    "parameter": "sample_arith", "in": "body",
                    "path": "<sample>", "type": "number",
                    "category": "arithmetic", "payload": str(sample + delta),
                    "expected": "观察边界行为",
                })

    # ------------------------------------------------------------------ #
    # 异常检测
    # ------------------------------------------------------------------ #
    def _detect_anomalies(self, options: Dict[str, Any]) -> None:
        self.findings.append({
            "category": "异常检测", "name": "500 错误监控", "severity": "high",
            "description": "Fuzz 期间任何 500 响应都应记录请求 Payload 并排查",
            "evidence": "规则: status>=500 即标记",
            "recommendation": "生产环境关闭详细错误；为 Fuzz 建立基线",
        })
        self.findings.append({
            "category": "异常检测", "name": "堆栈跟踪泄露", "severity": "high",
            "description": "响应中含 Traceback/Exception/Stack trace 即为信息泄露",
            "evidence": "特征: Traceback (most recent call last) / at java.lang.",
            "recommendation": "统一错误处理；生产环境不回显堆栈",
        })
        self.findings.append({
            "category": "异常检测", "name": "响应时间异常", "severity": "medium",
            "description": "某 Payload 导致响应时间 >3x 基线可能存在 ReDoS/时间盲注",
            "evidence": "规则: p99 延迟异常升高",
            "recommendation": "设置查询/请求超时；慢请求告警",
        })
        self.findings.append({
            "category": "异常检测", "name": "资源消耗 / OOM", "severity": "medium",
            "description": "超长字符串/嵌套对象可能耗尽内存/CPU",
            "evidence": "用例含 10KB+ 字符串 / 深度嵌套对象",
            "recommendation": "请求体大小限制；JSON 深度限制",
        })
        self.findings.append({
            "category": "异常检测", "name": "类型混淆", "severity": "high",
            "description": "将字符串改为数组/对象可能绕过校验",
            "evidence": "用例含 {\"id\":[\"...\"]} {\"id\":{\"$gt\":0}}",
            "recommendation": "严格类型校验（Pydantic/JSON Schema）；拒绝类型不符",
        })

    # ------------------------------------------------------------------ #
    # 报告
    # ------------------------------------------------------------------ #
    def _category_breakdown(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for c in self.cases:
            k = c.get("category", "unknown")
            out[k] = out.get(k, 0) + 1
        return out

    def _summary(self) -> Dict[str, Any]:
        return {
            "fuzz_cases": len(self.cases),
            "payloads_available": TOTAL_FUZZ_PAYLOADS,
            "anomaly_rules": len(self.findings),
        }

    def get_payloads(self, category: Optional[str] = None) -> Dict[str, Any]:
        if category:
            data = {k: v for k, v in FUZZ_PAYLOAD_LIBRARY.items() if k == category}
        else:
            data = dict(FUZZ_PAYLOAD_LIBRARY)
        return {
            "total_payloads": sum(len(v) for v in data.values()),
            "categories": list(data.keys()),
            "payloads": data,
        }
