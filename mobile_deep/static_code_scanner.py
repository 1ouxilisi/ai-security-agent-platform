# -*- coding: utf-8 -*-
"""
static_code_scanner.py — Smali / DEX 静态代码分析框架（方向3）。

能力：
    - 硬编码密钥 / 密码 / Token 正则检测（AKSK / 私钥 / Bearer / 连接串）
    - 不安全 API 调用检测（exec / Runtime / WebView / MessageDigest / Cipher 弱算法）
    - Smali 方法调用风格的字符串嗅探
    - 不依赖 JADX，直接对源码 / Smali 文本做模式匹配；真实 DEX 反编译留给 JADX
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple


# --------------------------------------------------------------------------- #
# 规则库
# --------------------------------------------------------------------------- #
SECRET_PATTERNS: List[Tuple[str, str, str]] = [
    # (rule_id, severity, compiled_regex)
    ("AWS_AKID", "high",
     r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("AWS_SECRET", "high",
     r"(?i)aws[_-]?secret[_-]?access[_-]?key[\"'\\s:=]+[A-Za-z0-9/+=]{40}"),
    ("PRIVATE_KEY_BLOCK", "critical",
     r"-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"),
    ("GENERIC_PASSWORD_ASSIGN", "medium",
     r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*[\"'][^\"'\s]{6,}[\"']"),
    ("BEARER_TOKEN", "high",
     r"Bearer\s+[A-Za-z0-9\-_\.]{20,}"),
    ("JWT_LIKE", "medium",
     r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ("MONGODB_URI", "high",
     r"mongodb(\+srv)?://[^\s\"']+:[^\s\"']+@[^\s\"']+"),
    ("MYSQL_CONN_STR", "medium",
     r"jdbc:mysql://[^\s\"']+:[^\s\"']+@"),
    ("ALIYUN_AK", "high",
     r"\bLTAI[0-9A-Za-z]{12,20}\b"),
    ("GOOGLE_API_KEY", "medium",
     r"\bAIza[0-9A-Za-z\-_]{35}\b"),
]

UNSAFE_API_PATTERNS: List[Tuple[str, str, str]] = [
    ("RUNTIME_EXEC", "high",
     r"Runtime\.getRuntime\(\)\.exec\(|\.method.*Ljava/lang/Runtime;->exec"),
    ("PROCESS_START", "high",
     r"ProcessBuilder\(|new\s+ProcessBuilder"),
    ("WEBVIEW_JS_BRIDGE", "critical",
     r"addJavascriptInterface\("),
    ("WEBVIEW_ALLOW_FILE", "high",
     r"setAllowFileAccess\(true\)|setAllowUniversalAccessFromFileURLs\(true\)"
     r"|setAllowFileAccessFromFileURLs\(true\)"),
    ("WEBVIEW_IGNORE_SSL", "critical",
     r"onReceivedSslError[\s\S]{0,80}?handler\.proceed\(\)"),
    ("SSL_TRUST_ALL", "critical",
     r"checkServerTrusted\s*\(\s*\S+\s*,\s*\S+\s*\)\s*\{|ALLOW_ALL_HOSTNAME_VERIFIER"),
    ("CIPHER_ECB", "high",
     r'Cipher\.getInstance\(\s*["\'](DES|DESede|RSA)\/ECB\/'),
    ("MESSAGE_DIGEST_MD5", "low",
     r'MessageDigest\.getInstance\(\s*["\'](MD5|SHA-?1)'),
    ("RANDOM_NOT_SECURE", "medium",
     r"new\s+Random\(\)|java/util/Random;-><init>"),
    ("LOG_VERBOSE", "low",
     r"Log\.(d|v|i|e|w)\("),
    ("OPEN_FILE_OUTPUT_WORLD", "high",
     r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE"),
    ("SQL_RAW", "medium",
     r"rawQuery\(\s*[\"'][^\"']*\+\s*|execSQL\(\s*[\"'][^\"']*\+"),
    ("WEBVIEW_LOAD_URL_JS", "medium",
     r"loadUrl\(\s*[\"']javascript:"),
]


class StaticCodeScanner:
    """静态代码扫描器。"""

    def __init__(self) -> None:
        self.compiled_secrets = [(rid, sev, re.compile(p))
                                 for rid, sev, p in SECRET_PATTERNS]
        self.compiled_unsafe = [(rid, sev, re.compile(p))
                                for rid, sev, p in UNSAFE_API_PATTERNS]

    # ------------------------------------------------------------------ #
    # 主入口
    # ------------------------------------------------------------------ #
    def scan(self, code_sample: str = "",
             smali_blobs: List[str] | None = None,
             file_name: str = "<inline>") -> Dict[str, Any]:
        blobs: List[Tuple[str, str]] = [(file_name, code_sample or "")]
        for i, s in enumerate(smali_blobs or []):
            blobs.append((f"smali_{i}.smali", s))

        findings: List[Dict[str, Any]] = []
        for src_name, blob in blobs:
            if not blob:
                continue
            findings.extend(self._scan_secrets(src_name, blob))
            findings.extend(self._scan_unsafe_api(src_name, blob))

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        findings.sort(key=lambda f: -severity_order.get(f["severity"], 0))

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        return {
            "scanner": "StaticCodeScanner",
            "files_scanned": len(blobs),
            "findings": findings,
            "counts": counts,
            "total": len(findings),
            "rules_loaded": len(self.compiled_secrets) + len(self.compiled_unsafe),
        }

    # ------------------------------------------------------------------ #
    # 硬编码密钥
    # ------------------------------------------------------------------ #
    def _scan_secrets(self, src: str, blob: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for rid, sev, rx in self.compiled_secrets:
            for m in rx.finditer(blob):
                snippet = self._redact(rid, m.group(0))
                out.append({
                    "rule_id": rid,
                    "category": "hardcoded_secret",
                    "severity": sev,
                    "file": src,
                    "match_snippet": snippet,
                    "line_hint": blob.count("\n", 0, m.start()) + 1,
                })
        return out

    # ------------------------------------------------------------------ #
    # 不安全 API
    # ------------------------------------------------------------------ #
    def _scan_unsafe_api(self, src: str, blob: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for rid, sev, rx in self.compiled_unsafe:
            for m in rx.finditer(blob):
                out.append({
                    "rule_id": rid,
                    "category": "unsafe_api",
                    "severity": sev,
                    "file": src,
                    "match_snippet": m.group(0)[:120],
                    "line_hint": blob.count("\n", 0, m.start()) + 1,
                })
        return out

    # ------------------------------------------------------------------ #
    # 脱敏：只显示首尾，避免把密钥回显到报告
    # ------------------------------------------------------------------ #
    @staticmethod
    def _redact(rule_id: str, match: str) -> str:
        if len(match) <= 8:
            return match
        if rule_id in ("AWS_AKID", "ALIYUN_AK", "GOOGLE_API_KEY",
                       "BEARER_TOKEN", "JWT_LIKE"):
            return match[:6] + "***" + match[-4:]
        return match[:6] + "***" + match[-4:]

    # ------------------------------------------------------------------ #
    # 规则清单（供前端展示）
    # ------------------------------------------------------------------ #
    def list_rules(self) -> Dict[str, Any]:
        return {
            "secret_rules": [{"rule_id": r, "severity": s}
                             for r, s, _ in SECRET_PATTERNS],
            "unsafe_api_rules": [{"rule_id": r, "severity": s}
                                 for r, s, _ in UNSAFE_API_PATTERNS],
        }
