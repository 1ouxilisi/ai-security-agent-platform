# -*- coding: utf-8 -*-
"""静态漏洞检测：硬编码密钥 / WebView 不安全配置 / 日志泄露 / 明文存储 / 导出组件。"""
from __future__ import annotations

import os
import re
import zipfile
from typing import Any, Dict, List, Tuple


# 正则规则
RULES: List[Dict[str, Any]] = [
    {"id": "hardcoded_secret", "title": "硬编码密钥/密码",
     "severity": "high",
     "pattern": re.compile(r"(api[_-]?key|secret|password|passwd|token|aws_secret|private[_-]?key)\s*[=:]\s*[\"'][A-Za-z0-9/+=_\-]{12,}[\"']", re.I)},
    {"id": "log_leak", "title": "日志泄露 (Log.d/Log.e)",
     "severity": "medium",
     "pattern": re.compile(r"Log\.[deiwv]\s*\(")},
    {"id": "webview_js", "title": "WebView 开启 JS",
     "severity": "medium",
     "pattern": re.compile(r"setJavaScriptEnabled\s*\(\s*true\s*\)")},
    {"id": "webview_file", "title": "WebView 允许文件访问",
     "severity": "high",
     "pattern": re.compile(r"setAllowFileAccess\s*\(\s*true\s*\)")},
    {"id": "webview_jsinterface", "title": "WebView addJavascriptInterface",
     "severity": "high",
     "pattern": re.compile(r"addJavascriptInterface\s*\(")},
    {"id": "weak_hash", "title": "弱哈希 MD5/SHA1",
     "severity": "low",
     "pattern": re.compile(r"MessageDigest\.getInstance\s*\(\s*\"(MD5|SHA-1)\"")},
    {"id": "http_url", "title": "明文 HTTP 硬编码",
     "severity": "medium",
     "pattern": re.compile(r"http://[A-Za-z0-9.\-]+")},
    {"id": "sharedpref", "title": "SharedPreferences 明文存储",
     "severity": "medium",
     "pattern": re.compile(r"getSharedPreferences\s*\([^)]*\)\.edit\(\)")},
]

EXPORTED_RE = re.compile(r"<(activity|service|receiver|provider)[^>]*android:exported=\"true\"[^>]*android:name=\"([^\"]+)\"")
EXPORTED_RE2 = re.compile(r"android:name=\"([^\"]+)\"[^>]*android:exported=\"true\"")


class StaticVulnDetector:
    def scan_apk(self, apk_path: str) -> Dict[str, Any]:
        if not os.path.exists(apk_path):
            return {"success": False, "error": f"文件不存在: {apk_path}"}
        findings: List[Dict[str, Any]] = []
        files_scanned = 0
        try:
            with zipfile.ZipFile(apk_path) as z:
                names = z.namelist()
                # 1) AndroidManifest.xml 静态导出组件
                manifest_txt = ""
                try:
                    from .apk_parser import ApkRealParser
                    manifest_txt = ApkRealParser()._decode_axml(z.read("AndroidManifest.xml"))
                except KeyError:
                    manifest_txt = ""
                for m in EXPORTED_RE.finditer(manifest_txt):
                    findings.append({"id": "exported_component", "severity": "medium",
                                     "title": "导出组件未设权限", "file": "AndroidManifest.xml",
                                     "detail": f"{m.group(1)}: {m.group(2)}"})
                for m in EXPORTED_RE2.finditer(manifest_txt):
                    findings.append({"id": "exported_component", "severity": "medium",
                                     "title": "导出组件未设权限", "file": "AndroidManifest.xml",
                                     "detail": f"组件: {m.group(1)}"})

                # 2) 在 dex / 资源文本里跑正则
                for n in names:
                    if not (n.endswith(".dex") or n.endswith(".xml") or n.endswith(".json")
                            or n.endswith(".properties") or n.endswith(".kt") or n.endswith(".java")):
                        continue
                    try:
                        blob = z.read(n)
                    except Exception:  # noqa: BLE001
                        continue
                    text = blob.decode("utf-8", errors="replace")
                    files_scanned += 1
                    for rule in RULES:
                        for m in rule["pattern"].finditer(text):
                            findings.append({
                                "id": rule["id"],
                                "severity": rule["severity"],
                                "title": rule["title"],
                                "file": n,
                                "detail": m.group(0)[:120],
                            })
        except Exception as e:  # noqa: BLE001
            return {"success": False, "error": str(e)}

        sev_count = {"high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1
        return {
            "success": True,
            "files_scanned": files_scanned,
            "total_findings": len(findings),
            "severity": sev_count,
            "findings": findings[:200],
        }
