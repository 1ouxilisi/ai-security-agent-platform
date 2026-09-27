# -*- coding: utf-8 -*-
"""
vuln_detector.py — 常见移动漏洞检测（方向3）。

覆盖：
    - WebView 不安全配置
    - 日志泄露（Log.d/e/i/v）
    - 硬编码密钥/密码
    - 备份允许（android:allowBackup=true）
    - 导出组件风险
    - 不安全存储（MODE_WORLD / 外部存储 / 明文 SharedPreferences）
"""
from __future__ import annotations

from typing import Any, Dict, List

from .static_code_scanner import StaticCodeScanner


class VulnDetector:
    """常见漏洞检测聚合器。"""

    def __init__(self) -> None:
        self.code_scanner = StaticCodeScanner()

    # ------------------------------------------------------------------ #
    # 主入口
    # ------------------------------------------------------------------ #
    def detect(self,
               manifest_signals: Dict[str, Any] | None = None,
               code_sample: str = "",
               components: Dict[str, List[Dict[str, Any]]] | None = None,
               storage_signals: Dict[str, Any] | None = None) -> Dict[str, Any]:
        manifest_signals = manifest_signals or {}
        components = components or {}
        storage_signals = storage_signals or {}

        vulns: List[Dict[str, Any]] = []
        vulns += self._check_webview(code_sample)
        vulns += self._check_log_leak(code_sample)
        vulns += self._check_backup(manifest_signals)
        vulns += self._check_exported_components(components)
        vulns += self._check_insecure_storage(code_sample, storage_signals)

        # 硬编码密钥由静态扫描器补
        sec = self.code_scanner.scan(code_sample=code_sample)
        for f in sec["findings"]:
            if f["category"] == "hardcoded_secret":
                vulns.append({
                    "id": f"HC-{f['rule_id']}",
                    "title": f"硬编码密钥/敏感信息: {f['rule_id']}",
                    "severity": f["severity"],
                    "evidence": f["match_snippet"],
                    "location": f"{f['file']}:{f['line_hint']}",
                    "fix": "将密钥移出代码，改用 NDK 加密 + 服务端下发",
                })

        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        vulns.sort(key=lambda v: -sev_rank.get(v["severity"], 0))
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in vulns:
            counts[v["severity"]] = counts.get(v["severity"], 0) + 1

        return {
            "detector": "VulnDetector",
            "vulns": vulns,
            "counts": counts,
            "total": len(vulns),
            "risk_level": self._overall(counts),
        }

    # ------------------------------------------------------------------ #
    # WebView
    # ------------------------------------------------------------------ #
    def _check_webview(self, code: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if "addJavascriptInterface(" in code:
            out.append({
                "id": "WV-001",
                "title": "WebView 开启 JS 桥（addJavascriptInterface）",
                "severity": "critical",
                "evidence": "addJavascriptInterface 调用",
                "location": "code_sample",
                "fix": "API<17 必须禁用；跨域白名单 + 仅暴露 @JavascriptInterface 白名单方法",
            })
        if "setAllowFileAccess(true)" in code or \
                "setAllowUniversalAccessFromFileURLs(true)" in code:
            out.append({
                "id": "WV-002",
                "title": "WebView 允许 file:// 访问",
                "severity": "high",
                "evidence": "setAllowFileAccess(true) / UniversalAccess",
                "location": "code_sample",
                "fix": "setAllowFileAccess(false)；跨域用 AssetLoader",
            })
        if "onReceivedSslError" in code and "proceed" in code:
            out.append({
                "id": "WV-003",
                "title": "WebView 忽略 SSL 错误",
                "severity": "critical",
                "evidence": "onReceivedSslError -> handler.proceed()",
                "location": "code_sample",
                "fix": "改为 handler.cancel() 并提示用户",
            })
        return out

    # ------------------------------------------------------------------ #
    # 日志泄露
    # ------------------------------------------------------------------ #
    def _check_log_leak(self, code: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        hits = sum(code.count(f"Log.{l}(") for l in ("d", "v", "i", "e", "w"))
        if hits >= 5:
            out.append({
                "id": "LOG-001",
                "title": "大量 Log 调用可能泄露敏感信息",
                "severity": "low",
                "evidence": f"Log.* 调用 {hits} 处",
                "location": "code_sample",
                "fix": "Release 包使用 ProGuard 移除 / BuildConfig.DEBUG 守卫",
            })
        return out

    # ------------------------------------------------------------------ #
    # allowBackup / debuggable
    # ------------------------------------------------------------------ #
    def _check_backup(self, manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if manifest.get("allow_backup"):
            out.append({
                "id": "BAK-001",
                "title": "android:allowBackup=true",
                "severity": "medium",
                "evidence": "allowBackup=true",
                "location": "AndroidManifest.xml",
                "fix": "设置 android:allowBackup=false 或 fullBackupContent 白名单",
            })
        if manifest.get("debuggable"):
            out.append({
                "id": "DBG-001",
                "title": "应用可调试（android:debuggable=true）",
                "severity": "high",
                "evidence": "debuggable=true",
                "location": "AndroidManifest.xml",
                "fix": "Release 构建必须 android:debuggable=false",
            })
        return out

    # ------------------------------------------------------------------ #
    # 导出组件
    # ------------------------------------------------------------------ #
    def _check_exported_components(self,
                                   components: Dict[str, List[Dict[str, Any]]]
                                   ) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for bucket, items in components.items():
            for c in items:
                if not isinstance(c, dict):
                    continue
                if c.get("exported"):
                    no_perm = not c.get("permission")
                    sev = "high" if no_perm else "medium"
                    out.append({
                        "id": f"EXP-{bucket[:3].upper()}-{len(out)+1:03d}",
                        "title": f"{bucket[:-1].capitalize()} 导出: {c.get('name')}",
                        "severity": sev,
                        "evidence": f"exported=true, permission={c.get('permission')}",
                        "location": "AndroidManifest.xml",
                        "fix": "显式 android:exported=false 或加 signature 级 permission",
                    })
        return out

    # ------------------------------------------------------------------ #
    # 不安全存储
    # ------------------------------------------------------------------ #
    def _check_insecure_storage(self, code: str,
                                storage: Dict[str, Any]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if "MODE_WORLD_READABLE" in code or "MODE_WORLD_WRITEABLE" in code:
            out.append({
                "id": "STG-001",
                "title": "MODE_WORLD_* 世界可读/可写",
                "severity": "high",
                "evidence": "MODE_WORLD_*",
                "location": "code_sample",
                "fix": "改用内部存储 + FileProvider",
            })
        if storage.get("shared_prefs_plain"):
            out.append({
                "id": "STG-002",
                "title": "SharedPreferences 明文存储敏感字段",
                "severity": "medium",
                "evidence": "shared_prefs_plain=True",
                "location": "shared_prefs/*.xml",
                "fix": "使用 EncryptedSharedPreferences / Keystore",
            })
        if storage.get("external_db"):
            out.append({
                "id": "STG-003",
                "title": "数据库存放外部存储",
                "severity": "medium",
                "evidence": "external_db=True",
                "location": "外部路径",
                "fix": "数据库放 /data/data/<pkg>/",
            })
        return out

    # ------------------------------------------------------------------ #
    @staticmethod
    def _overall(counts: Dict[str, int]) -> str:
        if counts.get("critical") or counts.get("high", 0) >= 3:
            return "high"
        if counts.get("medium", 0) >= 3:
            return "medium"
        return "low"
