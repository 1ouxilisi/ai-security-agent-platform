# -*- coding: utf-8 -*-
"""
mobile_deep_dashboard.py — 移动安全深度控制台聚合（方向3）。

把 APK 深度分析 / 静态扫描 / 权限评级 / 漏洞检测 / 动态框架聚合成一次"深度体检"。
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from .apk_deep_analyzer import APKDeepAnalyzer
from .static_code_scanner import StaticCodeScanner
from .permission_risk_rater import PermissionRiskRater
from .vuln_detector import VulnDetector
from .dynamic_framework import DynamicAnalysisFramework


# 演示用"样本 APK"信号（离线演示，不依赖真实文件）
DEMO_MANIFEST: Dict[str, Any] = {
    "package": "com.example.bankdemo",
    "version_name": "3.2.1",
    "version_code": 321,
    "min_sdk": 21,
    "target_sdk": 33,
    "app_name": "BankDemo",
    "permissions": [
        "android.permission.INTERNET",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.SYSTEM_ALERT_WINDOW",
    ],
    "allow_backup": True,
    "debuggable": False,
    "uses_cleartext_traffic": True,
    "components": {
        "activities": [
            {"name": "com.example.bankdemo.MainActivity", "exported": True},
            {"name": "com.example.bankdemo.SettingsActivity", "exported": False},
        ],
        "services": [
            {"name": "com.example.bankdemo.PushService", "exported": True,
             "permission": None},
        ],
        "receivers": [],
        "providers": [
            {"name": "com.example.bankdemo.SecretProvider",
             "exported": True, "authority": "com.example.bankdemo.secret"},
        ],
    },
    "signature": {"self_signed": True},
}

DEMO_CODE = """
public void initWebView(WebView wv) {
    wv.getSettings().setJavaScriptEnabled(true);
    wv.addJavascriptInterface(new JsBridge(), "bridge");
    wv.getSettings().setAllowFileAccess(true);
}
public void onReceivedSslError(WebView v, SslErrorHandler h, SslError e) {
    h.proceed();
}
private static final String AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
private static final String DB_URL = "mongodb://user:passw0rd@10.0.0.1:27017/app";
private static final String password = "Admin@123456";
new FileOutputStream(f, Context.MODE_WORLD_READABLE);
Log.d("BANK", "token=" + token);
"""


class MobileDeepDashboard:
    """控制台聚合器。"""

    def __init__(self) -> None:
        self.analyzer = APKDeepAnalyzer()
        self.scanner = StaticCodeScanner()
        self.rater = PermissionRiskRater()
        self.detector = VulnDetector()
        self.dynamic = DynamicAnalysisFramework()
        self._reports: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ #
    # 一键深度体检
    # ------------------------------------------------------------------ #
    def deep_assess(self,
                    apk_path: str = "",
                    manifest_signals: Optional[Dict[str, Any]] = None,
                    code_sample: str = "") -> Dict[str, Any]:
        manifest_signals = manifest_signals or {}
        rid = "rep-" + uuid.uuid4().hex[:10]

        # 1) APK 深度画像
        apk_info = self.analyzer.analyze(apk_path=apk_path,
                                          manifest_signals=manifest_signals,
                                          code_sample=code_sample)
        # 2) 静态代码扫描
        static_info = self.scanner.scan(code_sample=code_sample)
        # 3) 权限评级
        perm_info = self.rater.rate(
            apk_info["manifest"].get("permissions", []))
        # 4) 漏洞检测
        vuln_info = self.detector.detect(
            manifest_signals=apk_info["manifest"],
            code_sample=code_sample,
            components=apk_info["components"],
        )

        report = {
            "report_id": rid,
            "created_at": time.time(),
            "apk": apk_info,
            "static_scan": static_info,
            "permissions": perm_info,
            "vulns": vuln_info,
            "overall": self._overall(apk_info, static_info, perm_info,
                                     vuln_info),
        }
        self._reports[rid] = report
        return report

    # ------------------------------------------------------------------ #
    # 演示
    # ------------------------------------------------------------------ #
    def demo_assess(self) -> Dict[str, Any]:
        return self.deep_assess(manifest_signals=DEMO_MANIFEST,
                                 code_sample=DEMO_CODE)

    # ------------------------------------------------------------------ #
    # 报告列表 / 详情
    # ------------------------------------------------------------------ #
    def list_reports(self) -> List[Dict[str, Any]]:
        return [{"report_id": r["report_id"],
                 "package": r["apk"]["summary"]["package"],
                 "created_at": r["created_at"],
                 "overall_level": r["overall"]["level"]}
                for r in self._reports.values()]

    def get_report(self, rid: str) -> Optional[Dict[str, Any]]:
        return self._reports.get(rid)

    # ------------------------------------------------------------------ #
    # 动态分析转发
    # ------------------------------------------------------------------ #
    def dynamic_env(self) -> Dict[str, Any]:
        return self.dynamic.environment()

    def list_scripts(self) -> Dict[str, Any]:
        return self.dynamic.list_scripts()

    def get_script(self, name: str) -> Dict[str, Any]:
        return self.dynamic.get_script(name)

    def start_dynamic(self, pkg: str, script: str,
                      device_id: str = "") -> Dict[str, Any]:
        return self.dynamic.start_task(pkg, script, device_id)

    def list_dynamic_tasks(self) -> List[Dict[str, Any]]:
        return self.dynamic.list_tasks()

    # ------------------------------------------------------------------ #
    # 总分
    # ------------------------------------------------------------------ #
    @staticmethod
    def _overall(apk: Dict[str, Any], static: Dict[str, Any],
                 perm: Dict[str, Any], vuln: Dict[str, Any]) -> Dict[str, Any]:
        score = 10.0
        score -= min(3.0, static["counts"].get("critical", 0) * 1.5)
        score -= min(2.0, static["counts"].get("high", 0) * 0.5)
        score -= min(2.0, perm["dangerous_count"] * 0.3)
        score -= min(3.0, vuln["counts"].get("critical", 0) * 1.5)
        score -= min(1.5, vuln["counts"].get("high", 0) * 0.3)
        score = max(0.0, round(score, 2))
        level = "high" if score < 6.0 else ("medium" if score < 8.0 else "low")
        return {
            "score": score,
            "level": level,
            "headline": (f"{apk['summary']['package']} 共发现 "
                         f"{vuln['total']} 个漏洞, "
                         f"{static['total']} 条代码风险, "
                         f"{perm['dangerous_count']} 个危险权限"),
        }
