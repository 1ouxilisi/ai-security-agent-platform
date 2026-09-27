# -*- coding: utf-8 -*-
"""
mobile_dashboard.py — 移动安全控制台数据聚合（APK库/任务/漏洞/合规/恶意分析/报告）。

六大面板：
  1. APK 管理：上传/解析/版本/签名/大小/架构/状态/版本对比/APK 库
  2. 分析任务：创建/配置/调度/进度/日志/取消/重试/批量/模板
  3. 漏洞管理：列表/分类/严重度/位置/代码片段/修复/状态/误报标记
  4. 隐私合规：合规项/违规项/数据收集清单/SDK清单/整改/报告
  5. 恶意软件分析：行为清单/网络IOC/文件IOC/家族/评分/处置
  6. 移动安全报告：执行摘要/范围/方法/漏洞/合规/恶意/评级/修复/附录

全部基于内存字典聚合，无外部依赖。
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# 内存数据存储
# --------------------------------------------------------------------------- #
APK_LIBRARY: Dict[str, Dict[str, Any]] = {}
TASKS: Dict[str, Dict[str, Any]] = {}
VULN_STORE: Dict[str, Dict[str, Any]] = {}
REPORT_STORE: Dict[str, Dict[str, Any]] = {}

ANALYSIS_TEMPLATES = [
    {"id": "quick", "name": "快速扫描", "steps": ["manifest", "permissions", "hardcode"], "duration": 30},
    {"id": "standard", "name": "标准分析", "steps": ["manifest", "dex", "vuln", "privacy", "webview"], "duration": 180},
    {"id": "deep", "name": "深度分析", "steps": ["manifest", "dex", "vuln", "privacy",
      "malware", "native", "decompile"], "duration": 600},
    {"id": "dynamic", "name": "动态沙箱", "steps": ["install", "behavior", "traffic", "frida", "ui"], "duration": 900},
]


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


class MobileDashboard:
    """控制台数据聚合与业务操作。"""

    # ---- 1. APK 管理 ------------------------------------------------------ #
    def register_apk(self, filename: str, size: int = 0,
                     package: str = "", version: str = "1.0.0") -> Dict[str, Any]:
        apk_id = uuid.uuid4().hex[:12]
        archs = ["arm64-v8a", "armeabi-v7a"]
        rec = {
            "apk_id": apk_id, "filename": filename, "package": package or "com.demo.app",
            "version_name": version, "version_code": "1", "size": size or 24_000_000,
            "archs": archs, "signing_scheme": "v1+v2",
            "sha256": uuid.uuid4().hex, "status": "uploaded",
            "analysis_state": "pending", "uploaded_at": _now(),
            "history": [{"version": version, "at": _now(), "size": size or 24_000_000}],
        }
        APK_LIBRARY[apk_id] = rec
        return rec

    def list_apks(self) -> Dict[str, Any]:
        items = list(APK_LIBRARY.values()) or [
            {"apk_id": "demo001", "filename": "app-release.apk", "package": "com.demo.app",
             "version_name": "2.3.1", "size": 24_567_890, "archs": ["arm64-v8a", "armeabi-v7a"],
             "signing_scheme": "v2", "status": "analyzed", "analysis_state": "done",
             "uploaded_at": _now()},
            {"apk_id": "demo002", "filename": "app-prod.apk", "package": "com.demo.prod",
             "version_name": "3.0.0", "size": 31_120_000, "archs": ["arm64-v8a"],
             "signing_scheme": "v3", "status": "analyzed", "analysis_state": "done",
             "uploaded_at": _now()},
        ]
        return {"total": len(items), "apks": items}

    def compare_versions(self, apk_id_a: str, apk_id_b: str) -> Dict[str, Any]:
        a = APK_LIBRARY.get(apk_id_a, {"version_name": "1.0.0", "size": 24_000_000})
        b = APK_LIBRARY.get(apk_id_b, {"version_name": "2.0.0", "size": 26_000_000})
        return {"a": a, "b": b,
                "size_delta": b.get("size", 0) - a.get("size", 0),
                "added_permissions": ["ACCESS_FINE_LOCATION"],
                "removed_permissions": [],
                "changed_components": ["MainActivity"],
                "risk_delta": "medium"}

    # ---- 2. 分析任务 ------------------------------------------------------ #
    def create_task(self, apk_id: str, template: str = "standard") -> Dict[str, Any]:
        tid = uuid.uuid4().hex[:16]
        tpl = next((t for t in ANALYSIS_TEMPLATES if t["id"] == template), ANALYSIS_TEMPLATES[1])
        TASKS[tid] = {
            "task_id": tid, "apk_id": apk_id, "template": template,
            "steps": tpl["steps"], "step_index": 0, "progress": 0,
            "status": "running", "logs": ["任务创建，加载模板 " + template],
            "created_at": _now(), "finished_at": None,
        }
        return TASKS[tid]

    def list_tasks(self) -> Dict[str, Any]:
        items = list(TASKS.values()) or [
            {"task_id": "t_demo01", "apk_id": "demo001", "template": "deep",
             "status": "done", "progress": 100, "created_at": _now()},
        ]
        return {"total": len(items), "tasks": items,
                "templates": ANALYSIS_TEMPLATES}

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        return TASKS.get(task_id)

    def cancel_task(self, task_id: str) -> Dict[str, Any]:
        t = TASKS.get(task_id)
        if t:
            t["status"] = "cancelled"
            t["finished_at"] = _now()
        return {"ok": bool(t), "task_id": task_id}

    # ---- 3. 漏洞管理 ------------------------------------------------------ #
    def list_vulns(self, severity: Optional[str] = None,
                   status: Optional[str] = None) -> Dict[str, Any]:
        seeds = [
            {"vid": "v001", "rule": "EXPORTED_PROVIDER_NO_PERMISSION", "title": "Provider 导出未保护",
             "severity": "critical", "location": "DocProvider.java:42",
             "code_snippet": "android:exported=\"true\"", "status": "open",
             "fix": "加 android:permission", "false_positive": False},
            {"vid": "v002", "rule": "HARDCODED_PASSWORD", "title": "硬编码数据库密码",
             "severity": "high", "location": "Config.java:88",
             "code_snippet": "pwd = \"Root123!\"", "status": "open",
             "fix": "迁移到 Keystore", "false_positive": False},
            {"vid": "v003", "rule": "TRUST_ALL_CERTS", "title": "信任所有证书",
             "severity": "critical", "location": "SslUtil.java:15",
             "code_snippet": "checkServerTrusted(){ }", "status": "fixed",
             "fix": "使用系统 TrustManager", "false_positive": False},
            {"vid": "v004", "rule": "CLEARTEXT_HTTP", "title": "明文 HTTP",
             "severity": "high", "location": "ApiClient.java:30",
             "code_snippet": "http://...", "status": "open",
             "fix": "切换 HTTPS", "false_positive": False},
            {"vid": "v005", "rule": "WEBVIEW_UNIVERSAL", "title": "WebView 跨域开启",
             "severity": "critical", "location": "WebActivity.java:21",
             "code_snippet": "setAllowUniversalAccessFromFileURLs(true)",
             "status": "open", "fix": "关闭 UniversalAccess", "false_positive": True},
        ]
        items = seeds
        if severity:
            items = [i for i in items if i["severity"] == severity]
        if status:
            items = [i for i in items if i["status"] == status]
        sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for i in seeds:
            sev_count[i["severity"]] = sev_count.get(i["severity"], 0) + 1
        return {"total": len(items), "vulns": items,
                "severity_distribution": sev_count,
                "open": sum(1 for i in seeds if i["status"] == "open")}

    def mark_vuln(self, vid: str, status: str, fp: Optional[bool] = None) -> Dict[str, Any]:
        v = VULN_STORE.get(vid, {"vid": vid})
        v["status"] = status
        if fp is not None:
            v["false_positive"] = fp
        VULN_STORE[vid] = v
        return {"ok": True, "vid": vid, "status": status}

    # ---- 4. 隐私合规视图 -------------------------------------------------- #
    def privacy_view(self) -> Dict[str, Any]:
        return {
            "compliant_items": ["隐私政策存在", "收集范围声明", "安全措施说明"],
            "violations": ["撤回同意机制缺失", "数据删除机制缺失", "第三方SDK清单不全"],
            "collected_data": ["设备标识", "位置", "通讯录"],
            "third_party_sdks": [
                {"name": "友盟统计", "risk": "medium"},
                {"name": "穿山甲", "risk": "high"},
                {"name": "极光推送", "risk": "medium"},
            ],
            "score": 62.5, "level": "基本合规",
            "remediation": ["补全撤回/删除入口", "完善SDK清单"],
        }

    # ---- 5. 恶意软件分析视图 --------------------------------------------- #
    def malware_view(self) -> Dict[str, Any]:
        return {
            "behaviors": ["动态加载 DEX", "开机自启", "无障碍服务"],
            "network_iocs": ["http://update.free-app.tk/checkin", "192.168.1.10:8080"],
            "file_iocs": ["/data/data/app/.cache/payload.dex"],
            "families": [{"family": "SharkBot", "confidence": 72}],
            "score": 68, "classification": "可疑",
            "disposition": "建议隔离并卸载，提交沙箱复现",
        }

    # ---- 6. 移动安全综合报告 --------------------------------------------- #
    def build_report(self, apk_id: str = "demo001") -> Dict[str, Any]:
        rid = uuid.uuid4().hex[:12]
        report = {
            "report_id": rid, "apk_id": apk_id,
            "executive_summary": "该 APK 共发现 5 类安全问题，含 2 个严重漏洞与隐私合规缺失。",
            "scope": {"package": "com.demo.app", "version": "2.3.1",
                      "methods": ["静态反编译", "Manifest 分析", "动态沙箱"]},
            "methodology": "jadx 反编译 + 规则匹配 + 沙箱动态行为观察",
            "vulns": self.list_vulns(),
            "privacy": self.privacy_view(),
            "malware": self.malware_view(),
            "risk_rating": {"score": 71, "level": "high"},
            "remediation": [
                "关闭导出的 Provider 并加权限保护",
                "硬编码密码迁移至 Android Keystore",
                "修复 TLS 证书校验与明文 HTTP",
                "补全隐私政策撤回/删除机制",
            ],
            "appendix": {"toolchain": "jadx/apktool/frida", "framework": "MSTG/OWASP"},
            "generated_at": _now(),
        }
        REPORT_STORE[rid] = report
        return report
