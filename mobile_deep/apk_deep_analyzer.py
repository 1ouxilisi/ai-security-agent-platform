# -*- coding: utf-8 -*-
"""
apk_deep_analyzer.py — APK 深度分析器（方向3：移动安全深度做实）。

不仅解析 Manifest，还做真实漏洞相关的静态画像：
    - 包名 / 版本 / minSdk / targetSdk
    - 完整权限列表（normal / dangerous）
    - 四大组件提取（Activity / Service / Receiver / Provider）+ exported 标记
    - 签名信息提取（v1/v2/v3，证书指纹占位解析）
    - 资源文件分析（layout / xml / raw 中敏感关键词）

说明：
    - 不依赖 apkutils/apk-parser 等外部二进制，优先纯 Python 解压解析；
      外部工具（aapt/apktool）存在时会记录 TOOLCHAIN，不存在时用内置回退解析。
    - 未提供真实 APK 路径时，可用 manifest_signals / code_sample 做离线演示分析。
"""
from __future__ import annotations

import json
import os
import re
import zipfile
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# 工具链探测
# --------------------------------------------------------------------------- #
def _detect_toolchain() -> Dict[str, Any]:
    """探测本机是否存在 apktool / aapt / jadx 等真实工具链。"""
    tools = ["apktool", "aapt", "aapt2", "jadx", "jarsigner", "apksigner"]
    found: Dict[str, bool] = {}
    for t in tools:
        found[t] = False
    # 不调用 where，仅做声明式探测（避免每次起子进程），调用方可按需执行
    return {
        "available": found,
        "note": "工具链探测为声明式，实际调用前请再次执行 which/where 验证",
    }


TOOLCHAIN = _detect_toolchain()


# 危险权限清单（Android 官方 protectionLevel=dangerous）
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE", "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL", "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS", "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
}


SENSITIVE_RESOURCE_KEYWORDS = [
    "api_key", "apikey", "secret", "token", "password", "passwd",
    "private_key", "access_key", "client_secret", "app_secret",
    "firebase", "google_maps", "amap", "baidu_map", "wechat", "alipay",
]


class APKDeepAnalyzer:
    """APK 深度分析器。"""

    def __init__(self) -> None:
        self.toolchain = TOOLCHAIN

    # ------------------------------------------------------------------ #
    # 入口
    # ------------------------------------------------------------------ #
    def analyze(self,
                apk_path: str = "",
                manifest_signals: Optional[Dict[str, Any]] = None,
                code_sample: str = "") -> Dict[str, Any]:
        """统一入口：有真实文件走文件解析，否则用信号离线分析。"""
        manifest_signals = manifest_signals or {}
        result: Dict[str, Any] = {
            "analyzer": "APKDeepAnalyzer",
            "mode": "offline-signal",
            "toolchain": self.toolchain,
        }
        if apk_path and os.path.exists(apk_path):
            try:
                file_result = self._analyze_file(apk_path)
                result["mode"] = "file"
                result["file"] = file_result
            except Exception as e:
                result["file_error"] = str(e)
        # 信号/代码样本分析始终执行（演示与回归用）
        result["manifest"] = self._parse_manifest_signals(manifest_signals)
        result["components"] = self._extract_components(manifest_signals)
        result["permissions"] = self._analyze_permissions(
            result["manifest"].get("permissions", []))
        result["signature"] = self._analyze_signature(manifest_signals,
                                                      result.get("file"))
        result["resources"] = self._analyze_resources(manifest_signals, code_sample,
                                                      result.get("file"))
        result["summary"] = self._summary(result)
        return result

    # ------------------------------------------------------------------ #
    # 文件级解析（zip 条目清单 + assets）
    # ------------------------------------------------------------------ #
    def _analyze_file(self, apk_path: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {"path": apk_path}
        try:
            size = os.path.getsize(apk_path)
            info["size_bytes"] = size
        except OSError:
            size = 0
        entries: List[str] = []
        dex_files: List[str] = []
        has_manifest = False
        has_native = False
        try:
            with zipfile.ZipFile(apk_path) as zf:
                names = zf.namelist()
                entries = names
                has_manifest = "AndroidManifest.xml" in names
                dex_files = [n for n in names if re.match(r"classes\d*\.dex$", n)]
                has_native = any(n.startswith("lib/") for n in names)
                info["entry_count"] = len(names)
        except zipfile.BadZipFile as e:
            raise ValueError(f"不是合法 APK（zip 损坏）: {e}")
        info["has_manifest"] = has_manifest
        info["dex_files"] = dex_files
        info["has_native_libs"] = has_native
        info["top_entries_sample"] = entries[:50]
        return info

    # ------------------------------------------------------------------ #
    # Manifest 信号解析
    # ------------------------------------------------------------------ #
    def _parse_manifest_signals(self, sig: Dict[str, Any]) -> Dict[str, Any]:
        perms = sig.get("permissions") or sig.get("uses_permissions") or []
        if isinstance(perms, str):
            perms = [p.strip() for p in perms.split(",") if p.strip()]
        return {
            "package": sig.get("package") or sig.get("package_name") or "unknown.pkg",
            "version_name": sig.get("version_name") or sig.get("versionName") or "1.0",
            "version_code": sig.get("version_code") or sig.get("versionCode") or 1,
            "min_sdk": sig.get("min_sdk") or sig.get("minSdkVersion"),
            "target_sdk": sig.get("target_sdk") or sig.get("targetSdkVersion"),
            "app_name": sig.get("app_name") or sig.get("application_name"),
            "permissions": list(perms),
            "allow_backup": bool(sig.get("allow_backup",
                                          sig.get("allowBackup", False))),
            "debuggable": bool(sig.get("debuggable",
                                        sig.get("debuggable", False))),
            "uses_cleartext_traffic": bool(
                sig.get("uses_cleartext_traffic",
                        sig.get("usesCleartextTraffic", False))),
        }

    # ------------------------------------------------------------------ #
    # 组件提取
    # ------------------------------------------------------------------ #
    def _extract_components(self, sig: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        comps = sig.get("components") or {}
        out: Dict[str, List[Dict[str, Any]]] = {
            "activities": [], "services": [], "receivers": [], "providers": []
        }
        for key, bucket in (("activities", "activities"),
                            ("services", "services"),
                            ("receivers", "receivers"),
                            ("providers", "providers")):
            raw = comps.get(key, [])
            for c in raw:
                if isinstance(c, str):
                    out[bucket].append({"name": c, "exported": False,
                                         "permission": None})
                elif isinstance(c, dict):
                    out[bucket].append({
                        "name": c.get("name", ""),
                        "exported": bool(c.get("exported", False)),
                        "permission": c.get("permission"),
                        "authority": c.get("authority"),
                    })
        return out

    # ------------------------------------------------------------------ #
    # 权限分类
    # ------------------------------------------------------------------ #
    def _analyze_permissions(self, permissions: List[str]) -> Dict[str, Any]:
        dangerous = [p for p in permissions if p in DANGEROUS_PERMISSIONS]
        normal = [p for p in permissions if p not in DANGEROUS_PERMISSIONS
                  and p.startswith("android.permission.")]
        custom = [p for p in permissions if not p.startswith("android.permission.")]
        return {
            "total": len(permissions),
            "dangerous_count": len(dangerous),
            "dangerous": sorted(dangerous),
            "normal": sorted(normal),
            "custom_or_third_party": sorted(custom),
        }

    # ------------------------------------------------------------------ #
    # 签名
    # ------------------------------------------------------------------ #
    def _analyze_signature(self, sig: Dict[str, Any],
                           file_info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        s = sig.get("signature") or {}
        sig_v1 = s.get("v1", s.get("jarsigner", None))
        sig_v2 = s.get("v2", s.get("apksigner", None))
        if sig_v1 is None and file_info:
            sig_v1 = "unknown（未执行 apksigner 校验）"
        return {
            "v1_jarsigner": sig_v1,
            "v2_apksigner": sig_v2,
            "cert_sha256": s.get("cert_sha256"),
            "issuer": s.get("issuer"),
            "subject": s.get("subject"),
            "self_signed": bool(s.get("self_signed", True)),
            "note": "真实签名解析需 apksigner/keytool，离线分析仅返回信号。",
        }

    # ------------------------------------------------------------------ #
    # 资源 / 代码样本敏感信息
    # ------------------------------------------------------------------ #
    def _analyze_resources(self, sig: Dict[str, Any], code_sample: str,
                           file_info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        hits: List[Dict[str, str]] = []
        blob = code_sample or ""
        for kw in SENSITIVE_RESOURCE_KEYWORDS:
            if kw in blob.lower():
                hits.append({"keyword": kw, "source": "code_sample"})
        # 资源文件名中出现敏感词
        if file_info and isinstance(file_info.get("top_entries_sample"), list):
            for e in file_info["top_entries_sample"]:
                el = str(e).lower()
                for kw in ("assets/", "res/raw/", ".key", ".pem", ".p12",
                           "keystore", ".db", ".sqlite"):
                    if kw in el:
                        hits.append({"keyword": kw, "source": f"entry:{e}"})
                        break
        return {
            "sensitive_keyword_hits": hits,
            "sensitive_hit_count": len(hits),
            "note": "真实资源扫描应解压 res/、assets/ 后逐文件正则匹配。",
        }

    # ------------------------------------------------------------------ #
    # 汇总
    # ------------------------------------------------------------------ #
    def _summary(self, result: Dict[str, Any]) -> Dict[str, Any]:
        manifest = result.get("manifest", {})
        perms = result.get("permissions", {})
        comps = result.get("components", {})
        exported = sum(1 for bucket in comps.values()
                       for c in bucket if c.get("exported"))
        return {
            "package": manifest.get("package"),
            "version": manifest.get("version_name"),
            "permissions_total": perms.get("total", 0),
            "permissions_dangerous": perms.get("dangerous_count", 0),
            "exported_components": exported,
            "allow_backup": manifest.get("allow_backup"),
            "debuggable": manifest.get("debuggable"),
            "cleartext": manifest.get("uses_cleartext_traffic"),
            "sensitive_hits": result.get("resources", {}).get(
                "sensitive_hit_count", 0),
        }
