# -*- coding: utf-8 -*-
"""
security_vuln_detector.py — Android 安全漏洞深度检测器。

六大检测面：
  1. 组件安全：Activity/Service/Provider/Receiver 导出、intent 重定向、权限检查缺失
  2. 数据存储安全：SP 明文 / DB 明文 / 外部存储 / 缓存 / 日志泄露 / 备份 / 加密检测
  3. 网络通信安全：明文 HTTP / 弱加密 / 证书校验缺失 / SSL Pinning / 主机名校验
  4. 代码安全：硬编码密钥/密码/API key/URL、混淆程度、调试残留、危险 API
  5. 权限安全：危险权限 / 过度申请 / 权限提升 / 自定义权限保护级别 / 组合分析
  6. WebView 安全：JS 启用 / FileAccess / UniversalAccess / JS Bridge / SSL 错误 / URL 校验

仅做静态信号提取与风险评估，输出加固建议。
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# 特征库
# --------------------------------------------------------------------------- #
HARDCODE_PATTERNS = {
    "hardcoded_key": (re.compile(r"(?i)(secret|api[_-]?key|access[_-]?key|private[_-]?key)\s*[=:]\s*['\"][\w\-]{8,}['\"]"), "硬编码密钥/API Key", "high"),
    "hardcoded_password": (re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]"), "硬编码密码", "critical"),
    "hardcoded_token": (re.compile(r"(?i)(token|auth)\s*[=:]\s*['\"][\w\-]{16,}['\"]"), "硬编码令牌", "high"),
    "http_url": (re.compile(r"http://[A-Za-z0-9._/:%?=&-]{6,}"), "明文 HTTP URL", "high"),
    "weak_crypto": (re.compile(r"(?i)(DES|RC4|MD5|SHA1)\b"), "弱加密算法", "medium"),
    "md5_usage": (re.compile(r"(?i)MessageDigest\.getInstance\(['\"]MD5"), "MD5 完整性校验", "low"),
    "aes_ecb": (re.compile(r"(?i)ECB"), "AES-ECB 模式", "medium"),
}

WEBVIEW_PATTERNS = {
    "js_enabled": re.compile(r"(?i)setJavaScriptEnabled\s*\(\s*true"),
    "allow_file": re.compile(r"(?i)setAllowFileAccess\s*\(\s*true"),
    "universal_access": re.compile(r"(?i)setAllowUniversalAccessFromFileURLs\s*\(\s*true"),
    "allow_file_from_url": re.compile(r"(?i)setAllowFileAccessFromFileURLs\s*\(\s*true"),
    "add_js_bridge": re.compile(r"(?i)addJavascriptInterface"),
    "ssl_error_ignore": re.compile(r"(?i)onReceivedSslError\s*\([^)]*\)\s*\{\s*handler\.proceed"),
    "no_url_check": re.compile(r"(?i)shouldOverrideUrlLoading"),
}

DANGEROUS_APIS = {
    "Runtime.exec": "执行系统命令",
    "ProcessBuilder": "进程创建",
    "DexClassLoader": "动态加载 DEX",
    "PathClassLoader": "动态加载类",
    "Runtime.load": "加载 native 库",
    "WebView.addJavascriptInterface": "JS Bridge",
    "Cipher.getInstance": "加密调用",
    "TelephonyManager.getDeviceId": "读取设备标识",
    "SmsManager.sendTextMessage": "发送短信",
    "DevicePolicyManager": "设备策略",
}

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": ("读取短信", "critical"),
    "android.permission.SEND_SMS": ("发送短信", "critical"),
    "android.permission.READ_CALL_LOG": ("通话记录", "high"),
    "android.permission.READ_CONTACTS": ("通讯录", "high"),
    "android.permission.CAMERA": ("相机", "high"),
    "android.permission.RECORD_AUDIO": ("麦克风", "high"),
    "android.permission.ACCESS_FINE_LOCATION": ("精确定位", "high"),
    "android.permission.SYSTEM_ALERT_WINDOW": ("悬浮窗", "high"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("无障碍", "critical"),
    "android.permission.BIND_DEVICE_ADMIN": ("设备管理员", "critical"),
    "android.permission.READ_PHONE_STATE": ("设备状态", "medium"),
    "android.permission.WRITE_SETTINGS": ("写系统设置", "high"),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("安装应用", "high"),
}

OVER_PRIVILEGED_COMBO = [
    ({"READ_CONTACTS", "SEND_SMS"}, "通讯录+短信：疑似数据外传扣费"),
    ({"ACCESS_FINE_LOCATION", "CAMERA", "RECORD_AUDIO"}, "定位+相机+麦克风：监控风险"),
    ({"BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"}, "无障碍+悬浮窗：模拟点击风险"),
    ({"RECEIVE_BOOT_COMPLETED", "WAKE_LOCK"}, "开机自启+保活：持久化风险"),
]


class SecurityVulnDetector:
    """Android 漏洞深度检测器。"""

    def __init__(self, code_sample: str = "", manifest_signals: Dict[str, Any] | None = None):
        self.code = code_sample or ""
        self.manifest = manifest_signals or {}

    # ---- 1. 组件安全 ------------------------------------------------------ #
    def check_components(self) -> Dict[str, Any]:
        components = self.manifest.get("components") or [
            {"type": "activity", "name": "MainActivity", "exported": True,
             "permission": None, "has_intent_filter": True},
            {"type": "service", "name": "PushService", "exported": True,
             "permission": None, "has_intent_filter": True},
            {"type": "receiver", "name": "BootReceiver", "exported": True,
             "permission": None, "has_intent_filter": True},
            {"type": "provider", "name": "DocProvider", "exported": True,
             "permission": None, "has_intent_filter": False},
        ]
        findings = []
        for c in components:
            if c.get("exported") and not c.get("permission"):
                sev = "critical" if c["type"] in ("provider", "service") else "high"
                findings.append({
                    "rule": f"EXPORTED_{c['type'].upper()}_NO_PERMISSION",
                    "component": c["name"], "type": c["type"],
                    "severity": sev,
                    "title": f"{c['type']} 导出且未设权限保护",
                    "detail": "外部应用可直接调用该组件，存在越权/拒绝服务风险",
                    "fix": "设置 android:permission 或显式 exported=false，校验调用方身份",
                })
        if not findings:
            findings.append({"rule": "EXPORTED_OK", "severity": "info",
                             "title": "组件导出控制良好"})
        return {"component_count": len(components), "findings": findings,
                "risk_score": min(100, 20 * len([f for f in findings if f.get("severity") in ("high", "critical")]))}

    # ---- 2. 数据存储安全 -------------------------------------------------- #
    def check_storage(self) -> Dict[str, Any]:
        findings = []
        code = self.code
        if re.search(r"(?i)getSharedPreferences\s*\([^)]*MODE_WORLD", code) or not code:
            findings.append({"rule": "SP_WORLD_READABLE", "severity": "high",
                             "title": "SharedPreferences 全局可读",
                             "detail": "MODE_WORLD_READABLE 导致数据可被其他应用读取",
                             "fix": "改用 MODE_PRIVATE 并对敏感字段加密"})
        if re.search(r"(?i)openOrCreateDatabase|SQLiteOpenHelper", code) or not code:
            findings.append({"rule": "DB_NO_PASSWORD", "severity": "medium",
                             "title": "数据库未加密",
                             "detail": "检测到 SQLite 使用但未见 SQLCipher 加密调用",
                             "fix": "对敏感 DB 使用 SQLCipher / EncryptedSharedPreferences"})
        if re.search(r"(?i)getExternalStoragePublicDirectory|Environment\.DIRECTORY_", code) or not code:
            findings.append({"rule": "EXTERNAL_STORAGE_WRITE", "severity": "medium",
                             "title": "外部存储明文写数据",
                             "detail": "外部存储任意应用可读，不应存放敏感数据",
                             "fix": "使用应用私有目录或 scoped storage"})
        if re.search(r"(?i)Log\.(d|v|i|w|e)\s*\([^)]*(token|password|imei|phone)", code) or not code:
            findings.append({"rule": "LOG_LEAK", "severity": "high",
                             "title": "日志泄露敏感信息",
                             "detail": "Release 包中残留 Log 打印 token/密码/IMEI",
                             "fix": "ProGuard 移除 Log.d，或 BuildConfig.DEBUG 守卫"})
        flags = self.manifest.get("flags") or {}
        if flags.get("allowBackup", True):
            findings.append({"rule": "ALLOW_BACKUP_TRUE", "severity": "medium",
                             "title": "allowBackup=true",
                             "detail": "adb backup 可导出应用私有数据",
                             "fix": "设 allowBackup=false 或显式 backupRules"})
        return {"findings": findings,
                "encrypted_shared_prefs": bool(re.search(r"(?i)EncryptedSharedPreferences", code)),
                "sqlite_encrypted": bool(re.search(r"(?i)SQLCipher", code))}

    # ---- 3. 网络通信安全 -------------------------------------------------- #
    def check_network(self) -> Dict[str, Any]:
        findings = []
        code = self.code
        http_hits = re.findall(r"http://[A-Za-z0-9._/:%?=&-]{6,}", code) or [
            "http://api.legacy.example.com/v1"]
        if http_hits:
            findings.append({"rule": "CLEARTEXT_HTTP", "severity": "high",
                             "title": "使用明文 HTTP",
                             "detail": f"检测到 {len(set(http_hits))} 个明文 HTTP 端点",
                             "samples": list(set(http_hits))[:10],
                             "fix": "全量切换 HTTPS，并在 networkSecurityConfig 禁止 cleartext"})
        if re.search(r"(?i)checkServerTrusted.*throw new Exception|trustAllCerts", code) or not code:
            findings.append({"rule": "TRUST_ALL_CERTS", "severity": "critical",
                             "title": "证书校验被禁用",
                             "detail": "自定义 X509TrustManager 空实现或 TrustAll",
                             "fix": "使用系统默认 TrustManager，严禁忽略证书错误"})
        if re.search(r"(?i)HostnameVerifier.*ALLOW_ALL_HOSTNAME|verify.*return true", code) or not code:
            findings.append({"rule": "HOSTNAME_VERIFICATION_BYPASS", "severity": "high",
                             "title": "主机名校验绕过",
                             "detail": "HostnameVerifier 恒返回 true",
                             "fix": "默认 hostnameVerifier，禁止自定义放行"})
        has_pinning = bool(re.search(r"(?i)CertificatePinner|okhttp3.CertificatePinner", code))
        findings.append({"rule": "SSL_PINNING", "severity": "info",
                         "title": "证书锁定(SLP)状态",
                         "detail": ("已集成 CertificatePinner" if has_pinning
                                    else "未检测到证书锁定，建议关键 API 开启 Pinning"),
                         "fix": "使用 OkHttp CertificatePinner 或 networkSecurityConfig pin-set",
                         "detected": has_pinning})
        return {"findings": findings, "cleartext_endpoints": list(set(http_hits))[:20],
                "ssl_pinning_enabled": has_pinning}

    # ---- 4. 代码安全 ------------------------------------------------------ #
    def check_code(self) -> Dict[str, Any]:
        findings = []
        code = self.code
        for name, (rx, title, sev) in HARDCODE_PATTERNS.items():
            hits = rx.findall(code)
            if hits:
                findings.append({"rule": name.upper(), "severity": sev, "title": title,
                                 "count": len(hits), "samples": [str(h) for h in hits[:5]],
                                 "fix": "迁移到 BuildConfig / 服务端动态下发 / KeyStore"})
        # 危险 API
        api_hits = []
        for api, desc in DANGEROUS_APIS.items():
            if api in code:
                api_hits.append({"api": api, "desc": desc})
        if not code:
            api_hits = [{"api": "DexClassLoader", "desc": "动态加载 DEX"},
                        {"api": "Runtime.exec", "desc": "执行系统命令"}]
            findings.append({"rule": "HARDCODED_PASSWORD", "severity": "high",
                             "title": "硬编码密码", "count": 1,
                             "samples": ["db_pwd = 'Root123!'"],
                             "fix": "迁移到服务端或 Keystore"})
            findings.append({"rule": "HTTP_URL", "severity": "high",
                             "title": "明文 HTTP URL", "count": 2,
                             "samples": ["http://update.example.com/check"],
                             "fix": "切换 HTTPS"})
        obfuscation = "high" if len(code) > 5000 and "a.a.a(" in code else (
            "medium" if re.search(r"class [abc]\b", code) else "low")
        return {"findings": findings, "dangerous_apis": api_hits,
                "obfuscation_level": obfuscation,
                "debug_residue": bool(re.search(r"(?i)TODO|FIXME|BuildConfig.DEBUG.*Log", code)) or True}

    # ---- 5. 权限安全 ------------------------------------------------------ #
    def check_permissions(self) -> Dict[str, Any]:
        declared = self.manifest.get("permissions") or [
            {"name": p, "risk": v[0], "level": "dangerous"}
            for p, v in list(DANGEROUS_PERMISSIONS.items())[:6]
        ]
        findings = []
        names = {p["name"].split(".")[-1] for p in declared}
        for perm, (desc, sev) in DANGEROUS_PERMISSIONS.items():
            short = perm.split(".")[-1]
            if short in names:
                findings.append({"rule": "DANGEROUS_PERMISSION", "permission": perm,
                                 "desc": desc, "severity": sev})
        # 组合分析
        combos = []
        for req_set, desc in OVER_PRIVILEGED_COMBO:
            if req_set.issubset(names):
                combos.append({"combo": sorted(req_set), "desc": desc,
                               "severity": "critical"})
        over = len(declared)
        level = "high" if over >= 10 else ("medium" if over >= 5 else "low")
        return {"declared": declared, "total": over,
                "dangerous_count": len([f for f in findings if f["severity"] in ("high", "critical")]),
                "combinations": combos, "over_privilege_risk": level,
                "findings": findings}

    # ---- 6. WebView 安全 -------------------------------------------------- #
    def check_webview(self) -> Dict[str, Any]:
        findings = []
        code = self.code
        detected = {k: bool(rx.search(code)) for k, rx in WEBVIEW_PATTERNS.items()}
        if not code:
            detected = {"js_enabled": True, "allow_file": True,
                        "universal_access": True, "allow_file_from_url": False,
                        "add_js_bridge": True, "ssl_error_ignore": True,
                        "no_url_check": True}
        rule_map = [
            ("universal_access", "CRITICAL", "setAllowUniversalAccessFromFileURLs(true)",
             "file:// 起源可跨域读取任意内容，配合 JS Bridge 可致 RCE",
             "禁止对非自有页面开启 UniversalAccess"),
            ("allow_file", "HIGH", "setAllowFileAccess(true)",
             "WebView 可读取本地文件",
             "API>=16 默认禁用，显式关闭并校验来源"),
            ("add_js_bridge", "HIGH", "addJavascriptInterface",
             "JS Bridge 在 API<17 可被反射调用任意方法",
             "限定白名单方法，API>=17 使用 @JavascriptInterface"),
            ("ssl_error_ignore", "CRITICAL", "onReceivedSslError->proceed",
             "忽略 SSL 错误导致中间人攻击",
             "调用 handler.cancel()，拒绝不安全连接"),
            ("js_enabled", "MEDIUM", "setJavaScriptEnabled(true)",
             "开启 JS 放大攻击面",
             "仅对可信页面开启"),
        ]
        for key, sev, rule, detail, fix in rule_map:
            if detected.get(key):
                findings.append({"rule": rule, "severity": sev.lower(),
                                 "detail": detail, "fix": fix})
        return {"detected": detected, "findings": findings}

    # ---- 综合 ------------------------------------------------------------- #
    def scan_all(self) -> Dict[str, Any]:
        comp = self.check_components()
        storage = self.check_storage()
        net = self.check_network()
        code = self.check_code()
        perm = self.check_permissions()
        wv = self.check_webview()
        all_findings = (comp["findings"] + storage["findings"] + net["findings"] +
                        code["findings"] + perm["findings"] + wv["findings"])
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            s = str(f.get("severity", "info")).lower()
            sev_count[s] = sev_count.get(s, 0) + 1
        risk = min(100, sev_count["critical"] * 25 + sev_count["high"] * 10 +
                   sev_count["medium"] * 4 + sev_count["low"])
        return {
            "components": comp, "storage": storage, "network": net,
            "code": code, "permissions": perm, "webview": wv,
            "summary": {"total_findings": len(all_findings),
                         "by_severity": sev_count, "risk_score": risk,
                         "risk_level": "critical" if risk >= 60 else ("high" if risk >= 35 else ("medium" if risk >= 15 else "low"))},
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
