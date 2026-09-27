# -*- coding: utf-8 -*-
"""mobile_security_deep.py — 移动安全做实（方向1）。

能力：
    - APK 深度分析：包名 / 版本 / 权限 / 组件 / 签名（aapt / apkanalyzer / keytool）
    - 静态代码分析：硬编码密钥 / 不安全 API / 导出组件（grep + androguard 接口）
    - 动态分析接口：Frida 集成（如可用）
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

SUBPROCESS_TIMEOUT = 300

APK_ANALYZERS = ["aapt", "apktool", "androguard", "keytool", "jadx"]
FRIDA_SCRIPTS = [
    "ssl_unpinning.js", "root_detect_bypass.js",
    "crypto_listener.js", "trace_all.js",
]


def which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def run_cmd(cmd: List[str], timeout: int = SUBPROCESS_TIMEOUT) -> Dict[str, Any]:
    if not cmd:
        return {"success": False, "stdout": "", "stderr": "empty cmd",
                "returncode": -1, "elapsed_ms": 0}
    binary = cmd[0]
    if shutil.which(binary) is None:
        return {"success": False, "stdout": "",
                "stderr": f"工具未安装: {binary}",
                "returncode": 127, "elapsed_ms": 0, "tool_missing": binary}
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                              text=True, encoding="utf-8", errors="replace")
        return {
            "success": proc.returncode == 0,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "returncode": proc.returncode,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "cmd": cmd,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "stdout": "", "stderr": f"超时",
                "returncode": -1, "elapsed_ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": f"异常: {e}",
                "returncode": -1, "elapsed_ms": int((time.time() - t0) * 1000)}


class APKDeepAnalyzer:
    """APK 深度分析。"""

    def analyze(self, apk_path: str) -> Dict[str, Any]:
        if not os.path.exists(apk_path):
            return {"success": False, "error": f"APK 不存在: {apk_path}"}
        return {
            "basic": self._aapt_badging(apk_path),
            "permissions": self._aapt_permissions(apk_path),
            "components": self._components(apk_path),
            "signature": self._signature(apk_path),
            "static_issues": self._static_scan(apk_path),
        }

    def _aapt_badging(self, apk: str) -> Dict[str, Any]:
        if not which("aapt"):
            return {"available": False,
                    "hint": "apt install aapt / android-sdk-build-tools"}
        r = run_cmd(["aapt", "dump", "badging", apk], timeout=60)
        out = r.get("stdout", "")
        pkg = re.search(r"package: name='([^']+)' versionCode='(\d+)' "
                        r"versionName='([^']+)'", out)
        launch = re.search(r"launchable-activity: name='([^']+)'", out)
        sdk = re.search(r"sdkVersion:'(\d+)'", out)
        target = re.search(r"targetSdkVersion:'(\d+)'", out)
        return {
            "available": True,
            "package": pkg.group(1) if pkg else None,
            "version_code": pkg.group(2) if pkg else None,
            "version_name": pkg.group(3) if pkg else None,
            "launchable_activity": launch.group(1) if launch else None,
            "min_sdk": sdk.group(1) if sdk else None,
            "target_sdk": target.group(1) if target else None,
        }

    def _aapt_permissions(self, apk: str) -> Dict[str, Any]:
        if not which("aapt"):
            return {"available": False, "permissions": []}
        r = run_cmd(["aapt", "dump", "permissions", apk], timeout=60)
        perms = re.findall(r"uses-permission: name='([^']+)'", r.get("stdout", ""))
        dangerous = [p for p in perms if any(
            k in p for k in ["LOCATION", "CONTACT", "CAMERA",
                             "RECORD_AUDIO", "READ_SMS", "WRITE_SMS",
                             "READ_EXTERNAL", "WRITE_EXTERNAL",
                             "GET_ACCOUNTS", "READ_CALL_LOG"])]
        return {"available": True, "permissions": perms,
                "total": len(perms), "dangerous": dangerous}

    def _components(self, apk: str) -> Dict[str, Any]:
        if not which("aapt"):
            return {"available": False, "activities": [], "services": [],
                    "receivers": [], "providers": []}
        r = run_cmd(["aapt", "dump", "xmltree", apk, "AndroidManifest.xml"],
                    timeout=60)
        out = r.get("stdout", "")
        return {
            "available": True,
            "activities": re.findall(r"E: activity[^>]*android:name='([^']+)'", out),
            "services": re.findall(r"E: service[^>]*android:name='([^']+)'", out),
            "receivers": re.findall(r"E: receiver[^>]*android:name='([^']+)'", out),
            "providers": re.findall(r"E: provider[^>]*android:name='([^']+)'", out),
            "exported_true": len(re.findall(r"android:exported='true'", out)),
        }

    def _signature(self, apk: str) -> Dict[str, Any]:
        if not which("keytool"):
            return {"available": False, "hint": "keytool 未安装"}
        r = run_cmd(["keytool", "-printcert", "-jarfile", apk], timeout=60)
        out = r.get("stdout", "")
        md5 = re.search(r"MD5:\s+([0-9A-F:]+)", out)
        sha1 = re.search(r"SHA1:\s+([0-9A-F:]+)", out)
        sha256 = re.search(r"SHA256:\s+([0-9A-F:]+)", out)
        return {
            "available": True,
            "md5": md5.group(1) if md5 else None,
            "sha1": sha1.group(1) if sha1 else None,
            "sha256": sha256.group(1) if sha256 else None,
            "cert_owner": (re.search(r"Owner:\s+(.+)", out) or [None, None])[1]
            if re.search(r"Owner:\s+(.+)", out) else None,
        }

    def _static_scan(self, apk: str) -> Dict[str, Any]:
        """硬编码密钥 / 不安全 API（先解包再 grep）。"""
        issues: List[Dict[str, Any]] = []
        if not which("apktool"):
            return {"available": False,
                    "hint": "apktool 未安装（apt install apktool）",
                    "issues": issues}
        workdir = f"/tmp/apk_scan_{int(time.time())}"
        os.makedirs(workdir, exist_ok=True)
        r = run_cmd(["apktool", "d", "-f", "-o", workdir, apk], timeout=300)
        if r["returncode"] != 0:
            return {"available": False,
                    "error": r.get("stderr", "")[-500:], "issues": issues}

        # 硬编码密钥正则
        secret_patterns = {
            "AWS_AccessKey": r"AKIA[0-9A-Z]{16}",
            "AWS_SecretKey": r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([0-9a-zA-Z/+]{40})",
            "Google_API": r"AIza[0-9A-Za-z\-_]{35}",
            "PrivateKey": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
            "JWT": r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
            "Generic_Password": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
        }
        unsafe_apis = {
            "WebView_JS": r"setJavaScriptEnabled\(true\)",
            "WebView_File": r"setAllowFileAccess\(true\)",
            "TrustAllCerts": r"checkServerTrusted\(.*\)\s*\{\s*\}",
            "HostnameVerifier": r"verify\(.*\)\s*\{\s*return\s+true",
            "Debuggable": r"android:debuggable=\"true\"",
            "BackupAllowed": r"android:allowBackup=\"true\"",
        }
        for root, _dirs, files in os.walk(workdir):
            for fname in files:
                if not fname.endswith((".java", ".smali", ".xml", ".properties",
                                       ".json", ".kt")):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue
                for label, pat in {**secret_patterns, **unsafe_apis}.items():
                    for m in re.finditer(pat, content):
                        issues.append({
                            "type": label,
                            "file": os.path.relpath(fpath, workdir),
                            "match": m.group(0)[:80],
                        })
        return {"available": True, "issues": issues, "count": len(issues),
                "workdir": workdir}


class FridaIntegration:
    """Frida 动态分析接口（如可用）。"""

    def list_devices(self) -> Dict[str, Any]:
        if not which("frida") and not which("frida-ps"):
            return {"success": False, "error": "frida 未安装",
                    "install_hint": "pip install frida-tools",
                    "devices": []}
        r = run_cmd(["frida-ls-devices"], timeout=30)
        devices = []
        for line in r.get("stdout", "").splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3:
                devices.append({"id": parts[0], "type": parts[1],
                                "name": " ".join(parts[2:])})
        return {"success": True, "devices": devices}

    def spawn_script(self, device_id: str, package: str,
                     script: str) -> Dict[str, Any]:
        if not which("frida"):
            return {"success": False, "error": "frida 未安装"}
        return {
            "success": True,
            "message": "动态脚本已生成（需在已 root 设备上手动 attach）",
            "cmd": f"frida -D {device_id} -f {package} -l {script}",
            "script_templates": FRIDA_SCRIPTS,
        }


class MobileSecurityDeepEngine:
    """移动安全聚合。"""

    def __init__(self) -> None:
        self.apk = APKDeepAnalyzer()
        self.frida = FridaIntegration()
        self.tasks: Dict[str, Dict[str, Any]] = {}

    def analyze_apk(self, apk_path: str) -> Dict[str, Any]:
        tid = "apk_" + uuid.uuid4().hex[:10]
        t0 = time.time()
        result = self.apk.analyze(apk_path)
        self.tasks[tid] = {
            "task_id": tid, "apk": apk_path,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "result": result,
        }
        return {"success": True, "task_id": tid, "result": result}

    def tool_status(self) -> Dict[str, Any]:
        return {t: which(t) for t in APK_ANALYZERS}
