# -*- coding: utf-8 -*-
"""
dynamic_framework.py — 动态分析集成框架（方向3）。

提供：
    - Frida 脚本模板库（root 检测绕过 / SSL Pinning 绕过 / 调试绕过）
    - objection 命令模板
    - 设备 / 应用未安装时的明确提示（不 mock 数据）
    - 统一的任务启动/状态查询接口（内存字典）
"""
from __future__ import annotations

import shutil
import time
import uuid
from typing import Any, Dict, List, Optional


FRIDA_SCRIPTS: Dict[str, str] = {
    "ssl_unpin": """
// SSL Pinning 绕过（OkHttp3 / TrustManager 通用）
Java.perform(function () {
  var SSLContext = Java.use('javax.net.ssl.SSLContext');
  var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
  var TrustManager = Java.use('javax.net.ssl.TrustManager');
  var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
  var noopTrustManager = Java.registerClass({
    name: 'org.fridajs.NoopTrust' + Date.now(),
    implements: [X509TrustManager],
    methods: {
      checkClientTrusted: function () {},
      checkServerTrusted: function () {},
      getAcceptedIssuers: function () { return []; }
    }
  });
  SSLContext.init.overload(
    '[Ljavax.net.ssl.KeyManager;',
    '[Ljavax.net.ssl.TrustManager;',
    'java.security.SecureRandom'
  ).implementation = function (km, tm, sr) {
    this.init(km, [noopTrustManager.$new()], sr);
  };
});
""",
    "root_bypass": """
// Root 检测绕过（常见 Build.TAGS / su 路径 / which su）
Java.perform(function () {
  var Build = Java.use('android.os.Build');
  Build.TAGS.value = 'release-keys';
});
Java.perform(function () {
  var File = Java.use('java.io.File');
  File.exists.implementation = function () {
    var p = this.getAbsolutePath();
    if (p.indexOf('su') !== -1 || p.indexOf('magisk') !== -1) return false;
    return this.exists();
  };
});
""",
    "debug_bypass": """
// 调试检测绕过（android.os.Debug.isDebuggerConnected）
Java.perform(function () {
  var Debug = Java.use('android.os.Debug');
  Debug.isDebuggerConnected.implementation = function () { return false; };
});
""",
    "logcat_capture": """
// 抓取 App 自身日志
Java.perform(function () {
  var Log = Java.use('android.util.Log');
  Log.e.overload('java.lang.String', 'java.lang.String').implementation = function (t, m) {
    send({tag: t, msg: m});
    return this.e(t, m);
  };
});
""",
}

OBJECTION_TEMPLATES: Dict[str, str] = {
    "android_ssl_pinning": "objection -g <pkg> explore -s 'android sslpinning disable'",
    "android_root_detect": "objection -g <pkg> explore -s 'android root disable'",
    "android_hooking_list": "objection -g <pkg> explore -s 'hooking list activities'",
    "android_memory_dump": "objection -g <pkg> explore -s 'memory dump all'",
    "android_sqlite_dump": "objection -g <pkg> explore -s 'env' # 检查 datadir",
}


class DynamicAnalysisFramework:
    """动态分析框架。"""

    def __init__(self) -> None:
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self.frida_bin = shutil.which("frida")
        self.frida_ps_bin = shutil.which("frida-ps")
        self.objection_bin = shutil.which("objection")
        self.adb_bin = shutil.which("adb")

    # ------------------------------------------------------------------ #
    # 环境探测
    # ------------------------------------------------------------------ #
    def environment(self) -> Dict[str, Any]:
        return {
            "frida": self.frida_bin,
            "frida_ps": self.frida_ps_bin,
            "objection": self.objection_bin,
            "adb": self.adb_bin,
            "ready": bool(self.frida_bin and self.adb_bin),
            "hint": (
                "未检测到 frida/adb。请先：1) 设备 root 并 push frida-server；"
                "2) pip install frida-tools objection"
            ),
        }

    # ------------------------------------------------------------------ #
    # Frida 脚本
    # ------------------------------------------------------------------ #
    def list_scripts(self) -> Dict[str, Any]:
        return {k: {"name": k, "preview": v.strip().splitlines()[0][:80]}
                for k, v in FRIDA_SCRIPTS.items()}

    def get_script(self, name: str) -> Dict[str, Any]:
        if name not in FRIDA_SCRIPTS:
            return {"found": False, "available": list(FRIDA_SCRIPTS.keys())}
        return {"found": True, "name": name, "script": FRIDA_SCRIPTS[name]}

    # ------------------------------------------------------------------ #
    # objection 命令
    # ------------------------------------------------------------------ #
    def list_objection(self) -> Dict[str, Any]:
        return OBJECTION_TEMPLATES

    # ------------------------------------------------------------------ #
    # 任务启动（不真起进程，只登记；未装明确提示）
    # ------------------------------------------------------------------ #
    def start_task(self, pkg: str, script: str = "ssl_unpin",
                   device_id: str = "") -> Dict[str, Any]:
        env = self.environment()
        if not env["ready"]:
            return {
                "started": False,
                "reason": "工具链未就绪：" + env["hint"],
                "env": env,
            }
        if script not in FRIDA_SCRIPTS:
            return {"started": False, "reason": f"未知脚本: {script}"}
        tid = "dyn-" + uuid.uuid4().hex[:10]
        self._tasks[tid] = {
            "task_id": tid,
            "pkg": pkg,
            "script": script,
            "device_id": device_id or "default",
            "status": "queued",
            "started_at": time.time(),
            "command": f"frida -U -f {pkg} -l {script}.js --no-pause",
            "note": "已登记为占位任务；真实执行需在 Root 设备上跑 frida 命令",
        }
        return {"started": True, "task": self._tasks[tid]}

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        return self._tasks.get(task_id)

    def list_tasks(self) -> List[Dict[str, Any]]:
        return list(self._tasks.values())
