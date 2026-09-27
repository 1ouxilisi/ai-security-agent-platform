# -*- coding: utf-8 -*-
"""
plugin_sdk.py - 插件开发框架（SDK）

提供基类、接口、API 包装、上下文、工具集、模板/示例/测试/打包/发布。
"""

from __future__ import annotations

import os
import json
import time
import shutil
import hashlib
import zipfile
import tempfile
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


# ---------- 上下文 ----------
class PluginContext:
    """插件运行上下文。"""

    def __init__(self, plugin_id: str, user: str = "anonymous",
                 tenant: str = "default", task: Optional[Dict[str, Any]] = None,
                 config: Optional[Dict[str, Any]] = None,
                 lang: str = "zh-CN", timezone: str = "Asia/Shanghai") -> None:
        self.plugin_id = plugin_id
        self.user = user
        self.tenant = tenant
        self.task = task or {}
        self.config = config or {}
        self.lang = lang
        self.timezone = timezone
        self._log: List[str] = []

    def log(self, msg: str) -> None:
        self._log.append(f"[{_now()}] {msg}")

    def dump(self) -> Dict[str, Any]:
        return {
            "plugin_id": self.plugin_id, "user": self.user, "tenant": self.tenant,
            "task": self.task, "config": self.config, "lang": self.lang,
            "timezone": self.timezone, "logs": self._log[-50:],
        }


# ---------- 工具集 ----------
class PluginTools:
    """给插件用的常用工具。"""

    @staticmethod
    def sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def md5(data: bytes) -> str:
        return hashlib.md5(data).hexdigest()

    @staticmethod
    def http_get(url: str, timeout: int = 10) -> Dict[str, Any]:
        try:
            import urllib.request  # noqa: WPS433
            with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310
                body = r.read()
                return {"ok": True, "status": r.status, "body": body[:65536].decode("utf-8", "ignore")}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}

    @staticmethod
    def read_file(path: str, max_bytes: int = 65536) -> Dict[str, Any]:
        try:
            with open(path, "rb") as f:
                return {"ok": True, "data": f.read(max_bytes)}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}

    @staticmethod
    def validate_ip(ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    @staticmethod
    def now_iso() -> str:
        return _now()


# ---------- 基类 ----------
class BasePlugin:
    """插件基类：生命周期 init/start/stop/uninstall/config/validate。"""

    id: str = "base"
    name: str = "Base Plugin"
    version: str = "0.0.1"
    author: str = ""
    description: str = ""
    type: str = "other"

    def __init__(self, ctx: Optional[PluginContext] = None) -> None:
        self.ctx = ctx or PluginContext(self.id)
        self.tools = PluginTools()
        self._started = False

    def init(self) -> Dict[str, Any]:
        self.ctx.log(f"{self.id} init")
        return {"ok": True, "stage": "init"}

    def start(self) -> Dict[str, Any]:
        self._started = True
        self.ctx.log(f"{self.id} start")
        return {"ok": True, "stage": "start"}

    def stop(self) -> Dict[str, Any]:
        self._started = False
        self.ctx.log(f"{self.id} stop")
        return {"ok": True, "stage": "stop"}

    def uninstall(self) -> Dict[str, Any]:
        self.ctx.log(f"{self.id} uninstall")
        return {"ok": True, "stage": "uninstall"}

    def configure(self, settings: Dict[str, Any]) -> Dict[str, Any]:
        self.ctx.config.update(settings)
        return {"ok": True, "stage": "configure"}

    def validate(self) -> Dict[str, Any]:
        return {"ok": True, "stage": "validate"}


# ---------- 子类接口 ----------
class ScannerPlugin(BasePlugin):
    type = "scanner"

    def scan(self, target: str) -> Dict[str, Any]:
        raise NotImplementedError


class AnalyzerPlugin(BasePlugin):
    type = "analyzer"

    def analyze(self, data: Any) -> Dict[str, Any]:
        raise NotImplementedError


class ConnectorPlugin(BasePlugin):
    type = "connector"

    def connect(self) -> Dict[str, Any]:
        raise NotImplementedError


class VisualizationPlugin(BasePlugin):
    type = "visualization"

    def render(self, data: Any) -> Dict[str, Any]:
        raise NotImplementedError


class WorkflowPlugin(BasePlugin):
    type = "workflow"

    def run(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError


class NotificationPlugin(BasePlugin):
    type = "notification"

    def notify(self, message: str) -> Dict[str, Any]:
        raise NotImplementedError


class AIPlugin(BasePlugin):
    type = "ai"

    def infer(self, prompt: str) -> Dict[str, Any]:
        raise NotImplementedError


# ---------- 模板 / 示例 ----------
TEMPLATES: Dict[str, str] = {
    "scanner": '''# -*- coding: utf-8 -*-
from plugin_system.plugin_sdk import ScannerPlugin, PluginContext

class MyScanner(ScannerPlugin):
    id = "my-scanner"
    name = "My Scanner"
    version = "0.1.0"

    def scan(self, target: str) -> dict:
        return {"ok": True, "target": target, "findings": []}
''',
    "analyzer": '''# -*- coding: utf-8 -*-
from plugin_system.plugin_sdk import AnalyzerPlugin

class MyAnalyzer(AnalyzerPlugin):
    id = "my-analyzer"
    name = "My Analyzer"
    version = "0.1.0"

    def analyze(self, data):
        return {"ok": True, "result": "ok"}
''',
    "connector": '''# -*- coding: utf-8 -*-
from plugin_system.plugin_sdk import ConnectorPlugin

class MyConnector(ConnectorPlugin):
    id = "my-connector"
    version = "0.1.0"

    def connect(self):
        return {"ok": True}
''',
    "visualization": '''# -*- coding: utf-8 -*-
from plugin_system.plugin_sdk import VisualizationPlugin

class MyViz(VisualizationPlugin):
    id = "my-viz"
    version = "0.1.0"

    def render(self, data):
        return {"ok": True, "svg": "<svg/>"}
''',
    "workflow": '''# -*- coding: utf-8 -*-
from plugin_system.plugin_sdk import WorkflowPlugin

class MyWorkflow(WorkflowPlugin):
    id = "my-workflow"
    version = "0.1.0"

    def run(self, inputs):
        return {"ok": True, "outputs": {}}
''',
    "notification": '''# -*- coding: utf-8 -*-
from plugin_system.plugin_sdk import NotificationPlugin

class MyNotify(NotificationPlugin):
    id = "my-notify"
    version = "0.1.0"

    def notify(self, message):
        return {"ok": True}
''',
    "ai": '''# -*- coding: utf-8 -*-
from plugin_system.plugin_sdk import AIPlugin

class MyAI(AIPlugin):
    id = "my-ai"
    version = "0.1.0"

    def infer(self, prompt):
        return {"ok": True, "answer": ""}
''',
}


EXAMPLES: Dict[str, Dict[str, Any]] = {
    "scanner": {
        "code": TEMPLATES["scanner"],
        "config": {"threads": 50, "timeout": 10},
        "doc": "扫描器插件模板，实现 scan(target) 方法返回 findings 列表。",
    },
    "ai": {
        "code": TEMPLATES["ai"],
        "config": {"model": "gpt-4", "temperature": 0.2},
        "doc": "AI 插件模板，实现 infer(prompt) 返回 answer。",
    },
}


# ---------- 打包 / 发布 ----------
class PluginPackager:
    """打包插件为 zip / whl / tar.gz（模拟，实际产出 zip）。"""

    def __init__(self, workdir: Optional[str] = None) -> None:
        self.workdir = workdir or tempfile.mkdtemp(prefix="pkg_")

    def package(self, plugin_id: str, code: str, metadata: Dict[str, Any],
                fmt: str = "zip") -> Dict[str, Any]:
        pkg_dir = os.path.join(self.workdir, plugin_id)
        os.makedirs(pkg_dir, exist_ok=True)
        with open(os.path.join(pkg_dir, f"{plugin_id}.py"), "w", encoding="utf-8") as f:
            f.write(code)
        with open(os.path.join(pkg_dir, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)
        out_path = os.path.join(self.workdir, f"{plugin_id}.{fmt if fmt in ('zip','tar.gz') else 'zip'}")
        if fmt == "zip":
            with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as z:
                for root, _, files in os.walk(pkg_dir):
                    for fn in files:
                        full = os.path.join(root, fn)
                        z.write(full, arcname=os.path.relpath(full, pkg_dir))
        else:
            shutil.make_archive(out_path[:-len("." + fmt)], fmt, pkg_dir)
        with open(out_path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        return {"ok": True, "path": out_path, "format": fmt,
                "size": os.path.getsize(out_path), "sha256": digest}

    def validate_package(self, path: str) -> Dict[str, Any]:
        if not os.path.exists(path):
            return {"ok": False, "error": "文件不存在"}
        try:
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
                has_manifest = any(n.endswith("manifest.json") for n in names)
                return {"ok": has_manifest, "entries": names,
                        "has_manifest": has_manifest}
        except zipfile.BadZipFile:
            return {"ok": False, "error": "不是合法 zip"}

    def sign_package(self, path: str) -> Dict[str, Any]:
        if not os.path.exists(path):
            return {"ok": False, "error": "文件不存在"}
        with open(path, "rb") as f:
            sig = hashlib.sha256(f.read()).hexdigest()
        return {"ok": True, "signature": sig, "signed_at": _now()}


class PluginPublisher:
    """模拟发布：提交审核、版本管理、更新日志。"""

    def __init__(self) -> None:
        self.submissions: List[Dict[str, Any]] = []

    def submit(self, plugin_id: str, version: str, changelog: str) -> Dict[str, Any]:
        entry = {
            "id": f"sub-{int(time.time())}", "plugin_id": plugin_id,
            "version": version, "changelog": changelog,
            "submitted_at": _now(), "status": "pending_review",
        }
        self.submissions.append(entry)
        return {"ok": True, "submission": entry}

    def list_submissions(self) -> List[Dict[str, Any]]:
        return self.submissions


# ---------- 测试框架（骨架） ----------
class PluginTestRunner:
    """简单测试骨架：单元/集成/功能/性能/安全测试占位。"""

    def run(self, plugin_id: str) -> Dict[str, Any]:
        return {
            "ok": True, "plugin_id": plugin_id,
            "unit": {"passed": 1, "failed": 0},
            "integration": {"passed": 1, "failed": 0},
            "functional": {"passed": 1, "failed": 0},
            "performance": {"avg_ms": 12.5},
            "security": {"issues": 0},
        }


_default_sdk: Optional[Dict[str, Any]] = None


def get_sdk() -> Dict[str, Any]:
    global _default_sdk
    if _default_sdk is None:
        _default_sdk = {
            "packager": PluginPackager(),
            "publisher": PluginPublisher(),
            "tester": PluginTestRunner(),
            "templates": TEMPLATES,
            "examples": EXAMPLES,
        }
    return _default_sdk
