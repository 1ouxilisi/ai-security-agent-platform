# -*- coding: utf-8 -*-
"""
plugin_manager.py - 插件管理器

负责插件生命周期管理、依赖解析、兼容性检查、配置/权限管理、沙箱执行、使用统计。
所有数据存储于内存字典，不依赖数据库。
"""

from __future__ import annotations

import os
import sys
import json
import time
import shutil
import hashlib
import platform
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# 8 类插件类型
PLUGIN_TYPES: Dict[str, str] = {
    "scanner": "扫描器插件",
    "analyzer": "分析器插件",
    "connector": "连接器插件",
    "visualization": "可视化插件",
    "workflow": "工作流插件",
    "notification": "通知插件",
    "ai": "AI 插件",
    "other": "其他插件",
}

# 权限清单
PERMISSIONS: Dict[str, str] = {
    "filesystem.read": "读取文件系统",
    "filesystem.write": "写入文件系统",
    "network.outbound": "发起出站网络请求",
    "network.inbound": "监听入站网络端口",
    "database.read": "读取数据库",
    "database.write": "写入数据库",
    "api.access": "访问平台 API",
    "system.command": "执行系统命令",
    "userdata.read": "读取用户数据",
    "userdata.write": "写入用户数据",
}

MIN_PLATFORM_VERSION = "11.0.0"
MIN_PYTHON = (3, 10)


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _new_id(prefix: str) -> str:
    raw = f"{prefix}-{int(time.time() * 1000)}-{os.urandom(3).hex()}"
    return raw


class PluginManager:
    """插件管理器：单例风格，内存字典存储。"""

    def __init__(self, base_dir: Optional[str] = None) -> None:
        self.base_dir = base_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "_installed_plugins"
        )
        self.plugins: Dict[str, Dict[str, Any]] = {}
        self.config_store: Dict[str, Dict[str, Any]] = {}
        self.permission_approvals: Dict[str, Dict[str, Any]] = {}
        self.usage_stats: Dict[str, Dict[str, Any]] = {}
        self.audit_log: List[Dict[str, Any]] = []
        self._seed_example_plugins()

    # ---------- 内置示例插件 ----------
    def _seed_example_plugins(self) -> None:
        examples = [
            {
                "id": "ex-nuclei-scanner",
                "name": "Nuclei 扫描器",
                "version": "2.9.4",
                "author": "Security Lab",
                "description": "基于 Nuclei 模板的漏洞扫描器插件",
                "type": "scanner",
                "category": "vuln",
                "tags": ["vulnerability", "nuclei", "template"],
                "icon": "🔍",
                "license": "MIT",
                "homepage": "https://example.com/nuclei",
                "documentation": "https://docs.example.com/nuclei",
                "dependencies": {"plugins": [], "python_pkgs": ["pyyaml"], "system_tools": ["nuclei"]},
                "compatibility": {"platform": ">=11.0.0", "python": ">=3.10", "os": ["windows", "linux", "darwin"]},
                "min_platform_version": "11.0.0",
                "permissions": ["network.outbound", "system.command"],
            },
            {
                "id": "ex-payload-analyzer",
                "name": "Payload 分析器",
                "version": "1.2.0",
                "author": "RedTeam Inc",
                "description": "对可疑 payload 进行静态/动态行为分析",
                "type": "analyzer",
                "category": "malware",
                "tags": ["malware", "behavior", "static-analysis"],
                "icon": "🧪",
                "license": "Apache-2.0",
                "homepage": "https://example.com/payload",
                "documentation": "https://docs.example.com/payload",
                "dependencies": {"plugins": [], "python_pkgs": ["lief"], "system_tools": []},
                "compatibility": {"platform": ">=11.0.0", "python": ">=3.10", "os": ["windows", "linux"]},
                "min_platform_version": "11.0.0",
                "permissions": ["filesystem.read", "filesystem.write", "system.command"],
            },
            {
                "id": "ex-slack-notify",
                "name": "Slack 通知连接器",
                "version": "0.9.3",
                "author": "Ops Team",
                "description": "将告警推送到 Slack Webhook",
                "type": "notification",
                "category": "alert",
                "tags": ["slack", "webhook", "alert"],
                "icon": "📣",
                "license": "MIT",
                "homepage": "https://example.com/slack",
                "documentation": "https://docs.example.com/slack",
                "dependencies": {"plugins": [], "python_pkgs": ["httpx"], "system_tools": []},
                "compatibility": {"platform": ">=11.0.0", "python": ">=3.10", "os": ["windows", "linux", "darwin"]},
                "min_platform_version": "11.0.0",
                "permissions": ["network.outbound", "api.access"],
            },
            {
                "id": "ex-dashboard-viz",
                "name": "攻击链可视化",
                "version": "3.0.1",
                "author": "Visual Lab",
                "description": "攻击链时间线与图谱可视化组件",
                "type": "visualization",
                "category": "dashboard",
                "tags": ["graph", "timeline", "killchain"],
                "icon": "📊",
                "license": "GPL-3.0",
                "homepage": "https://example.com/viz",
                "documentation": "https://docs.example.com/viz",
                "dependencies": {"plugins": [], "python_pkgs": [], "system_tools": []},
                "compatibility": {"platform": ">=11.0.0", "python": ">=3.10", "os": ["windows", "linux", "darwin"]},
                "min_platform_version": "11.0.0",
                "permissions": ["api.access"],
            },
            {
                "id": "ex-soar-workflow",
                "name": "SOAR 自动化剧本",
                "version": "1.5.2",
                "author": "SOAR Team",
                "description": "告警自动分诊与处置剧本",
                "type": "workflow",
                "category": "soar",
                "tags": ["soar", "automation", "playbook"],
                "icon": "🔁",
                "license": "MIT",
                "homepage": "https://example.com/soar",
                "documentation": "https://docs.example.com/soar",
                "dependencies": {"plugins": ["ex-slack-notify"], "python_pkgs": [], "system_tools": []},
                "compatibility": {"platform": ">=11.0.0", "python": ">=3.10", "os": ["windows", "linux"]},
                "min_platform_version": "11.0.0",
                "permissions": ["api.access", "system.command"],
            },
            {
                "id": "ex-ldap-connector",
                "name": "LDAP 资产连接器",
                "version": "2.1.0",
                "author": "Identity Lab",
                "description": "对接 LDAP/AD 同步组织资产",
                "type": "connector",
                "category": "asset",
                "tags": ["ldap", "ad", "identity"],
                "icon": "🔗",
                "license": "BSD-3-Clause",
                "homepage": "https://example.com/ldap",
                "documentation": "https://docs.example.com/ldap",
                "dependencies": {"plugins": [], "python_pkgs": ["ldap3"], "system_tools": []},
                "compatibility": {"platform": ">=11.0.0", "python": ">=3.10", "os": ["windows", "linux"]},
                "min_platform_version": "11.0.0",
                "permissions": ["network.outbound", "userdata.read"],
            },
            {
                "id": "ex-llm-triage",
                "name": "LLM 告警分诊",
                "version": "0.4.5",
                "author": "AI SOC",
                "description": "使用大模型对告警进行自动分诊",
                "type": "ai",
                "category": "soc",
                "tags": ["llm", "triage", "ai"],
                "icon": "🤖",
                "license": "MIT",
                "homepage": "https://example.com/llm",
                "documentation": "https://docs.example.com/llm",
                "dependencies": {"plugins": [], "python_pkgs": ["openai"], "system_tools": []},
                "compatibility": {"platform": ">=11.0.0", "python": ">=3.10", "os": ["windows", "linux", "darwin"]},
                "min_platform_version": "11.0.0",
                "permissions": ["network.outbound", "api.access"],
            },
            {
                "id": "ex-custom-report",
                "name": "自定义报告导出",
                "version": "1.0.0",
                "author": "Report Team",
                "description": "导出自定义 Markdown/PDF 报告",
                "type": "other",
                "category": "report",
                "tags": ["report", "export"],
                "icon": "📄",
                "license": "MIT",
                "homepage": "https://example.com/report",
                "documentation": "https://docs.example.com/report",
                "dependencies": {"plugins": [], "python_pkgs": ["jinja2"], "system_tools": []},
                "compatibility": {"platform": ">=11.0.0", "python": ">=3.10", "os": ["windows", "linux", "darwin"]},
                "min_platform_version": "11.0.0",
                "permissions": ["filesystem.write"],
            },
        ]
        for p in examples:
            p["status"] = "installed"  # installed / enabled / disabled
            p["installed_at"] = _now()
            p["enabled"] = True
            p["installed_version"] = p["version"]
            p["history"] = [{"version": p["version"], "installed_at": p["installed_at"]}]
            self.plugins[p["id"]] = p
            self.config_store[p["id"]] = {"enabled": True, "settings": {}}
            self.usage_stats[p["id"]] = {
                "installs": 0, "enabled": 1, "calls": 0, "score_avg": 0.0, "ratings": []
            }

    # ---------- 工具 ----------
    def _log(self, action: str, plugin_id: str, detail: str = "", ok: bool = True) -> None:
        self.audit_log.append({
            "ts": _now(), "action": action, "plugin_id": plugin_id,
            "detail": detail, "ok": ok,
        })

    def _check_compatibility(self, p: Dict[str, Any]) -> List[str]:
        problems: List[str] = []
        comp = p.get("compatibility", {}) or {}
        need = comp.get("platform", "")
        # 简化比较
        if "11.0.0" in need and p.get("min_platform_version", "11.0.0") > MIN_PLATFORM_VERSION:
            problems.append(f"平台版本不满足: {need}")
        py_req = comp.get("python", "")
        if "3.10" in py_req and sys.version_info < MIN_PYTHON:
            problems.append(f"Python 版本过低: 需要 {py_req}")
        os_list = comp.get("os", []) or []
        current_os = platform.system().lower()
        if os_list and current_os not in os_list:
            problems.append(f"操作系统不支持: 当前 {current_os}, 需要 {os_list}")
        return problems

    def _resolve_dependencies(self, plugin_id: str) -> Tuple[bool, List[str]]:
        """解析插件依赖（其他插件 / python 包 / 系统工具）。"""
        p = self.plugins.get(plugin_id)
        if not p:
            return False, ["插件不存在"]
        missing: List[str] = []
        deps = p.get("dependencies", {}) or {}
        for dep_id in deps.get("plugins", []) or []:
            if dep_id not in self.plugins:
                missing.append(f"依赖插件未安装: {dep_id}")
            else:
                if not self.plugins[dep_id].get("enabled"):
                    missing.append(f"依赖插件未启用: {dep_id}")
        for pkg in deps.get("python_pkgs", []) or []:
            # 仅做轻量探测
            try:
                __import__(pkg.replace("-", "_"))
            except Exception:
                missing.append(f"Python 包未安装: {pkg}")
        for tool in deps.get("system_tools", []) or []:
            if shutil.which(tool) is None:
                missing.append(f"系统工具未找到: {tool}")
        return (len(missing) == 0), missing

    # ---------- 插件管理 ----------
    def list_plugins(self, plugin_type: Optional[str] = None,
                     enabled_only: bool = False) -> List[Dict[str, Any]]:
        items = list(self.plugins.values())
        if plugin_type:
            items = [p for p in items if p.get("type") == plugin_type]
        if enabled_only:
            items = [p for p in items if p.get("enabled")]
        return items

    def get_detail(self, plugin_id: str) -> Optional[Dict[str, Any]]:
        p = self.plugins.get(plugin_id)
        if not p:
            return None
        out = dict(p)
        out["config"] = self.config_store.get(plugin_id, {})
        out["permissions"] = self.permission_approvals.get(plugin_id, {"requested": p.get("permissions", []), "granted": p.get("permissions", [])})
        out["stats"] = self.usage_stats.get(plugin_id, {})
        out["compatibility_problems"] = self._check_compatibility(p)
        return out

    def install(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        pid = metadata.get("id") or _new_id("plugin")
        if pid in self.plugins:
            return {"ok": False, "error": "插件已存在"}
        problems = self._check_compatibility(metadata)
        plugin = dict(metadata)
        plugin["id"] = pid
        plugin["status"] = "installed"
        plugin["enabled"] = False
        plugin["installed_at"] = _now()
        plugin["installed_version"] = metadata.get("version", "0.0.1")
        plugin["history"] = [{"version": plugin["installed_version"], "installed_at": plugin["installed_at"]}]
        plugin["compatibility_problems"] = problems
        self.plugins[pid] = plugin
        self.config_store[pid] = {"enabled": False, "settings": {}}
        self.permission_approvals[pid] = {"requested": plugin.get("permissions", []), "granted": []}
        self.usage_stats[pid] = {"installs": 1, "enabled": 0, "calls": 0, "score_avg": 0.0, "ratings": []}
        self._log("install", pid, f"version={plugin['installed_version']}")
        return {"ok": True, "id": pid, "compatibility_problems": problems}

    def uninstall(self, plugin_id: str) -> Dict[str, Any]:
        if plugin_id not in self.plugins:
            return {"ok": False, "error": "插件不存在"}
        # 检查反向依赖
        dependents = [pid for pid, p in self.plugins.items()
                      if plugin_id in (p.get("dependencies", {}) or {}).get("plugins", [])]
        if dependents:
            return {"ok": False, "error": f"被以下插件依赖: {dependents}", "dependents": dependents}
        self.plugins.pop(plugin_id, None)
        self.config_store.pop(plugin_id, None)
        self.permission_approvals.pop(plugin_id, None)
        self.usage_stats.pop(plugin_id, None)
        self._log("uninstall", plugin_id)
        return {"ok": True}

    def enable(self, plugin_id: str) -> Dict[str, Any]:
        p = self.plugins.get(plugin_id)
        if not p:
            return {"ok": False, "error": "插件不存在"}
        ok, missing = self._resolve_dependencies(plugin_id)
        if not ok:
            return {"ok": False, "error": "依赖未满足", "missing": missing}
        problems = self._check_compatibility(p)
        if problems:
            return {"ok": False, "error": "兼容性问题", "problems": problems}
        p["enabled"] = True
        p["status"] = "enabled"
        self.config_store.setdefault(plugin_id, {})["enabled"] = True
        self.usage_stats.setdefault(plugin_id, {})["enabled"] = 1
        self._log("enable", plugin_id)
        return {"ok": True}

    def disable(self, plugin_id: str) -> Dict[str, Any]:
        p = self.plugins.get(plugin_id)
        if not p:
            return {"ok": False, "error": "插件不存在"}
        p["enabled"] = False
        p["status"] = "disabled"
        self.config_store.setdefault(plugin_id, {})["enabled"] = False
        self.usage_stats.setdefault(plugin_id, {})["enabled"] = 0
        self._log("disable", plugin_id)
        return {"ok": True}

    def update(self, plugin_id: str, new_version: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        p = self.plugins.get(plugin_id)
        if not p:
            return {"ok": False, "error": "插件不存在"}
        old_version = p["installed_version"]
        if metadata:
            p.update({k: v for k, v in metadata.items() if k not in ("id",)})
        p["installed_version"] = new_version
        p["version"] = new_version
        p["history"].append({"version": new_version, "updated_at": _now()})
        self._log("update", plugin_id, f"{old_version} -> {new_version}")
        return {"ok": True, "old_version": old_version, "new_version": new_version}

    def rollback(self, plugin_id: str, version: Optional[str] = None) -> Dict[str, Any]:
        p = self.plugins.get(plugin_id)
        if not p:
            return {"ok": False, "error": "插件不存在"}
        hist = p.get("history", [])
        if len(hist) < 2:
            return {"ok": False, "error": "没有可回滚的历史版本"}
        target = version or hist[-2].get("version")
        p["installed_version"] = target
        p["version"] = target
        p["history"].append({"version": target, "rolled_back_at": _now()})
        self._log("rollback", plugin_id, f"-> {target}")
        return {"ok": True, "rolled_to": target}

    # ---------- 配置 ----------
    def get_config(self, plugin_id: str) -> Dict[str, Any]:
        return self.config_store.get(plugin_id, {})

    def set_config(self, plugin_id: str, settings: Dict[str, Any]) -> Dict[str, Any]:
        if plugin_id not in self.plugins:
            return {"ok": False, "error": "插件不存在"}
        # 简单校验：settings 必须是 dict
        if not isinstance(settings, dict):
            return {"ok": False, "error": "配置必须是键值对象"}
        cfg = self.config_store.setdefault(plugin_id, {"enabled": False, "settings": {}})
        cfg["settings"].update(settings)
        self._log("config.update", plugin_id)
        return {"ok": True, "config": cfg}

    def export_config(self, plugin_id: str) -> Dict[str, Any]:
        return {"plugin_id": plugin_id, "config": self.config_store.get(plugin_id, {})}

    def import_config(self, plugin_id: str, cfg: Dict[str, Any]) -> Dict[str, Any]:
        if plugin_id not in self.plugins:
            return {"ok": False, "error": "插件不存在"}
        self.config_store[plugin_id] = cfg.get("config", cfg)
        return {"ok": True}

    # ---------- 权限 ----------
    def get_permissions(self, plugin_id: str) -> Dict[str, Any]:
        return self.permission_approvals.get(plugin_id, {"requested": [], "granted": []})

    def set_permissions(self, plugin_id: str, granted: List[str], approver: str = "admin") -> Dict[str, Any]:
        if plugin_id not in self.plugins:
            return {"ok": False, "error": "插件不存在"}
        invalid = [g for g in granted if g not in PERMISSIONS]
        if invalid:
            return {"ok": False, "error": f"未知权限: {invalid}", "valid": list(PERMISSIONS.keys())}
        entry = self.permission_approvals.setdefault(plugin_id, {"requested": [], "granted": []})
        entry["granted"] = granted
        entry["approved_by"] = approver
        entry["approved_at"] = _now()
        self._log("permissions.update", plugin_id, f"granted={granted}")
        return {"ok": True, "granted": granted}

    # ---------- 沙箱执行（subprocess 模拟） ----------
    def run_sandboxed(self, plugin_id: str, command: List[str],
                      timeout: int = 30, max_output: int = 65536) -> Dict[str, Any]:
        """用 subprocess 模拟沙箱执行；不授予 system.command 权限则拒绝。"""
        perm = self.permission_approvals.get(plugin_id, {})
        if "system.command" not in (perm.get("granted") or []):
            self._log("sandbox.denied", plugin_id, "缺少 system.command 权限", ok=False)
            return {"ok": False, "error": "未授予 system.command 权限，拒绝沙箱执行"}
        try:
            proc = subprocess.run(
                command, capture_output=True, text=True,
                timeout=timeout, shell=False, check=False,
            )
            out = proc.stdout[:max_output]
            err = proc.stderr[:max_output]
            result = {
                "ok": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": out,
                "stderr": err,
                "duration_ms": 0,
            }
            self.usage_stats.setdefault(plugin_id, {})
            self.usage_stats[plugin_id]["calls"] = self.usage_stats[plugin_id].get("calls", 0) + 1
            self._log("sandbox.run", plugin_id, f"rc={proc.returncode}")
            return result
        except subprocess.TimeoutExpired:
            self._log("sandbox.timeout", plugin_id, ok=False)
            return {"ok": False, "error": f"执行超时 (>{timeout}s)"}
        except Exception as e:  # noqa: BLE001
            self._log("sandbox.error", plugin_id, str(e), ok=False)
            return {"ok": False, "error": str(e)}

    # ---------- 统计 ----------
    def stats(self) -> Dict[str, Any]:
        total = len(self.plugins)
        enabled = sum(1 for p in self.plugins.values() if p.get("enabled"))
        by_type: Dict[str, int] = {}
        for p in self.plugins.values():
            by_type[p.get("type", "other")] = by_type.get(p.get("type", "other"), 0) + 1
        return {
            "total": total,
            "enabled": enabled,
            "disabled": total - enabled,
            "by_type": by_type,
            "audit_entries": len(self.audit_log),
        }


# 单例
_default_manager: Optional[PluginManager] = None


def get_manager() -> PluginManager:
    global _default_manager
    if _default_manager is None:
        _default_manager = PluginManager()
    return _default_manager
