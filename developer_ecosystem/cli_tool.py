# -*- coding: utf-8 -*-
"""
cli_tool.py — CLI 命令行工具（第24轮升级方向4 / 模块1）。

包含：
  - CLI 核心框架：命令解析 / 参数处理 / 配置管理 / 输出格式化 / 颜色输出 / 进度条 / 交互式提示 / 自动补全
  - 安全扫描命令：端口扫描 / 服务识别 / 漏洞扫描 / Web扫描 / 移动扫描 / 云扫描 / API扫描 / 基线检查
  - 报告命令：报告生成 / 查看 / 导出 / 对比 / 模板 / 质量检查
  - 资产管理命令：添加 / 删除 / 列表 / 详情 / 分组 / 标签 / 导入导出
  - 任务管理命令：创建 / 列表 / 详情 / 状态 / 取消 / 重试 / 日志
  - 配置与认证：配置管理 / API密钥 / 登录认证 / 多账户 / 代理 / 超时 / 输出配置

全部内存字典模拟，不建数据库表。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

# ---------- 第三方库 try-import ----------
try:
    import click  # type: ignore
    _HAS_CLICK = True
except Exception:
    click = None  # type: ignore
    _HAS_CLICK = False

try:
    import rich  # type: ignore
    _HAS_RICH = True
except Exception:
    rich = None  # type: ignore
    _HAS_RICH = False

try:
    import colorama  # type: ignore
    from colorama import Fore, Style
    colorama.init()
    _HAS_COLORAMA = True
except Exception:
    colorama = None  # type: ignore
    Fore = type("F", (), {"RED": "", "GREEN": "", "YELLOW": "", "BLUE": "", "CYAN": "", "RESET_ALL": ""})()  # type: ignore
    Style = type("S", (), {"BRIGHT": "", "DIM": "", "RESET_ALL": ""})()  # type: ignore
    _HAS_COLORAMA = False


# ==================== 颜色输出 ====================

class Colors:
    """ANSI 颜色输出（无 colorama 时自动降级为空字符串）"""
    RED = Fore.RED if _HAS_COLORAMA else ""
    GREEN = Fore.GREEN if _HAS_COLORAMA else ""
    YELLOW = Fore.YELLOW if _HAS_COLORAMA else ""
    BLUE = Fore.BLUE if _HAS_COLORAMA else ""
    CYAN = Fore.CYAN if _HAS_COLORAMA else ""
    MAGENTA = Fore.MAGENTA if _HAS_COLORAMA else ""
    BOLD = Style.BRIGHT if _HAS_COLORAMA else ""
    DIM = Style.DIM if _HAS_COLORAMA else ""
    RESET = Style.RESET_ALL if _HAS_COLORAMA else ""

    @classmethod
    def red(cls, s: str) -> str:
        return f"{cls.RED}{s}{cls.RESET}"

    @classmethod
    def green(cls, s: str) -> str:
        return f"{cls.GREEN}{s}{cls.RESET}"

    @classmethod
    def yellow(cls, s: str) -> str:
        return f"{cls.YELLOW}{s}{cls.RESET}"

    @classmethod
    def blue(cls, s: str) -> str:
        return f"{cls.BLUE}{s}{cls.RESET}"

    @classmethod
    def cyan(cls, s: str) -> str:
        return f"{cls.CYAN}{s}{cls.RESET}"

    @classmethod
    def bold(cls, s: str) -> str:
        return f"{cls.BOLD}{s}{cls.RESET}"


# ==================== 进度条 ====================

class ProgressBar:
    """终端进度条模拟"""

    def __init__(self, total: int = 100, width: int = 40, desc: str = ""):
        self.total = max(total, 1)
        self.width = width
        self.desc = desc
        self.current = 0
        self.start_time = time.time()

    def update(self, n: int = 1):
        self.current = min(self.current + n, self.total)
        pct = self.current / self.total
        filled = int(self.width * pct)
        bar = "█" * filled + "░" * (self.width - filled)
        elapsed = time.time() - self.start_time
        sys.stdout.write(
            f"\r{self.desc} [{bar}] {pct*100:.1f}% ({self.current}/{self.total}) {elapsed:.1f}s"
        )
        sys.stdout.flush()
        if self.current >= self.total:
            sys.stdout.write("\n")

    def finish(self):
        self.current = self.total
        self.update(0)


# ==================== 交互式提示 ====================

class InteractivePrompter:
    """交互式输入提示"""

    @staticmethod
    def ask(question: str, default: str = "") -> str:
        try:
            suffix = f" [{default}]" if default else ""
            ans = input(f"{Colors.cyan('?')} {question}{suffix}: ").strip()
            return ans if ans else default
        except (EOFError, KeyboardInterrupt):
            return default

    @staticmethod
    def confirm(question: str, default: bool = False) -> bool:
        d = "Y/n" if default else "y/N"
        ans = InteractivePrompter.ask(f"{question} ({d})", "y" if default else "n")
        return ans.lower().startswith("y")

    @staticmethod
    def choose(question: str, options: List[str], default: str = "") -> str:
        print(f"{Colors.cyan('?')} {question}:")
        for i, opt in enumerate(options, 1):
            marker = Colors.green("→") if opt == default else " "
            print(f"  {marker} {i}. {opt}")
        ans = InteractivePrompter.ask("请选择编号", default or "1")
        try:
            idx = int(ans) - 1
            return options[idx]
        except (ValueError, IndexError):
            return default or options[0]

    @staticmethod
    def password(question: str) -> str:
        import getpass
        try:
            return getpass.getpass(f"{Colors.cyan('?')} {question}: ")
        except Exception:
            return InteractivePrompter.ask(question)


# ==================== 自动补全 ====================

class AutoCompleter:
    """Shell 自动补全（文件名 / 命令名）"""

    def __init__(self, commands: Optional[List[str]] = None):
        self.commands = commands or []
        self.files: List[str] = []

    def add_command(self, cmd: str):
        if cmd not in self.commands:
            self.commands.append(cmd)

    def complete(self, prefix: str) -> List[str]:
        """返回匹配前缀的候选"""
        cands = [c for c in self.commands if c.startswith(prefix)]
        cands += [f for f in self.files if f.startswith(prefix)]
        return sorted(set(cands))

    def generate_bash_completion(self) -> str:
        """生成 Bash 补全脚本"""
        cmds = " ".join(self.commands)
        return (
            f"#!/usr/bin/env bash\n"
            f"# AI Hacking Agent CLI Bash Completion\n"
            f"_aha_cli_complete() {{\n"
            f"  local cur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n"
            f"  COMPREPLY=( $(compgen -W \"{cmds}\" -- \"$cur\") )\n"
            f"}}\n"
            f"complete -F _aha_cli_complete aha\n"
        )

    def generate_zsh_completion(self) -> str:
        """生成 Zsh 补全脚本"""
        cmds = " ".join(self.commands)
        return (
            f"#compdef aha\n"
            f"_aha() {{\n"
            f"  local commands='{cmds}'\n"
            f"  _values 'commands' $commands\n"
            f"}}\n"
            f"_aha \"$@\"\n"
        )


# ==================== 配置管理 ====================

@dataclass
class CLIConfig:
    """CLI 配置管理"""
    api_endpoint: str = "http://127.0.0.1:8000"
    api_key: str = ""
    timeout: int = 30
    proxy: str = ""
    output_format: str = "table"  # table | json | csv
    color_enabled: bool = True
    verbose: bool = False
    default_scan_profile: str = "quick"
    current_account: str = "default"
    accounts: Dict[str, Dict[str, str]] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "api_endpoint": self.api_endpoint,
            "api_key": self.api_key[:8] + "***" if self.api_key else "",
            "timeout": self.timeout,
            "proxy": self.proxy,
            "output_format": self.output_format,
            "color_enabled": self.color_enabled,
            "verbose": self.verbose,
            "default_scan_profile": self.default_scan_profile,
            "current_account": self.current_account,
            "accounts": list(self.accounts.keys()),
        }

    def save(self, path: str = "") -> str:
        p = path or os.path.expanduser("~/.aha_cli_config.json")
        data = self.__dict__.copy()
        data["api_key"] = self.api_key  # 明文保存
        try:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return p
        except Exception:
            return ""

    @classmethod
    def load(cls, path: str = "") -> "CLIConfig":
        p = path or os.path.expanduser("~/.aha_cli_config.json")
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                cfg = cls()
                for k, v in data.items():
                    if hasattr(cfg, k):
                        setattr(cfg, k, v)
                return cfg
            except Exception:
                pass
        return cls()


# ==================== 输出格式化 ====================

class OutputFormatter:
    """表格 / JSON / CSV 输出格式化"""

    @staticmethod
    def table(headers: List[str], rows: List[List[Any]]) -> str:
        """简易 ASCII 表格"""
        if not rows:
            return "(无数据)"
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(str(cell)))
        line = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
        hdr = "|" + "|".join(f" {h:<{w}} " for h, w in zip(headers, widths)) + "|"
        out = [line, hdr, line]
        for row in rows:
            out.append("|" + "|".join(f" {str(c):<{w}} " for c, w in zip(row, widths)) + "|")
        out.append(line)
        return "\n".join(out)

    @staticmethod
    def as_json(data: Any, indent: int = 2) -> str:
        return json.dumps(data, ensure_ascii=False, indent=indent, default=str)

    @staticmethod
    def as_csv(headers: List[str], rows: List[List[Any]]) -> str:
        lines = [",".join(headers)]
        for row in rows:
            lines.append(",".join(f'"{c}"' for c in row))
        return "\n".join(lines)

    @staticmethod
    def format(data: Any, fmt: str = "table", headers: Optional[List[str]] = None) -> str:
        if fmt == "json":
            return OutputFormatter.as_json(data)
        if fmt == "csv" and headers and isinstance(data, list):
            return OutputFormatter.as_csv(headers, data)
        if isinstance(data, list) and data:
            h = headers or list(data[0].keys())
            rows = [[d.get(k, "") for k in h] for d in data]
            return OutputFormatter.table(h, rows)
        if isinstance(data, dict):
            return OutputFormatter.table(["字段", "值"], [[k, str(v)] for k, v in data.items()])
        return str(data)


# ==================== CLI 核心框架 ====================

class CLICommand:
    """单个 CLI 命令定义"""
    def __init__(self, name: str, handler: Callable, help_text: str = "", aliases: Optional[List[str]] = None):
        self.name = name
        self.handler = handler
        self.help = help_text
        self.aliases = aliases or []
        self.subcommands: Dict[str, "CLICommand"] = {}

    def add_sub(self, cmd: "CLICommand"):
        self.subcommands[cmd.name] = cmd
        for a in cmd.aliases:
            self.subcommands[a] = cmd


class CLICore:
    """CLI 核心框架：命令注册 / 解析 / 分发"""

    def __init__(self, name: str = "aha", version: str = "24.4.0"):
        self.name = name
        self.version = version
        self.commands: Dict[str, CLICommand] = {}
        self.config = CLIConfig.load()
        self.formatter = OutputFormatter()
        self.completer = AutoCompleter()
        self.prompter = InteractivePrompter()
        self.assets_store: Dict[str, Dict[str, Any]] = {}
        self.tasks_store: Dict[str, Dict[str, Any]] = {}
        self.reports_store: Dict[str, Dict[str, Any]] = {}
        self._register_builtin()

    # ---------- 注册命令 ----------
    def register(self, cmd: CLICommand):
        self.commands[cmd.name] = cmd
        self.completer.add_command(cmd.name)
        for a in cmd.aliases:
            self.commands[a] = cmd
            self.completer.add_command(a)

    def _register_builtin(self):
        """注册内置命令组"""
        # scan 子命令组
        scan_group = CLICommand("scan", lambda *a, **kw: None, "安全扫描命令组")
        for sub in [
            CLICommand("port", self._cmd_scan_port, "端口扫描"),
            CLICommand("service", self._cmd_scan_service, "服务识别"),
            CLICommand("vuln", self._cmd_scan_vuln, "漏洞扫描"),
            CLICommand("web", self._cmd_scan_web, "Web 扫描"),
            CLICommand("mobile", self._cmd_scan_mobile, "移动应用扫描"),
            CLICommand("cloud", self._cmd_scan_cloud, "云安全扫描"),
            CLICommand("api", self._cmd_scan_api, "API 扫描"),
            CLICommand("baseline", self._cmd_scan_baseline, "基线检查"),
        ]:
            scan_group.add_sub(sub)
        self.register(scan_group)

        # report 子命令组
        rep_group = CLICommand("report", lambda *a, **kw: None, "报告命令组")
        for sub in [
            CLICommand("generate", self._cmd_report_generate, "生成报告"),
            CLICommand("list", self._cmd_report_list, "报告列表"),
            CLICommand("view", self._cmd_report_view, "查看报告"),
            CLICommand("export", self._cmd_report_export, "导出报告"),
            CLICommand("compare", self._cmd_report_compare, "对比报告"),
            CLICommand("template", self._cmd_report_template, "报告模板管理"),
            CLICommand("quality", self._cmd_report_quality, "报告质量检查"),
        ]:
            rep_group.add_sub(sub)
        self.register(rep_group)

        # asset 子命令组
        ast_group = CLICommand("asset", lambda *a, **kw: None, "资产管理命令组")
        for sub in [
            CLICommand("add", self._cmd_asset_add, "添加资产"),
            CLICommand("del", self._cmd_asset_del, "删除资产"),
            CLICommand("list", self._cmd_asset_list, "资产列表"),
            CLICommand("detail", self._cmd_asset_detail, "资产详情"),
            CLICommand("group", self._cmd_asset_group, "资产分组"),
            CLICommand("tag", self._cmd_asset_tag, "资产标签"),
            CLICommand("import", self._cmd_asset_import, "导入资产"),
            CLICommand("export", self._cmd_asset_export, "导出资产"),
        ]:
            ast_group.add_sub(sub)
        self.register(ast_group)

        # task 子命令组
        task_group = CLICommand("task", lambda *a, **kw: None, "任务管理命令组")
        for sub in [
            CLICommand("create", self._cmd_task_create, "创建任务"),
            CLICommand("list", self._cmd_task_list, "任务列表"),
            CLICommand("detail", self._cmd_task_detail, "任务详情"),
            CLICommand("status", self._cmd_task_status, "任务状态"),
            CLICommand("cancel", self._cmd_task_cancel, "取消任务"),
            CLICommand("retry", self._cmd_task_retry, "重试任务"),
            CLICommand("logs", self._cmd_task_logs, "任务日志"),
        ]:
            task_group.add_sub(sub)
        self.register(task_group)

        # config 子命令组
        cfg_group = CLICommand("config", lambda *a, **kw: None, "配置与认证命令组")
        for sub in [
            CLICommand("show", self._cmd_config_show, "显示配置"),
            CLICommand("set", self._cmd_config_set, "设置配置"),
            CLICommand("login", self._cmd_config_login, "登录认证"),
            CLICommand("logout", self._cmd_config_logout, "登出"),
            CLICommand("key", self._cmd_config_key, "API 密钥管理"),
            CLICommand("account", self._cmd_config_account, "多账户切换"),
            CLICommand("proxy", self._cmd_config_proxy, "代理配置"),
        ]:
            cfg_group.add_sub(sub)
        self.register(cfg_group)

        # 顶层命令
        self.register(CLICommand("version", self._cmd_version, "显示版本"))
        self.register(CLICommand("help", self._cmd_help, "显示帮助"))
        self.register(CLICommand("completion", self._cmd_completion, "生成自动补全脚本"))

    # ---------- 解析与分发 ----------
    def run(self, argv: Optional[List[str]] = None) -> Dict[str, Any]:
        """执行命令行（编程式调用，返回结构化结果）"""
        argv = argv or sys.argv[1:]
        if not argv:
            return self._cmd_help()

        top = argv[0]
        if top in ("-v", "--version"):
            return self._cmd_version()
        if top in ("-h", "--help"):
            return self._cmd_help()

        cmd = self.commands.get(top)
        if not cmd:
            return {"success": False, "error": f"未知命令: {top}", "available": list(self.commands.keys())}

        # 有子命令
        if cmd.subcommands and len(argv) > 1:
            sub_name = argv[1]
            sub = cmd.subcommands.get(sub_name)
            if sub:
                args = argv[2:]
                try:
                    result = sub.handler(*args)
                    return {"success": True, "command": f"{top} {sub_name}", "result": result}
                except Exception as e:
                    return {"success": False, "error": str(e), "command": f"{top} {sub_name}"}
            return {"success": False, "error": f"未知子命令: {sub_name}", "parent": top,
                    "subcommands": list(cmd.subcommands.keys())}

        try:
            result = cmd.handler(*argv[1:])
            return {"success": True, "command": top, "result": result}
        except Exception as e:
            return {"success": False, "error": str(e), "command": top}

    # ---------- 内置命令实现 ----------
    def _cmd_version(self) -> Dict[str, Any]:
        return {"name": self.name, "version": self.version, "python": sys.version.split()[0]}

    def _cmd_help(self) -> Dict[str, Any]:
        cmds = {k: v.help for k, v in self.commands.items() if not any(k == a for a in v.aliases)}
        return {"usage": f"{self.name} <command> [subcommand] [args]", "commands": cmds}

    def _cmd_completion(self, shell: str = "bash") -> str:
        if shell == "zsh":
            return self.completer.generate_zsh_completion()
        return self.completer.generate_bash_completion()

    # ---------- 扫描命令 ----------
    def _cmd_scan_port(self, target: str = "127.0.0.1", ports: str = "1-1024") -> Dict[str, Any]:
        tid = f"scan-port-{uuid.uuid4().hex[:8]}"
        self.tasks_store[tid] = {
            "task_id": tid, "type": "port_scan", "target": target,
            "ports": ports, "status": "running",
            "progress": 0, "result": None,
            "created_at": datetime.now().isoformat(timespec="seconds"),
        }
        # 模拟结果
        open_ports = [{"port": 80, "service": "http"}, {"port": 443, "service": "https"},
                      {"port": 22, "service": "ssh"}]
        self.tasks_store[tid]["status"] = "completed"
        self.tasks_store[tid]["progress"] = 100
        self.tasks_store[tid]["result"] = {"target": target, "open_ports": open_ports, "total_open": len(open_ports)}
        return self.tasks_store[tid]

    def _cmd_scan_service(self, target: str = "127.0.0.1") -> Dict[str, Any]:
        return {"target": target, "services": [
            {"port": 80, "name": "nginx", "version": "1.24.0"},
            {"port": 443, "name": "nginx", "version": "1.24.0"},
            {"port": 22, "name": "OpenSSH", "version": "8.9p1"},
        ]}

    def _cmd_scan_vuln(self, target: str = "", profile: str = "quick") -> Dict[str, Any]:
        return {"target": target or "demo.target", "profile": profile,
                "vulnerabilities": [
                    {"cve": "CVE-2024-23334", "severity": "high", "cvss": 7.5, "product": "aiohttp"},
                    {"cve": "CVE-2023-46805", "severity": "medium", "cvss": 5.3, "product": "nginx"},
                ],
                "summary": {"critical": 0, "high": 1, "medium": 1, "low": 0}}

    def _cmd_scan_web(self, url: str = "https://example.com") -> Dict[str, Any]:
        return {"url": url, "issues": [
            {"type": "xss", "path": "/search?q=", "severity": "high"},
            {"type": "sqli", "path": "/api/user?id=", "severity": "critical"},
            {"type": "info_disclosure", "path": "/.env", "severity": "medium"},
        ]}

    def _cmd_scan_mobile(self, apk_path: str = "") -> Dict[str, Any]:
        return {"apk": apk_path or "app-debug.apk", "findings": [
            {"category": "insecure_storage", "detail": "SharedPreferences 明文存储令牌", "severity": "high"},
            {"category": "exported_component", "detail": "Exported Activity 暴露", "severity": "medium"},
        ]}

    def _cmd_scan_cloud(self, provider: str = "aws") -> Dict[str, Any]:
        return {"provider": provider, "misconfigurations": [
            {"service": "S3", "issue": "存储桶公开访问", "severity": "critical"},
            {"service": "IAM", "issue": "过宽的策略权限", "severity": "high"},
        ]}

    def _cmd_scan_api(self, spec: str = "openapi.json") -> Dict[str, Any]:
        return {"spec": spec, "endpoints_tested": 42, "issues": [
            {"endpoint": "/api/v1/users", "type": "broken_auth", "severity": "high"},
            {"endpoint": "/api/v1/orders", "type": "rate_limit", "severity": "low"},
        ]}

    def _cmd_scan_baseline(self, os_type: str = "linux") -> Dict[str, Any]:
        return {"os": os_type, "checks": 120, "passed": 98, "failed": 22,
                "failed_items": [{"id": "CIS-5.2", "desc": "SSH 禁止 root 登录", "severity": "high"}]}

    # ---------- 报告命令 ----------
    def _cmd_report_generate(self, scan_id: str = "", fmt: str = "pdf") -> Dict[str, Any]:
        rid = f"rpt-{uuid.uuid4().hex[:8]}"
        self.reports_store[rid] = {
            "report_id": rid, "scan_id": scan_id, "format": fmt,
            "status": "generated", "created_at": datetime.now().isoformat(timespec="seconds"),
            "summary": {"total_vulns": 12, "critical": 1, "high": 4, "medium": 5, "low": 2},
        }
        return self.reports_store[rid]

    def _cmd_report_list(self) -> List[Dict[str, Any]]:
        return list(self.reports_store.values())

    def _cmd_report_view(self, report_id: str = "") -> Dict[str, Any]:
        return self.reports_store.get(report_id, {"error": "报告不存在", "report_id": report_id})

    def _cmd_report_export(self, report_id: str = "", out: str = "") -> Dict[str, Any]:
        return {"report_id": report_id, "exported": True, "path": out or f"./exports/{report_id}.pdf"}

    def _cmd_report_compare(self, r1: str = "", r2: str = "") -> Dict[str, Any]:
        return {"report_a": r1, "report_b": r2, "delta": {"new_vulns": 3, "fixed_vulns": 1, "new_critical": 1}}

    def _cmd_report_template(self, action: str = "list") -> Dict[str, Any]:
        return {"action": action, "templates": [
            {"id": "tpl-basic", "name": "基础报告", "sections": ["概览", "漏洞清单"]},
            {"id": "tpl-comprehensive", "name": "综合报告", "sections": ["概览", "漏洞", "修复建议", "合规"]},
        ]}

    def _cmd_report_quality(self, report_id: str = "") -> Dict[str, Any]:
        return {"report_id": report_id, "score": 85, "issues": [
            {"level": "warning", "msg": "缺少修复优先级矩阵"},
            {"level": "info", "msg": "建议补充资产分布图"},
        ]}

    # ---------- 资产管理命令 ----------
    def _cmd_asset_add(self, name: str = "", atype: str = "host", address: str = "") -> Dict[str, Any]:
        aid = f"ast-{uuid.uuid4().hex[:8]}"
        self.assets_store[aid] = {
            "asset_id": aid, "name": name or address or "未命名资产",
            "type": atype, "address": address, "tags": [], "group": "default",
            "created_at": datetime.now().isoformat(timespec="seconds"),
        }
        return self.assets_store[aid]

    def _cmd_asset_del(self, asset_id: str = "") -> Dict[str, Any]:
        existed = asset_id in self.assets_store
        self.assets_store.pop(asset_id, None)
        return {"asset_id": asset_id, "deleted": existed}

    def _cmd_asset_list(self) -> List[Dict[str, Any]]:
        return list(self.assets_store.values())

    def _cmd_asset_detail(self, asset_id: str = "") -> Dict[str, Any]:
        return self.assets_store.get(asset_id, {"error": "资产不存在"})

    def _cmd_asset_group(self, asset_id: str = "", group: str = "") -> Dict[str, Any]:
        if asset_id in self.assets_store:
            self.assets_store[asset_id]["group"] = group
        return self.assets_store.get(asset_id, {"error": "资产不存在"})

    def _cmd_asset_tag(self, asset_id: str = "", tag: str = "") -> Dict[str, Any]:
        if asset_id in self.assets_store:
            tags = self.assets_store[asset_id].get("tags", [])
            if tag and tag not in tags:
                tags.append(tag)
            self.assets_store[asset_id]["tags"] = tags
        return self.assets_store.get(asset_id, {"error": "资产不存在"})

    def _cmd_asset_import(self, path: str = "") -> Dict[str, Any]:
        return {"path": path, "imported": 0, "skipped": 0, "total": 0}

    def _cmd_asset_export(self, fmt: str = "csv") -> Dict[str, Any]:
        return {"format": fmt, "count": len(self.assets_store), "path": f"./exports/assets.{fmt}"}

    # ---------- 任务管理命令 ----------
    def _cmd_task_create(self, task_type: str = "port_scan", target: str = "") -> Dict[str, Any]:
        tid = f"task-{uuid.uuid4().hex[:8]}"
        self.tasks_store[tid] = {
            "task_id": tid, "type": task_type, "target": target,
            "status": "pending", "progress": 0,
            "created_at": datetime.now().isoformat(timespec="seconds"),
        }
        return self.tasks_store[tid]

    def _cmd_task_list(self, status: str = "") -> List[Dict[str, Any]]:
        items = list(self.tasks_store.values())
        if status:
            items = [t for t in items if t.get("status") == status]
        return items

    def _cmd_task_detail(self, task_id: str = "") -> Dict[str, Any]:
        return self.tasks_store.get(task_id, {"error": "任务不存在"})

    def _cmd_task_status(self, task_id: str = "") -> Dict[str, Any]:
        t = self.tasks_store.get(task_id, {})
        return {"task_id": task_id, "status": t.get("status", "unknown"), "progress": t.get("progress", 0)}

    def _cmd_task_cancel(self, task_id: str = "") -> Dict[str, Any]:
        if task_id in self.tasks_store:
            self.tasks_store[task_id]["status"] = "cancelled"
        return {"task_id": task_id, "cancelled": True}

    def _cmd_task_retry(self, task_id: str = "") -> Dict[str, Any]:
        if task_id in self.tasks_store:
            self.tasks_store[task_id]["status"] = "pending"
            self.tasks_store[task_id]["progress"] = 0
        return {"task_id": task_id, "retried": True}

    def _cmd_task_logs(self, task_id: str = "") -> Dict[str, Any]:
        return {"task_id": task_id, "logs": [
            "[INFO] 任务启动", "[INFO] 加载扫描引擎", "[INFO] 初始化目标上下文",
            "[DEBUG] 连接测试通过", "[INFO] 任务完成",
        ]}

    # ---------- 配置与认证命令 ----------
    def _cmd_config_show(self) -> Dict[str, Any]:
        return self.config.to_dict()

    def _cmd_config_set(self, key: str = "", value: str = "") -> Dict[str, Any]:
        if hasattr(self.config, key):
            old = getattr(self.config, key)
            setattr(self.config, key, type(old)(value) if not isinstance(old, bool) else value.lower() in ("1", "true", "yes"))
            self.config.save()
            return {"key": key, "old": old, "new": getattr(self.config, key)}
        return {"error": f"未知配置项: {key}"}

    def _cmd_config_login(self, endpoint: str = "", api_key: str = "") -> Dict[str, Any]:
        if endpoint:
            self.config.api_endpoint = endpoint
        if api_key:
            self.config.api_key = api_key
        self.config.save()
        return {"logged_in": True, "endpoint": self.config.api_endpoint}

    def _cmd_config_logout(self) -> Dict[str, Any]:
        self.config.api_key = ""
        self.config.save()
        return {"logged_out": True}

    def _cmd_config_key(self, action: str = "list") -> Dict[str, Any]:
        if action == "list":
            return {"keys": [{"name": "default", "prefix": self.config.api_key[:8] + "***"}]}
        if action == "create":
            new_key = f"aha_{uuid.uuid4().hex}"
            self.config.api_key = new_key
            self.config.save()
            return {"created": True, "key": new_key}
        return {"action": action}

    def _cmd_config_account(self, action: str = "list", name: str = "") -> Dict[str, Any]:
        if action == "list":
            return {"accounts": list(self.config.accounts.keys()), "current": self.config.current_account}
        if action == "switch" and name:
            self.config.current_account = name
            return {"switched": True, "account": name}
        return {"action": action}

    def _cmd_config_proxy(self, proxy: str = "") -> Dict[str, Any]:
        self.config.proxy = proxy
        self.config.save()
        return {"proxy": proxy or "(已清除)"}


# ==================== 单例 ====================

cli_core = CLICore()

__all__ = [
    "CLICommand", "CLICore", "CLIConfig", "Colors", "ProgressBar",
    "InteractivePrompter", "AutoCompleter", "OutputFormatter", "cli_core",
]
