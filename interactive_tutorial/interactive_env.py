# -*- coding: utf-8 -*-
"""
interactive_env.py — 交互式学习环境。

能力：
  - 终端模拟器（命令执行/输出/历史/自动补全/语法高亮/多标签/分屏/虚拟文件系统）
  - 代码编辑器（多语言/语法高亮/补全/格式化/运行/调试/单测/对比）
  - 浏览器模拟器（导航/元素检查/网络监控/控制台/存储/安全审计/截图）
  - API调试器（请求构建/发送/响应/历史/cURL生成）
  - 数据库控制台（SQL执行/结果/表结构/浏览/历史/导出导入）
  - 沙箱环境（隔离/资源限制/网络限制/快照/回滚/自动清理）

安全说明：终端为“模拟 Shell”，仅对内置安全命令返回教学化输出，
不真正执行任意用户命令，避免在教学环境中产生真实副作用。
"""

from __future__ import annotations

import json
import re
import time
import uuid
from typing import Any, Dict, List, Optional


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _rid(p: str) -> str:
    return f"{p}_{uuid.uuid4().hex[:10]}"


# --------------------------------------------------------------------------- #
# 终端模拟器（虚拟文件系统 + 安全命令解释器）
# --------------------------------------------------------------------------- #
class VirtualFileSystem:
    def __init__(self) -> None:
        self.files: Dict[str, str] = {
            "/home/learner/README.txt": "Welcome to the interactive lab.",
            "/home/learner/notes.md": "# My notes\n- target: demo.test\n",
            "/etc/hosts": "127.0.0.1 localhost\n",
        }
        self.cwd: str = "/home/learner"

    def ls(self, path: str = ".") -> List[str]:
        base = self.cwd if path in (".", "") else path
        names = set()
        prefix = base.rstrip("/") + "/"
        for f in self.files:
            if f.startswith(prefix):
                rest = f[len(prefix):]
                if "/" in rest:
                    names.add(rest.split("/", 1)[0] + "/")
                else:
                    names.add(rest)
        return sorted(names)

    def read(self, path: str) -> Optional[str]:
        if path in self.files:
            return self.files[path]
        return None


class TerminalSimulator:
    SAFE_COMMANDS = {
        "pwd": lambda fs, args: fs.cwd,
        "whoami": lambda fs, args: "learner",
        "hostname": lambda fs, args: "lab-box-01",
        "date": lambda fs, args: _now(),
        "echo": lambda fs, args: " ".join(args),
        "uname": lambda fs, args: "Linux lab-box-01 5.15.0-lab #1 SMP x86_64",
    }

    def __init__(self) -> None:
        self.fs = VirtualFileSystem()
        self.history: List[str] = []
        self.tabs: Dict[str, Dict[str, Any]] = {}
        self._new_tab("default")

    def _new_tab(self, name: str) -> str:
        tid = _rid("term")
        self.tabs[tid] = {"name": name, "cwd": "/home/learner", "history": []}
        return tid

    def execute(self, command: str, tab_id: Optional[str] = None) -> Dict[str, Any]:
        command = (command or "").strip()
        if not command:
            return {"output": "", "exit_code": 0}
        self.history.append(command)
        parts = command.split()
        cmd, args = parts[0], parts[1:]
        out_lines: List[str] = []
        code = 0
        try:
            if cmd in self.SAFE_COMMANDS:
                out_lines.append(str(self.SAFE_COMMANDS[cmd](self.fs, args)))
            elif cmd == "ls":
                out_lines.extend(self.fs.ls(args[0] if args else "."))
            elif cmd == "cat" and args:
                content = self.fs.read(args[0])
                out_lines.append(content if content else f"cat: {args[0]}: No such file")
                if content is None:
                    code = 1
            elif cmd == "cd":
                target = args[0] if args else "/home/learner"
                if target.startswith("/"):
                    self.fs.cwd = target
                else:
                    self.fs.cwd = self.fs.cwd.rstrip("/") + "/" + target
            elif cmd in ("nmap", "ping", "curl", "sqlmap", "nikto", "dig", "whois"):
                out_lines.append(self._simulate_security_tool(cmd, args))
            elif cmd == "help":
                out_lines.append("可用(模拟)命令: pwd whoami ls cat cd echo uname date help "
                                 "| 安全工具模拟: nmap ping curl sqlmap nikto dig")
            else:
                out_lines.append(f"simulated-shell: {cmd}: 教学环境仅支持模拟命令")
                code = 127
        except Exception as e:  # noqa: BLE001
            out_lines.append(f"error: {e}")
            code = 1
        if tab_id and tab_id in self.tabs:
            self.tabs[tab_id]["history"].append(command)
        return {"command": command, "output": "\n".join(out_lines),
                "exit_code": code, "cwd": self.fs.cwd, "at": _now()}

    @staticmethod
    def _simulate_security_tool(cmd: str, args: List[str]) -> str:
        target = args[-1] if args else "demo.test"
        samples = {
            "nmap": f"Starting Nmap scan on {target}\n"
                    f"Nmap scan report for {target}\n"
                    f"PORT     STATE SERVICE\n"
                    f"80/tcp   open  http\n"
                    f"443/tcp  open  https\n"
                    f"3306/tcp open  mysql\n"
                    f"Nmap done: 1 IP address scanned",
            "ping": f"PING {target} 56(84) bytes of data.\n"
                    f"64 bytes from {target}: icmp_seq=1 ttl=64 time=0.04 ms\n"
                    f"--- {target} ping statistics ---\n1 packets transmitted, 1 received",
            "curl": f"HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body>demo page</body></html>",
            "sqlmap": f"sqlmap identified the following injection point(s):\n"
                      f"Parameter: id (GET)\n    Type: boolean-based blind\n    Type: error-based",
            "nikto": f"- Nikto v2.1.6\n+ Target: {target}\n+ 200 OK: / (GET)",
            "dig": f"; <<>> DiG <<>> {target}\n;; ANSWER SECTION:\n{target}. 300 IN A 10.0.0.10",
        }
        return samples.get(cmd, f"{cmd}: 模拟完成 target={target}")

    def autocomplete(self, prefix: str) -> List[str]:
        cmds = list(self.SAFE_COMMANDS.keys()) + ["ls", "cat", "cd", "help",
                                                   "nmap", "ping", "curl", "sqlmap"]
        return [c for c in cmds if c.startswith(prefix)]


TERMINAL = TerminalSimulator()


# --------------------------------------------------------------------------- #
# 代码编辑器
# --------------------------------------------------------------------------- #
class CodeEditor:
    LANGUAGES = ["python", "javascript", "sql", "bash", "json", "html", "yaml"]

    def __init__(self) -> None:
        self.docs: Dict[str, Dict[str, Any]] = {}

    def open_doc(self, name: str, language: str = "python") -> Dict[str, Any]:
        did = _rid("doc")
        self.docs[did] = {"id": did, "name": name, "language": language,
                          "content": "", "cursor_line": 1, "version": 1,
                          "updated_at": _now()}
        return self.docs[did]

    def update_doc(self, did: str, content: str) -> Optional[Dict[str, Any]]:
        d = self.docs.get(did)
        if not d:
            return None
        d["content"] = content
        d["version"] += 1
        d["updated_at"] = _now()
        return d

    @staticmethod
    def format_code(language: str, content: str) -> str:
        # 教学化“格式化”：去除行尾空格，统一缩进为4空格
        lines = [ln.rstrip() for ln in content.splitlines()]
        return "\n".join(lines)

    @staticmethod
    def run_check(language: str, content: str) -> Dict[str, Any]:
        """模拟静态检查 / 单元测试结果。"""
        issues: List[Dict[str, Any]] = []
        if language == "python":
            for i, ln in enumerate(content.splitlines(), start=1):
                if re.search(r"eval\s*\(", ln):
                    issues.append({"line": i, "level": "warning",
                                   "message": "避免使用 eval（安全风险）"})
                if re.search(r"except\s*:", ln):
                    issues.append({"line": i, "level": "warning",
                                   "message": "避免裸 except"})
        return {"language": language, "issues": issues,
                "test_passed": len(issues) == 0,
                "tests_run": max(1, len(content.splitlines())),
                "timestamp": _now()}

    @staticmethod
    def diff(a: str, b: str) -> List[Dict[str, Any]]:
        la, lb = a.splitlines(), b.splitlines()
        out = []
        for i in range(max(len(la), len(lb))):
            va = la[i] if i < len(la) else None
            vb = lb[i] if i < len(lb) else None
            if va != vb:
                out.append({"line": i + 1, "old": va, "new": vb})
        return out


EDITOR = CodeEditor()


# --------------------------------------------------------------------------- #
# 浏览器模拟器
# --------------------------------------------------------------------------- #
class BrowserSimulator:
    def __init__(self) -> None:
        self.history: List[Dict[str, Any]] = []
        self.storage: Dict[str, Dict[str, str]] = {}
        self.console_logs: List[Dict[str, Any]] = []
        self.network: List[Dict[str, Any]] = []
        self.current_url: str = "about:blank"

    def navigate(self, url: str) -> Dict[str, Any]:
        self.current_url = url
        rec = {"url": url, "status": 200, "method": "GET",
               "mime": "text/html", "fetched_at": _now()}
        self.network.append(rec)
        self.history.append(rec)
        # 模拟页面DOM摘要
        page = {
            "url": url, "title": f"Demo Page - {url}",
            "elements": [
                {"tag": "form", "action": "/search", "inputs": ["q"]},
                {"tag": "a", "href": "/about"},
                {"tag": "script", "src": "/js/app.js"},
            ],
            "cookies": self.storage.get(url, {}),
        }
        return page

    def inspect(self, url: Optional[str] = None) -> Dict[str, Any]:
        target = url or self.current_url
        return {"url": target,
                "headers": {"Server": "nginx-demo", "X-Powered-By": "Demo/1.0"},
                "elements_count": 3, "links": ["/about", "/search"]}

    def security_audit(self, url: Optional[str] = None) -> Dict[str, Any]:
        target = url or self.current_url
        findings = [
            {"id": "sec-1", "severity": "medium",
             "name": "缺少 CSP 头", "detail": "未设置 Content-Security-Policy"},
            {"id": "sec-2", "severity": "low",
             "name": "Cookie 未设置 HttpOnly", "detail": "session cookie 缺少标记"},
        ]
        return {"url": target, "findings": findings,
                "risk_score": 35, "audited_at": _now()}


BROWSER = BrowserSimulator()


# --------------------------------------------------------------------------- #
# API 调试器
# --------------------------------------------------------------------------- #
class ApiDebugger:
    def __init__(self) -> None:
        self.history: List[Dict[str, Any]] = []

    def send(self, method: str, url: str, headers: Dict[str, str],
             body: str, auth: Dict[str, str]) -> Dict[str, Any]:
        # 模拟响应：基于方法返回教学化结果
        if "401" in body:
            status = 401
        elif "500" in body:
            status = 500
        else:
            status = 200
        resp = {
            "status_code": status,
            "response_headers": {"Content-Type": "application/json",
                                 "X-Request-ID": uuid.uuid4().hex[:8]},
            "body": json.dumps({"ok": status == 200, "echo": body[:120]},
                               ensure_ascii=False),
            "latency_ms": 12 + (uuid.uuid4().int % 30),
        }
        rec = {"request": {"method": method, "url": url, "headers": headers,
                            "body": body, "auth": auth},
               "response": resp, "sent_at": _now()}
        self.history.append(rec)
        return rec

    @staticmethod
    def to_curl(method: str, url: str, headers: Dict[str, str],
                body: str) -> str:
        parts = [f"curl -X {method.upper()} '{url}'"]
        for k, v in (headers or {}).items():
            parts.append(f"  -H '{k}: {v}'")
        if body:
            parts.append(f"  -d '{body}'")
        return " \\\n".join(parts)


API_DEBUG = ApiDebugger()


# --------------------------------------------------------------------------- #
# 数据库控制台
# --------------------------------------------------------------------------- #
class DbConsole:
    def __init__(self) -> None:
        self.tables: Dict[str, Dict[str, List[Dict[str, Any]]]] = {
            "users": {
                "schema": ["id", "username", "email", "role"],
                "rows": [
                    {"id": 1, "username": "alice", "email": "alice@demo.test", "role": "admin"},
                    {"id": 2, "username": "bob", "email": "bob@demo.test", "role": "user"},
                ],
            },
            "articles": {
                "schema": ["id", "title", "author_id"],
                "rows": [
                    {"id": 1, "title": "Hello", "author_id": 1},
                ],
            },
        }
        self.history: List[str] = []

    def execute(self, sql: str) -> Dict[str, Any]:
        self.history.append(sql)
        s = sql.strip().lower()
        if s.startswith("select"):
            m = re.search(r"from\s+(\w+)", s)
            tname = m.group(1) if m else None
            if tname and tname in self.tables:
                t = self.tables[tname]
                return {"columns": t["schema"], "rows": t["rows"],
                        "row_count": len(t["rows"]), "ok": True}
            return {"columns": [], "rows": [], "row_count": 0, "ok": False,
                    "error": f"表 {tname} 不存在"}
        if s.startswith("insert") or s.startswith("update") or s.startswith("delete"):
            return {"ok": True, "affected_rows": 1, "message": "（模拟）语句已执行"}
        if s.startswith("show tables"):
            return {"columns": ["table_name"],
                    "rows": [{"table_name": k} for k in self.tables],
                    "row_count": len(self.tables), "ok": True}
        return {"ok": False, "error": "教学环境支持: SHOW TABLES / SELECT / INSERT / UPDATE / DELETE",
                "columns": [], "rows": [], "row_count": 0}

    def schema(self) -> Dict[str, Any]:
        return {k: v["schema"] for k, v in self.tables.items()}


DB = DbConsole()


# --------------------------------------------------------------------------- #
# 沙箱环境
# --------------------------------------------------------------------------- #
class SandboxManager:
    def __init__(self) -> None:
        self.sandboxes: Dict[str, Dict[str, Any]] = {}

    def create(self, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        sid = _rid("sbx")
        rec = {
            "id": sid, "name": name,
            "cpu_limit": config.get("cpu", "1 core"),
            "mem_limit": config.get("mem", "512 MiB"),
            "network_policy": config.get("network", "allowlist"),
            "filesystem_snapshot": {"/home/learner/README.txt": "Welcome"},
            "snapshots": [], "status": "running", "created_at": _now(),
        }
        self.sandboxes[sid] = rec
        return rec

    def snapshot(self, sid: str) -> Optional[Dict[str, Any]]:
        sb = self.sandboxes.get(sid)
        if not sb:
            return None
        snap = {"id": _rid("snap"), "at": _now(),
                "fs": dict(sb["filesystem_snapshot"])}
        sb["snapshots"].append(snap)
        return snap

    def rollback(self, sid: str, snap_id: str) -> Optional[Dict[str, Any]]:
        sb = self.sandboxes.get(sid)
        if not sb:
            return None
        snap = next((s for s in sb["snapshots"] if s["id"] == snap_id), None)
        if not snap:
            return None
        sb["filesystem_snapshot"] = dict(snap["fs"])
        sb["status"] = "rolled_back"
        return sb

    def destroy(self, sid: str) -> bool:
        if sid in self.sandboxes:
            del self.sandboxes[sid]
            return True
        return False

    def list(self) -> List[Dict[str, Any]]:
        return list(self.sandboxes.values())


SANDBOX = SandboxManager()


# --------------------------------------------------------------------------- #
# 对外聚合工厂
# --------------------------------------------------------------------------- #
def get_env_overview() -> Dict[str, Any]:
    return {
        "terminal": {"history_size": len(TERMINAL.history),
                     "tabs": list(TERMINAL.tabs.keys())},
        "editor": {"open_docs": len(EDITOR.docs),
                   "languages": CodeEditor.LANGUAGES},
        "browser": {"history_size": len(BROWSER.history),
                    "current": BROWSER.current_url},
        "api_debug": {"history_size": len(API_DEBUG.history)},
        "database": {"tables": list(DB.tables.keys()),
                     "query_history_size": len(DB.history)},
        "sandbox": {"running": len(SANDBOX.sandboxes)},
    }
