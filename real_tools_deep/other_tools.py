# -*- coding: utf-8 -*-
"""
other_tools.py — Nikto / Hydra / nuclei / dirb / dirsearch 集成（真实执行版 / P0-1 修复）。

核心原则（P0-1）：
- 所有扫描类 API 必须真实调用对应命令，禁止 mock。
- 每个扫描器带 is_available()：shutil.which + 版本探针双重检测。
- 工具未安装 / shim 损坏时返回 {"success": False, "error": "工具未安装: xxx"}。
- 真实解析工具输出（nuclei JSONL / nikto 文本 / dirb / dirsearch）。
- 全部 subprocess 调用带超时（默认 300 秒）。

设计定位：仅用于经过授权的安全评估环境。
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 300

NIKTO_VULN_TYPES = [
    "file_upload", "cmd_exec", "xss", "sqli", "lfi",
    "backup_file", "old_software", "dangerous_file",
    "directory_listing", "misconfiguration", "ssl_vuln",
]

HYDRA_SERVICES = [
    "ssh", "ftp", "smtp", "pop3", "imap", "mysql",
    "postgresql", "redis", "mongodb", "rdp", "vnc",
    "http-get", "http-post",
]

NUCLEI_TEMPLATE_CATEGORIES = [
    "cves", "vulnerabilities", "exposed-panels",
    "malware", "technologies", "misconfiguration",
    "takeovers", "fuzzing", "miscellaneous",
]

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _run_command(args: List[str], timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="replace",
        )
        return {"returncode": proc.returncode, "stdout": proc.stdout or "",
                "stderr": proc.stderr or "", "timed_out": False, "error": None}
    except subprocess.TimeoutExpired as e:
        return {"returncode": -1, "stdout": "", "stderr": "", "timed_out": True,
                "error": f"命令执行超时（>{timeout}s）"}
    except FileNotFoundError as e:
        return {"returncode": -1, "stdout": "", "stderr": "", "timed_out": False,
                "error": f"工具未找到: {e}"}
    except Exception as e:  # noqa: BLE001
        return {"returncode": -1, "stdout": "", "stderr": "", "timed_out": False,
                "error": f"命令执行异常: {e}"}


def _probe(name: str, version_args: List[str], expect_tokens: List[str],
           timeout: int = 30) -> Dict[str, Any]:
    """通用探针：which + 版本命令。返回 {available, version, path, error}。"""
    resolved = shutil.which(name)
    if not resolved:
        return {"available": False, "version": "", "path": "",
                "error": f"未在 PATH 中找到 {name}"}
    out = _run_command([resolved] + version_args, timeout=timeout)
    text = (out["stdout"] + "\n" + out["stderr"]).strip()
    if out["returncode"] == 0 and any(tok in text.lower() for tok in expect_tokens):
        first = text.splitlines()[0] if text else ""
        return {"available": True, "version": first[:120], "path": resolved, "error": ""}
    return {"available": False, "version": "", "path": resolved,
            "error": (text[:200] or out["error"] or "版本探测失败").strip()}


def _summary_by_severity(items: List[Dict[str, Any]], sev_key: str = "severity") -> Dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for it in items:
        sev = str(it.get(sev_key, "info")).lower()
        if sev in out:
            out[sev] += 1
    return out


# --------------------------------------------------------------------------- #
# Nikto
# --------------------------------------------------------------------------- #
class NiktoScanner:
    def __init__(self, path: str = "nikto") -> None:
        self.path = path
        self.available = False
        self.version = ""
        self.probe_error = ""
        self.actual_path = ""
        self._check()

    def _check(self) -> None:
        p = _probe(self.path, ["-Version"], ["nikto"])
        self.available = p["available"]
        self.version = p["version"]
        self.actual_path = p["path"]
        self.probe_error = p["error"]

    def is_available(self) -> bool:
        return self.available

    def scan(self, target: str, port: int = 80, ssl: bool = False,
             timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
        if not self.available:
            return {"success": False, "data": None,
                    "error": f"工具未安装: nikto（{self.probe_error}）"}
        args = [self.actual_path, "-h", target, "-p", str(port)]
        if ssl:
            args.append("-ssl")
        started = time.time()
        ex = _run_command(args, timeout=timeout)
        duration = round(time.time() - started, 2)
        findings = self._parse(ex["stdout"] + "\n" + ex["stderr"])
        return {
            "success": not ex["timed_out"] and not ex["error"],
            "data": {
                "command": " ".join(args), "findings": findings,
                "mode": "real", "duration_sec": duration,
                "timed_out": ex["timed_out"],
                "summary": {"total_findings": len(findings),
                            "by_severity": _summary_by_severity(findings)},
                "executed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            },
            "error": ex["error"],
        }

    @staticmethod
    def _parse(output: str) -> List[Dict[str, Any]]:
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("+"):
                continue
            msg = line.lstrip("+ ").strip()
            if len(msg) < 8:
                continue
            low = msg.lower()
            sev = "info"
            if any(k in low for k in ["remote", "shell", "rce", "sql injection", "allowed"]):
                sev = "high"
            elif any(k in low for k in ["xss", "leak", "directory index", "outdated", "old", "cve"]):
                sev = "medium"
            elif any(k in low for k in ["eula", "banner", "end of"]):
                sev = "low"
            findings.append({"msg": msg, "severity": sev, "raw": line})
        return findings


# --------------------------------------------------------------------------- #
# Hydra（本机未安装，如实报告）
# --------------------------------------------------------------------------- #
class HydraScanner:
    def __init__(self, path: str = "hydra") -> None:
        self.path = path
        p = _probe(self.path, ["-h"], ["hydra", "login"])
        self.available, self.version = p["available"], p["version"]
        self.actual_path, self.probe_error = p["path"], p["error"]

    def is_available(self) -> bool:
        return self.available

    def crack(self, target: str, service: str, username: str = "",
              userlist: str = "", passlist: str = "",
              port: int = 0, threads: int = 4,
              timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
        if not self.available:
            return {"success": False, "data": None,
                    "error": f"工具未安装: hydra（{self.probe_error}）"}
        args = [self.actual_path]
        if username:
            args += ["-l", username]
        elif userlist:
            args += ["-L", userlist]
        if passlist:
            args += ["-P", passlist]
        args += ["-t", str(threads), "-f"]
        if port:
            args += ["-s", str(port)]
        args += [target, service]
        ex = _run_command(args, timeout=timeout)
        results = []
        for line in (ex["stdout"] + "\n" + ex["stderr"]).splitlines():
            if "[+]" in line:
                results.append({"raw": line.strip()})
        return {
            "success": not ex["timed_out"] and not ex["error"],
            "data": {"command": " ".join(args), "results": results,
                     "mode": "real", "timed_out": ex["timed_out"],
                     "executed_at": time.strftime("%Y-%m-%d %H:%M:%S")},
            "error": ex["error"],
        }


# --------------------------------------------------------------------------- #
# nuclei（真实 JSONL 解析）
# --------------------------------------------------------------------------- #
class NucleiScanner:
    def __init__(self, path: str = "nuclei") -> None:
        self.path = path
        p = _probe(self.path, ["-version"], ["nuclei"])
        self.available, self.version = p["available"], p["version"]
        self.actual_path, self.probe_error = p["path"], p["error"]

    def is_available(self) -> bool:
        return self.available

    def scan(self, target: str, templates: str = "",
             severity: str = "", tags: str = "",
             rate_limit: int = 150, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
        if not self.available:
            return {"success": False, "data": None,
                    "error": f"工具未安装: nuclei（{self.probe_error}）"}
        args = [self.actual_path, "-u", target, "-jsonl", "-silent",
                "-rate-limit", str(rate_limit), "-disable-update-check"]
        if templates:
            args += ["-t", templates]
        if severity:
            args += ["-severity", severity]
        if tags:
            args += ["-tags", tags]
        started = time.time()
        ex = _run_command(args, timeout=timeout)
        duration = round(time.time() - started, 2)
        findings = self._parse_jsonl(ex["stdout"])
        return {
            "success": not ex["timed_out"] and not ex["error"],
            "data": {
                "command": " ".join(args),
                "findings": findings,
                "mode": "real",
                "duration_sec": duration,
                "timed_out": ex["timed_out"],
                "stderr_tail": ex["stderr"][-800:],
                "summary": {"total_findings": len(findings),
                            "by_severity": _summary_by_severity(findings)},
                "executed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            },
            "error": ex["error"],
        }

    @staticmethod
    def _parse_jsonl(stdout: str) -> List[Dict[str, Any]]:
        """nuclei -jsonl 每行一个 JSON，提取 模板名/严重程度/匹配URL/描述。"""
        findings: List[Dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            info = obj.get("info", {}) or {}
            findings.append({
                "template_id": obj.get("template-id") or obj.get("templateID") or "",
                "template_path": obj.get("template-path") or "",
                "name": info.get("name", ""),
                "severity": (info.get("severity") or "info").lower(),
                "description": info.get("description", ""),
                "tags": info.get("tags", []),
                "matched_at": obj.get("matched-at") or obj.get("matched_at") or "",
                "type": obj.get("type", "http"),
                "host": obj.get("host", ""),
            })
        return findings

    def list_templates(self, category: str = "") -> List[Dict[str, Any]]:
        """返回引擎内置模板分类元数据（不代表本机模板数量）。"""
        return [{"category": c, "available": self.available,
                 "note": "模板需在本机 `nuclei -update-templates` 后由引擎提供"}
                for c in NUCLEI_TEMPLATE_CATEGORIES
                if not category or category == c]


# --------------------------------------------------------------------------- #
# dirb（真实执行；本机未安装时如实报告）
# --------------------------------------------------------------------------- #
class DirbScanner:
    def __init__(self, path: str = "dirb") -> None:
        self.path = path
        p = _probe(self.path, [], ["dirb"])
        self.available, self.version = p["available"], p["version"]
        self.actual_path, self.probe_error = p["path"], p["error"]

    def is_available(self) -> bool:
        return self.available

    def scan(self, url: str, wordlist: str = "",
             timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
        if not self.available:
            return {"success": False, "data": None,
                    "error": f"工具未安装: dirb（{self.probe_error}）"}
        args = [self.actual_path, url]
        if wordlist:
            args.append(wordlist)
        started = time.time()
        ex = _run_command(args, timeout=timeout)
        duration = round(time.time() - started, 2)
        results = []
        for line in (ex["stdout"] + "\n" + ex["stderr"]).splitlines():
            m = re.match(r"^\+\s+(.+?)\s+\(CODE:(\d+)\)", line.strip())
            if m:
                results.append({"path": m.group(1), "code": int(m.group(2))})
        return {
            "success": not ex["timed_out"] and not ex["error"],
            "data": {"command": " ".join(args), "results": results,
                     "mode": "real", "duration_sec": duration,
                     "timed_out": ex["timed_out"],
                     "executed_at": time.strftime("%Y-%m-%d %H:%M:%S")},
            "error": ex["error"],
        }


# --------------------------------------------------------------------------- #
# dirsearch（真实执行；本机未安装时如实报告）
# --------------------------------------------------------------------------- #
class DirsearchScanner:
    def __init__(self, path: str = "dirsearch") -> None:
        self.path = path
        # dirsearch 可能是 dirsearch(.bat)/dirsearch.py；尝试 --help
        p = _probe(self.path, ["--help"], ["dirsearch"])
        self.available, self.version = p["available"], p["version"]
        self.actual_path, self.probe_error = p["path"], p["error"]

    def is_available(self) -> bool:
        return self.available

    def scan(self, url: str, extensions: str = "php,html,txt",
             timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
        if not self.available:
            return {"success": False, "data": None,
                    "error": f"工具未安装: dirsearch（{self.probe_error}）"}
        out_dir = ""  # 不落地
        args = [self.actual_path, "-u", url, "-e", extensions, "-q", "--no-color", "-j"]
        started = time.time()
        ex = _run_command(args, timeout=timeout)
        duration = round(time.time() - started, 2)
        results = []
        for line in (ex["stdout"] + "\n" + ex["stderr"]).splitlines():
            m = re.search(r"\[(\d{3})\]\s+(.+)", line.strip())
            if m:
                results.append({"code": int(m.group(1)), "path": m.group(2)})
        return {
            "success": not ex["timed_out"] and not ex["error"],
            "data": {"command": " ".join(args), "results": results,
                     "mode": "real", "duration_sec": duration,
                     "timed_out": ex["timed_out"],
                     "executed_at": time.strftime("%Y-%m-%d %H:%M:%S")},
            "error": ex["error"],
        }


# --------------------------------------------------------------------------- #
# 统一管理器
# --------------------------------------------------------------------------- #
class OtherToolsManager:
    def __init__(self) -> None:
        self.nikto = NiktoScanner()
        self.hydra = HydraScanner()
        self.nuclei = NucleiScanner()
        self.dirb = DirbScanner()
        self.dirsearch = DirsearchScanner()

    def get_all_versions(self) -> Dict[str, Any]:
        return {
            "nikto": {"available": self.nikto.available, "version": self.nikto.version,
                      "path": self.nikto.actual_path, "error": self.nikto.probe_error},
            "hydra": {"available": self.hydra.available, "version": self.hydra.version,
                      "path": self.hydra.actual_path, "error": self.hydra.probe_error},
            "nuclei": {"available": self.nuclei.available, "version": self.nuclei.version,
                       "path": self.nuclei.actual_path, "error": self.nuclei.probe_error},
            "dirb": {"available": self.dirb.available, "version": self.dirb.version,
                     "path": self.dirb.actual_path, "error": self.dirb.probe_error},
            "dirsearch": {"available": self.dirsearch.available, "version": self.dirsearch.version,
                          "path": self.dirsearch.actual_path, "error": self.dirsearch.probe_error},
        }

    def is_available(self, tool: str) -> bool:
        t = getattr(self, tool, None)
        return bool(t and getattr(t, "available", False))

    def get_status(self) -> Dict[str, Any]:
        return {"tools": self.get_all_versions()}


_other_tools_mgr: Optional[OtherToolsManager] = None


def get_manager() -> OtherToolsManager:
    global _other_tools_mgr
    if _other_tools_mgr is None:
        _other_tools_mgr = OtherToolsManager()
    return _other_tools_mgr
