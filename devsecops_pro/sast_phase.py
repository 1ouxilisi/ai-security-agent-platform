# -*- coding: utf-8 -*-
"""
sast_phase.py — 阶段2：SAST 静态代码分析。

功能:
    - 真实 semgrep 集成（subprocess，超时 300s）
    - 支持 Python / JavaScript / Java / Go / Rust / C / C++
    - 规则包：OWASP Top10 / Security Audit / Secrets / CI
    - 未安装时用内置正则规则兜底（明确标注 fallback）
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SCAN_TIMEOUT = 300

SUPPORTED_LANGS = ("python", "javascript", "java", "go", "rust", "c", "cpp")
RULEPACKS = ("owasp", "security-audit", "secrets", "ci")


@dataclass
class SASTFinding:
    rule_id: str = ""
    severity: str = "medium"
    path: str = ""
    line: int = 0
    column: int = 0
    message: str = ""
    code: str = ""
    fix: str = ""
    source: str = "semgrep"  # semgrep / regex-fallback

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id, "severity": self.severity,
            "path": self.path, "line": self.line, "column": self.column,
            "message": self.message, "code": self.code, "fix": self.fix,
            "source": self.source,
        }


# --------------------------------------------------------------------------- #
# 内置正则兜底规则（semgrep 未安装时使用）
# --------------------------------------------------------------------------- #
FALLBACK_RULES = [
    {
        "id": "py.exec.hardcoded-shell",
        "lang": "python",
        "severity": "high",
        "pattern": re.compile(
            r'os\.system\s*\(\s*["\'][^"\']*\+|subprocess\.(?:call|run|Popen)'
            r'\s*\([^)]*shell\s*=\s*True', re.M),
        "message": "可能的命令注入：外部输入拼接进 shell",
        "fix": "使用 subprocess.run([...], shell=False) 并白名单校验参数。",
    },
    {
        "id": "py.sql.string-format",
        "lang": "python",
        "severity": "critical",
        "pattern": re.compile(
            r'execute\s*\(\s*f?["\'][^"\']*\{|execute\s*\([^)]*%|cursor\.execute\s*\([^)]*\+',
            re.M),
        "message": "可能的 SQL 注入：SQL 字符串拼接/格式化",
        "fix": "使用参数化查询 cursor.execute(sql, (params,))。",
    },
    {
        "id": "py.insecure-random",
        "lang": "python",
        "severity": "medium",
        "pattern": re.compile(r'\brandom\.random\(\)|\brandom\.choice\s*\(', re.M),
        "message": "使用伪随机数做安全决策（应使用 secrets 模块）",
        "fix": "敏感场景改用 secrets.randbelow / secrets.token_hex。",
    },
    {
        "id": "js.eval",
        "lang": "javascript",
        "severity": "high",
        "pattern": re.compile(r'\beval\s*\(', re.M),
        "message": "使用 eval() 执行动态代码，存在代码注入风险",
        "fix": "避免 eval，使用 JSON.parse 或显式函数映射。",
    },
    {
        "id": "js.insecure-regex",
        "lang": "javascript",
        "severity": "medium",
        "pattern": re.compile(r'innerHTML\s*=', re.M),
        "message": "innerHTML 赋值可能导致 XSS",
        "fix": "使用 textContent 或 DOMPurify 消毒。",
    },
    {
        "id": "java.exec",
        "lang": "java",
        "severity": "high",
        "pattern": re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\(', re.M),
        "message": "Runtime.exec 调用，注意命令注入",
        "fix": "使用 ProcessBuilder 并拆分参数数组。",
    },
    {
        "id": "go.sql-string",
        "lang": "go",
        "severity": "high",
        "pattern": re.compile(r'Query\s*\(\s*fmt\.Sprintf', re.M),
        "message": "Query 中使用 fmt.Sprintf 拼接 SQL",
        "fix": "使用 db.Query(sql, args...) 参数化。",
    },
    {
        "id": "generic.debug-commit",
        "lang": "python",
        "severity": "low",
        "pattern": re.compile(r'TODO\(security\)|FIXME\(security\)', re.M),
        "message": "存在安全相关 TODO/FIXME",
        "fix": "跟进并修复安全遗留项。",
    },
]

LANG_EXT = {
    "python": {".py"},
    "javascript": {".js", ".jsx", ".ts", ".tsx"},
    "java": {".java"},
    "go": {".go"},
    "rust": {".rs"},
    "c": {".c", ".h"},
    "cpp": {".cpp", ".cc", ".cxx", ".hpp"},
}


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


class SASTPhase:
    """阶段2：SAST 静态代码分析。"""

    def __init__(self) -> None:
        self.semgrep_bin = _which("semgrep")

    # ------------------------------------------------------------------ #
    def tool_status(self) -> Dict[str, Any]:
        return {
            "semgrep_installed": bool(self.semgrep_bin),
            "semgrep_path": self.semgrep_bin,
            "fallback": "内置正则规则（8 条）" if not self.semgrep_bin else "unused",
            "languages": list(SUPPORTED_LANGS),
            "rulepacks": list(RULEPACKS),
        }

    # ------------------------------------------------------------------ #
    def _map_rulepack(self, rulepack: str) -> str:
        return {
            "owasp": "p/owasp-top-ten",
            "security-audit": "p/security-audit",
            "secrets": "p/secrets",
            "ci": "p/ci",
        }.get(rulepack, "auto")

    # ------------------------------------------------------------------ #
    def scan(self, target_path: str,
             rulepack: str = "auto",
             languages: Optional[List[str]] = None
             ) -> Dict[str, Any]:
        t0 = time.time()
        result: Dict[str, Any] = {
            "target": target_path, "elapsed": 0.0,
            "tool": "semgrep" if self.semgrep_bin else "regex-fallback",
            "installed": bool(self.semgrep_bin),
            "rulepack": rulepack,
            "findings": [], "count": 0, "error": "",
        }
        if not os.path.exists(target_path):
            result["error"] = f"目标路径不存在: {target_path}"
            return result

        if self.semgrep_bin:
            try:
                cfg = self._map_rulepack(rulepack) if rulepack != "auto" else "auto"
                cmd = [self.semgrep_bin, "scan", "--json", "--config", cfg,
                       "--metrics=off", "--quiet", target_path]
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT,
                    encoding="utf-8", errors="replace")
                data = json.loads(proc.stdout or "{}")
                findings = self._parse_semgrep(data)
                result["findings"] = [f.to_dict() for f in findings]
                result["count"] = len(findings)
                result["stderr_tail"] = (proc.stderr or "")[-1000:]
            except subprocess.TimeoutExpired:
                result["error"] = f"semgrep 超时（>{SCAN_TIMEOUT}s）"
            except Exception as e:  # noqa: BLE001
                result["error"] = f"semgrep 执行失败: {type(e).__name__}: {e}"
                result["tool"] = "regex-fallback"
                result["installed"] = False
                result["findings"] = [f.to_dict() for f in self._fallback_scan(
                    target_path, languages)]
                result["count"] = len(result["findings"])
        else:
            result["message"] = (
                "semgrep 未安装，使用内置正则规则兜底扫描。"
                "安装: pip install semgrep")
            result["findings"] = [f.to_dict() for f in self._fallback_scan(
                target_path, languages)]
            result["count"] = len(result["findings"])

        result["elapsed"] = round(time.time() - t0, 2)
        return result

    # ------------------------------------------------------------------ #
    def _parse_semgrep(self, data: Dict[str, Any]) -> List[SASTFinding]:
        out: List[SASTFinding] = []
        sev_map = {"INFO": "info", "WARNING": "medium", "ERROR": "high"}
        for r in data.get("results", []):
            meta = r.get("extra", {})
            sev = meta.get("severity", "medium")
            sev = sev_map.get(sev, str(sev).lower())
            out.append(SASTFinding(
                rule_id=r.get("check_id", "").split(".")[-1],
                severity=sev,
                path=r.get("path", ""),
                line=r.get("start", {}).get("line", 0),
                column=r.get("start", {}).get("col", 0),
                message=meta.get("message", ""),
                code=meta.get("lines", "")[:400],
                fix=meta.get("fix", "") or "请参考规则文档修复",
                source="semgrep",
            ))
        return out

    # ------------------------------------------------------------------ #
    def _fallback_scan(self, target_path: str,
                       languages: Optional[List[str]] = None
                       ) -> List[SASTFinding]:
        out: List[SASTFinding] = []
        langs = languages or list(SUPPORTED_LANGS)
        for root, _dirs, files in os.walk(target_path):
            # 跳过虚拟环境 / 构建目录
            parts = root.replace("\\", "/").split("/")
            if any(p in ("node_modules", ".venv", "venv", "dist", "build",
                         ".git", "__pycache__") for p in parts):
                continue
            for fn in files:
                ext = os.path.splitext(fn)[1].lower()
                fpath = os.path.join(root, fn)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        text = f.read()
                except Exception:
                    continue
                for rule in FALLBACK_RULES:
                    if rule["lang"] not in langs and rule["lang"] != "generic":
                        # 只对匹配扩展名的语言生效
                        lang_exts = LANG_EXT.get(rule["lang"], set())
                        if ext not in lang_exts:
                            continue
                    for m in rule["pattern"].finditer(text):
                        line_no = text.count("\n", 0, m.start()) + 1
                        out.append(SASTFinding(
                            rule_id=rule["id"],
                            severity=rule["severity"],
                            path=os.path.relpath(fpath, target_path),
                            line=line_no,
                            message=rule["message"],
                            code=text[max(0, m.start()-40):m.end()+40],
                            fix=rule["fix"],
                            source="regex-fallback",
                        ))
        return out


_default: Optional[SASTPhase] = None


def get_sast_phase() -> SASTPhase:
    global _default
    if _default is None:
        _default = SASTPhase()
    return _default
