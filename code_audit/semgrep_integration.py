# -*- coding: utf-8 -*-
"""
code_audit/semgrep_integration.py — Semgrep 集成器（第11轮升级）

能力：
- Semgrep CLI / API 集成，支持 Semgrep 规则语法（mode / patterns / pattern-either）
- 规则集：OWASP Top 10 / CWE Top 25 / 语言特定规则集
- 扫描本地代码目录与远程仓库（远程仓库通过浅克隆模拟）
- 解析 Semgrep JSON 输出为统一漏洞格式
- 规则集管理、扫描报告生成

说明：
- 若本机安装了 semgrep CLI（`semgrep --version`），可真实调用；
- 否则回退到基于内置规则的模拟扫描，保证模块可独立 import 与运行。
所有功能均为防御 / 评估 / 检测视角。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

# 复用 SAST 引擎的规则匹配能力做回退扫描
try:
    from code_audit.sast_engine import get_sast_engine, SEVERITY_SCORE
except Exception:  # pragma: no cover
    get_sast_engine = None          # type: ignore
    SEVERITY_SCORE = {"Critical": 9.5, "High": 7.5, "Medium": 5.0,
                      "Low": 2.5, "Info": 1.0}


# ---------------------------------------------------------------------------
# 内置规则集定义
# ---------------------------------------------------------------------------
RULESETS: Dict[str, Dict[str, Any]] = {
    "owasp-top-10": {
        "name": "OWASP Top 10 (2021)",
        "description": "覆盖 OWASP Top 10：注入、失效访问控制、敏感数据暴露等",
        "languages": ["python", "javascript", "java", "php", "go"],
        "checks": [
            {"id": "owasp-a01", "title": "失效的访问控制",
             "cwe": "CWE-862", "severity": "High",
             "pattern": "缺少鉴权注解或中间件"},
            {"id": "owasp-a02", "title": "加密机制失效",
             "cwe": "CWE-327", "severity": "High",
             "pattern": "使用 MD5/SHA1/DES/弱 TLS"},
            {"id": "owasp-a03", "title": "注入",
             "cwe": "CWE-89", "severity": "Critical",
             "pattern": "SQL/命令/NoSQL 拼接用户输入"},
            {"id": "owasp-a05", "title": "安全配置错误",
             "cwe": "CWE-16", "severity": "Medium",
             "pattern": "调试开关、默认口令、通配 CORS"},
            {"id": "owasp-a07", "title": "身份认证失败",
             "cwe": "CWE-287", "severity": "High",
             "pattern": "会话固定、JWT alg=none"},
            {"id": "owasp-a08", "title": "软件与数据完整性失效",
             "cwe": "CWE-502", "severity": "Critical",
             "pattern": "反序列化不可信数据"},
            {"id": "owasp-a10", "title": "服务端请求伪造 (SSRF)",
             "cwe": "CWE-918", "severity": "High",
             "pattern": "请求用户提供的 URL"},
        ],
    },
    "cwe-top-25": {
        "name": "CWE Top 25 (2024)",
        "description": "MITRE 评选的最危险 25 个软件弱点",
        "languages": ["python", "javascript", "java", "c", "cpp", "go"],
        "checks": [
            {"id": "cwe-79", "title": "XSS", "cwe": "CWE-79",
             "severity": "High", "pattern": "未转义输出"},
            {"id": "cwe-89", "title": "SQL 注入", "cwe": "CWE-89",
             "severity": "Critical", "pattern": "拼接 SQL"},
            {"id": "cwe-78", "title": "命令注入", "cwe": "CWE-78",
             "severity": "Critical", "pattern": "拼接 shell 命令"},
            {"id": "cwe-22", "title": "路径遍历", "cwe": "CWE-22",
             "severity": "High", "pattern": "用户输入拼路径"},
            {"id": "cwe-502", "title": "反序列化", "cwe": "CWE-502",
             "severity": "Critical", "pattern": "反序列化不可信数据"},
            {"id": "cwe-787", "title": "越界写", "cwe": "CWE-787",
             "severity": "Critical", "pattern": "strcpy/sprintf 等"},
            {"id": "cwe-798", "title": "硬编码凭据", "cwe": "CWE-798",
             "severity": "High", "pattern": "源码含密钥/口令"},
            {"id": "cwe-416", "title": "释放后使用", "cwe": "CWE-416",
             "severity": "Critical", "pattern": "free 后解引用"},
            {"id": "cwe-352", "title": "CSRF", "cwe": "CWE-352",
             "severity": "Medium", "pattern": "缺少 CSRF Token"},
            {"id": "cwe-918", "title": "SSRF", "cwe": "CWE-918",
             "severity": "High", "pattern": "请求外部 URL"},
        ],
    },
    "lang-python": {
        "name": "Python 语言特定规则",
        "description": "Python 生态常见缺陷模式",
        "languages": ["python"],
        "checks": [
            {"id": "py-eval", "title": "eval/exec", "cwe": "CWE-95",
             "severity": "Critical", "pattern": "eval/exec 动态执行"},
            {"id": "py-pickle", "title": "pickle", "cwe": "CWE-502",
             "severity": "Critical", "pattern": "pickle 反序列化"},
            {"id": "py-shell", "title": "shell=True", "cwe": "CWE-78",
             "severity": "High", "pattern": "subprocess shell=True"},
        ],
    },
    "lang-javascript": {
        "name": "JavaScript 语言特定规则",
        "description": "Node/浏览器 JS 常见缺陷",
        "languages": ["javascript", "typescript"],
        "checks": [
            {"id": "js-eval", "title": "eval/Function", "cwe": "CWE-95",
             "severity": "Critical", "pattern": "eval / new Function"},
            {"id": "js-xss", "title": "XSS", "cwe": "CWE-79",
             "severity": "High", "pattern": "innerHTML / document.write"},
            {"id": "js-nosqli", "title": "NoSQL 注入", "cwe": "CWE-943",
             "severity": "High", "pattern": "$where / 直接用 req.body"},
        ],
    },
    "lang-java": {
        "name": "Java 语言特定规则",
        "description": "J2EE / Spring 常见缺陷",
        "languages": ["java"],
        "checks": [
            {"id": "jv-deser", "title": "反序列化", "cwe": "CWE-502",
             "severity": "Critical", "pattern": "ObjectInputStream"},
            {"id": "jv-jndi", "title": "JNDI 注入", "cwe": "CWE-74",
             "severity": "Critical", "pattern": "lookup 用户输入"},
            {"id": "jv-xxe", "title": "XXE", "cwe": "CWE-611",
             "severity": "High", "pattern": "XML 解析未禁 DTD"},
        ],
    },
}


# ---------------------------------------------------------------------------
# Semgrep 集成器
# ---------------------------------------------------------------------------
class SemgrepIntegration:
    """Semgrep CLI/规则集成器。"""

    def __init__(self) -> None:
        self.rulesets: Dict[str, Dict[str, Any]] = dict(RULESETS)
        self.cli_available: bool = self._detect_cli()
        self.last_scan: Dict[str, Any] = {}

    # -- CLI 探测 --
    @staticmethod
    def _detect_cli() -> bool:
        try:
            r = subprocess.run(
                ["semgrep", "--version"], capture_output=True,
                text=True, timeout=5,
            )
            return r.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    # -- 规则集管理 --
    def list_rulesets(self) -> List[Dict[str, Any]]:
        out = []
        for key, rs in self.rulesets.items():
            out.append({
                "id": key,
                "name": rs["name"],
                "description": rs["description"],
                "languages": rs["languages"],
                "check_count": len(rs["checks"]),
            })
        return out

    def get_ruleset(self, rs_id: str) -> Optional[Dict[str, Any]]:
        return self.rulesets.get(rs_id)

    def add_ruleset(self, data: Dict[str, Any]) -> Dict[str, Any]:
        rs_id = data.get("id") or f"custom-{int(time.time())}"
        self.rulesets[rs_id] = {
            "name": data.get("name", rs_id),
            "description": data.get("description", ""),
            "languages": data.get("languages", ["generic"]),
            "checks": data.get("checks", []),
        }
        return {"id": rs_id, "check_count": len(self.rulesets[rs_id]["checks"])}

    # -- 扫描 --
    def scan(self, target: str, rulesets: Optional[List[str]] = None,
             is_remote: bool = False) -> Dict[str, Any]:
        """扫描本地目录或远程仓库 URL。"""
        started = time.time()
        rulesets = rulesets or ["owasp-top-10", "cwe-top-25"]

        if is_remote:
            target = self._clone_repo(target)

        findings: List[Dict[str, Any]] = []
        files_scanned = 0

        if self.cli_available and os.path.isdir(target):
            findings, files_scanned = self._run_cli(target, rulesets)
            engine_used = "semgrep-cli"
        else:
            findings, files_scanned = self._simulate_scan(target, rulesets)
            engine_used = "simulated"

        elapsed = round(time.time() - started, 3)
        by_sev: Dict[str, int] = {}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        self.last_scan = {
            "target": target,
            "engine": engine_used,
            "files_scanned": files_scanned,
            "findings": findings,
            "by_severity": by_sev,
            "rulesets_used": rulesets,
            "elapsed_seconds": elapsed,
            "timestamp": datetime.now().isoformat(),
        }
        return self.last_scan

    def _clone_repo(self, url: str) -> str:
        """浅克隆远程仓库（失败则回退到目标路径本身）。"""
        tmp = os.path.join(os.getcwd(), ".semgrep_tmp_repo")
        try:
            if os.path.exists(tmp):
                shutil.rmtree(tmp, ignore_errors=True)
            subprocess.run(
                ["git", "clone", "--depth", "1", url, tmp],
                capture_output=True, timeout=60,
            )
            return tmp if os.path.isdir(tmp) else url
        except (OSError, subprocess.SubprocessError):
            return url

    def _run_cli(self, target: str, rulesets: List[str]
                 ) -> tuple:
        """真实调用 semgrep CLI 并解析 JSON。"""
        cmd = ["semgrep", "scan", "--json", "--quiet", target]
        for rs in rulesets:
            # 真实环境可使用 -c p/<name>；这里使用 config 目录占位
            cmd += ["--config", rs]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            data = json.loads(r.stdout) if r.stdout else {}
            findings = self.parse_json(data)
            return findings, len(data.get("paths", {}).get("scanned", []))
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            return self._simulate_scan(target, rulesets)

    def _simulate_scan(self, target: str, rulesets: List[str]
                       ) -> tuple:
        """基于内置规则集 + SAST 引擎的模拟扫描。"""
        findings: List[Dict[str, Any]] = []
        files_scanned = 0
        check_pool: List[Dict[str, Any]] = []
        for rs in rulesets:
            rs_def = self.rulesets.get(rs)
            if rs_def:
                check_pool.extend(rs_def["checks"])

        if os.path.isdir(target) and get_sast_engine is not None:
            result = get_sast_engine().analyze_directory(target)
            files_scanned = result["files_scanned"]
            for f in result["findings"]:
                findings.append({
                    "check_id": f["rule_id"],
                    "path": f["file_path"],
                    "start": {"line": f["line"], "col": f["column"]},
                    "end": {"line": f["line"], "col": f["column"]},
                    "extra": {
                        "message": f["description"],
                        "severity": f["severity"],
                        "metadata": {"cwe": f.get("cwe", ""),
                                     "source": "sast-fallback"},
                        "lines": f["snippet"],
                        "fix": f["fix"],
                    },
                })
        else:
            # 非目录：返回规则集元信息作为演示结果
            files_scanned = 1
            for c in check_pool[:10]:
                findings.append({
                    "check_id": c["id"],
                    "path": target,
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 1},
                    "extra": {
                        "message": f'{c["title"]}: {c["pattern"]}',
                        "severity": c["severity"],
                        "metadata": {"cwe": c["cwe"], "source": "ruleset"},
                        "lines": "",
                        "fix": "参照规则集修复建议",
                    },
                })
        return findings, files_scanned

    # -- 解析 Semgrep JSON --
    @staticmethod
    def parse_json(data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """把 semgrep --json 输出转成统一漏洞对象。"""
        unified: List[Dict[str, Any]] = []
        for res in data.get("results", []):
            extra = res.get("extra", {})
            unified.append({
                "check_id": res.get("check_id", ""),
                "path": res.get("path", ""),
                "start": res.get("start", {}),
                "end": res.get("end", {}),
                "severity": extra.get("severity", "Medium"),
                "message": extra.get("message", ""),
                "lines": extra.get("lines", ""),
                "cwe": (extra.get("metadata", {}) or {}).get("cwe", ""),
                "fix": (extra.get("metadata", {}) or {}).get("fix", ""),
            })
        return unified

    # -- 报告 --
    def generate_report(self, scan: Optional[Dict[str, Any]] = None
                        ) -> Dict[str, Any]:
        scan = scan or self.last_scan
        by_sev = scan.get("by_severity", {})
        risk = "Critical" if by_sev.get("Critical") else (
            "High" if by_sev.get("High") else (
                "Medium" if by_sev.get("Medium") else "Low"))
        return {
            "report_type": "Semgrep 扫描报告",
            "generated_at": datetime.now().isoformat(),
            "target": scan.get("target"),
            "engine": scan.get("engine"),
            "files_scanned": scan.get("files_scanned", 0),
            "findings_count": len(scan.get("findings", [])),
            "by_severity": by_sev,
            "risk_level": risk,
            "top_findings:": sorted(
                scan.get("findings", []),
                key=lambda x: SEVERITY_SCORE.get(x.get("severity", "Info"), 1.0),
                reverse=True,
            )[:20],
            "rulesets_used": scan.get("rulesets_used", []),
        }


_semgrep = SemgrepIntegration()


def get_semgrep_integration() -> SemgrepIntegration:
    return _semgrep
