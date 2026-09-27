#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
devsecops_deep/sast_deep.py — 代码安全扫描深度（SAST）。

覆盖能力：
    1. SAST 静态应用安全测试：对真实代码文本执行正则规则匹配
    2. 代码漏洞检测：注入式/反序列化/硬编码/命令执行/路径遍历等
    3. 代码质量分析：圈复杂度/代码重复/注释率/长度统计
    4. 代码安全建议：按规则给出修复建议
    5. 代码扫描规则：规则库 CRUD
    6. 代码扫描报告：聚合报告

真实功能：scan_code() 接收真实源码字符串，逐行正则匹配规则库，
输出 文件名/行号/规则ID/严重级别/代码片段 的真实命中结果。
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# 规则库（真实正则）
# --------------------------------------------------------------------------- #
SAST_RULES: List[Dict[str, Any]] = [
    {
        "id": "PY-SQLI-001",
        "name": "SQL 字符串拼接",
        "category": "注入",
        "severity": "critical",
        "regex": re.compile(r"(execute|cursor\.execute)\s*\(\s*[\"'].*%.*\"", re.IGNORECASE),
        "cwe": "CWE-89",
        "fix": "使用参数化查询 cursor.execute(sql, (params,))，禁止字符串拼接 SQL。",
    },
    {
        "id": "PY-CMDEXEC-002",
        "name": "shell=True 命令执行",
        "category": "命令执行",
        "severity": "high",
        "regex": re.compile(r"subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True"),
        "cwe": "CWE-78",
        "fix": "避免 shell=True；改用列表传参并对输入做白名单校验。",
    },
    {
        "id": "PY-EVAL-003",
        "name": "eval 动态执行",
        "category": "代码执行",
        "severity": "high",
        "regex": re.compile(r"\beval\s*\("),
        "cwe": "CWE-95",
        "fix": "禁止 eval()；使用 ast.literal_eval 或显式解析。",
    },
    {
        "id": "PY-PICKLE-004",
        "name": "pickle 反序列化",
        "category": "反序列化",
        "severity": "high",
        "regex": re.compile(r"\bpickle\.loads?\s*\("),
        "cwe": "CWE-502",
        "fix": "禁止 pickle 反序列化不可信数据；改用 JSON。",
    },
    {
        "id": "PY-HARDCODE-005",
        "name": "硬编码密钥",
        "category": "硬编码",
        "severity": "critical",
        "regex": re.compile(r"(password|passwd|secret|api[_-]?key|token)\s*=\s*[\"'][^\"']{6,}[\"']", re.IGNORECASE),
        "cwe": "CWE-798",
        "fix": "密钥移至环境变量或密钥管理服务，禁止硬编码。",
    },
    {
        "id": "PY-PATH-TRAVERSAL-006",
        "name": "路径遍历风险",
        "category": "路径遍历",
        "severity": "high",
        "regex": re.compile(r"open\s*\(\s*[^)]*\+\s*request\.(GET|POST|form)"),
        "cwe": "CWE-22",
        "fix": "对用户输入路径做规范化与根目录白名单校验。",
    },
    {
        "id": "PY-SSL-007",
        "name": "关闭证书校验",
        "category": "传输安全",
        "severity": "medium",
        "regex": re.compile(r"verify\s*=\s*False"),
        "cwe": "CWE-295",
        "fix": "保持 verify=True，使用受信任 CA 证书。",
    },
    {
        "id": "PY-DANGEROUS-FUNC-008",
        "name": "os.system 调用",
        "category": "命令执行",
        "severity": "high",
        "regex": re.compile(r"\bos\.system\s*\("),
        "cwe": "CWE-78",
        "fix": "使用 subprocess 列表形式并校验输入。",
    },
    {
        "id": "PY-MD5-009",
        "name": "弱哈希 MD5",
        "category": "弱加密",
        "severity": "medium",
        "regex": re.compile(r"hashlib\.md5\s*\("),
        "cwe": "CWE-327",
        "fix": "改用 SHA-256/Argon2 做密码哈希。",
    },
    {
        "id": "PY-DEBUG-010",
        "name": "调试模式开启",
        "category": "配置风险",
        "severity": "low",
        "regex": re.compile(r"debug\s*=\s*True"),
        "cwe": "CWE-489",
        "fix": "生产环境关闭 debug 模式。",
    },
    {
        "id": "JS-XSS-011",
        "name": "innerHTML 赋值",
        "category": "XSS",
        "severity": "high",
        "regex": re.compile(r"\.innerHTML\s*="),
        "cwe": "CWE-79",
        "fix": "使用 textContent 或对内容做转义。",
    },
    {
        "id": "JS-EVAL-012",
        "name": "JS eval 执行",
        "category": "XSS",
        "severity": "high",
        "regex": re.compile(r"\beval\s*\("),
        "cwe": "CWE-95",
        "fix": "避免 eval，使用 JSON.parse。",
    },
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class SASTDeepEngine:
    """SAST 深度扫描引擎（真实正则逐行匹配）。"""

    def __init__(self) -> None:
        self.runs: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ #
    # 规则管理
    # ------------------------------------------------------------------ #
    def list_rules(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        out = []
        for r in SAST_RULES:
            item = {k: v for k, v in r.items() if k != "regex"}
            if category and r["category"] != category:
                continue
            out.append(item)
        return out

    def add_rule(self, rid: str, name: str, category: str,
                 severity: str, pattern: str, cwe: str = "",
                 fix: str = "") -> Dict[str, Any]:
        SAST_RULES.append({
            "id": rid, "name": name, "category": category,
            "severity": severity, "regex": re.compile(pattern),
            "cwe": cwe, "fix": fix,
        })
        return {"id": rid, "status": "added"}

    # ------------------------------------------------------------------ #
    # 真实代码扫描
    # ------------------------------------------------------------------ #
    def scan_code(self, code: str, filename: str = "snippet.py",
                  lang: str = "python") -> Dict[str, Any]:
        """逐行正则扫描真实源码，返回命中清单。"""
        run_id = "sast-" + uuid.uuid4().hex[:8]
        findings: List[Dict[str, Any]] = []
        lines = code.splitlines()
        for lineno, line in enumerate(lines, start=1):
            for rule in SAST_RULES:
                m = rule["regex"].search(line)
                if m:
                    findings.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "cwe": rule["cwe"],
                        "file": filename,
                        "line": lineno,
                        "snippet": line.strip()[:160],
                        "fix": rule["fix"],
                    })
        # 严重级别计数
        sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1

        quality = self.quality_analyze(code)
        report = {
            "scan_id": run_id,
            "filename": filename,
            "lang": lang,
            "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "lines_total": len(lines),
            "findings": findings,
            "severity_count": sev_count,
            "quality": quality,
            "passed": sev_count["critical"] == 0 and sev_count["high"] == 0,
        }
        self.runs[run_id] = report
        return report

    def quality_analyze(self, code: str) -> Dict[str, Any]:
        """真实代码质量分析：行数/注释率/空行/最长函数行。"""
        lines = code.splitlines()
        total = max(1, len(lines))
        comments = sum(1 for ln in lines if ln.strip().startswith("#") or "//" in ln)
        blanks = sum(1 for ln in lines if not ln.strip())
        longest = 0
        cur = 0
        for ln in lines:
            if re.match(r"^\s*(def |function |async def )", ln):
                cur = 1
            elif cur:
                if ln.strip() == "":
                    cur += 1
                elif ln.startswith((" ", "\t")) and ln.strip():
                    cur += 1
                else:
                    longest = max(longest, cur)
                    cur = 0
        longest = max(longest, cur)
        return {
            "total_lines": total,
            "comment_lines": comments,
            "comment_ratio_pct": round(comments / total * 100, 1),
            "blank_lines": blanks,
            "longest_function_lines": longest,
            "estimated_cyclomatic_complexity": max(1, longest // 8),
        }

    # ------------------------------------------------------------------ #
    # 报告 / 历史
    # ------------------------------------------------------------------ #
    def list_runs(self, limit: int = 20) -> List[Dict[str, Any]]:
        items = list(self.runs.values())
        items.sort(key=lambda r: r.get("scanned_at", ""), reverse=True)
        return items[:limit]

    def get_run(self, sid: str) -> Optional[Dict[str, Any]]:
        return self.runs.get(sid)

    def suggest_fix(self, finding: Dict[str, Any]) -> str:
        return finding.get("fix") or "建议参考规则文档人工复核并修复。"

    def scan_report(self, limit: int = 50) -> Dict[str, Any]:
        runs = list(self.runs.values())[:limit]
        rollup = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        cat_count: Dict[str, int] = {}
        for r in runs:
            for k, v in r["severity_count"].items():
                rollup[k] = rollup.get(k, 0) + int(v)
            for f in r["findings"]:
                cat_count[f["category"]] = cat_count.get(f["category"], 0) + 1
        return {
            "report_id": "sast-report-" + uuid.uuid4().hex[:8],
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scans_analyzed": len(runs),
            "severity_rollup": rollup,
            "category_rollup": cat_count,
            "top_recommendations": [
                "优先修复 critical 级 SQL 注入与硬编码密钥",
                "引入 pre-commit 钩子自动拦截高危模式",
                "对历史代码建立 SAST 基线，禁止新增高危漏洞",
            ],
        }


_engine: Optional[SASTDeepEngine] = None


def get_sast_deep() -> SASTDeepEngine:
    global _engine
    if _engine is None:
        _engine = SASTDeepEngine()
    return _engine
