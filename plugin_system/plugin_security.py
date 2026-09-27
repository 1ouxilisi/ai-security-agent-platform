# -*- coding: utf-8 -*-
"""
plugin_security.py - 插件安全审核器

5 类安全检查：代码审计 / 依赖审计 / 权限审计 / 行为审计 / 恶意代码检测。
所有检查均为静态启发式，沙箱用 subprocess 模拟。
"""

from __future__ import annotations

import os
import re
import json
import shutil
import hashlib
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


# 恶意代码特征（仅作示例，用于检测视角）
MALICIOUS_PATTERNS: List[Dict[str, Any]] = [
    {"id": "m001", "name": "eval/exec 调用", "regex": r"\b(eval|exec)\s*\(", "severity": "high"},
    {"id": "m002", "name": "硬编码 Base64 长串", "regex": r"['\"][A-Za-z0-9+/]{120,}={0,2}['\"]", "severity": "medium"},
    {"id": "m003", "name": "subprocess shell=True", "regex": r"shell\s*=\s*True", "severity": "high"},
    {"id": "m004", "name": "敏感文件读取", "regex": r"(/etc/passwd|\.ssh/id_rsa|winnt)", "severity": "critical"},
    {"id": "m005", "name": "反向连接特征", "regex": r"(socket\.socket|connect\(.*\d{1,3}\.\d{1,3})", "severity": "critical"},
    {"id": "m006", "name": "混淆 import", "regex": r"__import__\s*\(\s*['\"](os|subprocess|pty)['\"]", "severity": "high"},
    {"id": "m007", "name": "可疑下载执行", "regex": r"(urllib\.request\.urlretrieve|wget\s|curl\s)", "severity": "medium"},
]

# 不安全 API
UNSAFE_APIS: List[str] = ["eval", "exec", "os.system", "pickle.loads", "marshal.loads", "yaml.load"]


class SecurityAuditor:
    """插件安全审核器。"""

    def __init__(self) -> None:
        self.reports: Dict[str, Dict[str, Any]] = {}
        self.quarantine: Dict[str, Dict[str, Any]] = {}
        self.audit_records: List[Dict[str, Any]] = []

    # ---------- 代码审计 ----------
    def code_audit(self, code: str) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        for pat in MALICIOUS_PATTERNS:
            for m in re.finditer(pat["regex"], code):
                findings.append({
                    "rule_id": pat["id"], "rule": pat["name"],
                    "severity": pat["severity"],
                    "line": code[:m.start()].count("\n") + 1,
                    "snippet": code[max(0, m.start() - 20):m.end() + 20],
                })
        for api in UNSAFE_APIS:
            if api in code:
                findings.append({
                    "rule_id": "u-" + api, "rule": f"不安全 API: {api}",
                    "severity": "medium", "line": -1, "snippet": api,
                })
        # 硬编码凭证
        if re.search(r"(password|passwd|api_key|secret)\s*=\s*['\"][^'\"]{6,}['\"]", code):
            findings.append({
                "rule_id": "cred-hc", "rule": "硬编码凭证",
                "severity": "critical", "line": -1, "snippet": "password=...",
            })
        return {"findings": findings, "count": len(findings)}

    # ---------- 依赖审计 ----------
    def dependency_audit(self, deps: Dict[str, List[str]]) -> Dict[str, Any]:
        issues: List[Dict[str, Any]] = []
        # 模拟已知恶意包
        known_malicious = {"evil-pkg", "malicious-pip", "totally-not-secure"}
        for pkg in deps.get("python_pkgs", []) or []:
            if pkg in known_malicious:
                issues.append({"pkg": pkg, "severity": "critical", "reason": "已知恶意包"})
        for tool in deps.get("system_tools", []) or []:
            if shutil.which(tool) is None:
                issues.append({"pkg": tool, "severity": "info", "reason": "系统工具未安装（需自行评估）"})
        return {"issues": issues, "count": len(issues)}

    # ---------- 权限审计 ----------
    def permission_audit(self, requested: List[str], purpose: str = "") -> Dict[str, Any]:
        risky = {"system.command", "userdata.read", "userdata.write", "network.inbound", "database.write"}
        granted_risky = [p for p in requested if p in risky]
        minimal_ok = len(granted_risky) <= 2
        return {
            "requested": requested,
            "risky_permissions": granted_risky,
            "minimal_compliant": minimal_ok,
            "suggestion": "建议遵循最小权限原则" if not minimal_ok else "权限申请合理",
        }

    # ---------- 行为审计（运行时模拟） ----------
    def behavior_audit(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        suspicious = 0
        for e in events:
            kind = e.get("kind", "")
            if kind in ("reverse_shell", "exfiltrate", "mass_file_read"):
                suspicious += 1
        return {"events": len(events), "suspicious": suspicious,
                "verdict": "suspicious" if suspicious else "clean"}

    # ---------- 恶意插件检测 ----------
    def detect_malicious(self, code: str, behavior_events: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        code_res = self.code_audit(code)
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "info": 1}
        score = 0
        for f in code_res["findings"]:
            score += sev_rank.get(f["severity"], 0)
        beh = self.behavior_audit(behavior_events or [])
        if beh["suspicious"]:
            score += 10
        verdict = "malicious" if score >= 12 else ("suspicious" if score >= 6 else "clean")
        return {"score": score, "verdict": verdict,
                "code_findings": code_res["findings"], "behavior": beh}

    # ---------- 审核流程 ----------
    def submit_for_review(self, plugin_id: str, code: str,
                          metadata: Dict[str, Any]) -> Dict[str, Any]:
        code_res = self.code_audit(code)
        dep_res = self.dependency_audit(metadata.get("dependencies", {}) or {})
        perm_res = self.permission_audit(metadata.get("permissions", []) or [])
        mal = self.detect_malicious(code)
        critical = sum(1 for f in code_res["findings"] if f["severity"] == "critical")
        auto_pass = critical == 0 and mal["verdict"] != "malicious"
        report = {
            "plugin_id": plugin_id,
            "submitted_at": _now(),
            "stage": "auto_review" if auto_pass else "manual_review",
            "auto_pass": auto_pass,
            "code_audit": code_res,
            "dependency_audit": dep_res,
            "permission_audit": perm_res,
            "malware_detection": mal,
            "conclusion": "通过自动审核，等待人工审核" if auto_pass else "需人工审核",
            "improvements": [f["rule"] for f in code_res["findings"] if f["severity"] in ("high", "critical")],
        }
        self.reports[plugin_id] = report
        self.audit_records.append({"plugin_id": plugin_id, "ts": _now(), "stage": report["stage"]})
        return {"ok": True, "report": report}

    def get_report(self, plugin_id: str) -> Optional[Dict[str, Any]]:
        return self.reports.get(plugin_id)

    # ---------- 沙箱（subprocess 模拟） ----------
    def run_in_sandbox(self, code: str, timeout: int = 10) -> Dict[str, Any]:
        """把代码写入临时文件，用受限子进程执行；仅做演示。"""
        try:
            with tempfile.NamedTemporaryFile(
                "w", suffix=".py", delete=False, encoding="utf-8"
            ) as f:
                f.write(code)
                path = f.name
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"写入临时文件失败: {e}"}
        try:
            proc = subprocess.run(
                ["python", path],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
            return {"ok": proc.returncode == 0, "returncode": proc.returncode,
                    "stdout": proc.stdout[:8192], "stderr": proc.stderr[:8192]}
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "沙箱执行超时"}
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    # ---------- 隔离 / 移除 ----------
    def quarantine_plugin(self, plugin_id: str, reason: str) -> Dict[str, Any]:
        self.quarantine[plugin_id] = {
            "plugin_id": plugin_id, "reason": reason,
            "quarantined_at": _now(), "status": "quarantined",
        }
        return {"ok": True, "entry": self.quarantine[plugin_id]}

    def list_quarantined(self) -> List[Dict[str, Any]]:
        return list(self.quarantine.values())

    # ---------- 统计 ----------
    def stats(self) -> Dict[str, Any]:
        malicious = sum(1 for r in self.reports.values()
                        if r.get("malware_detection", {}).get("verdict") == "malicious")
        return {
            "audited": len(self.reports),
            "quarantined": len(self.quarantine),
            "malicious_detected": malicious,
        }


import tempfile  # noqa: E402  (放在末尾避免顶部依赖污染)


_default_auditor: Optional[SecurityAuditor] = None


def get_auditor() -> SecurityAuditor:
    global _default_auditor
    if _default_auditor is None:
        _default_auditor = SecurityAuditor()
    return _default_auditor
