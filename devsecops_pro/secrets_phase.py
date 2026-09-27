# -*- coding: utf-8 -*-
"""
secrets_phase.py 鈥?闃舵4锛歋ecrets 鎵弿銆?
鍔熻兘:
    - 鐪熷疄 gitleaks 闆嗘垚锛坰ubprocess锛岃秴鏃?300s锛?    - 妫€娴?AWS Key / GCP Key / 绉侀挜 / JWT / 瀵嗙爜 / 杩炴帴涓?/ API Token
    - 鏀寔鍘嗗彶鎻愪氦鎵弿锛坓itleaks detect锛?    - 鏈畨瑁呮椂鐢ㄥ唴缃鍒欒鍒欏厹搴?"""

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


@dataclass
class SecretFinding:
    kind: str = ""
    severity: str = "high"
    file: str = ""
    line: int = 0
    match: str = ""
    rule_id: str = ""
    description: str = ""
    source: str = "gitleaks"

    def to_dict(self) -> Dict[str, Any]:
        # 鑴辨晱锛氬彧淇濈暀鍓?6 + 鍚?4 浣?        masked = self.match
        if len(masked) > 14:
            masked = masked[:6] + "..." + masked[-4:]
        return {
            "kind": self.kind, "severity": self.severity,
            "file": self.file, "line": self.line,
            "match_masked": masked, "rule_id": self.rule_id,
            "description": self.description, "source": self.source,
        }


# --------------------------------------------------------------------------- #
# 鍐呯疆姝ｅ垯鍏滃簳瑙勫垯
# --------------------------------------------------------------------------- #
BUILTIN_SECRET_RULES = [
    {"id": "aws-access-key", "kind": "AWS Access Key", "severity": "critical",
     "pattern": re.compile(r"AKIA[0-9A-Z]{16}"),
     "desc": "AWS Access Key ID"},
    {"id": "aws-secret-key", "kind": "AWS Secret Key", "severity": "critical",
     "pattern": re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"),
     "desc": "AWS Secret Access Key"},
    {"id": "gcp-key", "kind": "GCP Private Key", "severity": "critical",
     "pattern": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
     "desc": "Google API Key"},
    {"id": "private-key", "kind": "Private Key", "severity": "critical",
     "pattern": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
     "desc": "绉侀挜鏂囦欢鍐呭"},
    {"id": "jwt", "kind": "JWT Token", "severity": "high",
     "pattern": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
     "desc": "JWT Token"},
    {"id": "github-token", "kind": "GitHub Token", "severity": "critical",
     "pattern": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
     "desc": "GitHub Personal Access Token"},
    {"id": "slack-token", "kind": "Slack Token", "severity": "high",
     "pattern": re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,}"),
     "desc": "Slack Token"},
    {"id": "stripe-key", "kind": "Stripe Key", "severity": "high",
     "pattern": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
     "desc": "Stripe Live Secret Key"},
    {"id": "mailgun-key", "kind": "Mailgun Key", "severity": "medium",
     "pattern": re.compile(r"key-[0-9a-zA-Z]{32}"),
     "desc": "Mailgun API Key"},
    {"id": "db-conn", "kind": "Database Connection String", "severity": "high",
     "pattern": re.compile(
         r"(?:postgres|mysql|mongodb|redis|amqp)://[^\s:@/]+:[^\s:@/]+@[^\s/]+"),
     "desc": "鏁版嵁搴撹繛鎺ヤ覆锛堝惈瀵嗙爜锛?},
    {"id": "generic-password", "kind": "Hardcoded Password", "severity": "high",
     "pattern": re.compile(
         r"(?i)(?:password|passwd|pwd|api_key|apikey|secret|token)\s*[:=]\s*['\"]([^'\"]{8,})['\"]"),
     "desc": "纭紪鐮佸瘑鐮?Token"},
]


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


class SecretsPhase:
    """闃舵4锛歋ecrets 鎵弿銆?""

    def __init__(self) -> None:
        self.gitleaks_bin = _which("gitleaks")

    def tool_status(self) -> Dict[str, Any]:
        return {
            "gitleaks_installed": bool(self.gitleaks_bin),
            "gitleaks_path": self.gitleaks_bin,
            "fallback_rules": len(BUILTIN_SECRET_RULES),
            "detection_types": [r["kind"] for r in BUILTIN_SECRET_RULES],
        }

    # ------------------------------------------------------------------ #
    def scan(self, target_path: str,
             scan_history: bool = False) -> Dict[str, Any]:
        t0 = time.time()
        result: Dict[str, Any] = {
            "target": target_path, "elapsed": 0.0,
            "tool": "gitleaks" if self.gitleaks_bin else "regex-fallback",
            "installed": bool(self.gitleaks_bin),
            "scan_history": scan_history,
            "findings": [], "count": 0, "error": "",
        }
        if not os.path.exists(target_path):
            result["error"] = f"鐩爣璺緞涓嶅瓨鍦? {target_path}"
            return result

        if self.gitleaks_bin:
            try:
                out_json = os.path.join(
                    target_path, ".gitleaks-out.json")
                cmd = [self.gitleaks_bin, "detect",
                       "--source", target_path,
                       "--report-format", "json",
                       "--report-path", out_json,
                       "--exit-code", "0"]
                if not scan_history:
                    cmd.append("--no-git")
                proc = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=SCAN_TIMEOUT, encoding="utf-8", errors="replace")
                findings: List[SecretFinding] = []
                if os.path.exists(out_json):
                    with open(out_json, "r", encoding="utf-8", errors="replace") as f:
                        data = json.load(f)
                    for item in data:
                        findings.append(SecretFinding(
                            kind=item.get("RuleID", "unknown"),
                            severity="high",
                            file=item.get("File", ""),
                            line=item.get("StartLine", 0),
                            match=item.get("Secret", ""),
                            rule_id=item.get("RuleID", ""),
                            description="gitleaks 鍛戒腑",
                            source="gitleaks",
                        ))
                    try:
                        os.remove(out_json)
                    except Exception:
                        pass
                result["findings"] = [f.to_dict() for f in findings]
                result["count"] = len(findings)
                if proc.stderr:
                    result["stderr_tail"] = proc.stderr[-800:]
            except subprocess.TimeoutExpired:
                result["error"] = f"gitleaks 瓒呮椂锛?{SCAN_TIMEOUT}s锛?
            except Exception as e:  # noqa: BLE001
                result["error"] = f"gitleaks 鎵ц澶辫触: {e}"
                result["tool"] = "regex-fallback"
                result["installed"] = False
                fb = self._fallback_scan(target_path)
                result["findings"] = [f.to_dict() for f in fb]
                result["count"] = len(fb)
        else:
            result["message"] = (
                "gitleaks 鏈畨瑁咃紝浣跨敤鍐呯疆姝ｅ垯瑙勫垯鍏滃簳鎵弿銆?
                "瀹夎: https://github.com/gitleaks/gitleaks/releases")
            fb = self._fallback_scan(target_path)
            result["findings"] = [f.to_dict() for f in fb]
            result["count"] = len(fb)

        result["elapsed"] = round(time.time() - t0, 2)
        return result

    # ------------------------------------------------------------------ #
    def _fallback_scan(self, target_path: str) -> List[SecretFinding]:
        out: List[SecretFinding] = []
        for root, dirs, files in os.walk(target_path):
            parts = root.replace("\\", "/").split("/")
            if any(p in ("node_modules", ".venv", "venv", "dist", "build",
                         ".git", "__pycache__", ".idea", ".vscode")
                   for p in parts):
                continue
            for fn in files:
                ext = os.path.splitext(fn)[1].lower()
                if ext in (".png", ".jpg", ".jpeg", ".gif", ".ico", ".lock",
                           ".pyc", ".so", ".dll", ".exe", ".zip", ".tar",
                           ".gz", ".pdf", ".docx", ".xlsx"):
                    continue
                fpath = os.path.join(root, fn)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        text = f.read()
                except Exception:
                    continue
                for rule in BUILTIN_SECRET_RULES:
                    for m in rule["pattern"].finditer(text):
                        line_no = text.count("\n", 0, m.start()) + 1
                        out.append(SecretFinding(
                            kind=rule["kind"],
                            severity=rule["severity"],
                            file=os.path.relpath(fpath, target_path),
                            line=line_no,
                            match=m.group(0),
                            rule_id=rule["id"],
                            description=rule["desc"],
                            source="regex-fallback",
                        ))
        return out


_default: Optional[SecretsPhase] = None


def get_secrets_phase() -> SecretsPhase:
    global _default
    if _default is None:
        _default = SecretsPhase()
    return _default
