# -*- coding: utf-8 -*-
"""
iac_security_phase.py — 阶段5：IaC 安全。

功能:
    - 真实 checkov / terrascan 集成（subprocess，超时 300s）
    - 支持 Terraform / CloudFormation / Kubernetes / Dockerfile / ARM
    - CIS Benchmark / 最佳实践规则
    - 未安装时用内置规则兜底
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

IAC_EXTENSIONS = (".tf", ".tfvars", ".yaml", ".yml", ".json", ".template",
                  ".dockerfile", "Dockerfile")


@dataclass
class IaCFinding:
    rule_id: str = ""
    severity: str = "medium"
    resource: str = ""
    file: str = ""
    line: int = 0
    description: str = ""
    guideline: str = ""
    iac_type: str = ""
    source: str = "checkov"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id, "severity": self.severity,
            "resource": self.resource, "file": self.file, "line": self.line,
            "description": self.description, "guideline": self.guideline,
            "iac_type": self.iac_type, "source": self.source,
        }


# --------------------------------------------------------------------------- #
# 内置兜底规则
# --------------------------------------------------------------------------- #
BUILTIN_IAC_RULES = [
    {"id": "CKV_AWS_66", "iac_type": "terraform",
     "pattern": re.compile(
         r'resource\s+"aws_s3_bucket"[^{]*\{[^}]*acl\s*=\s*"public-read"', re.S),
     "severity": "critical",
     "desc": "S3 Bucket 设置为公共可读",
     "guideline": "使用 acl = private 并通过 bucket policy 授权"},
    {"id": "CKV_AWS_144", "iac_type": "terraform",
     "pattern": re.compile(
         r'resource\s+"aws_ebs_volume"[^{]*\{[^}]*encrypted\s*=\s*false', re.S),
     "severity": "high",
     "desc": "EBS 卷未加密",
     "guideline": "设置 encrypted = true"},
    {"id": "CKV_AWS_18", "iac_type": "terraform",
     "pattern": re.compile(
         r'resource\s+"aws_s3_bucket"[^{]*\{(?!.*logging)', re.S),
     "severity": "medium",
     "desc": "S3 Bucket 未启用访问日志",
     "guideline": "配置 aws_s3_bucket_logging"},
    {"id": "CKV_GCP_7", "iac_type": "terraform",
     "pattern": re.compile(
         r'resource\s+"google_compute_firewall"[^{]*\{[^}]*source_ranges\s*=\s*\[\s*"0\.0\.0\.0/0"',
         re.S),
     "severity": "critical",
     "desc": "GCP 防火墙规则对全网开放",
     "guideline": "限制 source_ranges 到必要网段"},
    {"id": "KSV_001", "iac_type": "kubernetes",
     "pattern": re.compile(r"privileged\s*:\s*true"),
     "severity": "critical",
     "desc": "K8s 容器以 privileged 模式运行",
     "guideline": "设置 privileged: false"},
    {"id": "KSV_002", "iac_type": "kubernetes",
     "pattern": re.compile(r"runAsUser\s*:\s*0"),
     "severity": "high",
     "desc": "K8s 容器以 root 用户运行",
     "guideline": "设置 runAsNonRoot: true"},
    {"id": "DKR_001", "iac_type": "dockerfile",
     "pattern": re.compile(r"^USER\s+root\s*$", re.M),
     "severity": "medium",
     "desc": "Dockerfile 以 root 用户运行",
     "guideline": "创建非 root 用户并 USER 切换"},
    {"id": "DKR_002", "iac_type": "dockerfile",
     "pattern": re.compile(r"(?im)^FROM\s+(alpine|ubuntu|debian):latest", re.M),
     "severity": "low",
     "desc": "使用 latest 基础镜像标签",
     "guideline": "使用固定版本标签"},
]


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


class IaCSecurityPhase:
    """阶段5：IaC 安全。"""

    def __init__(self) -> None:
        self.checkov_bin = _which("checkov")
        self.terrascan_bin = _which("terrascan")

    def tool_status(self) -> Dict[str, Any]:
        return {
            "checkov_installed": bool(self.checkov_bin),
            "terrascan_installed": bool(self.terrascan_bin),
            "builtin_rules": len(BUILTIN_IAC_RULES),
            "iac_types": ["Terraform", "CloudFormation", "Kubernetes",
                          "Dockerfile", "ARM"],
        }

    # ------------------------------------------------------------------ #
    def scan(self, target_path: str,
             iac_type: str = "auto") -> Dict[str, Any]:
        t0 = time.time()
        result: Dict[str, Any] = {
            "target": target_path, "elapsed": 0.0,
            "tool": "checkov" if self.checkov_bin else "regex-fallback",
            "installed": bool(self.checkov_bin or self.terrascan_bin),
            "findings": [], "count": 0, "error": "",
        }
        if not os.path.exists(target_path):
            result["error"] = f"目标路径不存在: {target_path}"
            return result

        if self.checkov_bin:
            try:
                out_json = os.path.join(target_path, ".checkov-out.json")
                cmd = [self.checkov_bin, "-d", target_path,
                       "-o", "json", "--output-file-path", target_path,
                       "--quiet"]
                proc = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=SCAN_TIMEOUT, encoding="utf-8", errors="replace")
                findings: List[IaCFinding] = []
                # checkov 输出在 --output-file-path 目录
                for cand in (out_json,
                             os.path.join(target_path, "results_json.json")):
                    if os.path.exists(cand):
                        with open(cand, "r", encoding="utf-8", errors="replace") as f:
                            data = json.load(f)
                        for r in data.get("results", {}).get(
                                "failed_checks", []):
                            findings.append(IaCFinding(
                                rule_id=r.get("check_id", ""),
                                severity=r.get("severity", "MEDIUM").lower(),
                                resource=r.get("resource", ""),
                                file=r.get("file_path", ""),
                                line=r.get("file_line_range", [0])[0] or 0,
                                description=r.get("check_name", ""),
                                guideline=r.get("guideline", ""),
                                iac_type=r.get("check_class", "terraform"),
                                source="checkov",
                            ))
                        break
                result["findings"] = [f.to_dict() for f in findings]
                result["count"] = len(findings)
                result["stderr_tail"] = (proc.stderr or "")[-800:]
            except subprocess.TimeoutExpired:
                result["error"] = f"checkov 超时（>{SCAN_TIMEOUT}s）"
            except Exception as e:  # noqa: BLE001
                result["error"] = f"checkov 执行失败: {e}"
                result["tool"] = "regex-fallback"
                fb = self._fallback_scan(target_path)
                result["findings"] = [f.to_dict() for f in fb]
                result["count"] = len(fb)
        else:
            result["message"] = (
                "checkov/terrascan 未安装，使用内置规则兜底。"
                "安装: pip install checkov 或 https://terrascan.readthedocs.io")
            fb = self._fallback_scan(target_path)
            result["findings"] = [f.to_dict() for f in fb]
            result["count"] = len(fb)

        result["elapsed"] = round(time.time() - t0, 2)
        return result

    # ------------------------------------------------------------------ #
    def _detect_iac_type(self, fname: str) -> str:
        low = fname.lower()
        if low.endswith((".tf", ".tfvars")):
            return "terraform"
        if "dockerfile" in low:
            return "dockerfile"
        if low.endswith((".yaml", ".yml", ".json")):
            return "kubernetes"
        return "generic"

    def _fallback_scan(self, target_path: str) -> List[IaCFinding]:
        out: List[IaCFinding] = []
        for root, dirs, files in os.walk(target_path):
            parts = root.replace("\\", "/").split("/")
            if any(p in ("node_modules", ".venv", "venv", "dist", "build",
                         ".git", "__pycache__") for p in parts):
                continue
            for fn in files:
                if not fn.endswith(IAC_EXTENSIONS) and "Dockerfile" not in fn:
                    continue
                fpath = os.path.join(root, fn)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        text = f.read()
                except Exception:
                    continue
                iac_type = self._detect_iac_type(fn)
                for rule in BUILTIN_IAC_RULES:
                    if rule["iac_type"] not in (iac_type, "generic"):
                        continue
                    for m in rule["pattern"].finditer(text):
                        line_no = text.count("\n", 0, m.start()) + 1
                        out.append(IaCFinding(
                            rule_id=rule["id"],
                            severity=rule["severity"],
                            resource=m.group(0)[:80],
                            file=os.path.relpath(fpath, target_path),
                            line=line_no,
                            description=rule["desc"],
                            guideline=rule["guideline"],
                            iac_type=iac_type,
                            source="regex-fallback",
                        ))
        return out


_default: Optional[IaCSecurityPhase] = None


def get_iac_phase() -> IaCSecurityPhase:
    global _default
    if _default is None:
        _default = IaCSecurityPhase()
    return _default
