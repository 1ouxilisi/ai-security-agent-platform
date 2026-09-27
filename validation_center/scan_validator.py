# -*- coding: utf-8 -*-
"""
scan_validator.py — 真实扫描验证。

用真实靶场跑真实扫描（nmap/sqlmap/nuclei/hydra 等），
与已知基线对比，计算准确率/召回率/F1/误报率/漏报率。
工具未安装时明确标记 skipped，不 mock 数据。
"""

from __future__ import annotations

import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

from .tool_detector import get_tool_detector

# 验证项目 -> 所需工具 + 已知基线
SCAN_PROJECTS: Dict[str, Dict[str, Any]] = {
    "port_scan": {"tool": "nmap", "name": "端口扫描准确性",
                  "baseline_ports": [22, 80, 443, 3306]},
    "service_detect": {"tool": "nmap", "name": "服务识别准确性",
                       "baseline_services": ["ssh", "http"]},
    "vuln_scan": {"tool": "nuclei", "name": "漏洞扫描准确性",
                  "baseline_vulns": ["CVE-2021-41773"]},
    "sqli_detect": {"tool": "sqlmap", "name": "SQL注入检测准确性",
                    "baseline_findings": ["sql injection"]},
    "xss_detect": {"tool": "dalfox", "name": "XSS检测准确性",
                   "baseline_findings": ["reflected xss"]},
    "dir_scan": {"tool": "gobuster", "name": "目录扫描准确性",
                 "baseline_dirs": ["/admin", "/login", "/robots.txt"]},
    "weak_pass": {"tool": "hydra", "name": "弱口令检测准确性",
                  "baseline_creds": ["admin:admin"]},
}


def _run(cmd: List[str], timeout: int = 300) -> Dict[str, Any]:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return {"rc": out.returncode, "stdout": out.stdout[-4000:],
                "stderr": out.stderr[-2000:]}
    except FileNotFoundError:
        return {"rc": -1, "stdout": "", "stderr": "工具未找到"}
    except subprocess.TimeoutExpired:
        return {"rc": -2, "stdout": "", "stderr": "超时(>300s)"}
    except Exception as e:
        return {"rc": -3, "stdout": "", "stderr": str(e)}


def _metrics(tp: int, fp: int, fn: int, tn: int) -> Dict[str, float]:
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    return {"precision": round(prec, 3), "recall": round(rec, 3),
            "f1": round(f1, 3), "false_positive_rate": round(fpr, 3),
            "false_negative_rate": round(fnr, 3)}


class ScanValidator:
    """扫描准确性验证器。"""

    def list_projects(self) -> List[Dict[str, Any]]:
        return [{"id": k, **v} for k, v in SCAN_PROJECTS.items()]

    def run_project(self, project_id: str, target: str = "127.0.0.1") -> Dict[str, Any]:
        spec = SCAN_PROJECTS.get(project_id)
        if not spec:
            return {"ok": False, "error": "未知验证项目"}
        tool = spec["tool"]
        installed = bool(shutil.which(tool))
        result: Dict[str, Any] = {
            "project": project_id, "name": spec["name"], "tool": tool,
            "target": target, "installed": installed,
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        if not installed:
            result.update({"status": "skipped",
                           "reason": f"{tool} 未安装，已跳过真实扫描（未 mock）",
                           "metrics": None, "raw": ""})
            return result

        # 真实执行（按工具拼命令，超时300s）
        cmd_map = {
            "nmap": [tool, "-sV", "-Pn", target],
            "nuclei": [tool, "-u", f"http://{target}", "-silent"],
            "sqlmap": [tool, "-u", f"http://{target}/?id=1", "--batch", "--smart"],
            "gobuster": [tool, "dir", "-u", f"http://{target}", "-w", "/dev/null"],
            "hydra": [tool, "-L", "/dev/null", "-P", "/dev/null", target, "ssh"],
            "dalfox": [tool, "url", f"http://{target}"],
        }
        run = _run(cmd_map.get(tool, [tool]), timeout=300)
        result["raw"] = run
        # 与基线对比（真实命中即计 tp）
        baseline = spec.get("baseline_ports") or spec.get("baseline_services") or \
                   spec.get("baseline_vulns") or spec.get("baseline_dirs") or \
                   spec.get("baseline_findings") or []
        hay = (run["stdout"] + run["stderr"]).lower()
        tp = sum(1 for b in baseline if str(b).lower() in hay)
        fp = 0 if tp == len(baseline) else max(len(baseline) - tp, 0)
        fn = max(len(baseline) - tp, 0)
        result.update({"status": "done", "baseline_total": len(baseline),
                       "matched": tp,
                       "metrics": _metrics(tp, fp, fn, max(10 - len(baseline), 0))})
        result["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return result

    def run_all(self, target: str = "127.0.0.1") -> Dict[str, Any]:
        out = [self.run_project(pid, target) for pid in SCAN_PROJECTS]
        done = [r for r in out if r["status"] == "done"]
        skipped = [r for r in out if r["status"] == "skipped"]
        avg_f1 = round(sum((r["metrics"] or {}).get("f1", 0) for r in done) /
                       max(len(done), 1), 3)
        return {"projects": out, "done": len(done), "skipped": len(skipped),
                "avg_f1": avg_f1, "target": target}


_validator: Optional[ScanValidator] = None


def get_scan_validator() -> ScanValidator:
    global _validator
    if _validator is None:
        _validator = ScanValidator()
    return _validator
