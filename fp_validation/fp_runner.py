# -*- coding: utf-8 -*-
"""fp_runner.py — 一键靶场验证执行器。

对 10 个靶场依次执行 nmap + nuclei + nikto + sqlmap 真实扫描（subprocess，
超时 300s），未安装工具时明确提示，不 mock。扫描输出解析为统一 finding
列表，交给 range_repository 做特征匹配。
"""
from __future__ import annotations

import shutil
import subprocess
from datetime import datetime
from typing import Any, Dict, List

from .range_repository import get_repository
from .metrics_calculator import get_calculator
from .rule_optimizer import get_optimizer


TOOL_TIMEOUT = 300


def _which(name: str) -> Dict[str, Any]:
    path = shutil.which(name)
    return {"available": bool(path), "path": path, "error": None if path else f"{name} not found in PATH"}


def _run(cmd: List[str], target: str, timeout: int = TOOL_TIMEOUT) -> Dict[str, Any]:
    """真实执行命令，返回 {ok, stdout, stderr, rc, error, elapsed_s}。"""
    t0 = datetime.utcnow()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        elapsed = (datetime.utcnow() - t0).total_seconds()
        return {
            "ok": proc.returncode == 0,
            "rc": proc.returncode,
            "stdout": (proc.stdout or "")[:20000],
            "stderr": (proc.stderr or "")[:4000],
            "error": None,
            "elapsed_s": round(elapsed, 2),
            "target": target,
            "cmd": cmd,
        }
    except FileNotFoundError as e:
        return {"ok": False, "rc": -1, "stdout": "", "stderr": "",
                "error": f"tool not found: {e}", "elapsed_s": 0.0,
                "target": target, "cmd": cmd}
    except subprocess.TimeoutExpired:
        return {"ok": False, "rc": -2, "stdout": "", "stderr": "",
                "error": f"timeout after {timeout}s", "elapsed_s": timeout,
                "target": target, "cmd": cmd}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "rc": -3, "stdout": "", "stderr": "",
                "error": str(e), "elapsed_s": 0.0,
                "target": target, "cmd": cmd}


def _parse_nmap(out: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or "open" not in line:
            continue
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "open":
            findings.append({
                "type": "open_port",
                "name": parts[2],
                "port": parts[0],
                "detail": line,
            })
    return findings


def _parse_nuclei(out: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    sev_map = {"critical": "critical", "high": "high", "medium": "medium",
               "low": "low", "info": "info"}
    for line in out.splitlines():
        if "] [" not in line:
            continue
        # nuclei 输出形如: [CVE-2021-44228] [http] [critical] http://...
        parts = line.split("] [")
        if len(parts) >= 3:
            template = parts[0].lstrip("[").strip()
            severity = parts[2].split("]")[0].strip().lower()
            url = parts[-1].strip()
            findings.append({
                "type": "nuclei",
                "name": template,
                "severity": sev_map.get(severity, "info"),
                "url": url,
                "detail": line[:300],
            })
    return findings


def _parse_nikto(out: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for line in out.splitlines():
        if line.startswith("+ ") and ("OSVDB" in line or "Server:" in line or
                                       "X-.*" in line or "E/" in line):
            findings.append({
                "type": "nikto_finding",
                "name": line.strip("+ ").strip()[:120],
                "detail": line[:300],
            })
    return findings


def _parse_sqlmap(out: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if "Parameter:" in out or "sqlmap identified" in out or "back-end DBMS" in out:
        findings.append({
            "type": "sql_injection",
            "name": "sqlmap confirmed injection",
            "detail": out[:500],
        })
    return findings


class FPRunner:
    """一键靶场验证执行器。"""

    def __init__(self) -> None:
        self.repo = get_repository()
        self.calc = get_calculator()
        self.opt = get_optimizer()
        self._history: List[Dict[str, Any]] = []

    def tools_status(self) -> Dict[str, Any]:
        return {
            "nmap": _which("nmap"),
            "nuclei": _which("nuclei"),
            "nikto": _which("nikto"),
            "sqlmap": _which("sqlmap"),
        }

    def scan_range(self, range_id: str, timeout: int = TOOL_TIMEOUT) -> Dict[str, Any]:
        """对单个靶场跑 nmap+nuclei+nikto+sqlmap。"""
        r = self.repo.get(range_id)
        if not r:
            return {"success": False, "error": f"unknown range {range_id}"}
        url = r["url"]
        # host 提取
        host = url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        tools = self.tools_status()
        raw: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        if tools["nmap"]["available"]:
            raw["nmap"] = _run(["nmap", "-sV", "-Pn", "--open", host], host, timeout)
            findings += _parse_nmap(raw["nmap"].get("stdout", ""))
        else:
            raw["nmap"] = {"error": tools["nmap"]["error"]}

        if tools["nuclei"]["available"]:
            raw["nuclei"] = _run(["nuclei", "-u", url, "-silent", "-nc",
                                  "-timeout", "10"], url, timeout)
            findings += _parse_nuclei(raw["nuclei"].get("stdout", ""))
        else:
            raw["nuclei"] = {"error": tools["nuclei"]["error"]}

        if tools["nikto"]["available"]:
            raw["nikto"] = _run(["nikto", "-h", url, "-nointeract"], url, timeout)
            findings += _parse_nikto(raw["nikto"].get("stdout", ""))
        else:
            raw["nikto"] = {"error": tools["nikto"]["error"]}

        # sqlmap 仅对 GET 型 URL 且带参数的靶场尝试
        if tools["sqlmap"]["available"] and "?" in url:
            raw["sqlmap"] = _run(["sqlmap", "-u", url, "--batch", "--dbs",
                                  "--level=1", "--risk=1"], url, timeout)
            findings += _parse_sqlmap(raw["sqlmap"].get("stdout", ""))
        else:
            raw["sqlmap"] = {"error": tools["sqlmap"]["error"] or "no parameter in URL, skipped"}

        match = self.repo.match_scan_to_known(range_id, findings)
        metrics = self.calc.compute_from_match(match)
        record = {
            "range_id": range_id,
            "range_name": r["name"],
            "url": url,
            "ts": datetime.utcnow().isoformat() + "Z",
            "raw_tools": {k: {kk: vv for kk, vv in v.items()
                              if kk in ("ok", "error", "elapsed_s", "rc")}
                          for k, v in raw.items()},
            "findings_count": len(findings),
            "match": match,
            "metrics": metrics,
        }
        return {"success": True, "record": record}

    def run_all(self, timeout: int = TOOL_TIMEOUT) -> Dict[str, Any]:
        """一键跑完 10 个靶场。"""
        per_range: List[Dict[str, Any]] = []
        details: List[Dict[str, Any]] = []
        for rid in self.repo.all_ids():
            res = self.scan_range(rid, timeout=timeout)
            if res.get("success"):
                rec = res["record"]
                per_range.append(rec["metrics"])
                details.append(rec)
            else:
                details.append({"range_id": rid, "error": res.get("error")})
        agg = self.calc.aggregate(per_range)
        summary = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "ranges_total": len(self.repo.all_ids()),
            "per_range_metrics": per_range,
            "aggregate": agg,
        }
        self._history.append(summary)
        return {"success": True, "summary": summary, "details": details}

    def history(self) -> List[Dict[str, Any]]:
        return list(self._history)

    def latest(self) -> Dict[str, Any] | None:
        return self._history[-1] if self._history else None


_singleton: FPRunner | None = None


def get_runner() -> FPRunner:
    global _singleton
    if _singleton is None:
        _singleton = FPRunner()
    return _singleton
