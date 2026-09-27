# -*- coding: utf-8 -*-
"""
fp_rate.py — 误报率 / 漏报率验证体系（P0-2 核心模块）。

目标：用已知漏洞靶场跑真实扫描（nmap + nuclei + nikto），对比已知漏洞清单，
计算误报率 / 漏报率 / 准确率(Precision) / 召回率(Recall) / F1。

设计：
- 全部内存字典模拟存储（靶场库 / 历史记录）。
- 扫描真实调用 real_tools_deep 的执行器；工具未安装时记录为 skipped，不造假。
- 匹配基于「已知漏洞类型关键词」与扫描发现的文本/严重度做归类比对。
- 生成 HTML 报告到 reports/ 目录，并保留历史记录用于趋势对比。

设计定位：仅用于授权的安全评估 / 工具自验证环境。
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional

from real_tools_deep import nmap_deep, other_tools

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")


# --------------------------------------------------------------------------- #
# 已知漏洞靶场清单
# --------------------------------------------------------------------------- #
DEFAULT_RANGES: Dict[str, Dict[str, Any]] = {
    "dvwa": {
        "name": "DVWA", "url": "http://127.0.0.1/dvwa/",
        "known_vuln_types": ["sqli", "xss", "csrf", "file_upload", "file_inclusion", "cmd_exec", "brute"],
        "known_vuln_count": 17,
        "difficulty": "easy", "status": "offline",
    },
    "juice_shop": {
        "name": "Juice Shop", "url": "http://127.0.0.1:3000/",
        "known_vuln_types": ["sqli", "xss", "ssrf", "idor", "broken_auth", "jwt", "xxe"],
        "known_vuln_count": 30, "difficulty": "medium", "status": "offline",
    },
    "webgoat": {
        "name": "WebGoat", "url": "http://127.0.0.1:8080/WebGoat/",
        "known_vuln_types": ["sqli", "xss", "csrf", "xxe", "idor", "mass_assignment"],
        "known_vuln_count": 25, "difficulty": "medium", "status": "offline",
    },
    "bwapp": {
        "name": "bWAPP", "url": "http://127.0.0.1/bwapp/",
        "known_vuln_types": ["sqli", "xss", "lfi", "rfi", "cmd_exec", "file_upload", "xml", "session"],
        "known_vuln_count": 100, "difficulty": "easy", "status": "offline",
    },
    "mutillidae": {
        "name": "Mutillidae", "url": "http://127.0.0.1/mutillidae/",
        "known_vuln_types": ["sqli", "xss", "lfi", "rfi", "csrf", "captcha_bypass"],
        "known_vuln_count": 40, "difficulty": "easy", "status": "offline",
    },
    "pikachu": {
        "name": "Pikachu", "url": "http://127.0.0.1/pikachu/",
        "known_vuln_types": ["sqli", "xss", "csrf", "file_upload", "rce", "include"],
        "known_vuln_count": 20, "difficulty": "easy", "status": "offline",
    },
    "vulhub": {
        "name": "Vulhub", "url": "http://127.0.0.1:8080/",
        "known_vuln_types": ["cve", "rce", "deserialization", "ssrf", "template_injection"],
        "known_vuln_count": 50, "difficulty": "hard", "status": "offline",
    },
    "metasploitable": {
        "name": "Metasploitable2", "url": "http://127.0.0.1:8180/",
        "known_vuln_types": ["rce", "sqli", "ftp_anon", "smb", "rsh", "distcc", "tomcat"],
        "known_vuln_count": 45, "difficulty": "hard", "status": "offline",
    },
}

# 漏洞类型关键词映射（用于把扫描发现归类到已知类型）
TYPE_KEYWORDS: Dict[str, List[str]] = {
    "sqli": ["sql", "sqli", "injection", "union select", "sql injection"],
    "xss": ["xss", "cross-site scripting", "script"],
    "rce": ["rce", "remote code", "command execution", "os command", "exec"],
    "ssrf": ["ssrf", "server-side request"],
    "idor": ["idor", "insecure direct", "broken access"],
    "lfi": ["lfi", "local file inclusion", "file inclusion"],
    "rfi": ["rfi", "remote file inclusion"],
    "file_upload": ["upload", "file upload"],
    "cmd_exec": ["command", "exec", "cmd", "shell"],
    "xxe": ["xxe", "xml external"],
    "cve": ["cve", "cve-"],
    "exposed_panel": ["panel", "dashboard", "admin", "exposed"],
}


class FPRateValidator:
    """误报率验证引擎。"""

    def __init__(self) -> None:
        self.ranges: Dict[str, Dict[str, Any]] = json.loads(json.dumps(DEFAULT_RANGES))
        self.history: List[Dict[str, Any]] = []
        self._nmap = nmap_deep.get_scanner()
        self._tools = other_tools.get_manager()

    # -- 靶场管理 ---------------------------------------------------------- #
    def list_ranges(self) -> List[Dict[str, Any]]:
        out = []
        for rid, r in self.ranges.items():
            out.append({"id": rid, **r})
        return out

    def add_range(self, rid: str, name: str, url: str,
                  known_vuln_types: List[str], known_vuln_count: int,
                  difficulty: str = "medium") -> Dict[str, Any]:
        self.ranges[rid] = {
            "name": name, "url": url,
            "known_vuln_types": known_vuln_types,
            "known_vuln_count": known_vuln_count,
            "difficulty": difficulty, "status": "unmanaged",
        }
        return self.ranges[rid]

    def update_range_status(self, rid: str, status: str) -> Dict[str, Any]:
        if rid not in self.ranges:
            return {"success": False, "error": f"靶场不存在: {rid}"}
        self.ranges[rid]["status"] = status
        return {"success": True, "data": self.ranges[rid]}

    # -- 扫描执行 ---------------------------------------------------------- #
    def _run_real_scans(self, url: str,
                        nmap_timeout: int = 120,
                        nuclei_timeout: int = 180,
                        nikto_timeout: int = 120) -> Dict[str, Any]:
        """对靶场 URL 跑 nmap + nuclei + nikto。工具未安装则 skipped。"""
        scheme_host = re.sub(r"^https?://", "", url).split("/")[0]
        host = scheme_host.split(":")[0]
        port = scheme_host.split(":")[1] if ":" in scheme_host else (
            "443" if url.startswith("https") else "80")

        results: Dict[str, Any] = {"nmap": None, "nuclei": None, "nikto": None}

        # nmap 端口/服务扫描
        if self._nmap.available:
            r = self._nmap.scan(
                [host], scan_type="connect",
                ports=f"{port},{int(port)+1},{port}",
                timing=4, version_detection=True, os_detection=False,
                timeout=nmap_timeout,
            )
            results["nmap"] = r
        else:
            results["nmap"] = {"success": False, "error": "工具未安装: nmap", "data": None}

        # nuclei
        if self._tools.nuclei.available:
            r = self._tools.nuclei.scan(url, timeout=nuclei_timeout)
            results["nuclei"] = r
        else:
            results["nuclei"] = {"success": False,
                                 "error": f"工具未安装: nuclei（{self._tools.nuclei.probe_error}）",
                                 "data": None}

        # nikto
        if self._tools.nikto.available:
            ssl = url.startswith("https")
            r = self._tools.nikto.scan(host, port=int(port), ssl=ssl, timeout=nikto_timeout)
            results["nikto"] = r
        else:
            results["nikto"] = {"success": False,
                                "error": f"工具未安装: nikto（{self._tools.nikto.probe_error}）",
                                "data": None}
        return results

    # -- 发现归类 ---------------------------------------------------------- #
    @staticmethod
    def _classify_findings(scan_results: Dict[str, Any]) -> List[str]:
        """把各工具发现归并成去重的漏洞类型命中列表。"""
        hits: List[str] = []
        texts: List[str] = []

        nm = (scan_results.get("nmap") or {}).get("data") or {}
        for s in (nm.get("parsed", {}).get("hosts", []) or []):
            for sc in s.get("scripts", []):
                texts.append(f"{sc.get('id','')} {sc.get('output','')}")

        nuc = ((scan_results.get("nuclei") or {}).get("data") or {}).get("findings", []) or []
        for f in nuc:
            texts.append(f"{f.get('name','')} {f.get('description','')} {f.get('template_id','')}")

        nk = ((scan_results.get("nikto") or {}).get("data") or {}).get("findings", []) or []
        for f in nk:
            texts.append(f.get("msg", ""))

        blob = " ".join(texts).lower()
        for vtype, kws in TYPE_KEYWORDS.items():
            if any(kw in blob for kw in kws):
                hits.append(vtype)
        return hits

    @staticmethod
    def _metrics(tp: int, fp: int, fn: int, total_known: int) -> Dict[str, float]:
        """计算 误报率/漏报率/准确率/召回率/F1。"""
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / total_known if total_known > 0 else 0.0
        fpr = fp / (tp + fp) if (tp + fp) > 0 else 0.0
        fnr = fn / total_known if total_known > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        return {
            "true_positive": tp, "false_positive": fp, "false_negative": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "f1_score": round(f1, 4),
        }

    # -- 一键验证 ---------------------------------------------------------- #
    def run_fp_test(self, range_id: Optional[str] = None,
                    url: str = "",
                    known_types: Optional[List[str]] = None,
                    known_count: int = 0,
                    timeouts: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
        """对指定靶场跑一次完整误报率验证。"""
        to = timeouts or {}
        if range_id and range_id in self.ranges:
            rng = self.ranges[range_id]
            target_url = rng["url"]
            expected_types = list(rng["known_vuln_types"])
            expected_count = int(rng["known_vuln_count"])
        else:
            target_url = url
            expected_types = known_types or []
            expected_count = known_count

        started = time.time()
        scans = self._run_real_scans(
            target_url,
            nmap_timeout=to.get("nmap", 120),
            nuclei_timeout=to.get("nuclei", 180),
            nikto_timeout=to.get("nikto", 120),
        )
        duration = round(time.time() - started, 2)

        hits = self._classify_findings(scans)
        hit_set = set(hits)
        expected_set = set(expected_types)

        tp = len(hit_set & expected_set)
        fp = len(hit_set - expected_set)
        fn = len(expected_set - hit_set)
        metrics = self._metrics(tp, fp, fn, max(expected_count, len(expected_set)))

        record = {
            "test_id": uuid.uuid4().hex[:12],
            "range_id": range_id or "custom",
            "range_name": (self.ranges.get(range_id, {}).get("name") if range_id else "自定义目标") or "自定义目标",
            "url": target_url,
            "expected_types": sorted(expected_set),
            "detected_types": sorted(hit_set),
            "expected_count": expected_count,
            "metrics": metrics,
            "tools": {
                "nmap": (scans.get("nmap") or {}).get("success"),
                "nuclei": (scans.get("nuclei") or {}).get("success"),
                "nikto": (scans.get("nikto") or {}).get("success"),
            },
            "tool_errors": {
                k: (v or {}).get("error") for k, v in scans.items() if not (v or {}).get("success")
            },
            "duration_sec": duration,
            "executed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.history.append(record)
        return record

    # -- 结果 / 历史 ------------------------------------------------------- #
    def get_latest(self) -> Optional[Dict[str, Any]]:
        return self.history[-1] if self.history else None

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(reversed(self.history[-limit:]))

    def get_trend(self) -> List[Dict[str, Any]]:
        return [{"test_id": h["test_id"], "executed_at": h["executed_at"],
                 "precision": h["metrics"]["precision"],
                 "recall": h["metrics"]["recall"],
                 "f1_score": h["metrics"]["f1_score"],
                 "fpr": h["metrics"]["false_positive_rate"],
                 "fnr": h["metrics"]["false_negative_rate"]}
                for h in self.history]

    # -- HTML 报告 --------------------------------------------------------- #
    def generate_html_report(self, record: Optional[Dict[str, Any]] = None) -> str:
        record = record or self.get_latest()
        if record is None:
            return "<html><body><h1>尚无验证记录</h1></body></html>"
        m = record["metrics"]
        rows = "".join(
            f"<tr><td>{t}</td><td>{'✅ 命中' if t in set(record['detected_types']) else '❌ 漏报'}</td></tr>"
            for t in record["expected_types"]
        )
        trend_rows = "".join(
            f"<tr><td>{h['executed_at']}</td><td>{h['precision']:.2%}</td>"
            f"<td>{h['recall']:.2%}</td><td>{h['f1_score']:.2%}</td>"
            f"<td>{h['fpr']:.2%}</td><td>{h['fnr']:.2%}</td></tr>"
            for h in self.get_trend()
        )
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>误报率验证报告 {record['test_id']}</title>
<style>body{{font-family:sans-serif;margin:24px;background:#0d1117;color:#e6edf3}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #30363d;padding:6px}}
.kpi{{display:inline-block;margin:8px;padding:12px;background:#161b22;border-radius:8px}}
</style></head><body>
<h1>误报率验证报告</h1>
<p>靶场：{record['range_name']} ({record['url']}) · 时间：{record['executed_at']}</p>
<div class="kpi">准确率(Precision)<br><b>{m['precision']:.2%}</b></div>
<div class="kpi">召回率(Recall)<br><b>{m['recall']:.2%}</b></div>
<div class="kpi">F1<br><b>{m['f1_score']:.2%}</b></div>
<div class="kpi">误报率<br><b>{m['false_positive_rate']:.2%}</b></div>
<div class="kpi">漏报率<br><b>{m['false_negative_rate']:.2%}</b></div>
<h2>已知漏洞类型比对</h2><table>{rows}</table>
<h2>历史趋势</h2><table><tr><th>时间</th><th>准确率</th><th>召回率</th><th>F1</th><th>误报率</th><th>漏报率</th></tr>{trend_rows}</table>
</body></html>"""
        os.makedirs(REPORTS_DIR, exist_ok=True)
        path = os.path.join(REPORTS_DIR, f"fp_rate_{record['test_id']}.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path


_validator: Optional[FPRateValidator] = None


def get_validator() -> FPRateValidator:
    global _validator
    if _validator is None:
        _validator = FPRateValidator()
    return _validator
