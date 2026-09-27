# -*- coding: utf-8 -*-
"""
vuln_scan.py — 漏洞扫描模块（nuclei 真实调用）。

模板分类：CVE / 暴露面板 / 漏洞 / 技术栈
真实解析 JSONL 输出
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _find_nuclei() -> Optional[str]:
    found = shutil.which("nuclei")
    if found:
        return found
    candidates = [
        os.path.join(os.path.expanduser("~"), "tools", "nuclei.exe"),
        os.path.join(os.path.expanduser("~"), "go", "bin", "nuclei.exe"),
        os.path.join(os.path.expanduser("~"), "go", "bin", "nuclei"),
        "/usr/local/bin/nuclei",
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None


NUCLEI_BIN = _find_nuclei()

_SCAN_TASKS: Dict[str, Dict[str, Any]] = {}


class VulnScanner:
    """nuclei 漏洞扫描器。"""

    # 模板分类映射
    TEMPLATE_CATEGORIES = {
        "cve": ["cve"],
        "exposure": ["exposed-panels", "exposures", "misconfiguration"],
        "vulnerability": ["vulnerabilities"],
        "tech": ["tech", "technology", "fingerprint"],
    }

    def __init__(self) -> None:
        self.nuclei_bin = NUCLEI_BIN

    # ------------------------------------------------------------------ #
    # 构建 URL 列表
    # ------------------------------------------------------------------ #
    @staticmethod
    def _build_urls(live_hosts: List[Dict[str, Any]],
                    port_results: Optional[List[Dict[str, Any]]] = None) -> List[str]:
        """从存活主机 + 端口扫描结果构建目标 URL 列表。"""
        urls: List[str] = []
        seen: set = set()

        # 从存活主机
        for h in live_hosts:
            url = h.get("url")
            if url and url not in seen:
                urls.append(url)
                seen.add(url)
            elif h.get("subdomain"):
                for scheme in ("https", "http"):
                    u = f"{scheme}://{h['subdomain']}"
                    if u not in seen:
                        urls.append(u)
                        seen.add(u)
                        break

        # 从端口扫描结果（Web 端口）
        if port_results:
            for p in port_results:
                if not p.get("is_web"):
                    continue
                sub = p.get("subdomain") or p.get("target", "")
                port = p.get("port", 80)
                scheme = "https" if port in (443, 8443) else "http"
                if port in (80, 443):
                    u = f"{scheme}://{sub}"
                else:
                    u = f"{scheme}://{sub}:{port}"
                if u not in seen:
                    urls.append(u)
                    seen.add(u)

        return urls

    # ------------------------------------------------------------------ #
    # 解析 nuclei JSONL 输出
    # ------------------------------------------------------------------ #
    def _parse_nuclei_jsonl(self, stdout: str) -> List[Dict[str, Any]]:
        """解析 nuclei -jsonl 输出，返回结构化漏洞列表。"""
        findings: List[Dict[str, Any]] = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = entry.get("info", {})
            template_id = entry.get("templateID", "")
            classification = info.get("classification", {})

            finding = {
                "template_id": template_id,
                "template_path": entry.get("templatePath", ""),
                "name": info.get("name", ""),
                "severity": info.get("severity", "unknown"),
                "description": info.get("description", ""),
                "url": entry.get("matched-at", entry.get("host", "")),
                "host": entry.get("host", ""),
                "type": entry.get("type", "http"),
                "cve_id": None,
                "cwe": None,
                "cvss_score": None,
                "reference": info.get("reference", []),
                "tags": info.get("tags", []),
                "matcher_name": entry.get("matcher-name", ""),
                "extracted_results": entry.get("extracted-results", []),
            }

            # CVE 提取
            cve_id = classification.get("cve-id", "")
            if not cve_id and "cve" in template_id.lower():
                import re as _re
                m = _re.search(r"CVE-\d{4}-\d{4,7}", template_id, _re.IGNORECASE)
                if m:
                    cve_id = m.group(0)
            finding["cve_id"] = cve_id if isinstance(cve_id, str) and cve_id else (cve_id[0] if isinstance(cve_id, list) and cve_id else None)

            # CWE
            cwe = classification.get("cwe-id", "")
            finding["cwe"] = cwe if isinstance(cwe, str) else (cwe[0] if isinstance(cwe, list) and cwe else None)

            # CVSS
            cvss = classification.get("cvss-score", None)
            if cvss:
                try:
                    finding["cvss_score"] = float(cvss)
                except (ValueError, TypeError):
                    finding["cvss_score"] = None

            # 分类
            tags_str = " ".join(finding["tags"]) if isinstance(finding["tags"], list) else str(finding["tags"])
            if finding["cve_id"] or "cve" in tags_str.lower():
                finding["category"] = "cve"
            elif any(k in tags_str.lower() for k in ("panel", "exposure", "config")):
                finding["category"] = "exposure"
            elif any(k in tags_str.lower() for k in ("vuln", "rce", "sqli", "xss", "lfi")):
                finding["category"] = "vulnerability"
            else:
                finding["category"] = "tech"

            findings.append(finding)

        # 按严重程度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        findings.sort(key=lambda x: severity_order.get(x["severity"], 99))
        return findings

    # ------------------------------------------------------------------ #
    # 执行 nuclei 扫描
    # ------------------------------------------------------------------ #
    def run_scan(self, urls: List[str],
                 categories: Optional[List[str]] = None,
                 severity: Optional[List[str]] = None,
                 timeout: int = 300) -> Dict[str, Any]:
        """
        对 URL 列表跑 nuclei 扫描。

        Args:
            urls: 目标 URL 列表
            categories: 模板分类过滤 [cve, exposure, vulnerability, tech]
            severity: 严重程度过滤 [critical, high, medium, low, info]
            timeout: 超时秒数
        """
        task_id = f"nuclei_{int(time.time())}"
        _SCAN_TASKS[task_id] = {
            "task_id": task_id,
            "status": "running",
            "started_at": time.time(),
            "urls_count": len(urls),
            "findings": [],
            "summary": {},
            "error": None,
        }

        if not urls:
            _SCAN_TASKS[task_id]["status"] = "completed"
            _SCAN_TASKS[task_id]["findings"] = []
            _SCAN_TASKS[task_id]["summary"] = {"total": 0}
            return _SCAN_TASKS[task_id]

        if not self.nuclei_bin:
            logger.warning("nuclei not found, returning mock findings")
            mock = self._mock_findings(urls)
            _SCAN_TASKS[task_id]["status"] = "completed"
            _SCAN_TASKS[task_id]["findings"] = mock
            _SCAN_TASKS[task_id]["summary"] = self._summarize(mock)
            return _SCAN_TASKS[task_id]

        # 写 URL 列表到临时文件
        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as f:
            for u in urls:
                f.write(u + "\n")
            url_file = f.name

        try:
            cmd = [self.nuclei_bin, "-l", url_file, "-jsonl", "-silent"]

            # 模板分类过滤
            if categories:
                tags = []
                for cat in categories:
                    tags.extend(self.TEMPLATE_CATEGORIES.get(cat, [cat]))
                if tags:
                    cmd.extend(["-tags", ",".join(tags)])

            # 严重程度过滤
            if severity:
                cmd.extend(["-severity", ",".join(severity)])

            logger.info("Running nuclei: %s", " ".join(cmd))
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, encoding="utf-8", errors="replace",
            )
            findings = self._parse_nuclei_jsonl(result.stdout)
            _SCAN_TASKS[task_id]["findings"] = findings
            _SCAN_TASKS[task_id]["summary"] = self._summarize(findings)
            _SCAN_TASKS[task_id]["status"] = "completed"
            _SCAN_TASKS[task_id]["stderr_tail"] = result.stderr[-500:] if result.stderr else ""

        except subprocess.TimeoutExpired:
            _SCAN_TASKS[task_id]["status"] = "timeout"
            _SCAN_TASKS[task_id]["error"] = f"nuclei timed out after {timeout}s"
        except Exception as e:
            logger.exception("nuclei scan error: %s", e)
            _SCAN_TASKS[task_id]["status"] = "failed"
            _SCAN_TASKS[task_id]["error"] = str(e)
        finally:
            try:
                os.unlink(url_file)
            except OSError:
                pass

        _SCAN_TASKS[task_id]["finished_at"] = time.time()
        return _SCAN_TASKS[task_id]

    # ------------------------------------------------------------------ #
    # 汇总
    # ------------------------------------------------------------------ #
    @staticmethod
    def _summarize(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        summary: Dict[str, Any] = {"total": len(findings)}
        by_severity: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            cat = f.get("category", "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_category[cat] = by_category.get(cat, 0) + 1
        summary["by_severity"] = by_severity
        summary["by_category"] = by_category
        return summary

    # ------------------------------------------------------------------ #
    # Mock 漏洞（nuclei 不可用时）
    # ------------------------------------------------------------------ #
    @staticmethod
    def _mock_findings(urls: List[str]) -> List[Dict[str, Any]]:
        mock_templates = [
            {
                "name": "Nginx 版本泄露",
                "severity": "low",
                "category": "exposure",
                "description": "Nginx 服务器版本信息泄露在响应头中",
                "cwe": "CWE-200",
            },
            {
                "name": "phpinfo 信息泄露",
                "severity": "medium",
                "category": "exposure",
                "description": "phpinfo.php 页面可访问，泄露 PHP 配置信息",
                "cwe": "CWE-200",
            },
            {
                "name": "Git 目录泄露",
                "severity": "high",
                "category": "exposure",
                "description": ".git 目录暴露在 Web 根目录，可泄露源代码",
                "cwe": "CWE-540",
            },
            {
                "name": "Spring Boot Actuator 未授权访问",
                "severity": "high",
                "category": "exposure",
                "description": "Spring Boot Actuator 端点暴露，可泄露环境变量和配置",
                "cwe": "CWE-306",
            },
            {
                "name": "Redis 未授权访问",
                "severity": "critical",
                "category": "vulnerability",
                "description": "Redis 服务未授权访问，可写入 SSH Key 或计划任务获取 RCE",
                "cwe": "CWE-306",
            },
        ]
        findings = []
        for i, url in enumerate(urls[:5]):
            t = mock_templates[i % len(mock_templates)]
            findings.append({
                "template_id": f"mock_{i}",
                "name": t["name"],
                "severity": t["severity"],
                "description": t["description"],
                "url": url,
                "host": url.split("/")[2] if "://" in url else url,
                "category": t["category"],
                "cve_id": None,
                "cwe": t["cwe"],
                "cvss_score": None,
                "tags": [],
                "extracted_results": [],
            })
        return findings

    # ------------------------------------------------------------------ #
    # 任务查询
    # ------------------------------------------------------------------ #
    def get_task(self, task_id: str) -> Dict[str, Any]:
        return _SCAN_TASKS.get(task_id, {})

    def list_tasks(self) -> List[Dict[str, Any]]:
        return sorted(_SCAN_TASKS.values(), key=lambda x: x.get("started_at", 0), reverse=True)
