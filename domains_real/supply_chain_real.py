# -*- coding: utf-8 -*-
"""supply_chain_real.py — 供应链安全做实模块。

真实 SBOM 生成：
    - 使用 syft 或 cyclonedx-cli 生成 SBOM
    - 支持 CycloneDX / SPDX 格式

真实组件漏洞检测：
    - 使用 grype 或 trivy 比对 CVE 数据库
    - 检测已知漏洞组件
    - 风险评级（CVSS / 严重程度）
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

# 内存存储
SBOM_RECORDS: Dict[str, Dict[str, Any]] = {}
VULN_RECORDS: Dict[str, Dict[str, Any]] = {}

DEFAULT_TIMEOUT = 300
_TOOL_CACHE: Dict[str, Optional[str]] = {}


def _which(name: str) -> Optional[str]:
    if name not in _TOOL_CACHE:
        _TOOL_CACHE[name] = shutil.which(name)
    return _TOOL_CACHE[name]


def _run_cmd(cmd: List[str], timeout: Optional[int] = None) -> Dict[str, Any]:
    to = timeout or DEFAULT_TIMEOUT
    started = time.time()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=to,
            encoding="utf-8", errors="replace",
        )
        return {
            "success": proc.returncode == 0,
            "cmd": cmd,
            "returncode": proc.returncode,
            "stdout": (proc.stdout or "")[:30000],
            "stderr": (proc.stderr or "")[:5000],
            "elapsed": round(time.time() - started, 2),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "success": False, "cmd": cmd, "returncode": None,
            "stdout": (e.stdout or "") if isinstance(e.stdout, str) else "",
            "stderr": f"执行超时（{to}s）",
            "elapsed": round(time.time() - started, 2), "timed_out": True,
        }
    except FileNotFoundError as e:
        return {
            "success": False, "cmd": cmd, "returncode": None,
            "stdout": "", "stderr": f"命令未找到: {e}",
            "elapsed": round(time.time() - started, 2), "timed_out": False,
        }
    except Exception as e:  # noqa: BLE001
        return {
            "success": False, "cmd": cmd, "returncode": None,
            "stdout": "", "stderr": f"执行异常: {e}",
            "elapsed": round(time.time() - started, 2), "timed_out": False,
        }


def tool_availability() -> Dict[str, Dict[str, Any]]:
    """检测供应链安全相关工具。"""
    tools = ["syft", "grype", "trivy", "cyclonedx", "cyclonedx-python", "dependency-track", "snyk"]
    result: Dict[str, Dict[str, Any]] = {}
    for t in tools:
        path = _which(t)
        result[t] = {"available": bool(path), "path": path}
    return result


# ============================================================
# 真实 SBOM 生成
# ============================================================
def generate_sbom_syft(
    target: str,
    output_format: str = "cyclonedx-json",
    output_file: Optional[str] = None,
    timeout: int = 300,
) -> Dict[str, Any]:
    """使用 syft 生成真实 SBOM。

    Args:
        target: 目标路径/镜像/目录，如 ./my-app 或 docker:image:tag
        output_format: cyclonedx-json / spdx-json / syft-json
        output_file: 输出文件路径（默认自动生成）
    """
    sf = _which("syft")
    if not sf:
        return {
            "success": False,
            "error": "syft 未安装。安装方法：curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin",
            "target": target,
        }

    if not output_file:
        ext = "json"
        output_file = os.path.join(
            os.environ.get("TEMP", "/tmp"),
            f"sbom_{int(time.time())}.{ext}",
        )

    cmd = [sf, target, "-o", output_format, "-o", f"json={output_file}"]
    r = _run_cmd(cmd, timeout=timeout)

    components: List[Dict[str, Any]] = []
    if os.path.exists(output_file):
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                sbom_data = json.load(f)
            # 解析 components
            comps = sbom_data.get("components", []) or sbom_data.get("artifacts", [])
            for c in comps[:1000]:
                components.append({
                    "name": c.get("name", ""),
                    "version": c.get("version", ""),
                    "type": c.get("type", ""),
                    "purl": c.get("purl", ""),
                    "licenses": [l.get("name", l) if isinstance(l, dict) else str(l) for l in (c.get("licenses") or [])],
                })
        except Exception as e:
            return {"success": False, "error": f"SBOM 解析失败: {e}", "raw": r}

    record_id = f"sbom_{int(time.time())}"
    record = {
        "id": record_id,
        "target": target,
        "format": output_format,
        "component_count": len(components),
        "components": components,
        "output_file": output_file,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed": r.get("elapsed"),
    }
    SBOM_RECORDS[record_id] = record
    return {"success": r["success"], "sbom": record, "raw": r}


def generate_sbom_cyclonedx(
    project_dir: str,
    output_format: str = "json",
    timeout: int = 300,
) -> Dict[str, Any]:
    """使用 cyclonedx-cli 或 cyclonedx-py 生成 SBOM。"""
    # 优先尝试 cyclonedx-py (Python)
    cx_py = _which("cyclonedx-py")
    cx_cli = _which("cyclonedx")

    if cx_py:
        output_file = os.path.join(os.environ.get("TEMP", "/tmp"), f"sbom_cdx_{int(time.time())}.json")
        cmd = [cx_py, "environment", "--of", output_format, "--outfile", output_file]
        r = _run_cmd(cmd, timeout=timeout)
    elif cx_cli:
        output_file = os.path.join(os.environ.get("TEMP", "/tmp"), f"sbom_cdx_{int(time.time())}.json")
        cmd = [cx_cli, "dir", project_dir, "--format", output_format, "--output", output_file]
        r = _run_cmd(cmd, timeout=timeout)
    else:
        return {
            "success": False,
            "error": "cyclonedx 工具未安装。安装方法：pip install cyclonedx-bom 或 npm install -g @cyclonedx/cyclonedx-cli",
            "project_dir": project_dir,
        }

    components: List[Dict[str, Any]] = []
    if os.path.exists(output_file):
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                sbom_data = json.load(f)
            comps = sbom_data.get("components", [])
            for c in comps[:1000]:
                components.append({
                    "name": c.get("name", ""),
                    "version": c.get("version", ""),
                    "type": c.get("type", ""),
                    "purl": c.get("purl", ""),
                })
        except Exception:
            pass

    record_id = f"sbom_cdx_{int(time.time())}"
    record = {
        "id": record_id,
        "target": project_dir,
        "format": f"cyclonedx-{output_format}",
        "component_count": len(components),
        "components": components,
        "output_file": output_file,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    SBOM_RECORDS[record_id] = record
    return {"success": r["success"], "sbom": record, "raw": r}


def list_sbom_records() -> List[Dict[str, Any]]:
    """列出所有已生成的 SBOM 记录。"""
    return list(SBOM_RECORDS.values())


def get_sbom_detail(sbom_id: str) -> Optional[Dict[str, Any]]:
    return SBOM_RECORDS.get(sbom_id)


# ============================================================
# 真实组件漏洞检测
# ============================================================
def scan_vulns_grype(
    sbom_file: str,
    output_format: str = "json",
    timeout: int = 300,
) -> Dict[str, Any]:
    """使用 grype 扫描 SBOM 文件中的已知漏洞。"""
    gp = _which("grype")
    if not gp:
        return {
            "success": False,
            "error": "grype 未安装。安装方法：curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin",
            "sbom_file": sbom_file,
        }
    if not os.path.exists(sbom_file):
        return {"success": False, "error": f"SBOM 文件不存在: {sbom_file}", "sbom_file": sbom_file}

    output_file = os.path.join(os.environ.get("TEMP", "/tmp"), f"grype_{int(time.time())}.json")
    cmd = [gp, sbom_file, "-o", output_format, "--file", output_file]
    r = _run_cmd(cmd, timeout=timeout)

    vulnerabilities: List[Dict[str, Any]] = []
    if os.path.exists(output_file):
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                grype_data = json.load(f)
            matches = grype_data.get("matches", [])
            for m in matches:
                vuln = m.get("vulnerability", {})
                artifact = m.get("artifact", {})
                vulnerabilities.append({
                    "id": vuln.get("id", ""),
                    "severity": vuln.get("severity", "Unknown"),
                    "package": artifact.get("name", ""),
                    "version": artifact.get("version", ""),
                    "description": vuln.get("description", "")[:500],
                    "fixed_in": ", ".join([f.get("version", "") for f in vuln.get("fix", {}).get("versions", [])]),
                    "cvss": vuln.get("cvss", []),
                    "urls": vuln.get("urls", []),
                })
        except Exception as e:
            return {"success": False, "error": f"grype 结果解析失败: {e}", "raw": r}

    # 风险评级汇总
    severity_counts: Dict[str, int] = {}
    for v in vulnerabilities:
        sev = v.get("severity", "Unknown").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    record_id = f"vuln_{int(time.time())}"
    record = {
        "id": record_id,
        "sbom_file": sbom_file,
        "vuln_count": len(vulnerabilities),
        "severity_breakdown": severity_counts,
        "vulnerabilities": vulnerabilities[:500],
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed": r.get("elapsed"),
    }
    VULN_RECORDS[record_id] = record
    return {"success": r["success"], "scan": record, "raw": r}


def scan_vulns_trivy(
    target: str,
    scan_type: str = "fs",
    severity: str = "CRITICAL,HIGH,MEDIUM",
    timeout: int = 300,
) -> Dict[str, Any]:
    """使用 trivy 扫描文件系统/镜像中的漏洞。"""
    tv = _which("trivy")
    if not tv:
        return {
            "success": False,
            "error": "trivy 未安装。安装方法：https://aquasecurity.github.io/trivy/latest/getting-started/installation/",
            "target": target,
        }
    output_file = os.path.join(os.environ.get("TEMP", "/tmp"), f"trivy_{int(time.time())}.json")
    cmd = [tv, scan_type, "--format", "json", "--output", output_file, "--severity", severity, target]
    r = _run_cmd(cmd, timeout=timeout)

    vulnerabilities: List[Dict[str, Any]] = []
    if os.path.exists(output_file):
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                trivy_data = json.load(f)
            results = trivy_data.get("Results", [])
            for res in results:
                target_name = res.get("Target", "")
                for v in res.get("Vulnerabilities", []):
                    vulnerabilities.append({
                        "id": v.get("VulnerabilityID", ""),
                        "severity": v.get("Severity", "Unknown"),
                        "package": v.get("PkgName", ""),
                        "version": v.get("InstalledVersion", ""),
                        "fixed_version": v.get("FixedVersion", ""),
                        "title": v.get("Title", ""),
                        "description": v.get("Description", "")[:500],
                        "target": target_name,
                        "cvss_score": v.get("CVSS", {}).get("nvd", {}).get("V3Score", None),
                    })
        except Exception as e:
            return {"success": False, "error": f"trivy 结果解析失败: {e}", "raw": r}

    severity_counts: Dict[str, int] = {}
    for v in vulnerabilities:
        sev = v.get("severity", "UNKNOWN").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    record_id = f"trivy_{int(time.time())}"
    record = {
        "id": record_id,
        "target": target,
        "scan_type": scan_type,
        "vuln_count": len(vulnerabilities),
        "severity_breakdown": severity_counts,
        "vulnerabilities": vulnerabilities[:500],
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed": r.get("elapsed"),
    }
    VULN_RECORDS[record_id] = record
    return {"success": r["success"], "scan": record, "raw": r}


def list_vuln_scans() -> List[Dict[str, Any]]:
    return list(VULN_RECORDS.values())


def get_vuln_scan_detail(scan_id: str) -> Optional[Dict[str, Any]]:
    return VULN_RECORDS.get(scan_id)


def risk_rating_summary() -> Dict[str, Any]:
    """汇总所有漏洞扫描的风险评级。"""
    total_scans = len(VULN_RECORDS)
    total_vulns = sum(v.get("vuln_count", 0) for v in VULN_RECORDS.values())
    by_severity: Dict[str, int] = {}
    for rec in VULN_RECORDS.values():
        for sev, count in rec.get("severity_breakdown", {}).items():
            by_severity[sev] = by_severity.get(sev, 0) + count
    risk_level = "low"
    if by_severity.get("critical", 0) > 0 or by_severity.get("CRITICAL", 0) > 0:
        risk_level = "critical"
    elif by_severity.get("high", 0) > 5 or by_severity.get("HIGH", 0) > 5:
        risk_level = "high"
    elif by_severity.get("medium", 0) > 10 or by_severity.get("MEDIUM", 0) > 10:
        risk_level = "medium"
    return {
        "total_scans": total_scans,
        "total_vulnerabilities": total_vulns,
        "by_severity": by_severity,
        "overall_risk_level": risk_level,
    }
