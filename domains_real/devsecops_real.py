# -*- coding: utf-8 -*-
"""devsecops_real.py — DevSecOps 做实模块。

真实 CI/CD 集成接口：
    - Jenkins 集成（触发构建/获取状态）
    - GitLab CI 集成（流水线状态/触发）
    - 流水线安全门禁（质量门禁配置）

真实 SAST 扫描：
    - 使用 Semgrep 做静态代码分析
    - 支持多语言
    - 规则库管理
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

# 内存存储
CI_CD_PIPELINES: Dict[str, Dict[str, Any]] = {}
SAST_SCAN_RECORDS: Dict[str, Dict[str, Any]] = {}
GATE_RULES: Dict[str, Dict[str, Any]] = {}
SEMGREP_RULE_PACKS: Dict[str, Dict[str, Any]] = {}

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
    """检测 DevSecOps 相关工具。"""
    tools = ["semgrep", "jenkins", "gitlab-ci-multi-runner", "trivy", "grype", "bandit", "eslint"]
    result: Dict[str, Dict[str, Any]] = {}
    for t in tools:
        path = _which(t)
        result[t] = {"available": bool(path), "path": path}
    return result


# ============================================================
# CI/CD 集成
# ============================================================
def jenkins_trigger_build(
    jenkins_url: str,
    job_name: str,
    token: str,
    params: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """触发 Jenkins 构建（通过 HTTP API，真实请求）。"""
    import urllib.request
    import urllib.error

    url = f"{jenkins_url.rstrip('/')}/job/{job_name}/buildWithToken?token={token}"
    if params:
        param_str = "&".join(f"{k}={v}" for k, v in params.items())
        url += f"&{param_str}"

    try:
        req = urllib.request.Request(url, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            return {
                "success": resp.status in (200, 201, 302),
                "status_code": resp.status,
                "jenkins_url": jenkins_url,
                "job_name": job_name,
                "triggered_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
    except urllib.error.HTTPError as e:
        return {"success": False, "error": f"Jenkins API HTTP {e.code}: {e.reason}", "status_code": e.code}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Jenkins 连接失败: {e}"}


def jenkins_get_build_status(
    jenkins_url: str,
    job_name: str,
    build_number: Optional[int] = None,
) -> Dict[str, Any]:
    """查询 Jenkins 构建状态。"""
    import urllib.request
    import urllib.error

    path = f"/job/{job_name}/lastBuild/api/json" if not build_number else f"/job/{job_name}/{build_number}/api/json"
    url = f"{jenkins_url.rstrip('/')}{path}"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return {
                "success": True,
                "job_name": data.get("fullName", job_name),
                "build_number": data.get("number"),
                "result": data.get("result"),
                "building": data.get("building"),
                "duration_ms": data.get("duration"),
                "timestamp": data.get("timestamp"),
                "url": data.get("url"),
            }
    except urllib.error.HTTPError as e:
        return {"success": False, "error": f"Jenkins API HTTP {e.code}"}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Jenkins 查询失败: {e}"}


def gitlab_ci_trigger_pipeline(
    gitlab_url: str,
    project_id: str,
    token: str,
    ref: str = "main",
    variables: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """触发 GitLab CI 流水线。"""
    import urllib.request
    import urllib.error

    url = f"{gitlab_url.rstrip('/')}/api/v4/projects/{project_id}/pipeline?ref={ref}&token={token}"
    if variables:
        var_parts = [f"variables[{k}]={v}" for k, v in variables.items()]
        url += "&" + "&".join(var_parts)
    try:
        req = urllib.request.Request(url, method="POST", headers={"PRIVATE-TOKEN": token})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return {
                "success": True,
                "pipeline_id": data.get("id"),
                "status": data.get("status"),
                "ref": data.get("ref"),
                "sha": data.get("sha"),
                "web_url": data.get("web_url"),
                "triggered_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
    except urllib.error.HTTPError as e:
        return {"success": False, "error": f"GitLab API HTTP {e.code}: {e.reason}"}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"GitLab 触发失败: {e}"}


def gitlab_ci_get_pipeline_status(
    gitlab_url: str,
    project_id: str,
    pipeline_id: int,
    token: str,
) -> Dict[str, Any]:
    """查询 GitLab CI 流水线状态。"""
    import urllib.request
    import urllib.error

    url = f"{gitlab_url.rstrip('/')}/api/v4/projects/{project_id}/pipelines/{pipeline_id}"
    try:
        req = urllib.request.Request(url, headers={"PRIVATE-TOKEN": token})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return {
                "success": True,
                "pipeline_id": data.get("id"),
                "status": data.get("status"),
                "ref": data.get("ref"),
                "sha": data.get("sha"),
                "web_url": data.get("web_url"),
                "created_at": data.get("created_at"),
                "updated_at": data.get("updated_at"),
            }
    except urllib.error.HTTPError as e:
        return {"success": False, "error": f"GitLab API HTTP {e.code}"}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"GitLab 查询失败: {e}"}


# ============================================================
# 流水线安全门禁
# ============================================================
SECURITY_GATE_TEMPLATES: List[Dict[str, Any]] = [
    {
        "id": "gate_001",
        "name": "Critical Vulnerability Block",
        "stage": "after_sast",
        "condition": "CRITICAL vulnerabilities > 0",
        "action": "block_pipeline",
        "enabled": True,
        "description": "阻断存在严重漏洞的构建",
    },
    {
        "id": "gate_002",
        "name": "High Vulnerability Warning",
        "stage": "after_sast",
        "condition": "HIGH vulnerabilities > 10",
        "action": "warn_allow",
        "enabled": True,
        "description": "高危漏洞超过10个时警告但不阻断",
    },
    {
        "id": "gate_003",
        "name": "Secrets Detection Block",
        "stage": "after_secret_scan",
        "condition": "leaked_secrets > 0",
        "action": "block_pipeline",
        "enabled": True,
        "description": "检测到密钥泄露立即阻断",
    },
    {
        "id": "gate_004",
        "name": "License Compliance Check",
        "stage": "after_license_scan",
        "condition": "gpl_v3_componets > 0",
        "action": "warn_review",
        "enabled": False,
        "description": "GPL v3 组件需人工审查",
    },
]


def list_security_gates() -> List[Dict[str, Any]]:
    return SECURITY_GATE_TEMPLATES


def create_security_gate(
    name: str,
    stage: str,
    condition: str,
    action: str,
    description: str = "",
) -> Dict[str, Any]:
    gate_id = f"gate_{int(time.time())}"
    gate = {
        "id": gate_id,
        "name": name,
        "stage": stage,
        "condition": condition,
        "action": action,
        "description": description,
        "enabled": True,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    GATE_RULES[gate_id] = gate
    return {"success": True, "gate": gate}


def evaluate_gates(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """根据 SAST 扫描结果评估安全门禁。"""
    decisions: List[Dict[str, Any]] = []
    should_block = False

    critical_count = scan_results.get("critical_count", 0)
    high_count = scan_results.get("high_count", 0)
    secrets_found = scan_results.get("secrets_count", 0)

    for gate in SECURITY_GATE_TEMPLATES:
        if not gate.get("enabled"):
            continue
        triggered = False
        if gate["id"] == "gate_001" and critical_count > 0:
            triggered = True
        elif gate["id"] == "gate_002" and high_count > 10:
            triggered = True
        elif gate["id"] == "gate_003" and secrets_found > 0:
            triggered = True

        if triggered:
            decisions.append({
                "gate_id": gate["id"],
                "gate_name": gate["name"],
                "triggered": True,
                "action": gate["action"],
            })
            if gate["action"] == "block_pipeline":
                should_block = True

    return {
        "should_block": should_block,
        "decisions": decisions,
        "summary": f"阻断: {should_block}, 触发规则数: {len(decisions)}",
    }


# ============================================================
# 真实 SAST 扫描（Semgrep）
# ============================================================
SEMGREP_SUPPORTED_LANGS = [
    "python", "javascript", "typescript", "java", "go",
    "ruby", "php", "c", "cpp", "csharp", "rust",
]

SEMGREP_RULE_PACK_BUILTIN: List[Dict[str, Any]] = [
    {"id": "p/security-audit", "name": "Security Audit", "description": "通用安全审计规则集"},
    {"id": "p/owasp-top-ten", "name": "OWASP Top 10", "description": "OWASP Top 10 风险检测"},
    {"id": "p/ci", "name": "CI Fast", "description": "CI/CD 快速扫描规则集"},
    {"id": "p/secrets", "name": "Secrets Detection", "description": "密钥/凭证泄露检测"},
    {"id": "p/bandit", "name": "Bandit Python", "description": "Python 安全规则（等价 Bandit）"},
    {"id": "p/javascript", "name": "JS Security", "description": "JavaScript 安全规则"},
]


def list_semgrep_rules() -> List[Dict[str, Any]]:
    """列出 Semgrep 内置规则包。"""
    return SEMGREP_RULE_PACK_BUILTIN


def semgrep_scan(
    target_path: str,
    config: str = "p/security-audit",
    lang: Optional[str] = None,
    timeout: int = 300,
    json_output: bool = True,
) -> Dict[str, Any]:
    """使用 Semgrep 真实执行静态代码分析。"""
    sg = _which("semgrep")
    if not sg:
        return {
            "success": False,
            "error": "semgrep 未安装。安装方法：pip install semgrep",
            "target_path": target_path,
        }
    if not os.path.exists(target_path):
        return {"success": False, "error": f"目标路径不存在: {target_path}", "target_path": target_path}

    output_file = os.path.join(os.environ.get("TEMP", "/tmp"), f"semgrep_{int(time.time())}.json")
    cmd = [sg, "scan", "--config", config, "--json", "--output", output_file, "--quiet"]
    if lang:
        cmd += ["--lang", lang]
    cmd.append(target_path)

    r = _run_cmd(cmd, timeout=timeout)

    findings: List[Dict[str, Any]] = []
    if os.path.exists(output_file):
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                sg_data = json.load(f)
            results = sg_data.get("results", [])
            for res in results:
                ext = res.get("extra", {})
                severity_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
                findings.append({
                    "check_id": res.get("check_id", ""),
                    "path": res.get("path", ""),
                    "line": res.get("start", {}).get("line", 0),
                    "severity": severity_map.get(ext.get("severity", "WARNING"), "medium"),
                    "message": ext.get("message", ""),
                    "fix": ext.get("fix", ""),
                    "metadata": {
                        "cwe": ext.get("metadata", {}).get("cwe", []),
                        "owasp": ext.get("metadata", {}).get("owasp", []),
                        "source": ext.get("metadata", {}).get("source", ""),
                    },
                })
        except Exception as e:
            return {"success": False, "error": f"semgrep 结果解析失败: {e}", "raw": r}

    severity_counts: Dict[str, int] = {}
    for f in findings:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    record_id = f"sast_{int(time.time())}"
    record = {
        "id": record_id,
        "target_path": target_path,
        "config": config,
        "findings_count": len(findings),
        "severity_breakdown": severity_counts,
        "findings": findings[:500],
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed": r.get("elapsed"),
    }
    SAST_SCAN_RECORDS[record_id] = record
    return {"success": r["success"], "scan": record, "raw": r}


def list_sast_scans() -> List[Dict[str, Any]]:
    return list(SAST_SCAN_RECORDS.values())


def get_sast_scan_detail(scan_id: str) -> Optional[Dict[str, Any]]:
    return SAST_SCAN_RECORDS.get(scan_id)


def add_custom_semgrep_rule(name: str, rule_yaml: str, description: str = "") -> Dict[str, Any]:
    """添加自定义 Semgrep 规则（存储到临时目录）。"""
    rules_dir = os.path.join(os.environ.get("TEMP", "/tmp"), "semgrep_custom_rules")
    os.makedirs(rules_dir, exist_ok=True)
    rule_file = os.path.join(rules_dir, f"{name}.yml")
    with open(rule_file, "w", encoding="utf-8") as f:
        f.write(rule_yaml)

    rule_id = f"custom_{int(time.time())}"
    SEMGREP_RULE_PACKS[rule_id] = {
        "id": rule_id,
        "name": name,
        "description": description,
        "rule_file": rule_file,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    return {"success": True, "rule": SEMGREP_RULE_PACKS[rule_id]}


def list_custom_semgrep_rules() -> List[Dict[str, Any]]:
    return list(SEMGREP_RULE_PACKS.values())
