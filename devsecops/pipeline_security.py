# -*- coding: utf-8 -*-
"""
pipeline_security.py — CI/CD 流水线安全审计。

覆盖：
    - 流水线配置审计（GitHub Actions / GitLab CI / Jenkins）
    - 构建脚本安全分析（脚本注入、特权、外联）
    - 敏感信息泄露检测（硬编码密钥 / Token / 密码）
    - 构建环境隔离评估
    - 依赖锁定检查
    - 制品签名验证
    - SBOM 生成与格式规范

设计定位：仅做静态审计与评估，输出发现与加固建议，不执行任意构建动作。
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 规则库
# --------------------------------------------------------------------------- #
CI_PLATFORMS: Dict[str, Dict[str, Any]] = {
    "github_actions": {
        "name": "GitHub Actions",
        "config_files": [".github/workflows/*.yml", ".github/workflows/*.yaml"],
        "risk_points": [
            "pull_request_target 触发器与 checkout 不可信 PR",
            "pull_request 事件中泄露 secrets",
            "第三方 Action 未固定 sha",
            "workflow_pull_request_request 权限过宽",
            "自托管 Runner 暴露公网",
        ],
    },
    "gitlab_ci": {
        "name": "GitLab CI/CD",
        "config_files": [".gitlab-ci.yml", ".gitlab/ci/*.yml"],
        "risk_points": [
            "include: remote 拉取不可信 YAML",
            "only/except 规则过宽",
            "Runner 共享且未隔离",
            "artifacts 未保护导致跨流水线泄露",
        ],
    },
    "jenkins": {
        "name": "Jenkins",
        "config_files": ["Jenkinsfile", "Jenkinsfile.*", "vars/*.groovy"],
        "risk_points": [
            "Jenkinsfile 中直接使用 credentials 到 shell",
            "未使用 sandbox 的 Groovy 脚本",
            "Agent 未隔离",
            "脚本命令拼接导致注入",
        ],
    },
}

# 硬编码密钥/Token 特征（仅用于模式识别示例，不回显真实值）
SECRET_PATTERNS: List[Dict[str, Any]] = [
    {"id": "aws_access_key", "name": "AWS Access Key ID",
     "regex": r"AKIA[0-9A-Z]{16}", "severity": "critical"},
    {"id": "aws_secret_key", "name": "AWS Secret Access Key",
     "regex": r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}",
     "severity": "critical"},
    {"id": "github_token", "name": "GitHub Personal Access Token",
     "regex": r"gh[pousr]_[0-9A-Za-z]{36,255}", "severity": "critical"},
    {"id": "github_old_token", "name": "GitHub OAuth Token",
     "regex": r"[0-9a-f]{40}", "severity": "high"},
    {"id": "gitlab_token", "name": "GitLab Personal Access Token",
     "regex": r"glpat-[0-9A-Za-z\-_]{20}", "severity": "critical"},
    {"id": "google_api", "name": "Google API Key",
     "regex": r"AIza[0-9A-Za-z\-_]{35}", "severity": "high"},
    {"id": "slack_token", "name": "Slack Bot Token",
     "regex": r"xox[baprs]-[0-9A-Za-z\-]{10,}", "severity": "high"},
    {"id": "private_key", "name": "私钥块",
     "regex": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
     "severity": "critical"},
    {"id": "db_password", "name": "数据库连接串密码",
     "regex": r"(?i)(?:postgres|mysql|mongodb|redis)://[^\s:@/]+:[^\s@/]+@",
     "severity": "critical"},
    {"id": "jwt_secret", "name": "JWT 密钥",
     "regex": r"(?i)jwt[_-]?(?:secret|key)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
     "severity": "high"},
    {"id": "generic_password", "name": "通用密码赋值",
     "regex": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
     "severity": "medium"},
]

# 构建脚本风险规则
SCRIPT_RULES: List[Dict[str, Any]] = [
    {"id": "script_sudo", "name": "构建脚本使用 sudo",
     "pattern": r"\bsudo\b", "severity": "high",
     "advice": "流水线内不应使用 sudo；如需特权请使用专用 Runner 并审计"},
    {"id": "script_curl_pipe_sh", "name": "curl|bash 模式",
     "pattern": r"curl[^|]*\|\s*(sudo\s*)?bash", "severity": "critical",
     "advice": "禁止 curl|bash；应固定版本并校验签名后再执行"},
    {"id": "script_wget_pipe", "name": "wget|sh 模式",
     "pattern": r"wget[^|]*\|\s*(sudo\s*)?sh", "severity": "critical",
     "advice": "禁止 wget|sh；下载后先校验哈希"},
    {"id": "script_chmod_777", "name": "chmod 777",
     "pattern": r"chmod\s+(-R\s+)?777\b", "severity": "medium",
     "advice": "最小化文件权限，避免 777"},
    {"id": "script_no_check_tls", "name": "curl 忽略 TLS 校验",
     "pattern": r"curl[^\n]*(-k|--insecure)", "severity": "high",
     "advice": "移除 -k/--insecure，使用受信 CA"},
    {"id": "script_eval", "name": "eval 拼接变量",
     "pattern": r"\beval\s+", "severity": "medium",
     "advice": "eval 易注入，改为显式命令"},
    {"id": "script_wget_no_check", "name": "wget 忽略证书",
     "pattern": r"wget[^\n]*--no-check-certificate", "severity": "high",
     "advice": "启用证书校验"},
]

SBOM_FORMATS: List[Dict[str, str]] = [
    {"id": "spdx-json", "name": "SPDX JSON", "standard": "ISO/IEC 5962"},
    {"id": "spdx-tagvalue", "name": "SPDX Tag-Value", "standard": "ISO/IEC 5962"},
    {"id": "cyclonedx-json", "name": "CycloneDX JSON", "standard": "OWASP"},
    {"id": "cyclonedx-xml", "name": "CycloneDX XML", "standard": "OWASP"},
]


# --------------------------------------------------------------------------- #
# 主类
# --------------------------------------------------------------------------- #
class PipelineSecurityAuditor:
    """CI/CD 流水线安全审计器。"""

    def __init__(self) -> None:
        self.scans: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # 流水线配置审计
    # ------------------------------------------------------------------ #
    def audit_pipeline_config(self, platform: str = "github_actions",
                              config_text: str = "",
                              signals: Optional[Dict[str, Any]] = None
                              ) -> Dict[str, Any]:
        signals = signals or {}
        plat = CI_PLATFORMS.get(platform, CI_PLATFORMS["github_actions"])
        findings: List[Dict[str, Any]] = []
        text = config_text or ""

        def add(fid: str, sev: str, title: str, advice: str,
                location: str = "pipeline.yml") -> None:
            findings.append({
                "id": fid, "severity": sev, "title": title,
                "advice": advice, "location": location,
            })

        if platform == "github_actions":
            if re.search(r"pull_request_target", text):
                add("gha_pr_target", "critical",
                    "使用 pull_request_target 触发器",
                    "该触发器在 secrets 上下文运行，禁止 checkout PR 代码后执行未审计步骤",
                    "on.pull_request_target")
            if re.search(r"\buses:\s*['\"]?[^@'\"]+@[^'\"]+['\"]?", text) and \
                    not re.search(r"uses:[^\n]*@[0-9a-f]{40}", text):
                add("gha_action_not_pinned", "high",
                    "第三方 Action 未固定 commit sha",
                    "将 uses: owner/action@v1 改为 owner/action@<full-sha>")
            if re.search(r"\bpermissions:\s*[\"\']?write-all[\"\']?", text) or \
                    re.search(r"contents:\s*write", text):
                add("gha_broad_perms", "high",
                    "工作流权限过宽 (write-all / contents:write)",
                    "使用最小权限 permissions: contents: read")
            if re.search(r"runs-on:\s*self-hosted", text):
                add("gha_self_hosted", "medium",
                    "使用自托管 Runner",
                    "自托管 Runner 需强制隔离、短命、不可复用到下一个任务")
        elif platform == "gitlab_ci":
            if re.search(r"include:\s*\n?\s*-\s*remote:", text):
                add("gl_include_remote", "critical",
                    "include: remote 拉取外部 YAML",
                    "远程 YAML 可被篡改，改用受信镜像仓 include 或 vendoring")
            if re.search(r"only:\s*\[.*branches.*\]", text) and \
                    re.search(r"\btags:\s*\[.*\]", text) is None:
                add("gl_broad_rules", "medium",
                    "only 规则过宽",
                    "显式列出受保护分支，避免通配")
        elif platform == "jenkins":
            if re.search(r"sh\s*['\"].*\$\{[^}]+\}.*['\"]", text):
                add("jk_var_injection", "high",
                    "Groovy 中变量直接拼接到 shell",
                    "使用 sh(script: ..., returnStdout: ...) 并白名单参数")

        # 通用：环境泄露
        if re.search(r"\benv:\s*", text) and re.search(
                r"\b(password|token|secret|key)\b", text, re.I):
            add("generic_env_secret", "high",
                "流水线 env 块疑似含敏感变量",
                "改用密钥存储（GitHub Secrets / GitLab CI Variables masked）")

        # 信号补充
        if signals.get("untrusted_pr_exec"):
            add("sig_untrusted_pr", "critical", "未受信 PR 可触发构建并访问 secrets",
                "隔离 PR 构建，禁止 secrets 注入")
        if signals.get("shared_runner"):
            add("sig_shared_runner", "high", "多任务共享 Runner",
                "启用每次任务新容器/新虚拟机")

        score = self._score(findings)
        result = {
            "scan_id": uuid.uuid4().hex[:12],
            "platform": platform,
            "platform_name": plat["name"],
            "config_files_expected": plat["config_files"],
            "risk_points_known": plat["risk_points"],
            "findings": findings,
            "findings_count": len(findings),
            "severity_dist": self._sev_dist(findings),
            "security_score": score,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.scans.append(result)
        return result

    # ------------------------------------------------------------------ #
    # 敏感信息泄露检测
    # ------------------------------------------------------------------ #
    def scan_hardcoded_secrets(self, content: str, source: str = "pipeline.yml"
                               ) -> Dict[str, Any]:
        hits: List[Dict[str, Any]] = []
        for pat in SECRET_PATTERNS:
            rx = pat.get("_re")
            if rx is None:
                try:
                    rx = re.compile(pat["regex"])
                except re.error:
                    continue
                pat["_re"] = rx
            for m in rx.finditer(content or ""):
                val = m.group(0)
                # 脱敏：不回显真实密钥
                masked = val[:4] + "***" + val[-2:] if len(val) > 8 else "***"
                hits.append({
                    "type_id": pat["id"],
                    "type_name": pat["name"],
                    "severity": pat["severity"],
                    "masked": masked,
                    "line_hint": content[:m.start()].count("\n") + 1,
                    "source": source,
                })
        return {
            "scan_id": uuid.uuid4().hex[:12],
            "source": source,
            "hits": hits,
            "total_hits": len(hits),
            "severity_dist": self._sev_dist(hits),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 构建脚本安全
    # ------------------------------------------------------------------ #
    def audit_build_script(self, script_text: str, filename: str = "build.sh"
                           ) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        for rule in SCRIPT_RULES:
            rx = rule.get("_re")
            if rx is None:
                try:
                    rx = re.compile(rule["pattern"])
                except re.error:
                    continue
                rule["_re"] = rx
            for m in rx.finditer(script_text or ""):
                findings.append({
                    "rule_id": rule["id"],
                    "severity": rule["severity"],
                    "title": rule["name"],
                    "advice": rule["advice"],
                    "line_hint": script_text[:m.start()].count("\n") + 1,
                    "file": filename,
                })
        return {
            "scan_id": uuid.uuid4().hex[:12],
            "file": filename,
            "findings": findings,
            "total": len(findings),
            "severity_dist": self._sev_dist(findings),
            "score": self._score(findings),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 构建环境隔离评估
    # ------------------------------------------------------------------ #
    def assess_build_isolation(self, signals: Optional[Dict[str, Any]] = None
                               ) -> Dict[str, Any]:
        s = signals or {}
        checks = [
            ("container_ephemeral", "每次任务使用一次性容器",
             s.get("container_ephemeral", False),
             "使用容器并在任务结束后销毁，禁止长期复用"),
            ("runner_isolated", "Runner 网络隔离",
             s.get("runner_isolated", False),
             "构建 Runner 与生产网络分段"),
            ("no_privileged", "未使用 privileged 容器",
             s.get("no_privileged", False),
             "避免 --privileged，使用 capabilities 最小化"),
            ("read_only_rootfs", "root 文件系统只读",
             s.get("read_only_rootfs", False),
             "使用 readOnlyRootFilesystem: true"),
            ("non_root_user", "以非 root 用户运行",
             s.get("non_root_user", True),
             "容器内 USER 为非 root"),
            ("no_docker_sock", "未挂载 /var/run/docker.sock",
             s.get("no_docker_sock", True),
             "挂载 docker.sock 等价于宿主机 root，禁止"),
            ("secret_short_ttl", "短期 Token/OIDC  federation",
             s.get("secret_short_ttl", False),
             "使用 OIDC 短期凭据，避免长期 Access Key"),
            ("build_vpc", "构建环境位于私有 VPC",
             s.get("build_vpc", False),
             "构建 Runner 走私有出口，出站白名单"),
        ]
        passed = sum(1 for c in checks if c[2])
        score = int(100 * passed / len(checks))
        gaps = [{"item": c[0], "name": c[1], "passed": c[2],
                 "advice": c[3]} for c in checks]
        return {
            "checks": gaps, "passed": passed, "total": len(checks),
            "score": score,
            "level": "强" if score >= 85 else "中" if score >= 60 else "弱",
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 依赖锁定检查
    # ------------------------------------------------------------------ #
    def check_dependency_locking(self, ecosystem: str = "python",
                                 signals: Optional[Dict[str, Any]] = None
                                 ) -> Dict[str, Any]:
        s = signals or {}
        expected = {
            "python": ["requirements.txt", "poetry.lock", "Pipfile.lock",
                       "uv.lock", "pyproject.toml"],
            "nodejs": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
            "java": ["pom.xml", "gradle.lockfile"],
            "go": ["go.mod", "go.sum"],
            "rust": ["Cargo.lock"],
        }.get(ecosystem, ["lockfile"])
        present = s.get("present_files", [])
        missing = [f for f in expected if f not in present]
        unpinned = s.get("unpinned_deps", [])
        return {
            "ecosystem": ecosystem,
            "expected_lock_files": expected,
            "present_files": present,
            "missing_lock_files": missing,
            "unpinned_dependencies": unpinned,
            "lock_ok": len(missing) == 0 and len(unpinned) == 0,
            "risk": "高" if missing or unpinned else "低",
            "advice": ("提交 lockfile 并固定精确版本；启用 Dependabot/Renovate 自动升级"
                       if missing or unpinned else "锁定状态良好"),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 制品签名验证
    # ------------------------------------------------------------------ #
    def verify_artifact_signing(self, signals: Optional[Dict[str, Any]] = None
                                ) -> Dict[str, Any]:
        s = signals or {}
        checks = [
            ("cosign_sign", "制品使用 cosign 签名", s.get("cosign_sign", False)),
            ("cosign_verify", "部署前强制验证签名", s.get("cosign_verify", False)),
            ("sbom_attest", "附带 SBOM attestation", s.get("sbom_attest", False)),
            ("provenance", "SLSA Provenance 证明", s.get("provenance", False)),
            ("keyless", "使用 keyless (OIDC) 签名", s.get("keyless", True)),
            ("sigstore_rekor", "Rekor 透明日志记录", s.get("sigstore_rekor", False)),
        ]
        passed = sum(1 for _, _, v in checks if v)
        return {
            "checks": [{"id": c[0], "name": c[1], "passed": c[2]} for c in checks],
            "passed": passed, "total": len(checks),
            "score": int(100 * passed / len(checks)),
            "status": "已签名验证" if passed >= 5 else "签名缺失",
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # SBOM 生成
    # ------------------------------------------------------------------ #
    def generate_sbom(self, components: Optional[List[Dict[str, Any]]] = None,
                      fmt: str = "cyclonedx-json") -> Dict[str, Any]:
        comps = components or [
            {"name": "fastapi", "version": "0.115.0", "type": "library",
             "supplier": "tiangolo", "license": "MIT"},
            {"name": "uvicorn", "version": "0.30.6", "type": "library",
             "supplier": "encode", "license": "BSD-3-Clause"},
            {"name": "pydantic", "version": "2.9.2", "type": "library",
             "supplier": "pydantic", "license": "MIT"},
        ]
        return {
            "sbom_id": uuid.uuid4().hex[:12],
            "format": fmt,
            "formats_supported": SBOM_FORMATS,
            "components": comps,
            "component_count": len(comps),
            "dependencies": len(comps),
            "licenses": sorted({c.get("license", "unknown") for c in comps}),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 工具方法
    # ------------------------------------------------------------------ #
    @staticmethod
    def _sev_dist(items: List[Dict[str, Any]]) -> Dict[str, int]:
        d: Dict[str, int] = {}
        for it in items:
            s = it.get("severity", "info")
            d[s] = d.get(s, 0) + 1
        return d

    @staticmethod
    def _score(findings: List[Dict[str, Any]]) -> int:
        weights = {"critical": 25, "high": 12, "medium": 5, "low": 1, "info": 0}
        penalty = sum(weights.get(f.get("severity", "info"), 0) for f in findings)
        return max(0, 100 - penalty)

    def list_scans(self) -> List[Dict[str, Any]]:
        return self.scans

    def get_report_markdown(self, result: Dict[str, Any]) -> str:
        lines = [
            "# CI/CD 流水线安全审计报告", "",
            f"- 平台: {result.get('platform_name', result.get('platform'))}",
            f"- 时间: {result.get('generated_at')}",
            f"- 发现总数: {result.get('findings_count')}",
            f"- 安全评分: {result.get('security_score')}", "",
            "## 严重度分布",
        ]
        for k, v in (result.get("severity_dist") or {}).items():
            lines.append(f"- {k}: {v}")
        lines += ["", "## 发现"]
        for f in result.get("findings", [])[:30]:
            lines.append(f"- [{f['severity']}] {f['title']} — {f['advice']}")
        return "\n".join(lines)


# 单例
_instance: Optional[PipelineSecurityAuditor] = None


def get_pipeline_auditor() -> PipelineSecurityAuditor:
    global _instance
    if _instance is None:
        _instance = PipelineSecurityAuditor()
    return _instance
