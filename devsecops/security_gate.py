# -*- coding: utf-8 -*-
"""
security_gate.py — 安全门禁与质量门。

覆盖：
    - 安全策略引擎
    - 阻断规则 / 警告规则
    - 豁免管理
    - 安全评分 0-100
    - 质量门禁
    - 流水线集成配置生成（GitHub Actions / GitLab CI / Jenkins）

设计定位：策略评估与配置生成，不阻断真实流水线。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


BLOCK_RULES: List[Dict[str, Any]] = [
    {"id": "blk_critical_cve", "name": "CRITICAL 漏洞",
     "condition": "critical_cve > 0", "action": "block",
     "description": "存在未修复的 CRITICAL 漏洞时阻断"},
    {"id": "blk_hardcoded_secret", "name": "硬编码密钥",
     "condition": "secret_hits.critical > 0", "action": "block",
     "description": "发现硬编码密钥时阻断"},
    {"id": "blk_dockerfile_critical", "name": "Dockerfile 严重问题",
     "condition": "dockerfile.critical > 0", "action": "block",
     "description": "Dockerfile 存在 critical 风险时阻断"},
    {"id": "blk_no_sign", "name": "未签名制品",
     "condition": "artifact_signed == false", "action": "block",
     "description": "制品未签名时阻断部署"},
    {"id": "blk_privileged", "name": "特权容器",
     "condition": "privileged_pod == true", "action": "block",
     "description": "禁止 privileged 容器部署"},
    {"id": "blk_license_gpl", "name": "GPL 许可证",
     "condition": "license_disallowed > 0", "action": "block",
     "description": "禁止引入不允许的许可证"},
]

WARN_RULES: List[Dict[str, Any]] = [
    {"id": "wrn_high_cve", "name": "HIGH 漏洞",
     "condition": "high_cve > 0", "action": "warn",
     "description": "HIGH 漏洞只警告，要求 7 天内修复"},
    {"id": "wrn_coverage_drop", "name": "覆盖率下降",
     "condition": "coverage_drop > 2", "action": "warn"},
    {"id": "wrn_medium_cve", "name": "MEDIUM 漏洞",
     "condition": "medium_cve > 5", "action": "warn"},
    {"id": "wrn_old_base", "name": "基础镜像 EOL 临近",
     "condition": "base_eol_days < 180", "action": "warn"},
    {"id": "wrn_no_sbom", "name": "SBOM 缺失",
     "condition": "sbom_present == false", "action": "warn"},
]

GATE_LEVELS = [
    {"id": "L0", "name": "无门禁", "score": 0,
     "desc": "仅记录，不阻断"},
    {"id": "L1", "name": "基础门禁", "score": 40,
     "desc": "阻断 CRITICAL CVE / 硬编码密钥"},
    {"id": "L2", "name": "标准门禁", "score": 60,
     "desc": "+ 镜像签名 / Dockerfile 关键项"},
    {"id": "L3", "name": "严格门禁", "score": 80,
     "desc": "+ 特权容器 / SBOM / 许可证"},
    {"id": "L4", "name": "最高门禁", "score": 90,
     "desc": "+ 覆盖率 / 基础镜像 EOL / 全部 warn 转 block"},
]


class SecurityGate:
    """安全门禁引擎。"""

    def __init__(self) -> None:
        self.exemptions: Dict[str, Dict[str, Any]] = {}
        self.history: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # 策略评估
    # ------------------------------------------------------------------ #
    def evaluate(self, signals: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        s = signals or {}
        ctx = {
            "critical_cve": s.get("critical_cve", 0),
            "high_cve": s.get("high_cve", 0),
            "medium_cve": s.get("medium_cve", 0),
            "secret_hits": {"critical": s.get("secret_critical", 0),
                            "high": s.get("secret_high", 0)},
            "dockerfile": {"critical": s.get("dockerfile_critical", 0),
                            "high": s.get("dockerfile_high", 0)},
            "artifact_signed": s.get("artifact_signed", False),
            "privileged_pod": s.get("privileged_pod", False),
            "license_disallowed": s.get("license_disallowed", 0),
            "coverage_drop": s.get("coverage_drop", 0),
            "base_eol_days": s.get("base_eol_days", 365),
            "sbom_present": s.get("sbom_present", True),
        }

        def resolved(rule: Dict[str, Any]) -> bool:
            eid = rule["id"]
            ex = self.exemptions.get(eid)
            if ex and ex.get("active") and \
                    ex.get("expires", "9999") > time.strftime("%Y-%m-%d"):
                return True
            return False

        triggered_blocks: List[Dict[str, Any]] = []
        triggered_warns: List[Dict[str, Any]] = []
        for r in BLOCK_RULES:
            cond_hit = self._eval_cond(r["condition"], ctx)
            if cond_hit and not resolved(r):
                triggered_blocks.append(r)
        for r in WARN_RULES:
            cond_hit = self._eval_cond(r["condition"], ctx)
            if cond_hit and not resolved(r):
                triggered_warns.append(r)

        score = self._score(ctx)
        passed = len(triggered_blocks) == 0
        result = {
            "gate_id": uuid.uuid4().hex[:12],
            "context": ctx,
            "blocked": triggered_blocks,
            "warned": triggered_warns,
            "passed": passed,
            "decision": "BLOCK" if not passed else "WARN" if triggered_warns else "PASS",
            "security_score": score,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.history.append(result)
        return result

    @staticmethod
    def _eval_cond(cond: str, ctx: Dict[str, Any]) -> bool:
        # 简化条件求值：不使用 eval，手写解释器
        try:
            if ">" in cond:
                left, right = cond.split(">", 1)
                return float(SecurityGate._pick(left.strip(), ctx)) > float(right.strip())
            if "==" in cond:
                left, right = cond.split("==", 1)
                val = SecurityGate._pick(left.strip(), ctx)
                return str(val).lower() == right.strip().lower()
        except Exception:
            return False
        return False

    @staticmethod
    def _pick(path: str, ctx: Dict[str, Any]) -> Any:
        cur: Any = ctx
        for part in path.split("."):
            if isinstance(cur, dict):
                cur = cur.get(part, 0)
            else:
                return 0
        return cur if cur not in (None, "") else 0

    @staticmethod
    def _score(ctx: Dict[str, Any]) -> int:
        pen = (ctx["critical_cve"] * 25 + ctx["high_cve"] * 8 +
               ctx["medium_cve"] * 2 +
               ctx["secret_hits"]["critical"] * 30 +
               ctx["secret_hits"]["high"] * 10 +
               ctx["dockerfile"]["critical"] * 20 +
               ctx["dockerfile"]["high"] * 5 +
               (0 if ctx["artifact_signed"] else 15) +
               (30 if ctx["privileged_pod"] else 0) +
               ctx["license_disallowed"] * 10 +
               (0 if ctx["sbom_present"] else 5))
        return max(0, 100 - int(pen))

    # ------------------------------------------------------------------ #
    # 豁免
    # ------------------------------------------------------------------ #
    def grant_exemption(self, rule_id: str, reason: str,
                        expires: str = "") -> Dict[str, Any]:
        self.exemptions[rule_id] = {
            "rule_id": rule_id, "reason": reason,
            "expires": expires or time.strftime("%Y-%m-%d",
                                                 time.localtime(time.time() + 7 * 86400)),
            "active": True, "granted_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return self.exemptions[rule_id]

    def list_exemptions(self) -> List[Dict[str, Any]]:
        return list(self.exemptions.values())

    def revoke_exemption(self, rule_id: str) -> bool:
        if rule_id in self.exemptions:
            self.exemptions[rule_id]["active"] = False
            return True
        return False

    # ------------------------------------------------------------------ #
    # 流水线集成配置生成
    # ------------------------------------------------------------------ #
    def generate_pipeline_config(self, platform: str = "github_actions",
                                  gate_level: str = "L2") -> Dict[str, Any]:
        if platform == "github_actions":
            content = (
                "name: devsecops-gate\n"
                "on: [pull_request]\n"
                "jobs:\n"
                "  gate:\n"
                "    runs-on: ubuntu-latest\n"
                "    permissions:\n"
                "      contents: read\n"
                "      security-events: write\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "      - uses: aquasecurity/trivy-action@0.24\n"
                "        with: {scan-type: 'fs', severity: 'CRITICAL,HIGH'}\n"
                "      - uses: gitleaks/gitleaks-action@v2\n"
                "      - uses: anchore/scan-action@v5\n"
                "        with: {severity-cutoff: 'Critical'}\n"
            )
        elif platform == "gitlab_ci":
            content = (
                "devsecops_gate:\n"
                "  image: docker:latest\n"
                "  services: [docker:dind]\n"
                "  script:\n"
                "    - trivy fs --exit-code 1 --severity CRITICAL,HIGH .\n"
                "    - gitleaks git --redact .\n"
                "  rules:\n"
                "    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'\n"
            )
        else:  # jenkins
            content = (
                "pipeline {\n"
                "  agent any\n"
                "  stages {\n"
                "    stage('Gate') {\n"
                "      steps {\n"
                "        sh 'trivy fs --exit-code 1 --severity CRITICAL,HIGH .'\n"
                "        sh 'gitleaks git --redact .'\n"
                "      }\n"
                "    }\n"
                "  }\n"
                "}\n"
            )
        return {
            "platform": platform,
            "gate_level": gate_level,
            "config_filename": {
                "github_actions": ".github/workflows/devsecops-gate.yml",
                "gitlab_ci": ".gitlab/ci/devsecops-gate.yml",
                "jenkins": "Jenkinsfile.security",
            }[platform],
            "content": content,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def list_rules(self) -> Dict[str, Any]:
        return {"block_rules": BLOCK_RULES, "warn_rules": WARN_RULES,
                "gate_levels": GATE_LEVELS}

    def list_history(self) -> List[Dict[str, Any]]:
        return self.history


_instance: Optional[SecurityGate] = None


def get_security_gate() -> SecurityGate:
    global _instance
    if _instance is None:
        _instance = SecurityGate()
    return _instance
