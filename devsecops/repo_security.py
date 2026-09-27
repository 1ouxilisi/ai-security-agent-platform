# -*- coding: utf-8 -*-
"""
repo_security.py — 代码仓库安全评估。

覆盖：
    - Git 配置审计（user、core、hooks、安全相关配置）
    - 分支保护规则
    - CODEOWNERS 检查
    - 提交签名验证
    - Secret 扫描（pre-commit 钩子建议）
    - 依赖漏洞 PR 检查
    - 合并门禁

设计定位：仅做配置审计与规则建议，不修改远端仓库。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


BRANCH_PROTECTION_RULES: List[Dict[str, Any]] = [
    {"id": "require_pr", "name": "要求 Pull Request", "severity": "high"},
    {"id": "require_review", "name": "要求 >=1 批准评审", "severity": "high"},
    {"id": "require_codeowner", "name": "要求 CODEOWNERS 评审", "severity": "medium"},
    {"id": "require_status", "name": "要求必需检查通过", "severity": "high"},
    {"id": "require_signed", "name": "要求已签名提交", "severity": "medium"},
    {"id": "no_force_push", "name": "禁止强制推送", "severity": "high"},
    {"id": "no_delete", "name": "禁止删除分支", "severity": "medium"},
    {"id": "up_to_date", "name": "要求分支与目标同步", "severity": "medium"},
    {"id": "dismiss_stale", "name": "新提交自动作废过时评审", "severity": "low"},
    {"id": "include_admins", "name": "规则覆盖管理员", "severity": "medium"},
]

PRE_COMMIT_HOOKS: List[Dict[str, Any]] = [
    {"id": "gitleaks", "name": "Gitleaks / TruffleHog Secret 扫描",
     "severity": "critical", "desc": "提交前扫描硬编码密钥"},
    {"id": "gitleaks-detect", "name": "git-secrets",
     "severity": "high", "desc": "AWS/GitHub token 模式"},
    {"id": "detect-private-key", "name": "detect-private-key",
     "severity": "critical", "desc": "禁止提交私钥"},
    {"id": "trailing-whitespace", "name": "行尾空白",
     "severity": "low", "desc": "代码规范"},
    {"id": "end-of-file-fixer", "name": "文件末尾换行",
     "severity": "low", "desc": "代码规范"},
    {"id": "check-merge-conflict", "name": "冲突标记检查",
     "severity": "medium", "desc": "避免提交冲突残留"},
    {"id": "detect-pii", "name": "PII 预扫描",
     "severity": "high", "desc": "手机号/身份证预拦截"},
    {"id": "bandit", "name": "Bandit Python 安全扫描",
     "severity": "medium", "desc": "Python 静态安全"},
    {"id": "eslint-security", "name": "ESLint security-plugin",
     "severity": "medium", "desc": "前端安全"},
]

MERGE_GATES: List[Dict[str, Any]] = [
    {"id": "unit_test", "name": "单元测试通过", "blocking": True},
    {"id": "lint", "name": "Lint 通过", "blocking": True},
    {"id": "sast", "name": "SAST 无高危", "blocking": True},
    {"id": "sca", "name": "SCA 无已知 RCE", "blocking": True},
    {"id": "secret_scan", "name": "无 Secret 泄露", "blocking": True},
    {"id": "license_check", "name": "许可证合规", "blocking": False},
    {"id": "coverage", "name": "覆盖率不下降", "blocking": False},
    {"id": "sbom", "name": "SBOM 生成成功", "blocking": False},
    {"id": "image_scan", "name": "镜像扫描无 CRITICAL", "blocking": True},
    {"id": "approval", "name": ">=1 批准", "blocking": True},
]


class RepoSecurityAssessor:
    """代码仓库安全评估器。"""

    def __init__(self) -> None:
        self.history: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # Git 配置审计
    # ------------------------------------------------------------------ #
    def audit_git_config(self, config: Optional[Dict[str, Any]] = None
                         ) -> Dict[str, Any]:
        cfg = config or {}
        checks = [
            ("user_email_valid", "user.email 使用公司域名",
             cfg.get("user_email_valid", False),
             "避免用个人邮箱提交公司代码"),
            ("tag_gpgsign", "tag.gpgsign=true",
             cfg.get("tag_gpgsign", False),
             "强制 tag 签名"),
            ("commit_gpgsign", "commit.gpgsign=true",
             cfg.get("commit_gpgsign", False),
             "强制提交签名"),
            ("push_follow_tags", "push.followTags=true",
             cfg.get("push_follow_tags", True),
             "推送时自动推 tag"),
            ("receive_deny_current", "receive.denyCurrentBranch=ignore (服务端)",
             cfg.get("receive_deny_current", False),
             "服务端禁止直接 push 到工作分支"),
            ("hooks_path", "自定义 hooks 目录",
             cfg.get("hooks_path", False),
             "统一管理 pre-commit hooks"),
            ("core_ssh_command", "固定 SSH 命令",
             cfg.get("core_ssh_command", False),
             "避免被 alias 劫持"),
            ("protocol_version", "protocol.version=2",
             cfg.get("protocol_version", True),
             "启用更安全的 Git 协议"),
        ]
        passed = sum(1 for c in checks if c[2])
        return {
            "checks": [{"id": c[0], "name": c[1], "passed": c[2],
                        "advice": c[3]} for c in checks],
            "passed": passed, "total": len(checks),
            "score": int(100 * passed / len(checks)),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 分支保护
    # ------------------------------------------------------------------ #
    def assess_branch_protection(self, enabled_rules: Optional[List[str]] = None
                                 ) -> Dict[str, Any]:
        enabled = set(enabled_rules or [])
        rows = []
        for r in BRANCH_PROTECTION_RULES:
            rows.append({**r, "enabled": r["id"] in enabled})
        missing = [r for r in rows if not r["enabled"]
                   and r["severity"] in ("high", "critical")]
        score = int(100 * sum(1 for r in rows if r["enabled"]) / len(rows))
        return {
            "rules": rows,
            "missing_high_priority": [r["id"] for r in missing],
            "score": score,
            "level": "强" if score >= 90 else "中" if score >= 60 else "弱",
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # CODEOWNERS
    # ------------------------------------------------------------------ #
    def check_codeowners(self, content: str = "",
                         files: Optional[List[str]] = None) -> Dict[str, Any]:
        files = files or []
        lines = [l for l in (content or "").splitlines() if l.strip()
                 and not l.strip().startswith("#")]
        owners: List[Dict[str, Any]] = []
        for l in lines:
            parts = l.split()
            if len(parts) >= 2:
                owners.append({"pattern": parts[0], "owners": parts[1:]})
        uncovered = [f for f in files if not any(
            self._match_pattern(o["pattern"], f) for o in owners)]
        return {
            "file_present": bool(content or owners),
            "rules": owners,
            "rule_count": len(owners),
            "uncovered_files": uncovered[:50],
            "uncovered_count": len(uncovered),
            "coverage": 100 - int(100 * len(uncovered) / max(1, len(files))),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    @staticmethod
    def _match_pattern(pattern: str, path: str) -> bool:
        pat = pattern.lstrip("/")
        if pat == "*":
            return True
        if pat.endswith("/"):
            return path.startswith(pat)
        if pat in path:
            return True
        return path == pat or path.startswith(pat + "/")

    # ------------------------------------------------------------------ #
    # 提交签名
    # ------------------------------------------------------------------ #
    def assess_commit_signing(self, signals: Optional[Dict[str, Any]] = None
                              ) -> Dict[str, Any]:
        s = signals or {}
        total = s.get("total_commits", 100)
        signed = s.get("signed_commits", 60)
        verified = s.get("verified_commits", int(signed * 0.9))
        return {
            "total_commits": total,
            "signed_commits": signed,
            "verified_commits": verified,
            "sign_ratio": round(signed / max(1, total) * 100, 1),
            "verify_ratio": round(verified / max(1, total) * 100, 1),
            "policy": s.get("policy", "advisory"),
            "status": "强制签名且全量验证" if signed == total and verified == total
                      else "建议推进强制签名",
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # Secret 扫描 (pre-commit)
    # ------------------------------------------------------------------ #
    def assess_secret_scan(self, enabled_hooks: Optional[List[str]] = None,
                           scan_results: Optional[Dict[str, Any]] = None
                           ) -> Dict[str, Any]:
        enabled = set(enabled_hooks or [])
        rows = [{**h, "enabled": h["id"] in enabled} for h in PRE_COMMIT_HOOKS]
        critical_missing = [h["id"] for h in rows
                            if not h["enabled"] and h["severity"] == "critical"]
        findings = (scan_results or {}).get("findings", [
            {"type": "AWS Key", "severity": "critical", "file": "config/prod.env"},
            {"type": "Slack Token", "severity": "high", "file": "deploy/notify.sh"},
        ])
        return {
            "hooks": rows,
            "critical_missing": critical_missing,
            "last_scan_findings": findings,
            "last_scan_total": len(findings),
            "score": int(100 * sum(1 for r in rows if r["enabled"]) / len(rows)),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 依赖漏洞 PR 检查
    # ------------------------------------------------------------------ #
    def assess_dep_pr(self, prs: Optional[List[Dict[str, Any]]] = None
                      ) -> Dict[str, Any]:
        prs = prs or [
            {"pr_id": "dependabot-fastapi-0.115", "package": "fastapi",
             "from": "0.104.0", "to": "0.115.0", "vuln_fixed": ["CVE-2024-..."],
             "age_days": 12, "approved": False, "merged": False},
            {"pr_id": "renovate-urllib3", "package": "urllib3",
             "from": "1.26.0", "to": "1.26.18", "vuln_fixed": ["CVE-2023-43804"],
             "age_days": 45, "approved": True, "merged": False},
        ]
        stale = [p for p in prs if p.get("age_days", 0) > 14 and not p.get("merged")]
        return {
            "prs": prs, "total": len(prs),
            "stale_pending": stale,
            "stale_count": len(stale),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 合并门禁
    # ------------------------------------------------------------------ #
    def assess_merge_gates(self, enabled: Optional[List[str]] = None
                           ) -> Dict[str, Any]:
        en = set(enabled or [])
        rows = [{**g, "enabled": g["id"] in en} for g in MERGE_GATES]
        missing_blocking = [g["id"] for g in rows
                            if g["blocking"] and g["id"] not in en]
        return {
            "gates": rows,
            "missing_blocking": missing_blocking,
            "score": int(100 * sum(1 for r in rows if r["enabled"]) / len(rows)),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def full_assess(self, signals: Optional[Dict[str, Any]] = None
                    ) -> Dict[str, Any]:
        s = signals or {}
        cfg = self.audit_git_config(s.get("git_config"))
        bp = self.assess_branch_protection(s.get("branch_rules"))
        co = self.check_codeowners(s.get("codeowners", ""),
                                   s.get("codeowner_files", []))
        cs = self.assess_commit_signing(s.get("commit_signing"))
        ss = self.assess_secret_scan(s.get("hooks"), s.get("secret_scan"))
        dp = self.assess_dep_pr(s.get("dep_prs"))
        mg = self.assess_merge_gates(s.get("merge_gates"))
        score = int((cfg["score"] + bp["score"] + ss["score"] + mg["score"]) / 4)
        result = {
            "scan_id": uuid.uuid4().hex[:12],
            "git_config": cfg, "branch_protection": bp,
            "codeowners": co, "commit_signing": cs,
            "secret_scan": ss, "dep_pr": dp, "merge_gates": mg,
            "overall_score": score,
            "overall_level": "强" if score >= 85 else "中" if score >= 60 else "弱",
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.history.append(result)
        return result

    def list_history(self) -> List[Dict[str, Any]]:
        return self.history


_instance: Optional[RepoSecurityAssessor] = None


def get_repo_assessor() -> RepoSecurityAssessor:
    global _instance
    if _instance is None:
        _instance = RepoSecurityAssessor()
    return _instance
