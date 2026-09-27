# -*- coding: utf-8 -*-
"""
cloud_security_real._base — 真实云安全检查共享基础。

设计原则（与 cloud_security_pro 一致，但更"真实"）:
    - 所有检查项统一为 Finding 结构，携带检查ID/描述/方法/预期/实际/状态/修复建议。
    - SDK 未安装 / 凭证未配置时，**绝不 mock 数据**，明确返回安装命令与配置指引。
    - 已配置凭证则真实调用云 API，逐条评估。

状态:
    pass        合规
    fail        不合规（发现风险）
    error       调用出错（权限/API 异常，真实错误信息）
    not_config  前置未就绪（SDK 未装 / 无凭证），附 hint
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEV_LABEL = {"critical": "严重", "high": "高危", "medium": "中危",
             "low": "低危", "info": "信息"}


@dataclass
class Finding:
    """单条真实检查结果。"""
    check_id: str = ""
    service: str = ""            # iam / s3 / ec2 / ad / oss ...
    title: str = ""
    description: str = ""
    method: str = ""             # 真实检查方法（调用了哪个 API）
    expected: str = ""           # 预期合规状态
    actual: str = ""             # 实际观测（真实证据）
    status: str = "pass"         # pass / fail / error / not_config
    severity: str = "medium"     # critical/high/medium/low/info
    resource: str = ""           # 资源 ARN / 名称
    remediation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id, "service": self.service,
            "title": self.title, "description": self.description,
            "method": self.method, "expected": self.expected,
            "actual": self.actual, "status": self.status,
            "severity": self.severity,
            "severity_label": SEV_LABEL.get(self.severity, self.severity),
            "resource": self.resource, "remediation": self.remediation,
            "evidence": self.evidence,
        }


@dataclass
class CheckReport:
    """一次真实检查的聚合结果。"""
    provider: str = ""
    service: str = ""
    sdk_installed: bool = True
    credentials_configured: bool = True
    ready: bool = True
    hint: str = ""
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    account_identity: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ #
    def add(self, f: Finding) -> Finding:
        self.findings.append(f)
        return f

    def summary(self) -> Dict[str, Any]:
        total = len(self.findings)
        by_sev: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0,
                                  "low": 0, "info": 0}
        by_status: Dict[str, int] = {"pass": 0, "fail": 0, "error": 0,
                                     "not_config": 0}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            by_status[f.status] = by_status.get(f.status, 0) + 1
        failed = by_status.get("fail", 0)
        pass_rate = round((by_status.get("pass", 0) / max(total, 1)) * 100, 1)
        return {
            "provider": self.provider, "service": self.service,
            "ready": self.ready, "sdk_installed": self.sdk_installed,
            "credentials_configured": self.credentials_configured,
            "hint": self.hint,
            "total": total, "passed": by_status.get("pass", 0),
            "failed": failed, "errors": by_status.get("error", 0),
            "not_config": by_status.get("not_config", 0),
            "pass_rate": pass_rate, "by_severity": by_sev,
            "by_status": by_status,
            "account_identity": self.account_identity,
            "errors_log": self.errors,
        }

    def to_dict(self) -> Dict[str, Any]:
        d = self.summary()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


# --------------------------------------------------------------------------- #
# SDK / 凭证检测
# --------------------------------------------------------------------------- #
def not_ready_report(provider: str, service: str,
                     hint: str,
                     sdk_installed: bool = True,
                     credentials_configured: bool = True) -> CheckReport:
    r = CheckReport(provider=provider, service=service,
                    sdk_installed=sdk_installed,
                    credentials_configured=credentials_configured,
                    ready=False, hint=hint)
    r.add(Finding(
        check_id=f"{service}.not_config", service=service,
        title="前置条件未就绪",
        description="SDK 未安装或云凭证未配置，未发起真实调用（不生成 mock 数据）。",
        method="import SDK + 凭证链检测", expected="SDK 已安装且凭证有效",
        actual=hint, status="not_config", severity="info",
        remediation=hint))
    return r


def safe_call(fn, *args, **kwargs):
    """执行一个真实云调用，返回 (ok, result_or_err)。"""
    try:
        return True, fn(*args, **kwargs)
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"


def severity_for(fail: bool, sev: str = "high") -> str:
    return sev if fail else "pass"
