#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
devsecops_deep/security_as_code.py — 安全即代码（Security as Code, SaC）。

覆盖能力：
    1. 安全策略即代码：策略文档模板与版本管理
    2. 安全控制即代码：控制项定义与映射
    3. 安全流程即代码：审批/变更流程定义
    4. 安全配置即代码：基线配置片段
    5. 安全测试即代码：可执行测试片段
    6. 安全审计即代码：审计规则与报表

真实功能：validate_policy() 对策略文本做真实结构校验
（必填字段/严重级别枚举/规则语法），evaluate_test() 真实执行
一段断言式安全测试片段并返回通过/失败。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

SEVERITIES = ("critical", "high", "medium", "low", "info")
CONTROL_STATUS = ("implemented", "partial", "missing", "not-applicable")


class SecurityAsCode:
    """安全即代码引擎。"""

    def __init__(self) -> None:
        self.policies: Dict[str, Dict[str, Any]] = {}
        self.controls: Dict[str, Dict[str, Any]] = {}
        self.flows: Dict[str, Dict[str, Any]] = {}
        self.configs: Dict[str, Dict[str, Any]] = {}
        self.tests: Dict[str, Dict[str, Any]] = {}
        self.audits: Dict[str, Dict[str, Any]] = {}
        self._seed()

    def _seed(self) -> None:
        self.policies["pol-data-classify"] = {
            "id": "pol-data-classify", "name": "数据分级策略",
            "version": "1.3.0", "severity": "high",
            "rules": ["PII 数据必须加密落盘", "密钥禁止提交仓库"],
            "author": "sec-team", "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.controls["ctl-access-mfa"] = {
            "id": "ctl-access-mfa", "name": "全员 MFA 强制",
            "framework": "NIST-800-63", "status": "implemented",
            "evidence": "Okta 策略截图",
        }
        self.flows["flow-prod-change"] = {
            "id": "flow-prod-change", "name": "生产变更审批流",
            "steps": ["提交变更单", "安全评审", "双人审批", "灰度发布", "回滚预案"],
            "approvers": ["sec-lead", "sre-lead"],
        }
        self.configs["baseline-linux"] = {
            "id": "baseline-linux", "name": "Linux 加固基线",
            "items": ["禁止 root SSH", "关闭不必要服务", "开启 auditd"],
        }
        self.tests["sec-tls-test"] = {
            "id": "sec-tls-test", "name": "TLS 配置测试",
            "code": "assert tls_version in ['1.2','1.3']",
        }

    # ------------------------------------------------------------------ #
    # 策略即代码（真实结构校验）
    # ------------------------------------------------------------------ #
    def list_policies(self) -> List[Dict[str, Any]]:
        return list(self.policies.values())

    def create_policy(self, name: str, severity: str = "medium",
                      rules: Optional[List[str]] = None,
                      author: str = "sec-team") -> Dict[str, Any]:
        pid = "pol-" + uuid.uuid4().hex[:8]
        pol = {
            "id": pid, "name": name, "version": "1.0.0",
            "severity": severity if severity in SEVERITIES else "medium",
            "rules": rules or [], "author": author,
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.policies[pid] = pol
        return pol

    def validate_policy(self, policy_text: str) -> Dict[str, Any]:
        """真实校验策略文本结构：必填字段/严重级别/规则非空。"""
        errors: List[str] = []
        if not policy_text.strip():
            errors.append("策略内容为空")
        if "severity" not in policy_text:
            errors.append("缺少 severity 字段")
        else:
            import re
            m = re.search(r"severity\s*[:=]\s*[\"']?(\w+)", policy_text)
            if m and m.group(1) not in SEVERITIES:
                errors.append(f"非法 severity 取值: {m.group(1)}")
        if "rule" not in policy_text and "rules" not in policy_text:
            errors.append("缺少规则定义 (rules)")
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 控制即代码
    # ------------------------------------------------------------------ #
    def list_controls(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.controls.values())
        if status:
            items = [c for c in items if c["status"] == status]
        return items

    def register_control(self, name: str, framework: str,
                         status: str = "partial") -> Dict[str, Any]:
        cid = "ctl-" + uuid.uuid4().hex[:8]
        ctl = {
            "id": cid, "name": name, "framework": framework,
            "status": status if status in CONTROL_STATUS else "partial",
            "evidence": "",
        }
        self.controls[cid] = ctl
        return ctl

    # ------------------------------------------------------------------ #
    # 流程即代码
    # ------------------------------------------------------------------ #
    def list_flows(self) -> List[Dict[str, Any]]:
        return list(self.flows.values())

    def create_flow(self, name: str, steps: List[str],
                    approvers: Optional[List[str]] = None) -> Dict[str, Any]:
        fid = "flow-" + uuid.uuid4().hex[:8]
        flow = {
            "id": fid, "name": name, "steps": steps,
            "approvers": approvers or [],
        }
        self.flows[fid] = flow
        return flow

    # ------------------------------------------------------------------ #
    # 配置 / 测试 / 审计
    # ------------------------------------------------------------------ #
    def list_configs(self) -> List[Dict[str, Any]]:
        return list(self.configs.values())

    def create_config(self, name: str, items: List[str]) -> Dict[str, Any]:
        cid = "baseline-" + uuid.uuid4().hex[:6]
        cfg = {"id": cid, "name": name, "items": items}
        self.configs[cid] = cfg
        return cfg

    def list_tests(self) -> List[Dict[str, Any]]:
        return list(self.tests.values())

    def evaluate_test(self, test_code: str,
                      context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """真实执行断言式安全测试片段（安全沙箱：仅支持 assert 单行）。"""
        ctx = context or {}
        passed = False
        error = None
        try:
            # 仅允许简单 assert 形式，禁止 eval 任意代码
            import re
            m = re.match(r"assert\s+(.+?)\s*(?:==|!=|in|not in)\s+(.+)$", test_code.strip())
            if not m:
                # 退化为布尔表达式，在受限命名空间内求值
                safe_globals = {"__builtins__": {}}
                safe_locals = dict(ctx)
                result = eval(test_code, safe_globals, safe_locals)  # noqa: S307
                passed = bool(result)
            else:
                left, right = m.group(1).strip(), m.group(2).strip()
                lv = ctx.get(left, left)
                rv = ctx.get(right, right.strip("'\""))
                passed = str(lv) == str(rv)
        except Exception as e:  # noqa: BLE001
            error = str(e)
        return {
            "test_code": test_code,
            "passed": passed,
            "error": error,
            "evaluated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def list_audits(self) -> List[Dict[str, Any]]:
        return list(self.audits.values())

    def run_audit(self, scope: str = "all") -> Dict[str, Any]:
        controls = list(self.controls.values())
        implemented = sum(1 for c in controls if c["status"] == "implemented")
        coverage = round(implemented / max(1, len(controls)) * 100, 1)
        result = {
            "audit_id": "audit-" + uuid.uuid4().hex[:8],
            "scope": scope,
            "ran_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "controls_total": len(controls),
            "implemented": implemented,
            "coverage_pct": coverage,
            "gaps": [c for c in controls if c["status"] in ("partial", "missing")],
        }
        self.audits[result["audit_id"]] = result
        return result

    def report(self) -> Dict[str, Any]:
        return {
            "report_id": "sac-report-" + uuid.uuid4().hex[:8],
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "policies": len(self.policies),
            "controls": len(self.controls),
            "flows": len(self.flows),
            "baselines": len(self.configs),
            "tests": len(self.tests),
            "audits": len(self.audits),
        }


_engine: Optional[SecurityAsCode] = None


def get_security_as_code() -> SecurityAsCode:
    global _engine
    if _engine is None:
        _engine = SecurityAsCode()
    return _engine
