# -*- coding: utf-8 -*-
"""
漏洞修复验证器（Remediation Verifier）—— 修复有效性评估

输入漏洞描述 + 修复方案，判断修复是否真正生效：
    - verify_rescan(vuln_id, target)      模拟重新扫描，确认漏洞签名是否消失
    - verify_config(target, config_checks) 检查修复配置是否生效
    - verify_patch_version(target, component, min_version) 验证组件版本是否达标

输出：result(fixed/partially_fixed/not_fixed/unverifiable) + evidence 列表 +
regression_risk(low/medium/high + 说明)。

内置 10+ 常见漏洞验证逻辑。纯模拟，不发起真实扫描。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from utils.logger import log  # type: ignore
except Exception:  # pragma: no cover
    import logging

    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("remediation_verifier")


# 每个漏洞类型的验证函数：(vuln, plan, current_state) -> (result, evidence[], regression_risk, note)
VerifyFn = Callable[[Dict[str, Any], Dict[str, Any], Dict[str, Any]],
                    Tuple[str, List[str], str, str]]


def _check_items(config_checks: Dict[str, Any], expected: Dict[str, Any]
                 ) -> Tuple[int, int, List[str]]:
    """比对配置项：返回 (匹配数, 总数, 证据)。"""
    matched = 0
    total = 0
    evidence = []
    for k, exp in expected.items():
        total += 1
        actual = (config_checks or {}).get(k, None)
        if isinstance(exp, (list, tuple, set)):
            ok = actual in exp
        else:
            ok = actual == exp
        if ok:
            matched += 1
            evidence.append(f"[OK] {k}={actual} 符合预期")
        else:
            evidence.append(f"[FAIL] {k}={actual} 不符合预期({exp})")
    return matched, total, evidence


class RemediationVerifier:
    """漏洞修复验证引擎。"""

    def __init__(self):
        self.verifiers: Dict[str, VerifyFn] = {}
        self.results: List[Dict[str, Any]] = []
        self._register_defaults()

    # ------------------------------------------------------------------ #
    # 内置验证逻辑
    # ------------------------------------------------------------------ #
    def _register_defaults(self) -> None:
        v = self.verifiers

        def sqli(vuln, plan, state):
            cc = plan.get("config_checks", {})
            exp = {"parameterized_query": True, "input_sanitized": True, "waf_rule": "active"}
            m, t, ev = _check_items(cc, exp)
            res = "fixed" if m == t else ("partially_fixed" if m > 0 else "not_fixed")
            risk = "low" if res == "fixed" else "medium"
            return res, ev, risk, "参数化查询落地后回归风险低；仅加 WAF 规则仍可能被绕过。"
        v["sql_injection"] = sqli

        def xss(vuln, plan, state):
            cc = plan.get("config_checks", {})
            exp = {"output_encoding": True, "csp_header": True, "input_validation": True}
            m, t, ev = _check_items(cc, exp)
            res = "fixed" if m == t else ("partially_fixed" if m >= 2 else "not_fixed")
            return res, ev, ("low" if res == "fixed" else "medium"), \
                "输出编码+CSP 双保险；仅过滤尖括号可能被编码绕过。"
        v["xss"] = xss

        def traversal(vuln, plan, state):
            cc = plan.get("config_checks", {})
            exp = {"path_normalized": True, "whitelist_based": True}
            m, t, ev = _check_items(cc, exp)
            res = "fixed" if m == t else ("partially_fixed" if m > 0 else "not_fixed")
            return res, ev, "low", "白名单映射文件后无业务回归。"
        v["directory_traversal"] = traversal

        def weak_password(vuln, plan, state):
            cc = plan.get("config_checks", {})
            exp = {"password_rotated": True, "mfa_enabled": True, "min_length_14": True}
            m, t, ev = _check_items(cc, exp)
            res = "fixed" if m >= 2 else ("partially_fixed" if m == 1 else "not_fixed")
            return res, ev, ("low" if res == "fixed" else "high"), \
                "未启用 MFA 且仅改口令，仍存在撞库风险。"
        v["weak_password"] = weak_password
        v["weak_credential"] = weak_password

        def expired_component(vuln, plan, state):
            comp = plan.get("component") or vuln.get("component", "unknown")
            min_ver = plan.get("min_version", "0.0.0")
            cur_ver = (state.get("versions") or {}).get(comp, plan.get("current_version", "0.0.0"))
            ev = [f"组件 {comp}: 当前 {cur_ver}，要求 >= {min_ver}"]
            ok = self._ver_ge(cur_ver, min_ver)
            return ("fixed" if ok else "not_fixed"), ev, "medium", \
                "升级组件可能引入 API 不兼容，需回归测试。"
        v["expired_component"] = expired_component
        v["outdated_component"] = expired_component

        def missing_header(vuln, plan, state):
            cc = plan.get("config_checks", {})
            expected_headers = plan.get("required_headers",
                                        ["HSTS", "X-Frame-Options", "X-Content-Type-Options"])
            present = cc.get("headers_present", [])
            missing = [h for h in expected_headers if h not in present]
            ev = [f"已配置响应头: {present}"]
            ev.append(f"仍缺失: {missing if missing else '无'}")
            res = "fixed" if not missing else ("partially_fixed" if len(missing) < len(expected_headers) else "not_fixed")
            return res, ev, "low", "补响应头几乎无业务回归。"
        v["missing_security_headers"] = missing_header
        v["missing_header"] = missing_header

        def open_port(vuln, plan, state):
            closed = plan.get("config_checks", {}).get("port_closed", False)
            fw_rule = plan.get("config_checks", {}).get("firewall_allowlist", False)
            ev = [f"端口已关闭: {closed}", f"防火墙白名单: {fw_rule}"]
            res = "fixed" if (closed or fw_rule) else "not_fixed"
            return res, ev, "medium", "关闭端口需确认无依赖业务。"
        v["open_port"] = open_port
        v["exposed_service"] = open_port

        def priv_escalation(vuln, plan, state):
            cc = plan.get("config_checks", {})
            exp = {"sudo_privilege_revoked": True, "kernel_patched": True, "SUID_cleaned": True}
            m, t, ev = _check_items(cc, exp)
            res = "fixed" if m == t else ("partially_fixed" if m >= 1 else "not_fixed")
            return res, ev, "high", "回收 sudo/内核补丁需验证运维流程可用性。"
        v["privilege_escalation"] = priv_escalation

        def info_disclosure(vuln, plan, state):
            cc = plan.get("config_checks", {})
            exp = {"debug_disabled": True, "stacktrace_hidden": True, "error_page_generic": True}
            m, t, ev = _check_items(cc, exp)
            res = "fixed" if m >= 2 else ("partially_fixed" if m == 1 else "not_fixed")
            return res, ev, "low", "关闭 debug 不影响正常业务。"
        v["information_disclosure"] = info_disclosure
        v["info_leak"] = info_disclosure

        def csrf(vuln, plan, state):
            cc = plan.get("config_checks", {})
            exp = {"csrf_token": True, "same_site_cookie": True, "referer_check": True}
            m, t, ev = _check_items(cc, exp)
            res = "fixed" if m >= 2 else ("partially_fixed" if m == 1 else "not_fixed")
            return res, ev, "low", "加 CSRF Token 对正常交互影响小。"
        v["csrf"] = csrf

    @staticmethod
    def _ver_ge(actual: str, minimum: str) -> bool:
        try:
            a = [int(x) for x in actual.split(".") if x.isdigit()]
            b = [int(x) for x in minimum.split(".") if x.isdigit()]
            a = (a + [0, 0, 0])[:3]
            b = (b + [0, 0, 0])[:3]
            return a >= b
        except Exception:
            return actual.strip() == minimum.strip()

    # ------------------------------------------------------------------ #
    # 公开验证方法
    # ------------------------------------------------------------------ #
    def verify_patch_version(self, target: str, component: str, min_version: str,
                             current_version: str = "0.0.0") -> Dict[str, Any]:
        """验证组件版本是否达到修复版本。"""
        ok = self._ver_ge(current_version, min_version)
        result = {
            "vuln_id": f"PATCH-{component}",
            "target": target,
            "component": component,
            "current_version": current_version,
            "min_version": min_version,
            "result": "fixed" if ok else "not_fixed",
            "evidence": [f"{component}: {current_version} >= {min_version} -> {ok}"],
            "regression_risk": "medium",
            "regression_note": "升级版本需回归兼容性测试。",
        }
        return result

    def verify_config(self, target: str, config_checks: Dict[str, Any],
                      expected: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """检查修复配置是否生效（通用键值比对）。"""
        expected = expected or {}
        m, t, ev = _check_items(config_checks, expected)
        ratio = m / t if t else 1.0
        res = "fixed" if ratio == 1 else ("partially_fixed" if ratio > 0 else "not_fixed")
        return {
            "target": target,
            "result": res,
            "evidence": ev,
            "matched": m,
            "total": t,
            "regression_risk": "low",
            "regression_note": "配置类变更回归风险通常较低。",
        }

    def verify_rescan(self, vuln_id: str, target: str,
                      current_signatures: Optional[List[str]] = None,
                      known_signatures: Optional[List[str]] = None) -> Dict[str, Any]:
        """模拟重新扫描：确认已知漏洞签名是否仍在响应中出现。"""
        known_signatures = known_signatures or []
        current_signatures = current_signatures or []
        still = [s for s in known_signatures if s in current_signatures]
        if not known_signatures:
            res = "unverifiable"
            note = "无已知漏洞签名，无法自动判定。"
        elif not still:
            res = "fixed"
            note = f"重扫未发现 {len(known_signatures)} 条已知签名。"
        else:
            res = "not_fixed"
            note = f"仍命中签名: {still}"
        return {
            "vuln_id": vuln_id,
            "target": target,
            "result": res,
            "evidence": [note, f"已知签名 {known_signatures}", f"当前命中 {still}"],
            "regression_risk": "low",
            "regression_note": "纯被动重扫，无回归风险。",
        }

    def verify(self, vuln_info: Dict[str, Any],
               remediation_plan: Dict[str, Any]) -> Dict[str, Any]:
        """
        综合验证一个漏洞的修复。
        vuln_info: {vuln_id, title, target, severity, vuln_type, ...}
        remediation_plan: {config_checks, component, min_version, required_headers, ...}
        """
        vtype = (vuln_info.get("vuln_type") or vuln_info.get("category") or "").lower()
        state = remediation_plan.get("current_state", {})
        verifier = self.verifiers.get(vtype)

        if verifier is None:
            # 退化到通用配置比对
            cc = remediation_plan.get("config_checks", {})
            matched = sum(1 for k, v in cc.items() if v is True or v in (
                "active", "enabled", "fixed", "yes"))
            res = "fixed" if matched == len(cc) and cc else "unverifiable"
            evidence = [f"未注册的漏洞类型 {vtype}，按配置项真值数判定"] + \
                       [f"{k}={v}" for k, v in cc.items()]
            result = {
                "vuln_id": vuln_info.get("vuln_id"),
                "title": vuln_info.get("title"),
                "target": vuln_info.get("target"),
                "severity": vuln_info.get("severity"),
                "vuln_type": vtype,
                "result": res,
                "evidence": evidence,
                "regression_risk": "medium",
                "regression_note": "缺少专用验证逻辑，建议人工复核。",
            }
        else:
            res, ev, risk, note = verifier(vuln_info, remediation_plan, state)
            result = {
                "vuln_id": vuln_info.get("vuln_id"),
                "title": vuln_info.get("title"),
                "target": vuln_info.get("target"),
                "severity": vuln_info.get("severity"),
                "vuln_type": vtype,
                "result": res,
                "evidence": ev,
                "regression_risk": risk,
                "regression_note": note,
            }
        self.results.append(result)
        return result

    def batch_verify(self, vuln_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """批量验证。每项为 {vuln_info, remediation_plan}。"""
        out = []
        for item in vuln_list:
            info = item.get("vuln_info", item)
            plan = item.get("remediation_plan", {})
            out.append(self.verify(info, plan))
        return out

    def get_verification_report(self) -> Dict[str, Any]:
        cnt: Dict[str, int] = {}
        for r in self.results:
            cnt[r["result"]] = cnt.get(r["result"], 0) + 1
        return {
            "generated_at": datetime.now().isoformat(),
            "total": len(self.results),
            "summary": cnt,
            "results": self.results,
        }


if __name__ == "__main__":
    vf = RemediationVerifier()
    fixed = vf.verify(
        {"vuln_id": "V1", "title": "SQL注入", "target": "example.com",
         "severity": "high", "vuln_type": "sql_injection"},
        {"config_checks": {"parameterized_query": True, "input_sanitized": True,
                          "waf_rule": "active"}})
    print("fixed ->", fixed["result"])
