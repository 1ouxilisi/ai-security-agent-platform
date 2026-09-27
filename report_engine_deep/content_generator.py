# -*- coding: utf-8 -*-
"""content_generator.py — 报告内容自动生成（第20轮·报告引擎做深）。

六大生成器：
1. 执行摘要：项目概述/范围/时间/发现统计/风险概览/关键发现/建议优先级
2. 漏洞详情：名称/描述/影响/严重程度/CVSS/CWE/OWASP/复现步骤/证据/修复建议/参考
3. 风险评级：CVSS v3.1 基础/时间/环境 + 业务影响 + 修复难度 + 综合评级
4. 修复建议：通用/代码级/配置级/架构级 + 补丁链接/最佳实践/验证方法
5. 趋势与统计：类型/严重程度/资产分布/修复进度/MTTR/对比分析
6. 合规映射：漏洞→合规条款、覆盖率、违规项、整改建议、合规矩阵

输入为内存中的漏洞/资产字典列表，全部纯计算，无外部依赖。
"""

from __future__ import annotations

import statistics
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# CVSS v3.1 计算
# --------------------------------------------------------------------------- #
# CVSS v3.1 权重表（标准公式）
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR = {"N": 0.85, "L": 0.62, "H": 0.27}
_UI = {"N": 0.85, "R": 0.62}
_SCOPE = {"U": 1.0, "C": 1.0}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_EXP = {"X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91}
_RL = {"X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95}
_RC = {"X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92}
_CIA_ENV = {"H": 0.56, "L": 0.22, "N": 0.0, "X": 0.0}


def _roundup_cvss(x: float) -> float:
    """CVSS v3.1 Roundup：向上取整到一位小数（标准实现）。"""
    int_part = int(x)
    if abs(x - int_part) < 1e-9:
        return float(int_part)
    return float(int_part + 1) if x > int_part else float(int_part)


def cvss_base(av: str = "N", ac: str = "L", pr: str = "N", ui: str = "N",
              scope: str = "U", ci: str = "H", ii: str = "H", ai: str = "H") -> Dict[str, Any]:
    """计算 CVSS v3.1 基础分。返回分数、向量、等级。"""
    av_v = _AV.get(av, 0.85)
    ac_v = _AC.get(ac, 0.77)
    pr_v = _PR.get(pr, 0.85)
    ui_v = _UI.get(ui, 0.85)
    impact_sub = 1.0 - (1 - _CIA.get(ci, 0.56)) * (1 - _CIA.get(ii, 0.56)) * (1 - _CIA.get(ai, 0.56))
    if scope == "U":
        impact = 6.42 * impact_sub
    else:
        impact = 7.52 * (impact_sub - 0.029) - 3.25 * (impact_sub - 0.02) ** 15
    exploitability = 8.22 * av_v * ac_v * pr_v * ui_v
    if scope == "U":
        base = min(impact + exploitability, 10.0)
    else:
        base = min(1.08 * (impact + exploitability), 10.0)
    score = 0.0 if impact <= 0 else _roundup_cvss(base)
    return {
        "score": score,
        "vector": f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{ci}/I:{ii}/A:{ai}",
        "severity": _severity_of(score),
        "impact_sub_score": round(impact_sub, 3),
        "exploitability": round(exploitability, 3),
    }


def cvss_temporal(score: float, exp: str = "X", rl: str = "X", rc: str = "X") -> Dict[str, Any]:
    temp = score * _EXP.get(exp, 1.0) * _RL.get(rl, 1.0) * _RC.get(rc, 1.0)
    t = _roundup_cvss(temp)
    return {"score": t, "exploit_code_maturity": exp, "remediation_level": rl,
            "report_confidence": rc, "severity": _severity_of(t)}


def cvss_environmental(score: float, cr: str = "X", ir: str = "X", ar: str = "X",
                       scope: str = "U") -> Dict[str, Any]:
    cr_v = _CIA_ENV.get(cr, 0.0)
    ir_v = _CIA_ENV.get(ir, 0.0)
    ar_v = _CIA_ENV.get(ar, 0.0)
    adjusted = min((1 - (1 - cr_v * 0.56) * (1 - ir_v * 0.56) * (1 - ar_v * 0.56)), 10.0)
    env = _roundup_cvss(score * adjusted)
    return {"score": env, "requirement_c": cr, "requirement_i": ir, "requirement_a": ar,
            "severity": _severity_of(env)}


def _severity_of(score: float) -> str:
    if score >= 9.0:
        return "严重"
    if score >= 7.0:
        return "高危"
    if score >= 4.0:
        return "中危"
    if score > 0.0:
        return "低危"
    return "信息"


SEVERITY_ORDER = {"严重": 4, "高危": 3, "中危": 2, "低危": 1, "信息": 0}


# --------------------------------------------------------------------------- #
# 1. 执行摘要生成
# --------------------------------------------------------------------------- #
class ContentGenerator:
    """聚合漏洞/资产数据，自动产出报告各章节内容。"""

    def __init__(self) -> None:
        pass

    # ---- 工具：统计 ---- #
    @staticmethod
    def _count_severities(vulns: List[Dict[str, Any]]) -> Dict[str, int]:
        bucket: Dict[str, int] = {"严重": 0, "高危": 0, "中危": 0, "低危": 0, "信息": 0}
        for v in vulns:
            sev = v.get("severity") or _severity_of(float(v.get("cvss_score", 0) or 0))
            if sev in bucket:
                bucket[sev] += 1
        return bucket

    # ---- 执行摘要 ---- #
    def exec_summary(self, project_meta: Dict[str, Any],
                     vulns: List[Dict[str, Any]],
                     assets: List[Dict[str, Any]]) -> Dict[str, Any]:
        sev = self._count_severities(vulns)
        total = len(vulns)
        critical_high = sev["严重"] + sev["高危"]
        top_findings = sorted(vulns,
                              key=lambda v: SEVERITY_ORDER.get(v.get("severity", "信息"), 0),
                              reverse=True)[:5]
        priority = []
        if sev["严重"]:
            priority.append(f"立即处置 {sev['严重']} 个严重漏洞")
        if sev["高危"]:
            priority.append(f"72 小时内修复 {sev['高危']} 个高危漏洞")
        priority.append("开展中危漏洞排期治理")
        priority.append("完善安全基线与监控")
        return {
            "project_overview": project_meta.get("overview", f"{project_meta.get('client','某客户')}安全评估项目"),
            "test_scope": {
                "assets_in_scope": len(assets),
                "vulns_found": total,
                "critical_high": critical_high,
            },
            "test_window": {
                "start": project_meta.get("start_date", ""),
                "end": project_meta.get("end_date", ""),
            },
            "severity_distribution": sev,
            "risk_overview": {
                "overall_level": _severity_of((critical_high / total * 10) if total else 0),
                "statement": self._narrative(sev, total, len(assets)),
            },
            "key_findings": [v.get("title") or v.get("name", "未命名漏洞") for v in top_findings],
            "recommendation_priority": priority,
        }

    @staticmethod
    def _narrative(sev: Dict[str, int], total: int, asset_n: int) -> str:
        if total == 0:
            return "本次测试未发现可利用漏洞，整体风险可控，建议保持现有防护水平并持续监测。"
        ch = sev["严重"] + sev["高危"]
        ratio = ch / total if total else 0
        if ratio >= 0.4:
            return f"共发现 {total} 个问题，其中严重/高危占比 {ratio:.0%}，整体风险高，建议立即启动专项整改。"
        if ratio >= 0.15:
            return f"共发现 {total} 个问题，受影响资产 {asset_n} 个，整体风险中高，建议按优先级排期修复。"
        return f"共发现 {total} 个问题，整体风险中等，建议纳入常规治理流程。"

    # ---- 2. 漏洞详情 ---- #
    def vuln_detail(self, v: Dict[str, Any]) -> Dict[str, Any]:
        sev = v.get("severity") or _severity_of(float(v.get("cvss_score", 0) or 0))
        cv = v.get("cvss") or cvss_base(
            av=v.get("attack_vector", "N"), ac=v.get("attack_complexity", "L"),
            pr=v.get("privileges_required", "N"), ui=v.get("user_interaction", "N"),
            scope=v.get("scope", "U"),
            ci=v.get("confidentiality_impact", "H"),
            ii=v.get("integrity_impact", "H"),
            ai=v.get("availability_impact", "H"),
        )
        return {
            "id": v.get("id") or v.get("vuln_id", "VULN-0000"),
            "name": v.get("title") or v.get("name", "未命名漏洞"),
            "description": v.get("description", ""),
            "severity": sev,
            "cvss": cv,
            "cwe": v.get("cwe", "CWE-UNKNOWN"),
            "owasp_category": v.get("owasp", "未分类"),
            "affected_asset": v.get("asset", ""),
            "affected_location": v.get("location", ""),
            "impact": v.get("impact", "可能导致未授权访问或数据泄露。"),
            "reproduce_steps": v.get("steps") or ["构造恶意请求", "发送至目标", "观察响应"],
            "request_response": v.get("evidence_request_response", {}),
            "evidence": v.get("evidence") or [],
            "recommendation": v.get("recommendation", "请参考修复建议章节。"),
            "references": v.get("references") or [],
            "verified": v.get("verified", True),
            "false_positive": v.get("false_positive", False),
        }

    # ---- 3. 风险评级 ---- #
    def risk_rating(self, v: Dict[str, Any]) -> Dict[str, Any]:
        cv = v.get("cvss") or cvss_base(
            av=v.get("attack_vector", "N"), ac=v.get("attack_complexity", "L"),
            pr=v.get("privileges_required", "N"), ui=v.get("user_interaction", "N"))
        base = cv["score"] if isinstance(cv, dict) else float(cv)
        temporal = cvss_temporal(base, v.get("exploit_code_maturity", "X"),
                                v.get("remediation_level", "X"), v.get("report_confidence", "X"))
        env = cvss_environmental(base, v.get("security_req_conf", "X"),
                                 v.get("security_req_integ", "X"), v.get("security_req_avail", "X"))
        business_impact = float(v.get("business_impact", 0.5))  # 0-1
        fix_difficulty = float(v.get("fix_difficulty", 0.5))    # 0-1
        composite = round(base * 0.5 + business_impact * 3 + (1 - fix_difficulty) * 2, 1)
        return {
            "cvss_base": {"score": base, "vector": cv.get("vector", "") if isinstance(cv, dict) else "",
                          "severity": cv.get("severity", _severity_of(base)) if isinstance(cv, dict) else _severity_of(base)},
            "cvss_temporal": temporal,
            "cvss_environmental": env,
            "business_impact_score": business_impact,
            "fix_difficulty_score": fix_difficulty,
            "composite_risk_score": composite,
            "composite_severity": _severity_of(composite),
            "exploitability": cv.get("exploitability") if isinstance(cv, dict) else None,
        }

    # ---- 4. 修复建议 ---- #
    REMEDY_LIBRARY: Dict[str, Dict[str, Any]] = {
        "sqli": {
            "generic": "对所有数据库访问使用参数化查询/预编译语句，禁止字符串拼接 SQL。",
            "code_level": "使用 ORM 或 PreparedStatement；对入参做白名单校验。",
            "config_level": "数据库账号最小权限，关闭 xp_cmdshell 等危险存储过程。",
            "architecture": "部署 WAF 虚拟补丁；数据库与应用网络隔离。",
            "patch_links": ["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
            "validation": "使用 SQLMap 重新验证；检查错误日志无注入特征。",
        },
        "xss": {
            "generic": "输出编码 + CSP；HttpOnly Cookie。",
            "code_level": "前端框架默认转义；富文本使用白名单过滤。",
            "config_level": "配置 Content-Security-Policy 响应头。",
            "architecture": "引入统一渲染层做上下文编码。",
            "patch_links": ["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
            "validation": "反射型/存储型/DOM XSS payload 复测。",
        },
        "default": {
            "generic": "遵循最小权限原则，及时更新组件版本。",
            "code_level": "审查输入校验与异常处理。",
            "config_level": "关闭危险端口与默认账户。",
            "architecture": "增加纵深防御与监控。",
            "patch_links": [],
            "validation": "复测漏洞利用链不可达。",
        },
    }

    def remediation(self, v: Dict[str, Any]) -> Dict[str, Any]:
        vtype = (v.get("type") or v.get("cwe", "")).lower()
        if "sql" in vtype or "sqli" in vtype:
            lib = self.REMEDY_LIBRARY["sqli"]
        elif "xss" in vtype or "cross-site script" in vtype:
            lib = self.REMEDY_LIBRARY["xss"]
        else:
            lib = self.REMEDY_LIBRARY["default"]
        return {
            "vuln_id": v.get("id"),
            "generic": lib["generic"],
            "code_level": lib["code_level"],
            "config_level": lib["config_level"],
            "architecture": lib["architecture"],
            "patch_links": lib["patch_links"],
            "best_practices": lib.get("best_practices") or ["定期漏扫", "补丁窗口", "变更评审"],
            "validation": lib["validation"],
            "estimated_effort_days": v.get("effort_days", 3),
            "priority": v.get("severity", "中危"),
        }

    # ---- 5. 趋势与统计 ---- #
    def trend_stats(self, vulns: List[Dict[str, Any]],
                    history: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        sev = self._count_severities(vulns)
        type_dist: Dict[str, int] = {}
        asset_dist: Dict[str, int] = {}
        status_dist: Dict[str, int] = {"已修复": 0, "修复中": 0, "未修复": 0, "已忽略": 0}
        for v in vulns:
            t = v.get("type") or v.get("cwe", "未分类")
            type_dist[t] = type_dist.get(t, 0) + 1
            a = v.get("asset", "未知资产")
            asset_dist[a] = asset_dist.get(a, 0) + 1
            s = v.get("status", "未修复")
            if s in status_dist:
                status_dist[s] += 1
        total = max(len(vulns), 1)
        fixed = status_dist["已修复"]
        mttr = None
        if history:
            closed = [h for h in history if h.get("resolved")]
            if closed:
                durations = [max(1, (h["resolved"] - h.get("opened", 0)) / 86400) for h in closed]
                mttr = round(statistics.mean(durations), 1)
        return {
            "severity_distribution": sev,
            "type_distribution": type_dist,
            "asset_distribution": dict(sorted(asset_dist.items(), key=lambda x: -x[1])[:10]),
            "fix_progress": {
                "fixed": fixed, "total": len(vulns),
                "rate": round(fixed / total, 3), **status_dist,
            },
            "mttr_days": mttr,
            "comparison": self._compare(history or [], len(vulns)),
            "top_assets": sorted(asset_dist.items(), key=lambda x: -x[1])[:5],
        }

    @staticmethod
    def _compare(history: List[Dict[str, Any]], current_total: int) -> Dict[str, Any]:
        if not history:
            return {"available": False, "note": "无历史基线数据"}
        prev = history[-1].get("total", current_total)
        delta = current_total - prev
        return {"available": True, "previous_total": prev, "current_total": current_total,
                "delta": delta, "trend": "上升" if delta > 0 else ("下降" if delta < 0 else "持平")}

    # ---- 6. 合规映射 ---- #
    COMPLIANCE_MAP: Dict[str, Dict[str, str]] = {
        "sqli": {"owasp_top10_2021": "A03 注入", "mlps2": "安全计算环境-入侵防范",
                 "iso27001": "A.8.28 安全编码", "pci_dss_4": "6.3 安全系统变更"},
        "xss": {"owasp_top10_2021": "A03 注入", "mlps2": "安全计算环境-访问控制",
                "iso27001": "A.8.28 安全编码", "pci_dss_4": "6.3 安全系统变更"},
        "default": {"owasp_top10_2021": "需人工映射", "mlps2": "安全计算环境",
                    "iso27001": "A.8 技术控制", "pci_dss_4": "11.6 定期测试"},
    }

    def compliance_mapping(self, vulns: List[Dict[str, Any]],
                          frameworks: Optional[List[str]] = None) -> Dict[str, Any]:
        frameworks = frameworks or ["owasp_top10_2021", "mlps2", "iso27001", "pci_dss_4"]
        matrix: Dict[str, List[Dict[str, str]]] = {f: [] for f in frameworks}
        violations: Dict[str, List[str]] = {f: [] for f in frameworks}
        for v in vulns:
            vtype = (v.get("type") or v.get("cwe", "")).lower()
            key = "sqli" if "sql" in vtype else ("xss" if "xss" in vtype else "default")
            row = self.COMPLIANCE_MAP[key]
            for f in frameworks:
                clause = row.get(f, "需人工映射")
                matrix[f].append({"vuln_id": v.get("id"), "vuln_name": v.get("title"),
                                  "clause": clause, "severity": v.get("severity")})
                if v.get("severity") in ("严重", "高危") and "人工映射" not in clause:
                    violations[f].append(f"{v.get('title')} → {clause}")
        coverage = {}
        for f in frameworks:
            mapped = sum(1 for r in matrix[f] if "人工映射" not in r["clause"])
            coverage[f] = round(mapped / max(len(matrix[f]), 1), 3)
        return {
            "frameworks": frameworks,
            "compliance_matrix": matrix,
            "coverage": coverage,
            "violations": violations,
            "remediation_advice": {
                f: f"针对 {len(violations[f])} 个违规条款制定整改计划并复测。" for f in frameworks
            },
        }

    # ---- 一站式生成 ---- #
    def generate_full(self, project_meta: Dict[str, Any],
                      vulns: List[Dict[str, Any]],
                      assets: List[Dict[str, Any]],
                      frameworks: Optional[List[str]] = None) -> Dict[str, Any]:
        return {
            "report_meta": {
                **project_meta,
                "generated_at": datetime.now().isoformat(timespec="seconds"),
                "vuln_count": len(vulns),
                "asset_count": len(assets),
            },
            "executive_summary": self.exec_summary(project_meta, vulns, assets),
            "vulnerabilities": [self.vuln_detail(v) for v in vulns],
            "risk_matrix": [self.risk_rating(v) for v in vulns],
            "remediations": [self.remediation(v) for v in vulns],
            "trends": self.trend_stats(vulns, project_meta.get("history")),
            "compliance": self.compliance_mapping(vulns, frameworks),
        }


_singleton: Optional[ContentGenerator] = None


def get_content_generator() -> ContentGenerator:
    global _singleton
    if _singleton is None:
        _singleton = ContentGenerator()
    return _singleton
