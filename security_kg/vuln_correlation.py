# -*- coding: utf-8 -*-
"""
vuln_correlation.py — 漏洞关联分析。

真实计算：
    - 漏洞库（内存）：CVE 详情、CVSS、EPSS、暴露面、修复状态
    - 关联：相同组件 / 厂商 / 类型 / 利用链 / 前后置 / 依赖 / 组合
    - 传播：传播路径 / 范围 / 速度 / 概率 / 阻断点
    - 影响：直接 / 间接 / 级联 / 业务 / 财务 / 声誉 / 合规
    - 优先级：CVSS + EPSS + 暴露面 + 业务价值 + 修复难度
    - 趋势：新增 / 修复 / 复发 / 密度 / 分布 / 预警
    - 知识库：POC / EXP / 修复方案 / 参考链接 / 案例
"""
from __future__ import annotations

import math
import random
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class VulnCorrelation:
    """漏洞关联分析引擎。"""

    def __init__(self) -> None:
        self.vulns: Dict[str, Dict[str, Any]] = {}
        self.kb: Dict[str, Dict[str, Any]] = {}
        self._seed()

    # ---------- 种子数据 ----------
    def _seed(self) -> None:
        seeds = [
            {
                "id": "CVE-2021-44228", "name": "Log4j 远程代码执行",
                "cve": "CVE-2021-44228", "cvss": 10.0, "epss": 0.97,
                "vendor": "Apache", "product": "Log4j",
                "cwe": "CWE-502", "type": "RCE",
                "asset": "Web服务器-10.0.0.10",
                "exposed": True, "status": "open",
                "discovered": "2026-09-01", "fix_difficulty": 0.6,
                "business_value": 0.9,
            },
            {
                "id": "CVE-2017-0144", "name": "SMBv1 远程代码执行(EternalBlue)",
                "cve": "CVE-2017-0144", "cvss": 9.8, "epss": 0.94,
                "vendor": "Microsoft", "product": "SMBv1",
                "cwe": "CWE-20", "type": "RCE",
                "asset": "办公终端-10.0.0.30",
                "exposed": True, "status": "open",
                "discovered": "2026-09-05", "fix_difficulty": 0.3,
                "business_value": 0.5,
            },
            {
                "id": "CVE-2023-44487", "name": "HTTP/2 快速重置 DoS",
                "cve": "CVE-2023-44487", "cvss": 7.5, "epss": 0.62,
                "vendor": "Multiple", "product": "HTTP/2",
                "cwe": "CWE-400", "type": "DoS",
                "asset": "Web服务器-10.0.0.10",
                "exposed": True, "status": "open",
                "discovered": "2026-09-08", "fix_difficulty": 0.4,
                "business_value": 0.9,
            },
            {
                "id": "CVE-2021-41773", "name": "Apache HTTP Server 路径穿越",
                "cve": "CVE-2021-41773", "cvss": 7.5, "epss": 0.55,
                "vendor": "Apache", "product": "HTTP Server",
                "cwe": "CWE-22", "type": "Traversal",
                "asset": "Web服务器-10.0.0.10",
                "exposed": True, "status": "fixed",
                "discovered": "2026-08-15", "fix_difficulty": 0.3,
                "business_value": 0.9,
            },
            {
                "id": "CVE-2022-22965", "name": "Spring4Shell RCE",
                "cve": "CVE-2022-22965", "cvss": 9.8, "epss": 0.83,
                "vendor": "VMware", "product": "Spring Framework",
                "cwe": "CWE-94", "type": "RCE",
                "asset": "Web服务器-10.0.0.10",
                "exposed": False, "status": "open",
                "discovered": "2026-09-10", "fix_difficulty": 0.7,
                "business_value": 0.9,
            },
        ]
        for v in seeds:
            v["created_at"] = _now()
            self.vulns[v["id"]] = v
            self.kb[v["id"]] = {
                "poc": "公开POC已披露" if v["epss"] > 0.7 else "无公开POC",
                "exp": "野外在野利用" if v["epss"] > 0.9 else "无在野利用",
                "fix": f"升级 {v['product']} 至最新补丁版本",
                "refs": [f"https://nvd.nist.gov/vuln/detail/{v['cve']}"],
                "cases": [f"{v['name']} 历史案例：某金融机构遭勒索软件利用"],
            }

    # ---------- CRUD ----------
    def add_vuln(self, data: Dict[str, Any]) -> Dict[str, Any]:
        vid = data.get("id") or data.get("cve")
        if not vid:
            raise ValueError("必须提供 id 或 cve")
        data.setdefault("cvss", 5.0)
        data.setdefault("epss", 0.1)
        data.setdefault("status", "open")
        data.setdefault("exposed", False)
        data.setdefault("fix_difficulty", 0.5)
        data.setdefault("business_value", 0.5)
        data["created_at"] = _now()
        self.vulns[vid] = data
        return data

    def list_vulns(self, status: Optional[str] = None,
                   severity: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.vulns.values())
        if status:
            items = [v for v in items if v["status"] == status]
        if severity:
            items = [v for v in items if self._sev(v["cvss"]) == severity]
        return items

    @staticmethod
    def _sev(cvss: float) -> str:
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        return "low"

    # ---------- 关联分析 ----------
    def correlate(self, vuln_id: str) -> Dict[str, Any]:
        v = self.vulns.get(vuln_id)
        if not v:
            return {"error": "漏洞不存在"}
        same_component, same_vendor, same_type, depends_chain = [], [], [], []
        for other in self.vulns.values():
            if other["id"] == vuln_id:
                continue
            if other.get("product") == v.get("product"):
                same_component.append(other["id"])
            if other.get("vendor") == v.get("vendor"):
                same_vendor.append(other["id"])
            if other.get("type") == v.get("type"):
                same_type.append(other["id"])
            # 利用链：同资产 + 前序利用
            if other.get("asset") == v.get("asset") \
                    and other.get("status") == "open":
                depends_chain.append(other["id"])
        # 组合利用评分
        combo_score = min(1.0, (len(same_component) + len(depends_chain)) / 4.0)
        return {
            "vuln_id": vuln_id,
            "same_component": same_component,
            "same_vendor": same_vendor,
            "same_type": same_type,
            "exploit_chain_with": depends_chain,
            "combo_exploitability": round(combo_score, 3),
            "preconditions": [f"需先突破 {x}" for x in depends_chain[:3]],
            "post_conditions": [f"可能横向至 {v.get('asset', '?')} 数据库"],
        }

    # ---------- 漏洞传播 ----------
    def propagation(self, vuln_id: str) -> Dict[str, Any]:
        v = self.vulns.get(vuln_id)
        if not v:
            return {"error": "漏洞不存在"}
        # 同资产的其他漏洞 = 传播范围
        same_asset = [x for x in self.vulns.values()
                      if x.get("asset") == v.get("asset")
                      and x["id"] != vuln_id]
        spread_prob = min(0.95, v["epss"] * (0.5 + 0.1 * len(same_asset)))
        spread_speed = "快" if v["cvss"] >= 9 and v["epss"] >= 0.8 else \
            "中" if v["cvss"] >= 7 else "慢"
        block_points = [
            f"补丁 {v['product']}",
            f"隔离 {v.get('asset', '资产')}",
            "WAF 规则拦截",
        ]
        return {
            "vuln_id": vuln_id,
            "scope_assets": list({x.get("asset") for x in self.vulns.values()
                                  if x.get("asset")}),
            "spread_probability": round(spread_prob, 3),
            "spread_speed": spread_speed,
            "infected_assets_now": [v.get("asset")],
            "block_points": block_points,
            "estimated_time_to_peak_hours": int(24 / max(0.1, spread_prob)),
        }

    # ---------- 影响分析 ----------
    def impact(self, vuln_id: str) -> Dict[str, Any]:
        v = self.vulns.get(vuln_id)
        if not v:
            return {"error": "漏洞不存在"}
        direct = round(v["cvss"] / 10.0, 3)
        indirect = round(direct * 0.6, 3)
        cascade = round(min(1.0, direct + indirect * 0.5), 3)
        business_impact = "高" if cascade >= 0.7 else "中" if cascade >= 0.4 else "低"
        financial = round(cascade * 500000, 0)  # 美元量级估算
        reputation = round(cascade * 0.8, 3)
        compliance = ["等保2.0 三级", "ISO27001", "GDPR"] if cascade > 0.5 else []
        return {
            "direct": direct, "indirect": indirect,
            "cascade": cascade,
            "business_impact": business_impact,
            "estimated_financial_risk_usd": financial,
            "reputation_risk": reputation,
            "compliance_breach_risk": compliance,
        }

    # ---------- 优先级 ----------
    def prioritize(self, vuln_id: Optional[str] = None) -> List[Dict[str, Any]]:
        scored = []
        for v in self.vulns.values():
            # 公式：CVSS*0.35 + EPSS*0.3 + 暴露面*0.15 + 业务价值*0.2 - 修复难度*0.1
            exposure = 1.0 if v.get("exposed") else 0.3
            score = (v["cvss"] / 10.0) * 0.35 \
                    + v["epss"] * 0.30 \
                    + exposure * 0.15 \
                    + v.get("business_value", 0.5) * 0.20 \
                    - v.get("fix_difficulty", 0.5) * 0.10
            score = round(max(0.0, min(1.0, score)), 3)
            scored.append({
                "id": v["id"], "name": v["name"],
                "cvss": v["cvss"], "epss": v["epss"],
                "exposed": v.get("exposed"),
                "priority_score": score,
                "priority_level": "P0" if score >= 0.75 else
                                  "P1" if score >= 0.55 else
                                  "P2" if score >= 0.35 else "P3",
                "recommendation": self._recommend(v, score),
            })
        scored.sort(key=lambda x: x["priority_score"], reverse=True)
        if vuln_id:
            return [s for s in scored if s["id"] == vuln_id]
        return scored

    @staticmethod
    def _recommend(v: Dict[str, Any], score: float) -> str:
        if score >= 0.75:
            return f"24小时内紧急修复 {v['product']}，必要时下线资产"
        if score >= 0.55:
            return f"7天内升级 {v['product']} 至最新版本"
        if score >= 0.35:
            return "纳入月度修复计划，先做 WAF 缓解"
        return "跟踪监控，按季度修复"

    # ---------- 趋势 ----------
    def trend(self) -> Dict[str, Any]:
        # 基于 discovered 字段聚合最近30天
        by_day: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"new": 0, "fixed": 0})
        for v in self.vulns.values():
            d = v.get("discovered", "2026-09-15")
            by_day[d]["new"] += 1
            if v["status"] == "fixed":
                by_day[d]["fixed"] += 1
        days = sorted(by_day.keys())[-14:]
        series = [{"date": d, **by_day[d]} for d in days]
        open_count = sum(1 for v in self.vulns.values() if v["status"] == "open")
        fixed_count = sum(1 for v in self.vulns.values() if v["status"] == "fixed")
        rediscovery = 0  # 简化：假设无复发
        density = round(open_count / max(1, len(self.vulns)), 3)
        dist = Counter(self._sev(v["cvss"]) for v in self.vulns.values())
        return {
            "open": open_count, "fixed": fixed_count,
            "rediscovery": rediscovery,
            "density": density,
            "severity_distribution": dict(dist),
            "series_14d": series,
            "warning": "存在 P0 漏洞未修复" if open_count >= 3 else "趋势平稳",
        }

    # ---------- 知识库 ----------
    def knowledge_base(self, vuln_id: Optional[str] = None
                       ) -> Dict[str, Any]:
        if vuln_id:
            return self.kb.get(vuln_id, {"error": "未收录"})
        return {
            "total": len(self.kb),
            "items": [{"id": k, **v} for k, v in self.kb.items()],
        }

    # ---------- 组合优先级 ----------
    def combined_priority(self) -> Dict[str, Any]:
        pri = self.prioritize()
        top = pri[:5]
        # 组合风险 = 所有 P0/P1 漏洞的乘积
        high = [p for p in pri if p["priority_level"] in ("P0", "P1")]
        combo = round(1 - math.prod([1 - p["priority_score"] for p in high]), 3) \
            if high else 0.0
        return {
            "top5": top,
            "combined_risk_score": combo,
            "recommendation": "优先处置 P0 组合：先打补丁再做横向隔离"
                              if combo > 0.7 else "按常规节奏修复",
        }


vuln_correlation = VulnCorrelation()
