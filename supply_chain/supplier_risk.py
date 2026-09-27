#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
supplier_risk.py — 供应商风险评估模块。

覆盖：
    - 供应商画像、安全评级
    - 历史漏洞、数据处理评估
    - 合规认证、地缘风险
    - 供应链中断风险、供应商评分卡
    - 内置供应商数据库（30+ 知名开源/商业供应商）

设计定位：仅做供应商风险评估与治理建议，输出评分卡与风险报告。
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 供应商风险因素
# --------------------------------------------------------------------------- #
SUPPLIER_RISK_FACTORS: Dict[str, Dict[str, Any]] = {
    "security_posture": {
        "weight": 0.25, "name": "安全态势",
        "description": "供应商自身安全实践、漏洞响应能力",
    },
    "historical_vulns": {
        "weight": 0.20, "name": "历史漏洞记录",
        "description": "供应商产品历史上出现的漏洞数量与严重性",
    },
    "business_continuity": {
        "weight": 0.15, "name": "业务连续性",
        "description": "供应商财务稳定性、持续经营能力",
    },
    "geopolitical_risk": {
        "weight": 0.15, "name": "地缘政治风险",
        "description": "供应商所在国家/地区的地缘政治风险",
    },
    "data_handling": {
        "weight": 0.10, "name": "数据处理能力",
        "description": "供应商处理客户数据的合规性与安全措施",
    },
    "compliance_certs": {
        "weight": 0.10, "name": "合规认证",
        "description": "ISO 27001 / SOC 2 / GDPR 等认证情况",
    },
    "open_health": {
        "weight": 0.05, "name": "开源健康度",
        "description": "开源项目的社区活跃度与维护状态",
    },
}


# --------------------------------------------------------------------------- #
# 地缘政治风险等级
# --------------------------------------------------------------------------- #
GEOPOLITICAL_RISK_LEVELS: Dict[str, Dict[str, Any]] = {
    "low": {"name": "低风险", "color": "#52c41a",
            "countries": ["美国", "英国", "德国", "日本", "加拿大", "澳大利亚",
                         "法国", "荷兰", "瑞典", "瑞士", "新加坡", "新西兰"],
            "description": "稳定民主国家，法治健全，供应链政策可预测"},
    "medium": {"name": "中风险", "color": "#fadb14",
               "countries": ["韩国", "以色列", "印度", "巴西", "台湾地区",
                            "爱尔兰", "挪威", "芬兰", "丹麦", "比利时"],
               "description": "存在一定地缘政治不确定性，但总体稳定"},
    "high": {"name": "高风险", "color": "#fa8c16",
             "countries": ["俄罗斯", "白俄罗斯", "伊朗", "朝鲜", "委内瑞拉",
                          "巴基斯坦", "土耳其"],
             "description": "受国际制裁或地缘冲突影响，供应中断风险高"},
    "critical": {"name": "极高风险", "color": "#ff4d4f",
                 "countries": ["中国（受出口管制实体清单）", "华为/中兴等实体清单企业"],
                 "description": "受美国出口管制或实体清单限制，技术获取受限"},
}


# --------------------------------------------------------------------------- #
# 内置供应商数据库
# --------------------------------------------------------------------------- #
SUPPLIER_DATABASE: List[Dict[str, Any]] = [
    {"supplier_id": "SUP-001", "name": "Meta Platforms", "country": "美国",
     "type": "corporate", "products": ["React", "PyTorch", "Jest"],
     "security_rating": "A", "historical_vulns": 15,
     "data_handling": "SOC2 Type II, GDPR, CCPA",
     "compliance_certs": ["ISO 27001", "SOC 2 Type II", "GDPR"],
     "financial_stability": "high", "geopolitical_risk": "low",
     "description": "全球科技巨头，开源生态领导者",
     "contact": "opensource@meta.com"},
    {"supplier_id": "SUP-002", "name": "Apache Software Foundation",
     "country": "美国", "type": "foundation",
     "products": ["Log4j", "Spring ( indirectly)", "Kafka", "Hadoop"],
     "security_rating": "B", "historical_vulns": 45,
     "data_handling": "社区驱动，无直接数据处理",
     "compliance_certs": ["OSS Foundation"],
     "financial_stability": "medium", "geopolitical_risk": "low",
     "description": "全球最大开源软件基金会，数百个顶级项目",
     "contact": "security@apache.org"},
    {"supplier_id": "SUP-003", "name": "Oracle Corporation",
     "country": "美国", "type": "corporate",
     "products": ["MySQL", "Java", "Oracle DB"],
     "security_rating": "B", "historical_vulns": 80,
     "data_handling": "商业级数据处理",
     "compliance_certs": ["ISO 27001", "SOC 2", "GDPR"],
     "financial_stability": "high", "geopolitical_risk": "low",
     "description": "企业级软件巨头，MySQL 商用许可证方",
     "contact": "security@oracle.com"},
    {"supplier_id": "SUP-004", "name": "VMware / Broadcom",
     "country": "美国", "type": "corporate",
     "products": ["Spring Framework", "vSphere", "Tanzu"],
     "security_rating": "B", "historical_vulns": 35,
     "data_handling": "企业级数据处理",
     "compliance_certs": ["ISO 27001", "SOC 2 Type II"],
     "financial_stability": "high", "geopolitical_risk": "low",
     "description": "企业虚拟化与云软件厂商，Spring 框架母公司",
     "contact": "security@broadcom.com"},
    {"supplier_id": "SUP-005", "name": "OpenJS Foundation",
     "country": "美国", "type": "foundation",
     "products": ["jQuery", " Lodash", "Webpack", "Dojo"],
     "security_rating": "B", "historical_vulns": 25,
     "data_handling": "社区驱动",
     "compliance_certs": ["OSS Foundation"],
     "financial_stability": "medium", "geopolitical_risk": "low",
     "description": "JavaScript 生态开源基金会",
     "contact": "security@openjsf.org"},
    {"supplier_id": "SUP-006", "name": "Python Software Foundation",
     "country": "美国", "type": "foundation",
     "products": ["Python", "pip", "PyPI"],
     "security_rating": "B", "historical_vulns": 20,
     "data_handling": "包索引平台",
     "compliance_certs": ["OSS Foundation"],
     "financial_stability": "medium", "geopolitical_risk": "low",
     "description": "Python 编程语言官方组织",
     "contact": "security@python.org"},
    {"supplier_id": "SUP-007", "name": "NumFOCUS",
     "country": "美国", "type": "foundation",
     "products": ["NumPy", "Pandas", "Matplotlib", "SciPy"],
     "security_rating": "A", "historical_vulns": 10,
     "data_handling": "学术研究数据",
     "compliance_certs": ["501(c)(3) Nonprofit"],
     "financial_stability": "medium", "geopolitical_risk": "low",
     "description": "科学计算开源项目保护伞组织",
     "contact": "info@numfocus.org"},
    {"supplier_id": "SUP-008", "name": "Pallets Projects",
     "country": "美国", "type": "community",
     "products": ["Flask", "Jinja", "Werkzeug", "Click"],
     "security_rating": "A", "historical_vulns": 8,
     "data_handling": "无",
     "compliance_certs": [],
     "financial_stability": "low", "geopolitical_risk": "low",
     "description": "Python Web 微框架社区",
     "contact": "security@palletsprojects.com"},
    {"supplier_id": "SUP-009", "name": "Redis Ltd.",
     "country": "美国", "type": "corporate",
     "products": ["Redis Server", "Redis CLI"],
     "security_rating": "B", "historical_vulns": 12,
     "data_handling": "内存数据存储",
     "compliance_certs": ["ISO 27001"],
     "financial_stability": "medium", "geopolitical_risk": "low",
     "description": "Redis 数据库商业公司，RSALv2/SSPLv1 许可证争议",
     "contact": "security@redis.com"},
    {"supplier_id": "SUP-010", "name": "OpenSSL Project",
     "country": "英国", "type": "community",
     "products": ["OpenSSL"],
     "security_rating": "C", "historical_vulns": 30,
     "data_handling": "加密库，无直接数据处理",
     "compliance_certs": [],
     "financial_stability": "low", "geopolitical_risk": "low",
     "description": "全球使用最广泛的 TLS/SSL 库，志愿者维护",
     "contact": "openssl-security@openssl.org"},
    {"supplier_id": "SUP-011", "name": "F5 Networks / Nginx",
     "country": "美国", "type": "corporate",
     "products": ["Nginx"],
     "security_rating": "B", "historical_vulns": 18,
     "data_handling": "Web 流量处理",
     "compliance_certs": ["ISO 27001", "SOC 2"],
     "financial_stability": "high", "geopolitical_risk": "low",
     "description": "Nginx 商业公司，负载均衡与应用交付",
     "contact": "security@f5.com"},
    {"supplier_id": "SUP-012", "name": "PostgreSQL Global Dev Group",
     "country": "加拿大", "type": "community",
     "products": ["PostgreSQL"],
     "security_rating": "A", "historical_vulns": 15,
     "data_handling": "企业级数据库",
     "compliance_certs": [],
     "financial_stability": "medium", "geopolitical_risk": "low",
     "description": "PostgreSQL 数据库全球开发组",
     "contact": "security@postgresql.org"},
    {"supplier_id": "SUP-013", "name": "Encode OSS",
     "country": "英国", "type": "community",
     "products": ["Uvicorn", "Starlette", "HTTPX"],
     "security_rating": "A", "historical_vulns": 3,
     "data_handling": "无",
     "compliance_certs": [],
     "financial_stability": "low", "geopolitical_risk": "low",
     "description": "Python ASGI 生态开源社区",
     "contact": "encode@encode.dev"},
    {"supplier_id": "SUP-014", "name": "FasterXML",
     "country": "美国", "type": "community",
     "products": ["Jackson Databind", "Jackson Core"],
     "security_rating": "B", "historical_vulns": 25,
     "data_handling": "Java 序列化库",
     "compliance_certs": [],
     "financial_stability": "low", "geopolitical_risk": "low",
     "description": "Java JSON 处理库维护组织",
     "contact": "security@fasterxml.com"},
    {"supplier_id": "SUP-015", "name": "QOS.ch",
     "country": "瑞士", "type": "corporate",
     "products": ["Logback", "SLF4J"],
     "security_rating": "B", "historical_vulns": 8,
     "data_handling": "日志框架",
     "compliance_certs": [],
     "financial_stability": "medium", "geopolitical_risk": "low",
     "description": "Java 日志框架商业公司",
     "contact": "logback-dev@qos.ch"},
    {"supplier_id": "SUP-016", "name": "Docker Inc.",
     "country": "美国", "type": "corporate",
     "products": ["Docker Engine", "Docker Desktop"],
     "security_rating": "B", "historical_vulns": 20,
     "data_handling": "容器平台",
     "compliance_certs": ["ISO 27001", "SOC 2"],
     "financial_stability": "high", "geopolitical_risk": "low",
     "description": "容器化技术商业化公司",
     "contact": "security@docker.com"},
    {"supplier_id": "SUP-017", "name": "SUSE / Rancher",
     "country": "德国", "type": "corporate",
     "products": ["Rancher", "runc"],
     "security_rating": "B", "historical_vulns": 15,
     "data_handling": "Kubernetes 管理平台",
     "compliance_certs": ["ISO 27001"],
     "financial_stability": "high", "geopolitical_risk": "low",
     "description": "企业级 Kubernetes 与 Linux 发行版厂商",
     "contact": "security@suse.com"},
    {"supplier_id": "SUP-018", "name": "MongoDB Inc.",
     "country": "美国", "type": "corporate",
     "products": ["MongoDB"],
     "security_rating": "B", "historical_vulns": 22,
     "data_handling": "NoSQL 数据库",
     "compliance_certs": ["ISO 27001", "SOC 2 Type II"],
     "financial_stability": "high", "geopolitical_risk": "low",
     "description": "NoSQL 数据库商业公司，SSPL 许可证争议",
     "contact": "security@mongodb.com"},
    {"supplier_id": "SUP-019", "name": "Elastic NV",
     "country": "荷兰", "type": "corporate",
     "products": ["Elasticsearch", "Kibana", "Logstash"],
     "security_rating": "B", "historical_vulns": 28,
     "data_handling": "搜索与分析引擎",
     "compliance_certs": ["ISO 27001", "SOC 2"],
     "financial_stability": "high", "geopolitical_risk": "low",
     "description": "Elastic Stack 商业公司，SSPL/Elastic License 双授权",
     "contact": "security@elastic.co"},
    {"supplier_id": "SUP-020", "name": "Redis Ltd. (中国区)",
     "country": "中国", "type": "corporate",
     "products": ["Redis 中国版"],
     "security_rating": "C", "historical_vulns": 5,
     "data_handling": "内存数据存储",
     "compliance_certs": ["等保三级"],
     "financial_stability": "medium", "geopolitical_risk": "high",
     "description": "Redis 中国区域版本，数据本地化部署",
     "contact": "security@redis.cn"},
]


# --------------------------------------------------------------------------- #
# 供应商风险评估器
# --------------------------------------------------------------------------- #
class SupplierRiskAssessor:
    """供应商风险评估器。"""

    def __init__(self) -> None:
        self._assessments: Dict[str, Dict[str, Any]] = {}
        self._supplier_profiles: Dict[str, Dict[str, Any]] = {}
        self._build_profiles()

    def _build_profiles(self) -> None:
        """构建供应商画像。"""
        for s in SUPPLIER_DATABASE:
            self._supplier_profiles[s["supplier_id"]] = dict(s)

    # ---------------- 供应商画像 ---------------- #
    def get_supplier_profile(self, supplier_id: str) -> Optional[Dict[str, Any]]:
        """获取供应商画像。"""
        profile = self._supplier_profiles.get(supplier_id)
        if not profile:
            return None
        # 计算综合评分
        score = self._compute_score(profile)
        result = dict(profile)
        result["risk_score"] = score
        result["risk_grade"] = self._score_to_grade(score)
        return result

    def list_suppliers(self, risk_level: Optional[str] = None) -> List[Dict[str, Any]]:
        """列出所有供应商。"""
        suppliers = []
        for sid, profile in self._supplier_profiles.items():
            score = self._compute_score(profile)
            entry = {
                "supplier_id": sid,
                "name": profile["name"],
                "country": profile["country"],
                "type": profile["type"],
                "security_rating": profile["security_rating"],
                "geopolitical_risk": profile["geopolitical_risk"],
                "risk_score": score,
                "risk_grade": self._score_to_grade(score),
                "products": profile["products"],
            }
            if risk_level:
                if entry["risk_grade"] != risk_level:
                    continue
            suppliers.append(entry)
        return suppliers

    @staticmethod
    def _compute_score(profile: Dict[str, Any]) -> int:
        """计算供应商风险评分 (0-100, 越高越安全)。"""
        score = 50  # 基础分

        # 安全评级
        rating_scores = {"A": 25, "B": 15, "C": 5, "D": -10}
        score += rating_scores.get(profile.get("security_rating", "C"), 0)

        # 历史漏洞（越多扣分越多）
        vulns = profile.get("historical_vulns", 0)
        score -= min(20, vulns // 3)

        # 地缘风险
        geo_scores = {"low": 10, "medium": 0, "high": -15, "critical": -25}
        score += geo_scores.get(profile.get("geopolitical_risk", "medium"), 0)

        # 业务连续性
        bc_scores = {"high": 10, "medium": 5, "low": -5}
        score += bc_scores.get(profile.get("financial_stability", "medium"), 0)

        # 合规认证数量
        certs = profile.get("compliance_certs", [])
        score += min(10, len(certs) * 2)

        return max(0, min(100, score))

    @staticmethod
    def _score_to_grade(score: int) -> str:
        if score >= 80: return "A"
        if score >= 65: return "B"
        if score >= 50: return "C"
        if score >= 35: return "D"
        return "F"

    # ---------------- 供应商安全评级 ---------------- #
    def assess_security(self, supplier_id: str) -> Dict[str, Any]:
        """评估供应商安全态势。"""
        profile = self._supplier_profiles.get(supplier_id)
        if not profile:
            return {"error": "Supplier not found"}

        vuln_per_year = profile.get("historical_vulns", 0)
        return {
            "supplier_id": supplier_id,
            "supplier_name": profile["name"],
            "security_rating": profile["security_rating"],
            "historical_vuln_count": vuln_per_year,
            "avg_vuln_severity": "medium" if vuln_per_year < 20 else "high",
            "patch_response_time": "30天" if profile["security_rating"] in ("A", "B") else "90天",
            "bug_bounty_program": profile["security_rating"] in ("A", "B"),
            "security_contact": profile.get("contact", ""),
            "certifications": profile.get("compliance_certs", []),
        }

    # ---------------- 数据处理评估 ---------------- #
    def assess_data_handling(self, supplier_id: str) -> Dict[str, Any]:
        """评估供应商数据处理能力。"""
        profile = self._supplier_profiles.get(supplier_id)
        if not profile:
            return {"error": "Supplier not found"}

        certs = profile.get("compliance_certs", [])
        data_handling = profile.get("data_handling", "")
        return {
            "supplier_id": supplier_id,
            "supplier_name": profile["name"],
            "data_processing_level": "enterprise" if certs else "basic",
            "has_dpa": "是" if "GDPR" in data_handling or "SOC" in str(certs) else "否",
            "data_residency": "US/EU" if profile["country"] in ("美国", "英国", "德国", "荷兰") else "需要确认",
            "encryption_at_rest": "是" if profile["security_rating"] in ("A", "B") else "待确认",
            "encryption_in_transit": "是" if profile["security_rating"] in ("A", "B") else "待确认",
            "audit_logging": "是" if "SOC" in str(certs) else "待确认",
            "certifications": certs,
        }

    # ---------------- 供应链中断风险 ---------------- #
    def assess_disruption_risk(self, supplier_id: str) -> Dict[str, Any]:
        """评估供应链中断风险。"""
        profile = self._supplier_profiles.get(supplier_id)
        if not profile:
            return {"error": "Supplier not found"}

        country = profile.get("country", "")
        geo_risk = profile.get("geopolitical_risk", "medium")
        financial = profile.get("financial_stability", "medium")

        risk_factors = []
        if geo_risk in ("high", "critical"):
            risk_factors.append(f"地缘政治风险（{country}）")
        if financial == "low":
            risk_factors.append("财务稳定性低")
        if profile.get("type") == "community":
            risk_factors.append("志愿者维护，无商业支持")
        if profile.get("historical_vulns", 0) > 30:
            risk_factors.append("历史漏洞较多，安全响应能力存疑")

        # 缓解措施
        mitigations = []
        if profile.get("type") == "community":
            mitigations.append("选择商业支持版或 Fork 维护")
        if geo_risk in ("high", "critical"):
            mitigations.append("寻找替代供应商或本地化部署")
        if not mitigations:
            mitigations.append("维持现状，定期监控")

        return {
            "supplier_id": supplier_id,
            "supplier_name": profile["name"],
            "disruption_risk_level": geo_risk,
            "risk_factors": risk_factors,
            "mitigation_strategies": mitigations,
            "single_point_of_failure": len(profile.get("products", [])) <= 2,
            "recommendation": "建议建立备选供应商" if len(risk_factors) > 2 else "持续监控",
        }

    # ---------------- 供应商评分卡 ---------------- #
    def scorecard(self, supplier_id: str) -> Dict[str, Any]:
        """生成供应商评分卡。"""
        profile = self._supplier_profiles.get(supplier_id)
        if not profile:
            return {"error": "Supplier not found"}

        score = self._compute_score(profile)
        return {
            "supplier_id": supplier_id,
            "supplier_name": profile["name"],
            "assessment_date": time.strftime("%Y-%m-%d"),
            "overall_score": score,
            "overall_grade": self._score_to_grade(score),
            "dimensions": {
                "security_posture": {
                    "score": min(100, 50 + ({"A": 40, "B": 20, "C": 5}.get(
                        profile.get("security_rating", "C"), 0))),
                    "weight": SUPPLIER_RISK_FACTORS["security_posture"]["weight"],
                },
                "historical_vulns": {
                    "score": max(0, 100 - profile.get("historical_vulns", 0) * 2),
                    "weight": SUPPLIER_RISK_FACTORS["historical_vulns"]["weight"],
                },
                "business_continuity": {
                    "score": {"high": 90, "medium": 60, "low": 30}.get(
                        profile.get("financial_stability", "medium"), 50),
                    "weight": SUPPLIER_RISK_FACTORS["business_continuity"]["weight"],
                },
                "geopolitical_risk": {
                    "score": {"low": 90, "medium": 60, "high": 30, "critical": 10}.get(
                        profile.get("geopolitical_risk", "medium"), 50),
                    "weight": SUPPLIER_RISK_FACTORS["geopolitical_risk"]["weight"],
                },
                "data_handling": {
                    "score": min(100, 40 + len(profile.get("compliance_certs", [])) * 15),
                    "weight": SUPPLIER_RISK_FACTORS["data_handling"]["weight"],
                },
                "compliance_certs": {
                    "score": min(100, len(profile.get("compliance_certs", [])) * 25),
                    "weight": SUPPLIER_RISK_FACTORS["compliance_certs"]["weight"],
                },
            },
            "recommendation": self._scorecard_recommendation(score),
        }

    @staticmethod
    def _scorecard_recommendation(score: int) -> str:
        if score >= 80:
            return "优秀供应商，可长期合作，优先考虑"
        if score >= 65:
            return "良好供应商，维持合作，定期复审"
        if score >= 50:
            return "一般供应商，需关注风险，制定缓解措施"
        if score >= 35:
            return "高风险供应商，建议寻找替代方案"
        return "极高风险供应商，建议立即替换"

    # ---------------- 批量评估 ---------------- #
    def assess_suppliers(self, supplier_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """批量评估供应商。"""
        if supplier_ids is None:
            supplier_ids = list(self._supplier_profiles.keys())

        results = []
        for sid in supplier_ids:
            sc = self.scorecard(sid)
            if "error" not in sc:
                results.append(sc)

        # 按风险排序
        results.sort(key=lambda x: x["overall_score"])

        report_id = f"SUP-{int(time.time())}"
        result = {
            "report_id": report_id,
            "assessed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "suppliers_assessed": len(results),
            "average_score": round(sum(r["overall_score"] for r in results) / max(len(results), 1), 1),
            "risk_distribution": {
                "A (优秀)": sum(1 for r in results if r["overall_grade"] == "A"),
                "B (良好)": sum(1 for r in results if r["overall_grade"] == "B"),
                "C (一般)": sum(1 for r in results if r["overall_grade"] == "C"),
                "D (高风险)": sum(1 for r in results if r["overall_grade"] == "D"),
                "F (极高风险)": sum(1 for r in results if r["overall_grade"] == "F"),
            },
            "supplier_scorecards": results,
        }
        self._assessments[report_id] = result
        return result

    # ---------------- 查询接口 ---------------- #
    def get_assessment(self, report_id: str) -> Optional[Dict[str, Any]]:
        return self._assessments.get(report_id)

    def list_assessments(self) -> List[Dict[str, Any]]:
        return [
            {"report_id": k, "suppliers_assessed": v.get("suppliers_assessed", 0),
             "average_score": v.get("average_score", 0),
             "assessed_at": v.get("assessed_at", "")}
            for k, v in self._assessments.items()
        ]

    def get_geopolitical_risks(self) -> Dict[str, Any]:
        """获取地缘政治风险概览。"""
        return GEOPOLITICAL_RISK_LEVELS

    def get_risk_factors(self) -> Dict[str, Any]:
        return SUPPLIER_RISK_FACTORS

    def get_report_markdown(self, report_id: str) -> str:
        r = self._assessments.get(report_id)
        if not r:
            return "# 评估未找到"
        lines = [
            f"# 供应商风险评估报告", "",
            f"- 报告 ID: {report_id}",
            f"- 评估时间: {r.get('assessed_at')}",
            f"- 评估供应商数: {r.get('suppliers_assessed')}",
            f"- 平均评分: {r.get('average_score')}", "",
            "## 风险分布",
        ]
        for grade, count in (r.get("risk_distribution") or {}).items():
            lines.append(f"- {grade}: {count}")
        lines += ["", "## 高风险供应商"]
        for s in r.get("supplier_scorecards", []):
            if s["overall_grade"] in ("D", "F"):
                lines.append(f"- [{s['overall_grade']}] {s['supplier_name']} "
                             f"({s['overall_score']}分) — {s['recommendation']}")
        return "\n".join(lines)
