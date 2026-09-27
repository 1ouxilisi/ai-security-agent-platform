"""
风险优先级排序算法
基于CVSS评分、可利用性、业务影响、暴露程度等多维度计算风险优先级
"""
from typing import List, Dict, Any, Optional
import time


class RiskPrioritizationEngine:
    """风险优先级排序引擎"""

    def __init__(self):
        self.prioritized_risks = []

    def prioritize_all(self, assessment_results: Dict[str, Any],
                       attack_analysis: Dict[str, Any],
                       business_context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        全面风险优先级排序
        :param assessment_results: 暴露面评估结果
        :param attack_analysis: 攻击路径分析结果
        :param business_context: 业务上下文（可选）
        :return: 优先级排序结果
        """
        self.prioritized_risks = []
        findings = assessment_results.get("findings", [])

        for finding in findings:
            priority = self._calculate_priority(finding, attack_analysis, business_context)
            self.prioritized_risks.append(priority)

        # 按优先级分数排序
        self.prioritized_risks.sort(key=lambda x: x["priority_score"], reverse=True)

        # 生成分级建议
        remediation_plan = self._generate_remediation_plan()

        # 生成风险矩阵
        risk_matrix = self._generate_risk_matrix()

        return {
            "total_risks": len(self.prioritized_risks),
            "prioritized_risks": self.prioritized_risks[:50],
            "remediation_plan": remediation_plan,
            "risk_matrix": risk_matrix,
            "summary": self._generate_summary(),
            "prioritization_time": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    def _calculate_priority(self, finding: Dict, attack_analysis: Dict,
                             business_context: Optional[Dict]) -> Dict:
        """计算单个风险的优先级"""
        # 1. CVSS基础评分（0-10）
        cvss_score = finding.get("cvss_score", 5.0)

        # 2. 可利用性评分（0-10）
        exploitability = self._calculate_exploitability(finding, attack_analysis)

        # 3. 业务影响评分（0-10）
        business_impact = self._calculate_business_impact(finding, business_context)

        # 4. 暴露程度评分（0-10）
        exposure = self._calculate_exposure(finding)

        # 5. 检测难度评分（0-10，越难检测分越高）
        detection_difficulty = self._calculate_detection_difficulty(finding)

        # 综合优先级分数（加权平均）
        # CVSS 30%, 可利用性 25%, 业务影响 25%, 暴露程度 15%, 检测难度 5%
        priority_score = (
            cvss_score * 0.30 +
            exploitability * 0.25 +
            business_impact * 0.25 +
            exposure * 0.15 +
            detection_difficulty * 0.05
        ) * 10  # 转换为0-100分

        # 优先级等级
        if priority_score >= 80:
            priority_level = "P0 - 紧急"
            sla = "24小时内修复"
        elif priority_score >= 60:
            priority_level = "P1 - 高"
            sla = "7天内修复"
        elif priority_score >= 40:
            priority_level = "P2 - 中"
            sla = "30天内修复"
        elif priority_score >= 20:
            priority_level = "P3 - 低"
            sla = "90天内修复"
        else:
            priority_level = "P4 - 信息"
            sla = "下次定期维护时处理"

        return {
            "finding": finding,
            "priority_score": round(priority_score, 1),
            "priority_level": priority_level,
            "sla": sla,
            "scores": {
                "cvss": cvss_score,
                "exploitability": exploitability,
                "business_impact": business_impact,
                "exposure": exposure,
                "detection_difficulty": detection_difficulty
            }
        }

    def _calculate_exploitability(self, finding: Dict, attack_analysis: Dict) -> float:
        """计算可利用性评分"""
        severity = finding.get("severity", "low")
        base_scores = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 1.0}
        score = base_scores.get(severity, 3.0)

        # 检查是否在攻击路径中
        entry_points = attack_analysis.get("entry_points", [])
        for ep in entry_points:
            if ep.get("asset") == finding.get("asset") and ep.get("port") == finding.get("port"):
                score = min(score + 1.5, 10)
                break

        return round(score, 1)

    def _calculate_business_impact(self, finding: Dict, business_context: Optional[Dict]) -> float:
        """计算业务影响评分"""
        severity = finding.get("severity", "low")
        base_scores = {"critical": 9.0, "high": 7.0, "medium": 4.5, "low": 2.0, "info": 1.0}
        score = base_scores.get(severity, 3.0)

        # 如果有业务上下文，根据资产重要性调整
        if business_context:
            asset = finding.get("asset", "")
            critical_assets = business_context.get("critical_assets", [])
            important_assets = business_context.get("important_assets", [])

            if asset in critical_assets:
                score = min(score + 2.0, 10)
            elif asset in important_assets:
                score = min(score + 1.0, 10)

        return round(score, 1)

    def _calculate_exposure(self, finding: Dict) -> float:
        """计算暴露程度评分"""
        ftype = finding.get("type", "")

        # 公网直接暴露的服务风险高
        if "port" in ftype:
            port = finding.get("port", 0)
            high_risk_ports = [23, 445, 6379, 27017, 3389, 9200, 11211]
            if port in high_risk_ports:
                return 9.5
            return 7.0

        # 云存储公开访问
        if "cloud" in ftype:
            return 10.0

        # 证书问题
        if "certificate" in ftype:
            return 5.0

        # 信息泄露
        if "information" in ftype or "dns" in ftype:
            return 4.0

        # 明文传输
        if "plaintext" in ftype:
            return 6.0

        return 5.0

    def _calculate_detection_difficulty(self, finding: Dict) -> float:
        """计算检测难度评分"""
        ftype = finding.get("type", "")

        # 端口暴露容易检测
        if "port" in ftype:
            return 2.0

        # 配置错误中等难度
        if "cloud" in ftype or "certificate" in ftype:
            return 4.0

        # 信息泄露需要内容分析
        if "information" in ftype or "dns" in ftype:
            return 6.0

        # 明文传输需要流量分析
        if "plaintext" in ftype:
            return 5.0

        return 5.0

    def _generate_remediation_plan(self) -> Dict:
        """生成修复计划"""
        plan = {
            "P0": [], "P1": [], "P2": [], "P3": [], "P4": []
        }

        for risk in self.prioritized_risks:
            level = risk["priority_level"].split(" - ")[0]
            if level in plan:
                plan[level].append({
                    "asset": risk["finding"].get("asset"),
                    "title": risk["finding"].get("title"),
                    "recommendation": risk["finding"].get("recommendation"),
                    "priority_score": risk["priority_score"],
                    "sla": risk["sla"]
                })

        # 统计
        stats = {level: len(items) for level, items in plan.items()}

        return {
            "summary": stats,
            "plan": plan,
            "total_effort_estimate": self._estimate_effort(stats)
        }

    def _generate_risk_matrix(self) -> Dict:
        """生成风险矩阵（可能性×影响）"""
        matrix = {
            "high_impact_high_prob": [],
            "high_impact_low_prob": [],
            "low_impact_high_prob": [],
            "low_impact_low_prob": []
        }

        for risk in self.prioritized_risks:
            impact = risk["scores"]["business_impact"]
            prob = risk["scores"]["exploitability"]

            if impact >= 6 and prob >= 6:
                matrix["high_impact_high_prob"].append(risk["finding"]["title"])
            elif impact >= 6 and prob < 6:
                matrix["high_impact_low_prob"].append(risk["finding"]["title"])
            elif impact < 6 and prob >= 6:
                matrix["low_impact_high_prob"].append(risk["finding"]["title"])
            else:
                matrix["low_impact_low_prob"].append(risk["finding"]["title"])

        return {
            "matrix": {k: len(v) for k, v in matrix.items()},
            "details": matrix
        }

    def _generate_summary(self) -> Dict:
        """生成摘要"""
        p0 = sum(1 for r in self.prioritized_risks if r["priority_level"].startswith("P0"))
        p1 = sum(1 for r in self.prioritized_risks if r["priority_level"].startswith("P1"))
        p2 = sum(1 for r in self.prioritized_risks if r["priority_level"].startswith("P2"))
        p3 = sum(1 for r in self.prioritized_risks if r["priority_level"].startswith("P3"))
        p4 = sum(1 for r in self.prioritized_risks if r["priority_level"].startswith("P4"))

        avg_score = sum(r["priority_score"] for r in self.prioritized_risks) / len(self.prioritized_risks) if self.prioritized_risks else 0

        return {
            "total_risks": len(self.prioritized_risks),
            "p0_critical": p0,
            "p1_high": p1,
            "p2_medium": p2,
            "p3_low": p3,
            "p4_info": p4,
            "average_priority_score": round(avg_score, 1),
            "top_risks": [r["finding"]["title"] for r in self.prioritized_risks[:5]]
        }

    def _estimate_effort(self, stats: Dict) -> str:
        """估算修复工作量"""
        p0_effort = stats.get("P0", 0) * 4  # 每个P0约4小时
        p1_effort = stats.get("P1", 0) * 2  # 每个P1约2小时
        p2_effort = stats.get("P2", 0) * 1  # 每个P2约1小时
        p3_effort = stats.get("P3", 0) * 0.5  # 每个P3约0.5小时

        total_hours = p0_effort + p1_effort + p2_effort + p3_effort

        if total_hours < 8:
            return f"约{total_hours:.1f}小时（1人天内）"
        elif total_hours < 40:
            return f"约{total_hours:.1f}小时（约{total_hours/8:.1f}人天）"
        else:
            return f"约{total_hours:.1f}小时（约{total_hours/40:.1f}人周）"
