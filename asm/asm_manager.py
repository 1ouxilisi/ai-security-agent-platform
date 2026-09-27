"""
攻击面管理主管理器
整合资产发现、暴露面评估、攻击路径分析、风险优先级排序
"""
from typing import Dict, Any, Optional
import time
import json
import os

from .asset_discovery import AssetDiscoveryEngine
from .exposure_assessment import ExposureAssessmentEngine
from .attack_path_analysis import AttackPathAnalysisEngine
from .risk_prioritization import RiskPrioritizationEngine


class ASMManager:
    """攻击面管理主管理器"""

    def __init__(self, data_dir: Optional[str] = None):
        self.asset_discovery = AssetDiscoveryEngine()
        self.exposure_assessment = ExposureAssessmentEngine()
        self.attack_path_analysis = AttackPathAnalysisEngine()
        self.risk_prioritization = RiskPrioritizationEngine()

        self.data_dir = data_dir or os.path.join(os.path.dirname(__file__), "..", "data", "asm")
        os.makedirs(self.data_dir, exist_ok=True)

        self.scan_history = []
        self._load_history()

    def run_full_assessment(self, target: str, options: Optional[Dict] = None,
                             business_context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        运行完整攻击面评估
        :param target: 目标（域名/IP/IP段/URL）
        :param options: 扫描选项
        :param business_context: 业务上下文
        :return: 完整评估报告
        """
        start_time = time.time()

        # 阶段1：资产发现
        discovery_result = self.asset_discovery.discover_all(target, options)

        # 阶段2：暴露面评估
        assessment_result = self.exposure_assessment.assess_all(discovery_result["assets"])

        # 阶段3：攻击路径分析
        attack_result = self.attack_path_analysis.analyze_all(assessment_result, discovery_result["assets"])

        # 阶段4：风险优先级排序
        prioritization_result = self.risk_prioritization.prioritize_all(
            assessment_result, attack_result, business_context)

        end_time = time.time()

        # 整合结果
        full_report = {
            "report_id": f"ASM_{int(time.time())}",
            "target": target,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration_seconds": round(end_time - start_time, 2),
            "phase1_asset_discovery": discovery_result,
            "phase2_exposure_assessment": assessment_result,
            "phase3_attack_path_analysis": attack_result,
            "phase4_risk_prioritization": prioritization_result,
            "executive_summary": self._generate_executive_summary(discovery_result, assessment_result,
                                                                     attack_result, prioritization_result),
            "overall_risk_score": assessment_result["overall_risk_score"]
        }

        # 保存历史
        self._save_to_history(full_report)

        return full_report

    def quick_scan(self, target: str) -> Dict[str, Any]:
        """快速扫描（只做资产发现+端口评估）"""
        discovery_result = self.asset_discovery.discover_all(target, {"ports": "top20", "max_threads": 30})
        assessment_result = self.exposure_assessment.assess_all(discovery_result["assets"])

        return {
            "target": target,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "assets": discovery_result["summary"],
            "risk_distribution": assessment_result["risk_distribution"],
            "overall_risk": assessment_result["overall_risk_score"],
            "top_findings": assessment_result["asset_risks"][:5]
        }

    def get_history(self, limit: int = 20) -> list:
        """获取扫描历史"""
        return self.scan_history[:limit]

    def get_report(self, report_id: str) -> Optional[Dict]:
        """获取指定报告"""
        report_path = os.path.join(self.data_dir, f"{report_id}.json")
        if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return None

    def compare_reports(self, report_id1: str, report_id2: str) -> Dict:
        """对比两次扫描结果"""
        report1 = self.get_report(report_id1)
        report2 = self.get_report(report_id2)

        if not report1 or not report2:
            return {"error": "报告不存在"}

        # 对比资产变化
        assets1 = set(a["ip"] for a in report1["phase1_asset_discovery"]["assets"]["ip_addresses"])
        assets2 = set(a["ip"] for a in report2["phase1_asset_discovery"]["assets"]["ip_addresses"])

        new_assets = assets2 - assets1
        removed_assets = assets1 - assets2

        # 对比风险变化
        risk1 = report1["phase2_exposure_assessment"]["risk_distribution"]
        risk2 = report2["phase2_exposure_assessment"]["risk_distribution"]

        risk_changes = {}
        for key in ["critical", "high", "medium", "low"]:
            risk_changes[key] = risk2.get(key, 0) - risk1.get(key, 0)

        return {
            "report1": report_id1,
            "report2": report_id2,
            "asset_changes": {
                "new": list(new_assets),
                "removed": list(removed_assets),
                "unchanged": list(assets1 & assets2)
            },
            "risk_changes": risk_changes,
            "overall_score_change": (
                report2["overall_risk_score"]["score"] - report1["overall_risk_score"]["score"]
            )
        }

    def _generate_executive_summary(self, discovery, assessment, attack, prioritization) -> Dict:
        """生成执行摘要"""
        return {
            "target": discovery["target"],
            "total_assets_discovered": discovery["summary"]["total_ips"],
            "total_open_ports": discovery["summary"]["total_open_ports"],
            "total_vulnerabilities_found": assessment["total_findings"],
            "risk_distribution": assessment["risk_distribution"],
            "overall_risk_level": assessment["overall_risk_score"]["level"],
            "overall_risk_score": assessment["overall_risk_score"]["score"],
            "attack_paths_found": attack["feasibility"]["total_paths"],
            "attack_feasibility": attack["feasibility"]["level"],
            "p0_critical_risks": prioritization["summary"]["p0_critical"],
            "p1_high_risks": prioritization["summary"]["p1_high"],
            "top_5_risks": prioritization["summary"]["top_risks"],
            "remediation_effort": prioritization["remediation_plan"]["total_effort_estimate"],
            "key_recommendations": [
                "立即修复P0级严重风险",
                "关闭不必要的公网暴露端口",
                "实施网络分段，限制横向移动",
                "启用多因素认证",
                "定期进行攻击面评估"
            ]
        }

    def _save_to_history(self, report: Dict):
        """保存到历史"""
        history_entry = {
            "report_id": report["report_id"],
            "target": report["target"],
            "scan_time": report["scan_time"],
            "duration_seconds": report["duration_seconds"],
            "total_assets": report["phase1_asset_discovery"]["summary"]["total_ips"],
            "total_findings": report["phase2_exposure_assessment"]["total_findings"],
            "risk_level": report["overall_risk_score"]["level"],
            "risk_score": report["overall_risk_score"]["score"]
        }
        self.scan_history.insert(0, history_entry)
        self.scan_history = self.scan_history[:100]  # 保留最近100条

        # 保存完整报告
        report_path = os.path.join(self.data_dir, f"{report['report_id']}.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        # 保存历史索引
        history_path = os.path.join(self.data_dir, "history.json")
        with open(history_path, "w", encoding="utf-8") as f:
            json.dump(self.scan_history, f, ensure_ascii=False, indent=2)

    def _load_history(self):
        """加载历史"""
        history_path = os.path.join(self.data_dir, "history.json")
        if os.path.exists(history_path):
            try:
                with open(history_path, "r", encoding="utf-8") as f:
                    self.scan_history = json.load(f)
            except Exception:
                self.scan_history = []
