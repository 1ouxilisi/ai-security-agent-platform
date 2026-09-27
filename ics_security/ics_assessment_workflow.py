# -*- coding: utf-8 -*-
"""
ics_assessment_workflow.py - 工控综合评估工作流（第12轮 ICS/SCADA 深化模块）。

步骤：资产发现 -> 协议分析 -> 漏洞检测 -> 基线检查 -> 异常行为检测
      -> 结果聚合 -> 风险评级 -> 报告生成。

并行执行（线程池），结果聚合（去重/合并/关联），整体风险评级与修复优先级。
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict, List, Optional

from ics_security.asset_discovery import AssetDiscovery, create_asset_discovery
from ics_security.protocol_analyzer import ProtocolAnalyzer, create_protocol_analyzer
from ics_security.vulnerability_detector import VulnerabilityDetector, create_vulnerability_detector
from ics_security.baseline_checker import BaselineChecker, create_baseline_checker
from ics_security.anomaly_detector import AnomalyDetector, create_anomaly_detector
from ics_security.threat_intel import ICSThreatIntel, create_threat_intel


SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


class ICSAssessmentWorkflow:
    """工控综合评估工作流。"""

    STEPS = ["asset_discovery", "protocol_analysis", "vulnerability_scan",
             "baseline_check", "anomaly_detection", "threat_intel_match",
             "aggregation", "risk_rating", "report"]

    def __init__(self, timeout: float = 1.0):
        self.discovery = create_asset_discovery(timeout=timeout)
        self.proto = create_protocol_analyzer()
        self.vuln = create_vulnerability_detector()
        self.baseline = create_baseline_checker()
        self.anomaly = create_anomaly_detector()
        self.intel = create_threat_intel()

    # ---------- 各步骤（均可独立调用）----------

    def step_discovery(self, targets: List[str]) -> Dict[str, Any]:
        return self.discovery.discover(targets)

    def step_protocol_analysis(self, frames: List[Dict[str, str]]) -> Dict[str, Any]:
        analysis = self.proto.analyze_batch(frames)
        report = self.proto.generate_report(analysis)
        return {"analysis": analysis, "report": report}

    def step_vuln_scan(self, assets: List[Dict[str, Any]]) -> Dict[str, Any]:
        scan = self.vuln.scan(assets)
        report = self.vuln.generate_report(scan)
        return {"scan": scan, "report": report}

    def step_baseline(self, evidence: Optional[Dict[str, bool]] = None) -> Dict[str, Any]:
        result = self.baseline.check(evidence)
        report = self.baseline.generate_report(result)
        return {"result": result, "report": report}

    def step_anomaly(self, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        payload = payload or {}
        result = self.anomaly.detect(**payload)
        report = self.anomaly.generate_report(result)
        return {"result": result, "report": report}

    def step_threat_intel(self, observables: List[Dict[str, str]]) -> Dict[str, Any]:
        match = self.intel.match(observables)
        report = self.intel.generate_report(match)
        return {"match": match, "report": report}

    # ---------- 聚合 ----------

    @staticmethod
    def aggregate(results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """去重/合并/关联各步骤结果。"""
        merged: Dict[str, Any] = {"steps_completed": []}

        disc = results.get("asset_discovery", {})
        merged["assets"] = disc.get("assets", [])
        merged["asset_count"] = disc.get("asset_count", 0)

        # 漏洞去重
        vuln_scan = results.get("vulnerability_scan", {}).get("scan", {})
        findings = vuln_scan.get("findings", [])
        seen, uniq = set(), []
        for f in findings:
            key = (f.get("asset_id"), f.get("cve"))
            if key not in seen:
                seen.add(key)
                uniq.append(f)
        merged["vuln_findings"] = uniq

        # 异常告警
        anomaly_result = results.get("anomaly_detection", {}).get("result", {})
        merged["alerts"] = anomaly_result.get("alarms", [])
        merged["correlations"] = anomaly_result.get("correlations", [])

        # 威胁命中
        intel_match = results.get("threat_intel", {}).get("match", {})
        merged["threat_hits"] = intel_match.get("hits", [])
        merged["threat_level"] = intel_match.get("threat_level", "none")

        # 基线
        baseline_result = results.get("baseline_check", {}).get("result", {})
        merged["baseline_score"] = baseline_result.get("score")
        merged["baseline_level"] = baseline_result.get("compliance_level")
        merged["baseline_gaps"] = baseline_result.get("gap_analysis", [])

        # 协议异常
        proto_anoms = results.get("protocol_analysis", {}).get("analysis", {}).get("anomalies", [])
        merged["protocol_anomalies"] = proto_anoms

        merged["steps_completed"] = [k for k, v in results.items() if v]
        return merged

    # ---------- 整体风险评级 ----------

    @staticmethod
    def overall_risk(agg: Dict[str, Any]) -> Dict[str, Any]:
        score = 0
        drivers: List[str] = []

        dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in agg.get("vuln_findings", []):
            dist[f["severity"]] = dist.get(f["severity"], 0) + 1
        score += dist["critical"] * 8 + dist["high"] * 4 + dist["medium"] * 1.5
        if dist["critical"]:
            drivers.append(f"{dist['critical']} 个 critical 漏洞")
        if dist["high"]:
            drivers.append(f"{dist['high']} 个 high 漏洞")

        # 告警
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for a in agg.get("alerts", []):
            sev[a["severity"]] = sev.get(a["severity"], 0) + 1
        score += sev["critical"] * 10 + sev["high"] * 5
        if sev["critical"]:
            drivers.append(f"{sev['critical']} 条 critical 异常告警")

        # 威胁情报
        if agg.get("threat_level") in ("critical", "high"):
            score += 15
            drivers.append(f"命中 {agg.get('threat_level')} 级威胁情报")

        # 基线扣分
        bscore = agg.get("baseline_score") or 100
        if bscore < 60:
            score += (60 - bscore) / 2
            drivers.append(f"基线合规仅 {bscore}/100")

        score = round(min(score, 100), 1)
        if score >= 60:
            level = "critical"
        elif score >= 35:
            level = "high"
        elif score >= 15:
            level = "medium"
        else:
            level = "low"
        return {"score": score, "level": level, "drivers": drivers}

    # ---------- 主入口 ----------

    def run(self,
            targets: Optional[List[str]] = None,
            protocol_frames: Optional[List[Dict[str, str]]] = None,
            baseline_evidence: Optional[Dict[str, bool]] = None,
            anomaly_payload: Optional[Dict[str, Any]] = None,
            threat_observables: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
        started = datetime.now()
        results: Dict[str, Any] = {}
        targets = targets or []

        # 1) 资产发现（先跑，后续步骤依赖其结果）
        try:
            results["asset_discovery"] = self.step_discovery(targets)
        except Exception as e:
            results["asset_discovery"] = {"error": str(e), "assets": [], "asset_count": 0}

        assets = results["asset_discovery"].get("assets", [])

        # 2) 后续步骤并行
        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = {
                "protocol_analysis": ex.submit(self.step_protocol_analysis, protocol_frames or []),
                "vulnerability_scan": ex.submit(self.step_vuln_scan, assets),
                "baseline_check": ex.submit(self.step_baseline, baseline_evidence or {}),
                "anomaly_detection": ex.submit(self.step_anomaly, anomaly_payload or {}),
                "threat_intel": ex.submit(self.step_threat_intel, threat_observables or []),
            }
            for k, fu in futs.items():
                try:
                    results[k] = fu.result()
                except Exception as e:
                    results[k] = {"error": str(e)}

        # 3) 聚合 + 评级
        agg = self.aggregate(results)
        risk = self.overall_risk(agg)

        # 4) 修复优先级
        priorities = self._fix_priority(agg, risk)

        # 5) 综合报告
        report = self._build_report(agg, risk, priorities, started)

        return {
            "status": "success",
            "risk": risk,
            "aggregate": agg,
            "fix_priority": priorities,
            "report": report,
            "steps": results,
            "duration_seconds": round((datetime.now() - started).total_seconds(), 2),
            "legal_note": "本评估全程只读/被动分析，未向任何工控设备下发控制指令。",
        }

    @staticmethod
    def _fix_priority(agg: Dict[str, Any], risk: Dict[str, Any]) -> List[Dict[str, Any]]:
        prio: List[Dict[str, Any]] = []
        crits = [f for f in agg.get("vuln_findings", []) if f["severity"] == "critical"]
        if crits:
            prio.append({"rank": 1, "window": "立即(24h)",
                         "items": [f"{f['cve']}({f['ip']})" for f in crits[:8]],
                         "action": "补丁/隔离"})
        alarms_c = [a for a in agg.get("alerts", []) if a["severity"] in ("critical", "high")]
        if alarms_c:
            prio.append({"rank": 2, "window": "短期(72h)",
                         "items": [a["type"] for a in alarms_c[:8]],
                         "action": "应急响应"})
        gaps_high = [g for g in agg.get("baseline_gaps", []) if g.get("severity_hint") == "high"]
        if gaps_high:
            prio.append({"rank": 3, "window": "中期(30d)",
                         "items": [g["rule_id"] for g in gaps_high[:8]],
                         "action": "基线加固"})
        if agg.get("threat_level") in ("critical", "high"):
            prio.append({"rank": 4, "window": "持续",
                         "items": agg.get("threat_hits", [])[:5],
                         "action": "威胁狩猎+封禁IOC"})
        if not prio:
            prio.append({"rank": 9, "window": "例行", "items": ["维持监控"], "action": "巡检"})
        return prio

    @staticmethod
    def _build_report(agg: Dict[str, Any], risk: Dict[str, Any],
                      priorities: List[Dict[str, Any]], started: datetime) -> Dict[str, Any]:
        return {
            "title": "工控系统安全综合评估报告",
            "generated_at": datetime.now().isoformat(),
            "overall_risk": risk,
            "asset_summary": {
                "total_assets": agg.get("asset_count", 0),
                "assets": [
                    {"asset_id": a.get("asset_id"), "ip": a.get("ip"),
                     "types": a.get("device_types"), "vendor": a["fingerprint"].get("vendor"),
                     "model": a["fingerprint"].get("model"),
                     "risk": a["risk"]["level"]}
                    for a in agg.get("assets", [])
                ],
            },
            "vulnerabilities": {
                "total": len(agg.get("vuln_findings", [])),
                "items": agg.get("vuln_findings", [])[:30],
            },
            "baseline": {"score": agg.get("baseline_score"),
                         "level": agg.get("baseline_level"),
                         "gaps": agg.get("baseline_gaps", [])[:20]},
            "anomalies": {"total": len(agg.get("alerts", [])),
                          "items": agg.get("alerts", [])[:20],
                          "correlations": agg.get("correlations", [])},
            "threat_intel": {"level": agg.get("threat_level"),
                             "hits": agg.get("threat_hits", [])},
            "fix_priority": priorities,
            "hardening_advice": [
                "实施 IT/OT 网络分段与工业防火墙白名单",
                "PLC 启用写保护、改默认口令、限制 102/502/44818 来源",
                "部署工业协议异常检测与关键操作告警",
                "建立固件补丁测试与变更流程",
                "工程师站 USB 管控 + 应用白名单",
                "OT 日志集中收集并接入 SIEM",
                "定期做离线备份与恢复演练",
            ],
            "conclusion": (f"整体风险等级 {risk['level']}（{risk['score']}/100）。"
                           + ("建议立即启动整改。" if risk["level"] in ("critical", "high")
                              else "维持监控并持续加固。")),
            "elapsed": round((datetime.now() - started).total_seconds(), 2),
        }


def create_assessment_workflow(timeout: float = 1.0) -> ICSAssessmentWorkflow:
    return ICSAssessmentWorkflow(timeout=timeout)
