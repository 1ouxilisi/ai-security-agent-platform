# -*- coding: utf-8 -*-
"""
devsecops_workflow.py — DevSecOps 全链路综合评估工作流。

串联：代码 → 构建 → 部署 → 运行时，聚合结果，风险评级，修复优先级。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from devsecops.pipeline_security import get_pipeline_auditor
from devsecops.repo_security import get_repo_assessor
from devsecops.build_artifact_security import get_build_artifact_security
from devsecops.deployment_runtime_security import get_deployment_runtime_security
from devsecops.security_gate import get_security_gate
from devsecops.devsecops_maturity import get_devsecops_maturity


WORKFLOW_STEPS = [
    {"id": "repo", "name": "代码仓库安全", "stage": "code"},
    {"id": "pipeline", "name": "流水线安全", "stage": "code"},
    {"id": "build", "name": "构建与制品安全", "stage": "build"},
    {"id": "deploy", "name": "部署与运行时安全", "stage": "deploy"},
    {"id": "gate", "name": "安全门禁", "stage": "quality"},
    {"id": "maturity", "name": "成熟度评估", "stage": "governance"},
]


class DevSecOpsWorkflow:
    """全链路评估工作流。"""

    def __init__(self) -> None:
        self.history: List[Dict[str, Any]] = []

    def run(self, signals: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        s = signals or {}
        started = time.strftime("%Y-%m-%d %H:%M:%S")

        pipeline = get_pipeline_auditor()
        repo = get_repo_assessor()
        build = get_build_artifact_security()
        runtime = get_deployment_runtime_security()
        gate = get_security_gate()
        maturity = get_devsecops_maturity()

        repo_result = repo.full_assess(s.get("repo"))
        pipeline_result = pipeline.audit_pipeline_config(
            s.get("platform", "github_actions"),
            s.get("pipeline_config", ""), s.get("pipeline_signals"))
        build_result = build.scan_dockerfile(s.get("dockerfile", ""))
        image_result = build.scan_image_vulns(
            s.get("image", "app:latest"), s.get("vulns"))
        deploy_result = runtime.audit_workload(
            s.get("kind", "Deployment"), s.get("manifest"))
        runtime_result = runtime.assess_runtime_detection(s.get("runtime_alerts"))
        gate_result = gate.evaluate(s.get("gate_signals"))
        maturity_result = maturity.assess(s.get("maturity_signals"))

        scores = {
            "repo": repo_result["overall_score"],
            "pipeline": pipeline_result["security_score"],
            "build": build_result["score"],
            "image": image_result["score"],
            "deploy": deploy_result["score"],
            "gate": gate_result["security_score"],
            "maturity": maturity_result["total_score"],
        }
        overall = round(sum(scores.values()) / len(scores), 1)
        rating = self._rate(overall, gate_result)
        priorities = self._prioritize(repo_result, pipeline_result,
                                      build_result, image_result,
                                      deploy_result, gate_result)
        finished = time.strftime("%Y-%m-%d %H:%M:%S")
        result = {
            "scan_id": uuid.uuid4().hex[:12],
            "started_at": started, "finished_at": finished,
            "steps": WORKFLOW_STEPS,
            "scores": scores,
            "overall_score": overall,
            "rating": rating,
            "modules": {
                "repo": repo_result, "pipeline": pipeline_result,
                "build": build_result, "image": image_result,
                "deploy": deploy_result, "runtime": runtime_result,
                "gate": gate_result, "maturity": maturity_result,
            },
            "top_priorities": priorities,
            "conclusion": self._conclusion(overall, rating),
        }
        self.history.append(result)
        return result

    @staticmethod
    def _rate(score: float, gate: Dict[str, Any]) -> Dict[str, Any]:
        if gate.get("decision") == "BLOCK":
            level = "critical"
        elif score >= 85:
            level = "low"
        elif score >= 70:
            level = "medium"
        elif score >= 50:
            level = "high"
        else:
            level = "critical"
        return {"risk_level": level, "risk_score": score,
                "gate_decision": gate.get("decision")}

    @staticmethod
    def _prioritize(repo, pipeline, build, image, deploy, gate
                    ) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for f in pipeline.get("findings", [])[:5]:
            items.append({"severity": f["severity"], "module": "pipeline",
                          "title": f["title"], "action": f["advice"]})
        for f in build.get("findings", [])[:5]:
            items.append({"severity": f["severity"], "module": "build",
                          "title": f["title"], "action": f["advice"]})
        for v in image.get("vulns", [])[:5]:
            items.append({"severity": v["severity"], "module": "image",
                          "title": f"{v['id']} {v['pkg']}",
                          "action": f"升级到 {v.get('fixed', 'latest')}"})
        for f in deploy.get("findings", [])[:5]:
            items.append({"severity": f["severity"], "module": "deploy",
                          "title": f["title"], "action": "修复配置"})
        for b in gate.get("blocked", []):
            items.append({"severity": "critical", "module": "gate",
                          "title": b["name"], "action": b["description"]})
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        items.sort(key=lambda x: order.get(x["severity"], 9))
        return items[:20]

    @staticmethod
    def _conclusion(score: float, rating: Dict[str, Any]) -> str:
        if rating["risk_level"] == "critical":
            return "全链路存在阻断性问题，禁止上线，需立即修复"
        if rating["risk_level"] == "high":
            return "存在高危问题，需在本周内修复后发布"
        if rating["risk_level"] == "medium":
            return "整体可控，建议在下个迭代修复中危项"
        return "DevSecOps 链路健康，可按计划发布"

    def list_history(self) -> List[Dict[str, Any]]:
        return self.history


_instance: Optional[DevSecOpsWorkflow] = None


def get_devsecops_workflow() -> DevSecOpsWorkflow:
    global _instance
    if _instance is None:
        _instance = DevSecOpsWorkflow()
    return _instance
