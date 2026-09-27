#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api_scan_workflow.py — API 安全综合扫描工作流（专业级深化）。

步骤：
    OpenAPI 解析 → 认证授权测试 → 注入测试 → 业务逻辑检测 →
    安全配置检查 → 结果聚合 → 风险评级 → 报告生成

支持增量扫描（只扫描变更端点）。
设计定位：编排各检测模块，输出聚合报告与修复优先级。
"""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional

from api_security_pro.openapi_parser import OpenAPIProParser
from api_security_pro.auth_authorization import AuthAuthorizationTester
from api_security_pro.injection_tester import InjectionTester
from api_security_pro.business_logic import BusinessLogicDetector
from api_security_pro.security_config import SecurityConfigChecker
from api_security_pro.fuzz_engine import FuzzEngine


WORKFLOW_STEPS = [
    {"id": "openapi", "name": "OpenAPI 解析", "module": "openapi_parser"},
    {"id": "auth", "name": "认证授权测试", "module": "auth_authorization"},
    {"id": "injection", "name": "注入测试", "module": "injection_tester"},
    {"id": "business", "name": "业务逻辑检测", "module": "business_logic"},
    {"id": "config", "name": "安全配置检查", "module": "security_config"},
    {"id": "fuzz", "name": "Fuzz 测试", "module": "fuzz_engine"},
    {"id": "aggregate", "name": "结果聚合", "module": "workflow"},
    {"id": "rating", "name": "风险评级", "module": "workflow"},
    {"id": "report", "name": "报告生成", "module": "workflow"},
]


# 修复优先级权重
_PRIORITY_WEIGHT = {
    "critical": (10, "立即修复"),
    "high": (6, "72 小时内修复"),
    "medium": (3, "两周内修复"),
    "low": (1, "计划修复"),
    "info": (0, "记录即可"),
}


class APISecurityProWorkflow:
    """API 安全综合扫描工作流。"""

    def __init__(self) -> None:
        self.parser = OpenAPIProParser()
        self.auth_tester = AuthAuthorizationTester()
        self.injection_tester = InjectionTester()
        self.logic_detector = BusinessLogicDetector()
        self.config_checker = SecurityConfigChecker()
        self.fuzz_engine = FuzzEngine()
        self._scan_cache: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ #
    # 主入口
    # ------------------------------------------------------------------ #
    def run_scan(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """执行综合扫描。

        config:
            openapi_url / openapi_content / content_type
            base_url, auth_token, jwt_token, api_key
            incremental: bool, baseline_endpoints: List[str]
            response_headers: Dict
            sample_response: str
        """
        scan_id = config.get("scan_id") or uuid.uuid4().hex[:12]
        started = time.strftime("%Y-%m-%d %H:%M:%S")
        steps_status: List[Dict[str, Any]] = []

        # 1. OpenAPI 解析
        openapi_result = self._step_openapi(config, steps_status)
        endpoints = openapi_result.get("endpoints", [])

        # 增量扫描：过滤变更端点
        if config.get("incremental") and config.get("baseline_endpoints"):
            baseline = set(config["baseline_endpoints"])
            endpoints = [e for e in endpoints
                         if f"{e['method']} {e['path']}" not in baseline]
            steps_status.append({
                "step": "incremental", "status": "ok",
                "message": f"增量模式：过滤后 {len(endpoints)} 个变更端点",
            })

        # 2-6. 各检测模块
        auth_result = self._step_auth(config, endpoints, steps_status)
        injection_result = self._step_injection(config, endpoints, steps_status)
        business_result = self._step_business(config, endpoints, steps_status)
        config_result = self._step_config(config, steps_status)
        fuzz_result = self._step_fuzz(config, endpoints, steps_status)

        # 7. 聚合
        aggregate = self._aggregate(
            openapi_result, auth_result, injection_result,
            business_result, config_result, fuzz_result,
        )
        steps_status.append({"step": "aggregate", "status": "ok",
                             "message": f"聚合 {aggregate['total_findings']} 个发现"})

        # 8. 风险评级
        rating = self._rate(aggregate)
        steps_status.append({"step": "rating", "status": "ok",
                             "message": f"风险等级: {rating['risk_level']}"})

        # 9. 报告
        report = self._build_report(
            scan_id, started, steps_status,
            openapi_result, auth_result, injection_result,
            business_result, config_result, fuzz_result,
            aggregate, rating,
        )
        steps_status.append({"step": "report", "status": "ok",
                             "message": "报告生成完成"})

        self._scan_cache[scan_id] = report
        return report

    # ------------------------------------------------------------------ #
    # 各步骤
    # ------------------------------------------------------------------ #
    def _step_openapi(self, config: Dict[str, Any],
                      steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        try:
            if config.get("openapi_url"):
                result = self.parser.parse_from_url(config["openapi_url"])
            elif config.get("openapi_content"):
                result = self.parser.parse_from_string(
                    config["openapi_content"], config.get("content_type", "json"))
            else:
                result = {"valid": False, "endpoints": [], "errors": ["未提供 OpenAPI 规范"]}
            steps.append({"step": "openapi", "status": "ok" if result.get("valid") else "warn",
                          "message": f"解析到 {len(result.get('endpoints', []))} 个端点"})
            return result
        except Exception as e:
            steps.append({"step": "openapi", "status": "error", "message": str(e)})
            return {"valid": False, "endpoints": [], "errors": [str(e)]}

    def _step_auth(self, config: Dict[str, Any],
                   endpoints: List[Dict[str, Any]],
                   steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        try:
            opts = {
                "jwt_token": config.get("jwt_token", ""),
                "api_key": config.get("api_key", ""),
                "cookie_flags": config.get("cookie_flags", {}),
            }
            result = self.auth_tester.run_tests(endpoints, opts)
            steps.append({"step": "auth", "status": "ok",
                          "message": f"{result['total_findings']} 个发现"})
            return result
        except Exception as e:
            steps.append({"step": "auth", "status": "error", "message": str(e)})
            return {"total_findings": 0, "findings": [], "by_severity": {}, "summary": {}}

    def _step_injection(self, config: Dict[str, Any],
                       endpoints: List[Dict[str, Any]],
                       steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        try:
            params = []
            for ep in endpoints:
                for p in ep.get("parameters", []):
                    params.append({
                        "name": p.get("name", ""),
                        "in": p.get("in", ""),
                        "type": p.get("type", "string"),
                        "path": ep.get("path", ""),
                    })
            if not params:
                params = None
            result = self.injection_tester.run_tests(params)
            steps.append({"step": "injection", "status": "ok",
                          "message": f"{result['total_findings']} 个发现"})
            return result
        except Exception as e:
            steps.append({"step": "injection", "status": "error", "message": str(e)})
            return {"total_findings": 0, "findings": [], "by_severity": {}}

    def _step_business(self, config: Dict[str, Any],
                      endpoints: List[Dict[str, Any]],
                      steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        try:
            result = self.logic_detector.detect(endpoints)
            steps.append({"step": "business", "status": "ok",
                          "message": f"{result['total_findings']} 个发现"})
            return result
        except Exception as e:
            steps.append({"step": "business", "status": "error", "message": str(e)})
            return {"total_findings": 0, "findings": [], "by_severity": {}}

    def _step_config(self, config: Dict[str, Any],
                    steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        try:
            result = self.config_checker.check(
                response_headers=config.get("response_headers"),
                options={
                    "sample_response": config.get("sample_response", ""),
                    "debug_mode": config.get("debug_mode", False),
                    "request_origin": config.get("request_origin", ""),
                },
            )
            steps.append({"step": "config", "status": "ok",
                          "message": f"评分 {result['score']} ({result['grade']})"})
            return result
        except Exception as e:
            steps.append({"step": "config", "status": "error", "message": str(e)})
            return {"total_findings": 0, "score": 0, "grade": "N/A", "findings": []}

    def _step_fuzz(self, config: Dict[str, Any],
                  endpoints: List[Dict[str, Any]],
                  steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        try:
            params = []
            for ep in endpoints:
                for p in ep.get("parameters", []):
                    params.append({
                        "name": p.get("name", ""),
                        "in": p.get("in", ""),
                        "type": p.get("type", "string"),
                        "path": ep.get("path", ""),
                    })
            result = self.fuzz_engine.run(params)
            steps.append({"step": "fuzz", "status": "ok",
                          "message": f"{result['total_cases']} 个 Fuzz 用例"})
            return result
        except Exception as e:
            steps.append({"step": "fuzz", "status": "error", "message": str(e)})
            return {"total_cases": 0, "findings": [], "summary": {}}

    # ------------------------------------------------------------------ #
    # 聚合
    # ------------------------------------------------------------------ #
    @staticmethod
    def _aggregate(*results: Dict[str, Any]) -> Dict[str, Any]:
        all_findings: List[Dict[str, Any]] = []
        for r in results:
            for f in r.get("findings", []) or []:
                all_findings.append(f)

        # 去重：按 (category, name, endpoint/parameter)
        seen: set = set()
        deduped: List[Dict[str, Any]] = []
        for f in all_findings:
            key = (f.get("category"), f.get("name"),
                   f.get("endpoint") or f.get("parameter", ""))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(f)

        by_severity: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        for f in deduped:
            s = f.get("severity", "info")
            c = f.get("category", "unknown")
            by_severity[s] = by_severity.get(s, 0) + 1
            by_category[c] = by_category.get(c, 0) + 1

        return {
            "total_findings": len(deduped),
            "raw_findings": len(all_findings),
            "by_severity": by_severity,
            "by_category": by_category,
            "findings": deduped,
        }

    # ------------------------------------------------------------------ #
    # 风险评级
    # ------------------------------------------------------------------ #
    @staticmethod
    def _rate(aggregate: Dict[str, Any]) -> Dict[str, Any]:
        bs = aggregate.get("by_severity", {})
        score = sum(_PRIORITY_WEIGHT.get(s, (0, ""))[0] * c
                    for s, c in bs.items())
        if bs.get("critical", 0) > 0:
            risk = "严重"
        elif bs.get("high", 0) >= 3:
            risk = "高"
        elif bs.get("high", 0) > 0 or bs.get("medium", 0) >= 3:
            risk = "中"
        else:
            risk = "低"

        # 修复优先级
        priorities = []
        for f in aggregate.get("findings", []):
            sev = f.get("severity", "info")
            weight, sla = _PRIORITY_WEIGHT.get(sev, (0, ""))
            priorities.append({
                "finding": f.get("name"),
                "category": f.get("category"),
                "severity": sev,
                "sla": sla,
                "priority_score": weight,
                "endpoint": f.get("endpoint", ""),
            })
        priorities.sort(key=lambda x: -x["priority_score"])

        return {
            "risk_level": risk,
            "risk_score": score,
            "top_priorities": priorities[:20],
        }

    # ------------------------------------------------------------------ #
    # 报告
    # ------------------------------------------------------------------ #
    @staticmethod
    def _build_report(
        scan_id: str, started: str, steps: List[Dict[str, Any]],
        openapi: Dict[str, Any], auth: Dict[str, Any],
        injection: Dict[str, Any], business: Dict[str, Any],
        config_r: Dict[str, Any], fuzz: Dict[str, Any],
        aggregate: Dict[str, Any], rating: Dict[str, Any],
    ) -> Dict[str, Any]:
        endpoints = openapi.get("endpoints", [])
        return {
            "scan_id": scan_id,
            "started_at": started,
            "finished_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "workflow_steps": steps,
            "openapi_summary": openapi.get("summary", {}),
            "openapi_compliance": openapi.get("compliance", []),
            "openapi_gaps": openapi.get("documentation_gaps", {}),
            "auth_summary": auth.get("summary", {}),
            "auth_findings_count": auth.get("total_findings", 0),
            "injection_summary": injection.get("summary", {}),
            "injection_findings_count": injection.get("total_findings", 0),
            "business_summary": business.get("summary", {}),
            "business_findings_count": business.get("total_findings", 0),
            "config_score": config_r.get("score", 0),
            "config_grade": config_r.get("grade", "N/A"),
            "fuzz_summary": fuzz.get("summary", {}),
            "aggregate": aggregate,
            "rating": rating,
            "endpoints_overview": [
                {"method": e["method"], "path": e["path"],
                 "operation_id": e.get("operation_id", ""),
                 "tags": e.get("tags", [])}
                for e in endpoints
            ],
            "conclusion": (
                f"本次扫描共发现 {aggregate['total_findings']} 项安全问题，"
                f"风险等级为 {rating['risk_level']}。"
                f"建议按 P1（立即修复）→ P2（72 小时）→ P3（两周）顺序处理。"
            ),
        }

    # ------------------------------------------------------------------ #
    # 查询
    # ------------------------------------------------------------------ #
    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        return self._scan_cache.get(scan_id)

    def list_scans(self) -> List[Dict[str, Any]]:
        return [
            {"scan_id": k, "finished_at": v.get("finished_at"),
             "risk_level": v.get("rating", {}).get("risk_level"),
             "total_findings": v.get("aggregate", {}).get("total_findings")}
            for k, v in self._scan_cache.items()
        ]

    @staticmethod
    def endpoint_signature(endpoints: List[Dict[str, Any]]) -> str:
        """计算端点集合的指纹，用于增量扫描判断变更。"""
        keys = sorted(f"{e.get('method','')} {e.get('path','')}" for e in endpoints)
        return hashlib.sha256("|".join(keys).encode()).hexdigest()[:16]


# 全局单例
_workflow: Optional[APISecurityProWorkflow] = None


def get_pro_workflow() -> APISecurityProWorkflow:
    global _workflow
    if _workflow is None:
        _workflow = APISecurityProWorkflow()
    return _workflow
