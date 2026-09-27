#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
workflow.py — API 安全测试工作流编排。

8 个步骤：
    1. parse_openapi       解析 OpenAPI 规范
    2. endpoint_discovery  端点发现和分类
    3. param_extraction    参数提取
    4. auth_analysis       认证方式分析
    5. param_fuzz          参数 fuzz 测试
    6. logic_test          逻辑漏洞测试
    7. risk_assessment     风险评估
    8. report_generation   报告生成

设计定位：
    - 只做检测性测试，不利用漏洞；通过 fuzz_intensity 控制载荷规模。
    - 异步线程执行不阻塞调用方；扫描任务存于全局字典 _scans。
    - 本模块仅用于授权的安全评估与合规检查。
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from api_security.openapi_parser import OpenAPIParser
from api_security.param_fuzzer import ParamFuzzer, PAYLOAD_LIBRARY
from api_security.logic_tester import LogicTester


# 8 个工作流步骤定义（顺序执行）
WORKFLOW_STEPS: List[Dict[str, Any]] = [
    {"step": "parse_openapi", "name": "解析OpenAPI规范"},
    {"step": "endpoint_discovery", "name": "端点发现与分类"},
    {"step": "param_extraction", "name": "参数提取"},
    {"step": "auth_analysis", "name": "认证方式分析"},
    {"step": "param_fuzz", "name": "参数Fuzz测试"},
    {"step": "logic_test", "name": "逻辑漏洞测试"},
    {"step": "risk_assessment", "name": "风险评估"},
    {"step": "report_generation", "name": "报告生成"},
]

# 强度配置：(关键参数 only, 每类 payload 数, 是否全量逻辑测试)
_INTENSITY = {
    "low": {"key_params_only": True, "payloads_per_type": 5, "logic_full": False},
    "medium": {"key_params_only": False, "payloads_per_type": 10, "logic_full": False},
    "high": {"key_params_only": False, "payloads_per_type": 0, "logic_full": True},
}

_RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class APISecurityWorkflow:
    """API 安全测试工作流。"""

    def __init__(self) -> None:
        self.parser = OpenAPIParser()
        self.fuzzer = ParamFuzzer()
        self.tester = LogicTester()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # 任务生命周期
    # ------------------------------------------------------------------ #
    def create_scan(self, config: Dict[str, Any]) -> str:
        """创建扫描任务，返回 scan_id。"""
        try:
            scan_id = "scan_" + uuid.uuid4().hex[:12]
            now = datetime.utcnow().isoformat()
            with self._lock:
                _scans[scan_id] = {
                    "scan_id": scan_id,
                    "config": config,
                    "status": "pending",
                    "current_step": "",
                    "progress": 0,
                    "steps_total": len(WORKFLOW_STEPS),
                    "step_history": [],
                    "created_at": now,
                    "updated_at": now,
                    "result": {},
                    "error": None,
                }
            return scan_id
        except Exception as e:
            # 即使异常也返回一个 id，便于上层定位
            return f"scan_error_{uuid.uuid4().hex[:8]}:{e}"

    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """获取扫描状态。"""
        try:
            s = _scans.get(scan_id)
            if not s:
                return {"status": "not_found", "error": f"扫描 {scan_id} 不存在"}
            return {
                "scan_id": scan_id,
                "status": s["status"],
                "current_step": s["current_step"],
                "progress": s["progress"],
                "step_history": s["step_history"],
                "error": s["error"],
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def run_scan(self, scan_id: str) -> None:
        """执行扫描（threading.Thread 异步执行）。"""
        def _worker():
            try:
                self._execute_scan(scan_id)
            except Exception as e:
                with self._lock:
                    s = _scans.get(scan_id)
                    if s:
                        s["status"] = "failed"
                        s["error"] = str(e)
                        s["updated_at"] = datetime.utcnow().isoformat()
        t = threading.Thread(target=_worker, daemon=True)
        t.start()

    # ------------------------------------------------------------------ #
    # 执行管线
    # ------------------------------------------------------------------ #
    def _set_step(self, scan_id: str, step_name: str, idx: int, total: int) -> None:
        pct = int((idx / total) * 100)
        with self._lock:
            s = _scans.get(scan_id)
            if s:
                s["status"] = "running"
                s["current_step"] = step_name
                s["progress"] = pct
                s["step_history"].append({"step": step_name, "at": datetime.utcnow().isoformat()})
                s["updated_at"] = datetime.utcnow().isoformat()

    def _execute_scan(self, scan_id: str) -> None:
        s = _scans.get(scan_id)
        if not s:
            return
        config = s.get("config", {}) or {}
        intensity = config.get("fuzz_intensity", "medium")
        icfg = _INTENSITY.get(intensity, _INTENSITY["medium"])
        base_url = config.get("base_url", "")
        auth_token = config.get("auth_token", "")
        options = dict(config.get("rate_limit") or {})
        options.setdefault("request_interval", 0.5)
        options.setdefault("timeout", 10)

        total = len(WORKFLOW_STEPS)
        parsed: Dict[str, Any] = {}
        endpoints: List[Dict[str, Any]] = []
        vulns: List[Dict[str, Any]] = []

        for idx, step in enumerate(WORKFLOW_STEPS, start=1):
            self._set_step(scan_id, step["step"], idx - 1, total)
            try:
                if step["step"] == "parse_openapi":
                    content = config.get("openapi_content", "")
                    url = config.get("openapi_url", "")
                    if content:
                        parsed = self.parser.parse_from_string(content, config.get("content_type", "json"))
                    elif url:
                        parsed = self.parser.parse_from_url(url)
                    else:
                        parsed = {"valid": False, "errors": ["未提供 openapi_url 或 openapi_content"], "parsed": {}}

                elif step["step"] == "endpoint_discovery":
                    p = parsed.get("parsed", {}) if isinstance(parsed, dict) else {}
                    endpoints = p.get("endpoints", []) if isinstance(p, dict) else []
                    classes = self.parser.classify_endpoints(endpoints)
                    with self._lock:
                        s["result"]["endpoint_classes"] = {k: len(v) for k, v in classes.items()}

                elif step["step"] == "param_extraction":
                    all_params: List[Dict[str, Any]] = []
                    for ep in endpoints:
                        for p in ep.get("param_details", []) or []:
                            all_params.append({"endpoint": ep.get("path"), "method": ep.get("method"), **p})
                    with self._lock:
                        s["result"]["total_params"] = len(all_params)
                        s["result"]["params"] = all_params[:200]

                elif step["step"] == "auth_analysis":
                    p = parsed.get("parsed", {}) if isinstance(parsed, dict) else {}
                    auth_methods = p.get("auth_methods", []) if isinstance(p, dict) else []
                    with self._lock:
                        s["result"]["auth_methods"] = auth_methods

                elif step["step"] == "param_fuzz":
                    # 不真正对外部目标发请求；按配置枚举将测试的 payload 集合，形成"待执行"结果
                    fuzz_types = config.get("test_types") or self.fuzzer.get_fuzz_types()
                    fuzz_types = [t for t in fuzz_types if t in self.fuzzer.get_fuzz_types()]
                    max_pp = icfg["payloads_per_type"]
                    fuzz_results: List[Dict[str, Any]] = []
                    target_params = []
                    for ep in endpoints:
                        for p in ep.get("param_details", []) or []:
                            target_params.append((ep, p))
                    if icfg["key_params_only"]:
                        # 只测路径参数和 body 必填字段
                        target_params = [(ep, p) for (ep, p) in target_params
                                         if p.get("location") in ("path",) or p.get("required")]
                    for ep, p in target_params[:50]:
                        for ft in fuzz_types:
                            payloads = PAYLOAD_LIBRARY.get(ft, [])
                            if max_pp and max_pp > 0:
                                payloads = payloads[:max_pp]
                            for pl in payloads:
                                fuzz_results.append({
                                    "param_name": p.get("name"),
                                    "endpoint": ep.get("path"),
                                    "method": ep.get("method"),
                                    "fuzz_type": ft,
                                    "payload_preview": (pl[:40] + "…") if len(pl) > 40 else pl,
                                    "status": "planned",
                                    "detected": False,
                                    "risk_level": "info",
                                })
                    with self._lock:
                        s["result"]["fuzz_results"] = fuzz_results
                        s["result"]["fuzz_planned"] = len(fuzz_results)

                elif step["step"] == "logic_test":
                    test_types = config.get("logic_test_types") or self.tester.get_test_types()
                    logic_results: List[Dict[str, Any]] = []
                    sample_eps = endpoints[:10]
                    for ep in sample_eps:
                        for tt in test_types:
                            logic_results.append({
                                "test_type": tt,
                                "endpoint": ep.get("path"),
                                "method": ep.get("method"),
                                "status": "planned",
                                "detected": False,
                                "risk_level": "info",
                                "remediation": self.tester.remediation.get(tt, ""),
                            })
                    with self._lock:
                        s["result"]["logic_results"] = logic_results

                elif step["step"] == "risk_assessment":
                    # 聚合：把 fuzz/logic 的 planned 项按规则赋风险等级（演示性）
                    merged: List[Dict[str, Any]] = []
                    fr = (s.get("result", {}) or {}).get("fuzz_results", [])
                    lr = (s.get("result", {}) or {}).get("logic_results", [])
                    for item in fr:
                        merged.append({
                            "source": "fuzz",
                            "type": item.get("fuzz_type"),
                            "endpoint": item.get("endpoint"),
                            "method": item.get("method"),
                            "param": item.get("param_name"),
                            "risk_level": item.get("risk_level", "info"),
                            "evidence": item.get("payload_preview", ""),
                            "remediation": "",
                        })
                    for item in lr:
                        merged.append({
                            "source": "logic",
                            "type": item.get("test_type"),
                            "endpoint": item.get("endpoint"),
                            "method": item.get("method"),
                            "param": "",
                            "risk_level": item.get("risk_level", "info"),
                            "evidence": "planned",
                            "remediation": item.get("remediation", ""),
                        })
                    merged.sort(key=lambda x: _RISK_ORDER.get(x["risk_level"], 99))
                    with self._lock:
                        s["result"]["vulnerabilities"] = merged
                        s["result"]["vuln_count"] = len(merged)

                elif step["step"] == "report_generation":
                    with self._lock:
                        s["result"]["report"] = self._build_report(s)
            except Exception as e:
                with self._lock:
                    s["step_history"].append({"step": step["step"], "error": str(e),
                                              "at": datetime.utcnow().isoformat()})

        # 完成
        with self._lock:
            s["status"] = "completed"
            s["progress"] = 100
            s["current_step"] = "done"
            s["updated_at"] = datetime.utcnow().isoformat()

    # ------------------------------------------------------------------ #
    # 查询接口
    # ------------------------------------------------------------------ #
    def get_scan_result(self, scan_id: str) -> Dict[str, Any]:
        try:
            s = _scans.get(scan_id)
            if not s:
                return {"error": f"扫描 {scan_id} 不存在"}
            return {"scan_id": scan_id, "status": s["status"], "result": s.get("result", {})}
        except Exception as e:
            return {"error": str(e)}

    def get_endpoints(self, scan_id: str) -> List[Dict[str, Any]]:
        try:
            s = _scans.get(scan_id)
            if not s:
                return []
            parsed = s.get("result", {})
            # endpoints 在 parse 阶段已存进 parsed 结果
            p = self.parser.spec
            if p:
                return self.parser.get_endpoints(p)
            return parsed.get("endpoints", [])
        except Exception:
            return []

    def get_vulnerabilities(self, scan_id: str,
                          severity: Optional[str] = None) -> List[Dict[str, Any]]:
        try:
            s = _scans.get(scan_id)
            if not s:
                return []
            vulns = s.get("result", {}).get("vulnerabilities", [])
            if severity:
                vulns = [v for v in vulns if v.get("risk_level") == severity]
            return vulns
        except Exception:
            return []

    def generate_report(self, scan_id: str, fmt: str = "json") -> Dict[str, Any]:
        try:
            s = _scans.get(scan_id)
            if not s:
                return {"error": f"扫描 {scan_id} 不存在"}
            report = s.get("result", {}).get("report") or self._build_report(s)
            if fmt.lower() == "html":
                return {"format": "html", "content": self._report_to_html(report)}
            return {"format": "json", "content": report}
        except Exception as e:
            return {"error": str(e)}

    def _build_report(self, s: Dict[str, Any]) -> Dict[str, Any]:
        try:
            r = s.get("result", {}) or {}
            vulns = r.get("vulnerabilities", [])
            by_risk: Dict[str, int] = {}
            by_type: Dict[str, int] = {}
            for v in vulns:
                by_risk[v.get("risk_level", "info")] = by_risk.get(v.get("risk_level", "info"), 0) + 1
                by_type[v.get("type", "unknown")] = by_type.get(v.get("type", "unknown"), 0) + 1
            return {
                "scan_id": s.get("scan_id"),
                "status": s.get("status"),
                "generated_at": datetime.utcnow().isoformat(),
                "endpoint_count": r.get("total_params") and len(self.parser.get_endpoints()) or 0,
                "vuln_count": len(vulns),
                "by_risk": by_risk,
                "by_type": by_type,
                "endpoints_class": r.get("endpoint_classes", {}),
                "auth_methods": r.get("auth_methods", []),
                "vulnerabilities": vulns,
            }
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def _report_to_html(report: Dict[str, Any]) -> str:
        try:
            rows = "".join(
                f"<tr><td>{v.get('type','')}</td><td>{v.get('endpoint','')}</td>"
                f"<td>{v.get('risk_level','')}</td><td>{v.get('evidence','')}</td></tr>"
                for v in report.get("vulnerabilities", [])[:200]
            )
            return (
                "<html><head><meta charset='utf-8'><title>API安全报告</title></head>"
                "<body style='font-family:sans-serif;padding:20px'>"
                f"<h1>API 安全测试报告</h1>"
                f"<p>扫描ID: {report.get('scan_id','')}</p>"
                f"<p>状态: {report.get('status','')}</p>"
                f"<p>生成时间: {report.get('generated_at','')}</p>"
                "<h2>漏洞列表</h2>"
                "<table border='1' cellpadding='6' cellspacing='0'>"
                "<tr><th>类型</th><th>端点</th><th>风险等级</th><th>证据</th></tr>"
                f"{rows}</table></body></html>"
            )
        except Exception as e:
            return f"<html><body>报告生成失败: {e}</body></html>"

    def get_scan_history(self) -> List[Dict[str, Any]]:
        try:
            out = []
            with self._lock:
                for sid, s in _scans.items():
                    out.append({
                        "scan_id": sid,
                        "status": s["status"],
                        "progress": s["progress"],
                        "created_at": s["created_at"],
                        "updated_at": s["updated_at"],
                        "vuln_count": s.get("result", {}).get("vuln_count", 0),
                    })
            out.sort(key=lambda x: x.get("created_at", ""), reverse=True)
            return out
        except Exception:
            return []

    def get_stats(self) -> Dict[str, Any]:
        try:
            total = len(_scans)
            all_vulns: List[Dict[str, Any]] = []
            for s in _scans.values():
                all_vulns.extend(s.get("result", {}).get("vulnerabilities", []))
            by_risk: Dict[str, int] = {}
            by_type: Dict[str, int] = {}
            for v in all_vulns:
                by_risk[v.get("risk_level", "info")] = by_risk.get(v.get("risk_level", "info"), 0) + 1
                by_type[v.get("type", "unknown")] = by_type.get(v.get("type", "unknown"), 0) + 1
            return {
                "total_scans": total,
                "total_vulns": len(all_vulns),
                "by_risk": by_risk,
                "by_type": by_type,
            }
        except Exception as e:
            return {"error": str(e)}


# 全局扫描任务存储
_scans: Dict[str, Dict[str, Any]] = {}

# 全局单例
_workflow: Optional[APISecurityWorkflow] = None


def get_api_security_workflow() -> APISecurityWorkflow:
    global _workflow
    if _workflow is None:
        _workflow = APISecurityWorkflow()
    return _workflow


__all__ = ["APISecurityWorkflow", "get_api_security_workflow", "WORKFLOW_STEPS", "_scans"]
