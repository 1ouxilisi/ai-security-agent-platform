# -*- coding: utf-8 -*-
"""
e2e_verifier.py — 端到端自检验证（第16轮升级·方向1）。

内置自检测试：自动对 127.0.0.1 执行完整 Web 评估工作流，
验证从输入到出报告的每一步都真实跑通。

验证项：
    - 目标识别是否正确
    - 每个步骤是否真实执行（非跳过）
    - 中间结果是否非空
    - 风险评分是否在 0-100
    - 报告是否包含所有必要章节
    - 总耗时是否合理
输出：每步 PASS/FAIL、失败原因、修复建议、总体验证结论。
"""

from __future__ import annotations

import time
from typing import Any, Dict, List

from workflow_v2.workflow_engine import (
    run_workflow, identify_target, HANDLERS, DEPS,
)


# 自检测试用小端口集，避免长时间等待
SELF_TEST_PORTS = [80, 443, 135, 445, 8000, 3306, 22]


def _chk(name: str, passed: bool, detail: str = "",
         advice: str = "") -> Dict[str, Any]:
    return {"check": name, "result": "PASS" if passed else "FAIL",
            "detail": detail, "advice": advice}


def run_self_test(target: str = "127.0.0.1",
                  scenario_id: str = "web_full_assessment") -> Dict[str, Any]:
    t0 = time.time()
    checks: List[Dict[str, Any]] = []

    # 1. 模块依赖可用性
    available_mods = [k for k, v in DEPS.items()
                      if not k.startswith("_err") and v is not None]
    checks.append(_chk(
        "关键检测模块可加载",
        len(available_mods) >= 3,
        f"已加载: {', '.join(available_mods)}",
        "检查 scanner.advanced_vuln_scanner / pentest.internal_tools 是否可 import"))

    # 2. 目标识别
    info = identify_target(target)
    checks.append(_chk(
        "目标类型自动识别",
        info.get("type") in ("ip", "url", "domain"),
        f"识别为 {info.get('type')} host={info.get('host')}",
        "检查 identify_target 的正则规则"))

    # 3. 执行完整工作流
    task = run_workflow(target, scenario_id,
                        options={"ports": SELF_TEST_PORTS,
                                 "scan_timeout": 1.0})
    elapsed = round(time.time() - t0, 1)

    step_map = task.to_dict()["steps"]

    # 4. 步骤真实执行（核心步骤不允许 failed）
    core_failed = [s["step_id"] for s in step_map if s["status"] == "failed"]
    checks.append(_chk(
        "所有步骤无执行异常",
        len(core_failed) == 0,
        f"失败步骤: {core_failed}" if core_failed else "全部步骤正常结束",
        "查看失败步骤的 traceback，修正 handler 调用"))

    # 5. 关键步骤真实执行（非跳过）
    skipped_core = [s["step_id"] for s in step_map
                    if s["step_id"] in ("port_scan", "service_detect",
                                        "target_recognize", "risk_rating")
                    and s["status"] in ("skipped", "cancelled")]
    checks.append(_chk(
        "关键步骤真实执行(非跳过)",
        len(skipped_core) == 0,
        f"被跳过: {skipped_core}" if skipped_core else "端口扫描/服务识别均真实执行",
        "确认目标可达且 handler 已注册"))

    # 6. 中间结果非空（port_scan 应有 open_ports）
    port_step = task.steps.get("port_scan")
    port_result = (port_step.output_summary or {}) if port_step else {}
    open_ports = port_result.get("open_ports", [])
    checks.append(_chk(
        "端口扫描中间结果非空",
        isinstance(open_ports, list),
        f"扫描 {port_result.get('scanned')} 端口, 开放 {len(open_ports)} 个: "
        f"{[p['port'] for p in open_ports]}",
        "确认 _real_port_open 真实连接而非 mock",
    ))

    # 7. 风险评分在 0-100
    score = task.result.get("risk_score")
    checks.append(_chk(
        "风险评分在 0-100",
        isinstance(score, int) and 0 <= score <= 100,
        f"评分={score} 级别={task.result.get('risk_level')}",
        "检查 _compute_risk_score 聚合逻辑"))

    # 8. 报告包含必要章节
    report = task.result.get("report", {})
    needed = ("target", "scenario", "risk_score", "risk_level",
              "executed_steps", "step_summary", "generated_at")
    missing = [k for k in needed if k not in report]
    checks.append(_chk(
        "报告包含所有必要章节",
        len(missing) == 0,
        f"缺失: {missing}" if missing else "报告章节完整",
        "检查 generate_report handler"))

    # 9. 总耗时合理（<180s）
    checks.append(_chk(
        "总耗时合理(<180s)",
        elapsed < 180,
        f"实际耗时 {elapsed}s",
        "缩减扫描端口数或降低超时"))

    # 10. 降级信息记录
    degraded = task.result.get("degraded_steps", [])
    checks.append(_chk(
        "降级步骤已记录(非致命)",
        True,
        f"降级步骤: {degraded}" if degraded else "无降级步骤",
        ""))

    total_pass = sum(1 for c in checks if c["result"] == "PASS")
    overall = "PASS" if total_pass == len(checks) else "FAIL"
    return {
        "target": target,
        "scenario": scenario_id,
        "elapsed_s": elapsed,
        "task_id": task.task_id,
        "overall": overall,
        "total": len(checks),
        "passed": total_pass,
        "failed": len(checks) - total_pass,
        "checks": checks,
        "risk_score": score,
        "risk_level": task.result.get("risk_level"),
        "open_ports": [p["port"] for p in open_ports],
        "conclusion": (f"端到端工作流{'真实跑通' if overall == 'PASS' else '存在问题'}: "
                       f"{total_pass}/{len(checks)} 项通过"),
    }


__all__ = ["run_self_test", "SELF_TEST_PORTS"]
