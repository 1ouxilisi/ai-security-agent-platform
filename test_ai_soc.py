# -*- coding: utf-8 -*-
"""
AI 安全运营（AI SOC）模块 - 自测脚本

验证内容：
    1. 模块导入（6 个核心类 + 路由）
    2. AnomalyDetector 主方法（基线学习/检测/评分/报告/状态）
    3. AlertCorrelator 主方法（关联/攻击链/聚合/优先级/误报/报告）
    4. EventClassifier 主方法（分类/严重程度/自动分配/升级/统计/报告）
    5. RootCauseAnalyzer 主方法（分析/证据/评分/修复建议/报告）
    6. ResponseAdvisor 主方法（建议/优先级/模板/验证/报告）
    7. SOCAssistant 主方法（聊天/问答/指导/报告/知识检索/上下文）
    8. API 路由导入与端点数量
"""
import os
import sys

# 确保项目根目录在 path 中
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

test_results = []


def test(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    test_results.append({"name": name, "status": status})
    print(f"  [{status}] {name}" + (f" - {detail}" if detail else ""))


print("=" * 60)
print("  AI 安全运营（AI SOC）模块 - 自测")
print("=" * 60)

# ==================== 1. 模块导入测试 ====================
print("\n【1. 模块导入测试】")
try:
    from ai_soc.anomaly_detector import AnomalyDetector, anomaly_detector
    test("导入 AnomalyDetector + 单例", True)
except Exception as e:
    test("导入 AnomalyDetector + 单例", False, str(e))

try:
    from ai_soc.alert_correlator import AlertCorrelator, alert_correlator
    test("导入 AlertCorrelator + 单例", True)
except Exception as e:
    test("导入 AlertCorrelator + 单例", False, str(e))

try:
    from ai_soc.event_classifier import EventClassifier, event_classifier
    test("导入 EventClassifier + 单例", True)
except Exception as e:
    test("导入 EventClassifier + 单例", False, str(e))

try:
    from ai_soc.root_cause_analyzer import RootCauseAnalyzer, root_cause_analyzer
    test("导入 RootCauseAnalyzer + 单例", True)
except Exception as e:
    test("导入 RootCauseAnalyzer + 单例", False, str(e))

try:
    from ai_soc.response_advisor import ResponseAdvisor, response_advisor
    test("导入 ResponseAdvisor + 单例", True)
except Exception as e:
    test("导入 ResponseAdvisor + 单例", False, str(e))

try:
    from ai_soc.soc_assistant import SOCAssistant, soc_assistant
    test("导入 SOCAssistant + 单例", True)
except Exception as e:
    test("导入 SOCAssistant + 单例", False, str(e))

try:
    import ai_soc
    test("导入 ai_soc 包 (__init__)", hasattr(ai_soc, "anomaly_detector"))
except Exception as e:
    test("导入 ai_soc 包 (__init__)", False, str(e))

# ==================== 2. AnomalyDetector ====================
print("\n【2. AnomalyDetector 异常检测器】")
try:
    from ai_soc.anomaly_detector import anomaly_detector
    bl = anomaly_detector.learn_baseline({
        "performance": {"cpu": [30, 32, 28, 31, 29], "memory": [40, 42, 41, 43, 40]}
    })
    test("learn_baseline 学习基线", "series" in bl)
except Exception as e:
    test("learn_baseline 学习基线", False, str(e))

try:
    task_id = anomaly_detector.detect(
        traffic_data={"bandwidth": [100, 110, 105, 5000], "ports": [22, 4444]},
        performance_data={"cpu": [30, 35, 95], "memory": [40, 42, 90]},
        log_data={"error_rate": 8.5, "lines": ["segfault at 0x0", "authentication failure for root"]},
        behavior_data={"login_hour": 3, "source_ip": "8.8.8.8"},
    )
    test("detect 返回 task_id", task_id.startswith("anom-"), task_id)
    status = anomaly_detector.get_task_status(task_id)
    test("get_task_status 完成", status.get("status") == "completed", str(status.get("total_anomalies")))
    results = anomaly_detector.get_results(task_id)
    test("get_results 返回异常列表", len(results) > 0, f"{len(results)} 条")
    rep = anomaly_detector.generate_report(task_id)
    test("generate_report 生成报告", rep.get("report_type") == "anomaly_detection")
except Exception as e:
    test("AnomalyDetector 主流程", False, str(e))

# ==================== 3. AlertCorrelator ====================
print("\n【3. AlertCorrelator 告警关联分析器】")
try:
    from ai_soc.alert_correlator import alert_correlator
    alerts = [
        {"source_ip": "1.2.3.4", "mitre_tactic": "reconnaissance", "severity": "low", "title": "scan_test"},
        {"source_ip": "1.2.3.4", "mitre_tactic": "initial_access", "attack_type": "port_scan", "severity": "medium"},
        {"source_ip": "1.2.3.4", "mitre_tactic": "execution", "attack_type": "exploit", "severity": "high", "confidence": 90},
        {"source_ip": "1.2.3.4", "mitre_tactic": "exfiltration", "attack_type": "data_exfiltration", "severity": "critical"},
        {"source_ip": "5.6.7.8", "mitre_tactic": "reconnaissance", "severity": "info", "title": "legitimate_scan"},
    ]
    tid = alert_correlator.correlate(alerts)
    test("correlate 返回 task_id", tid.startswith("corr-"), tid)
    chains = alert_correlator.get_attack_chains(tid)
    test("identify_attack_chains 识别攻击链", len(chains) >= 1, f"{len(chains)} 条")
    agg = alert_correlator.get_aggregated(tid)
    test("aggregate_alerts 聚合告警", isinstance(agg, list))
    pri = alert_correlator.calculate_priority({"attack_chain_phase": 6, "severity": "critical", "confidence": 90})
    test("calculate_priority 优先级", 0 <= pri <= 100, str(pri))
    fp = alert_correlator.detect_false_positives([{"source_ip": "127.0.0.1", "severity": "info"}])
    test("detect_false_positives 误报识别", fp[0].get("is_false_positive") is True)
    rep = alert_correlator.generate_report(tid)
    test("generate_report 关联报告", rep.get("report_type") == "alert_correlation")
except Exception as e:
    test("AlertCorrelator 主流程", False, str(e))

# ==================== 4. EventClassifier ====================
print("\n【4. EventClassifier 事件分类器】")
try:
    from ai_soc.event_classifier import event_classifier
    ev = event_classifier.classify({
        "event_id": "evt-test-1", "title": "ransomware detected on host",
        "message": "trojan backdoor c2 beacon", "impact_scope": 5,
        "asset_criticality": "critical", "data_sensitivity": "high",
    })
    test("classify 分类事件", ev.get("category") in ["恶意软件", "其他"], ev.get("category"))
    sev = event_classifier.assess_severity({"category": "数据泄露", "impact_scope": 10,
                                            "asset_criticality": "critical", "data_sensitivity": "high"})
    test("assess_severity 严重程度", sev.get("severity") in ("critical", "high"), sev.get("severity"))
    assign = event_classifier.auto_assign(ev)
    test("auto_assign 自动分配", "assignee" in assign)
    test("auto_escalate 自动升级", assign["escalation"].get("escalated") in (True, False))
    stats = event_classifier.get_stats()
    test("get_stats 统计", stats.get("total_classified") >= 1)
    rep = event_classifier.generate_report()
    test("generate_report 分类报告", rep.get("report_type") == "event_classification")
except Exception as e:
    test("EventClassifier 主流程", False, str(e))

# ==================== 5. RootCauseAnalyzer ====================
print("\n【5. RootCauseAnalyzer 根因分析器】")
try:
    from ai_soc.root_cause_analyzer import root_cause_analyzer
    rc_tid = root_cause_analyzer.analyze(
        "evt-test-1",
        logs=["permission denied for user", "invalid config in nginx.conf", "segmentation fault"],
        topology={"nodes": ["web", "db"], "edges": ["web->db"]},
        timeline=[{"ts": "t0", "msg": "invalid config"}, {"ts": "t1", "msg": "outage"}],
    )
    test("analyze 返回 task_id", rc_tid.startswith("rca-"), rc_tid)
    res = root_cause_analyzer.get_results(rc_tid)
    test("score_root_causes 根因评分", len(res) > 0, f"{len(res)} 候选")
    evd = root_cause_analyzer.get_evidence(rc_tid)
    test("collect_evidence 证据收集", len(evd) > 0)
    fix = root_cause_analyzer.get_fix_suggestions("配置错误")
    test("get_fix_suggestions 修复建议", "steps" in fix)
    rep = root_cause_analyzer.generate_report(rc_tid)
    test("generate_report 根因报告", rep.get("report_type") == "root_cause_analysis")
except Exception as e:
    test("RootCauseAnalyzer 主流程", False, str(e))

# ==================== 6. ResponseAdvisor ====================
print("\n【6. ResponseAdvisor 响应建议器】")
try:
    from ai_soc.response_advisor import response_advisor
    advice = response_advisor.advise({
        "event_id": "evt-test-1", "event_type": "入侵", "severity": "critical",
        "impact_scope": 10, "business_impact": "critical",
    })
    test("advise 生成响应建议", len(advice.get("response_steps", [])) == 4)
    pri = response_advisor.get_priority({"severity": "critical", "impact_scope": 10, "business_impact": "critical"})
    test("get_priority 响应优先级", 0 <= pri <= 100, str(pri))
    tpl = response_advisor.get_templates("入侵")
    test("get_templates 响应模板", "入侵" in tpl)
    ver = response_advisor.verify_response("evt-test-1", ["隔离主机", "封禁IP", "清除后门"])
    test("verify_response 响应验证", "checks" in ver)
    rep = response_advisor.generate_report("evt-test-1")
    test("generate_report 响应报告", rep.get("report_type") == "response_advice")
except Exception as e:
    test("ResponseAdvisor 主流程", False, str(e))

# ==================== 7. SOCAssistant ====================
print("\n【7. SOCAssistant 安全运营助手】")
try:
    from ai_soc.soc_assistant import soc_assistant
    chat_res = soc_assistant.chat("当前安全状态怎么样？")
    test("chat 自然语言交互", chat_res.get("intent") is not None)
    ans = soc_assistant.answer_question("漏洞怎么修复？")
    test("answer_question 智能问答", len(ans) > 0)
    guide = soc_assistant.guide_action("alert")
    test("guide_action 操作指导", "steps" in guide)
    rep = soc_assistant.generate_report("daily", {"period": "今日"})
    test("generate_report 生成报告", rep.get("report_type") == "daily")
    kn = soc_assistant.search_knowledge("CVE")
    test("search_knowledge 知识检索", isinstance(kn, list))
    ctx = soc_assistant.get_context()
    test("get_context 上下文", "active_task" in ctx)
except Exception as e:
    test("SOCAssistant 主流程", False, str(e))

# ==================== 8. API 路由导入 ====================
print("\n【8. API 路由导入测试】")
try:
    from api_server.ai_soc_routes import router
    routes = [r.path for r in router.routes]
    test("导入 ai_soc_routes.router", router is not None)
    test("路由端点数量 >= 18", len(routes) >= 18, f"{len(routes)} 个")
    must_have = ["/anomaly/detect", "/alert/correlate", "/event/classify",
                 "/root-cause/analyze", "/response/advise", "/assistant/chat"]
    missing = [m for m in must_have if not any(m in p for p in routes)]
    test("关键端点存在", len(missing) == 0, f"缺失:{missing}" if missing else "全部存在")
except Exception as e:
    test("API 路由导入", False, str(e))

# ==================== 汇总 ====================
print("\n" + "=" * 60)
passed = sum(1 for r in test_results if r["status"] == "PASS")
total = len(test_results)
print(f"  测试结果: {passed}/{total} 通过")
if passed == total:
    print("  全部通过 ✓")
else:
    failed = [r["name"] for r in test_results if r["status"] == "FAIL"]
    print(f"  失败项: {failed}")
print("=" * 60)

sys.exit(0 if passed == total else 1)
