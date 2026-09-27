# -*- coding: utf-8 -*-
"""Round 7 升级验证脚本：依次执行验证1-5 + 端到端 DAG 测试。"""
import sys, os, time, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

results = []

def check(name, fn):
    try:
        out = fn()
        results.append((name, True, out))
        print(f"[PASS] {name}: {out}")
    except Exception as e:
        results.append((name, False, str(e)))
        print(f"[FAIL] {name}: {e}")

# 1. engine
def t1():
    from workflow.engine import dag_engine, DAGWorkflowEngine
    assert dag_engine is not None
    assert isinstance(dag_engine, DAGWorkflowEngine)
    return "engine OK"
check("1.engine导入", t1)

# 2. templates
def t2():
    from workflow.templates import list_templates, get_template
    ts = list_templates()
    assert len(ts) == 8, f"期望8个模板, 实际{len(ts)}"
    ids = [t["id"] for t in ts]
    for tid in ["pentest_full","web_security","mobile_security","internal_assessment",
                "domain_audit","ai_agent_security","blockchain_security","compliance_audit"]:
        assert tid in ids, f"缺少模板 {tid}"
        assert get_template(tid) is not None
    return f"templates: {len(ts)} -> {ids}"
check("2.templates列表", t2)

# 3. builder
def t3():
    from workflow.builder import WorkflowBuilder
    b = WorkflowBuilder()
    wf = b.create_workflow("test", "desc")
    b.add_step(wf, "s1", "Step1", "tool_call", {"tool": "test"}, [], None, "continue", 1)
    v = b.validate_workflow(wf)
    assert v["valid"] is True, v
    # 测试循环依赖检测
    b.add_step(wf, "s2", "Step2", "tool_call", {"tool": "t2"}, ["s1"], None, "continue", 0)
    v2 = b.validate_workflow(wf)
    assert v2["valid"] is True
    # 测试循环
    wf2 = b.create_workflow("c", "x")
    b.add_step(wf2, "a", "A", "tool_call", {}, ["b"])
    b.add_step(wf2, "b", "B", "tool_call", {}, ["a"])
    v3 = b.validate_workflow(wf2)
    assert v3["valid"] is False, "应检测到循环依赖"
    return f"validate ok (s2 chain valid, cycle detected: {not v3['valid']})"
check("3.builder构建与校验", t3)

# 4. scheduler
def t4():
    from workflow.scheduler import scheduler
    assert scheduler is not None
    return "scheduler OK"
check("4.scheduler导入", t4)

# 5. routes
def t5():
    from api_server.workflow_routes import router
    n = len(router.routes)
    assert n >= 20, f"路由数量异常: {n}"
    return f"routes: {n}"
check("5.routes导入", t5)

# 6. 端到端 DAG 执行：2步（step1无依赖，step2依赖step1）
def t6():
    from workflow.engine import dag_engine, StepStatus
    steps = [
        {"step_id": "step1", "name": "第一步", "action_type": "tool_call",
         "action_params": {"tool": "demo_tool", "value": 42}, "depends_on": []},
        {"step_id": "step2", "name": "第二步", "action_type": "tool_call",
         "action_params": {"tool": "demo_tool2"}, "depends_on": ["step1"]},
    ]
    inst = dag_engine.create_instance("e2e_test", "example.com", steps,
                                      description="端到端测试", params={})
    # 同步执行（dry-run，无外部执行器）
    dag_engine.run(inst.instance_id)

    s1 = inst.steps["step1"]
    s2 = inst.steps["step2"]
    assert s1.status == StepStatus.COMPLETED, f"step1 状态={s1.status}"
    assert s2.status == StepStatus.COMPLETED, f"step2 状态={s2.status}"
    # step2 必须在 step1 之后执行（start_time 单调）
    assert s2.start_time >= s1.start_time, "依赖顺序错误"
    # 聚合结果
    agg = inst.aggregated_result
    assert agg["summary"]["total_steps"] == 2
    assert agg["summary"]["completed"] == 2
    assert inst.status.value == "completed"
    return (f"2步DAG执行成功: step1={s1.status.value}, step2={s2.status.value}, "
            f"风险分={agg['risk_score']}, 耗时={agg['summary']['duration_seconds']}s")
check("6.端到端DAG执行", t6)

# 7. 模板实例化
def t7():
    from workflow.templates import instantiate_template
    wf = instantiate_template("web_security", "https://demo.example.com", {"extra": "x"})
    assert wf["steps"], "步骤为空"
    # 验证 {target} 已替换
    raw = json.dumps(wf, ensure_ascii=False)
    assert "https://demo.example.com" in raw
    assert "{target}" not in raw, "占位符未替换干净"
    return f"模板实例化: {len(wf['steps'])}步, target已替换"
check("7.模板实例化占位符", t7)

# 8. 调度器 cron 解析
def t8():
    from workflow.scheduler import _match_cron
    from datetime import datetime
    dt = datetime(2026, 9, 13, 10, 30)  # 周日
    assert _match_cron("30 10 * * *", dt) is True
    assert _match_cron("*/15 * * * *", dt) is True
    assert _match_cron("0 10 * * *", dt) is False
    return "cron 匹配 OK"
check("8.cron解析", t8)

print("\n" + "="*60)
passed = sum(1 for _, ok, _ in results if ok)
print(f"总计: {passed}/{len(results)} 通过")
sys.exit(0 if passed == len(results) else 1)
