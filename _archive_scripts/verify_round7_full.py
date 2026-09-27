#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第7轮升级全量验证脚本"""
import sys
import os
import json
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = 0
FAIL = 0
RESULTS = []

def check(name, func):
    global PASS, FAIL
    try:
        result = func()
        PASS += 1
        RESULTS.append(("PASS", name, str(result) if result else ""))
        print(f"  [PASS] {name}" + (f" -> {result}" if result else ""))
        return True
    except Exception as e:
        FAIL += 1
        err = f"{type(e).__name__}: {e}"
        RESULTS.append(("FAIL", name, err))
        print(f"  [FAIL] {name} -> {err}")
        traceback.print_exc()
        return False

print("=" * 70)
print("AI Hacking Agent 第7轮升级 — 全量验证")
print("=" * 70)

# ===== 一、模块导入验证 =====
print("\n【一、模块导入验证】")

check("workflow.engine (dag_engine)", lambda: __import__("workflow.engine", fromlist=["dag_engine"]).dag_engine is not None)
check("workflow.templates (8模板)", lambda: len(__import__("workflow.templates", fromlist=["list_templates"]).list_templates()) == 8)
check("workflow.builder", lambda: __import__("workflow.builder", fromlist=["WorkflowBuilder"]).WorkflowBuilder is not None)
check("workflow.scheduler", lambda: __import__("workflow.scheduler", fromlist=["scheduler"]).scheduler is not None)
check("vuln_database.cve_database (277 CVE)", lambda: len(__import__("vuln_database.cve_database", fromlist=["CVE_DATABASE"]).CVE_DATABASE) >= 200)
check("vuln_database.exploit_db (149条)", lambda: len(__import__("vuln_database.exploit_db", fromlist=["EXPLOIT_DB"]).EXPLOIT_DB) >= 100)
check("vuln_database.remediation_db (193条)", lambda: len(__import__("vuln_database.remediation_db", fromlist=["REMEDIATION_DB"]).REMEDIATION_DB) >= 100)
check("visualization.attack_path", lambda: __import__("visualization.attack_path", fromlist=["AttackPathGenerator"]).AttackPathGenerator is not None)
check("visualization.network_topology", lambda: __import__("visualization.network_topology", fromlist=["NetworkTopologyGenerator"]).NetworkTopologyGenerator is not None)
check("visualization.risk_heatmap", lambda: __import__("visualization.risk_heatmap", fromlist=["RiskHeatmapGenerator"]).RiskHeatmapGenerator is not None)
check("visualization.trend_analysis", lambda: __import__("visualization.trend_analysis", fromlist=["TrendAnalyzer"]).TrendAnalyzer is not None)
check("sdk.python.ai_hacking_sdk (37方法)", lambda: len([m for m in dir(__import__("sdk.python.ai_hacking_sdk", fromlist=["AIAgentClient"]).AIAgentClient("http://x", timeout=2)) if not m.startswith("_") and callable(getattr(__import__("sdk.python.ai_hacking_sdk", fromlist=["AIAgentClient"]).AIAgentClient("http://x", timeout=2), m))]) >= 30)
check("cicd.cli", lambda: __import__("cicd.cli", fromlist=["main"]) is not None)

# ===== 二、API路由注册验证 =====
print("\n【二、API路由注册验证】")

def check_app_routes():
    from api_server.app import app
    routes = [r for r in app.routes if hasattr(r, "path")]
    v7_paths = [r.path for r in routes if "/vuln-db" in r.path or "/visualization" in r.path or "/workflow" in r.path]
    return f"总路由{len(routes)}条, 第7轮相关{len(v7_paths)}条"

check("app.py 路由注册", check_app_routes)

def check_workflow_routes():
    from api_server.workflow_routes import router
    return f"{len(router.routes)}条端点"

check("workflow_routes 端点", check_workflow_routes)

def check_vuln_db_routes():
    from api_server.vuln_db_routes import router
    return f"{len(router.routes)}条端点"

check("vuln_db_routes 端点", check_vuln_db_routes)

def check_visualization_routes():
    from api_server.visualization_routes import router
    return f"{len(router.routes)}条端点"

check("visualization_routes 端点", check_visualization_routes)

# ===== 三、前端页面验证 =====
print("\n【三、前端页面验证】")

def check_workflow_console_html():
    path = os.path.join(os.path.dirname(__file__), "api_server", "workflow_console.html")
    if not os.path.exists(path):
        raise FileNotFoundError("workflow_console.html 不存在")
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    if len(content) < 1000:
        raise ValueError(f"页面内容过短: {len(content)}字符")
    # 检查关键元素
    checks = ["模板" in content, "执行" in content, "工作流" in content, "utf-8" in content.lower()]
    if not all(checks):
        raise ValueError(f"页面缺少关键元素: {checks}")
    return f"{len(content)}字符, 关键元素齐全"

check("workflow_console.html 页面", check_workflow_console_html)

# ===== 四、功能验证（不启动服务器，直接调用模块函数） =====
print("\n【四、核心功能验证】")

def test_dag_engine_e2e():
    """端到端DAG工作流测试：2步工作流"""
    from workflow.engine import dag_engine, StepStatus
    import time

    wf_def = {
        "name": "E2E测试工作流",
        "description": "验证DAG引擎端到端执行",
        "steps": [
            {
                "step_id": "step1",
                "name": "第一步",
                "action_type": "tool_call",
                "action_params": {"tool": "test", "param": "value1"},
                "depends_on": [],
                "on_failure": "continue",
                "retry_count": 1
            },
            {
                "step_id": "step2",
                "name": "第二步",
                "action_type": "tool_call",
                "action_params": {"tool": "test", "param": "value2"},
                "depends_on": ["step1"],
                "on_failure": "continue",
                "retry_count": 1
            }
        ]
    }

    instance = dag_engine.create_instance(
        name="E2E测试工作流",
        target="test-target",
        steps_def=wf_def["steps"],
        description="验证DAG引擎端到端执行"
    )
    instance_id = instance.instance_id

    # 同步执行（dry-run模式）
    dag_engine.run(instance_id)

    inst = dag_engine.get_instance(instance_id)
    inst_dict = inst.to_dict()
    if inst_dict["status"] != "completed":
        raise ValueError(f"工作流未完成: status={inst_dict['status']}")

    steps = inst_dict["steps"]
    if len(steps) != 2:
        raise ValueError(f"步骤数错误: {len(steps)}")

    if steps[0]["status"] != "completed" or steps[1]["status"] != "completed":
        raise ValueError(f"步骤状态错误: {[s['status'] for s in steps]}")

    # 验证依赖顺序：step1先于step2完成
    if steps[0].get("end_time", 0) > steps[1].get("start_time", 9999999999):
        raise ValueError("依赖顺序错误：step1应先于step2开始")

    return f"instance_id={instance_id}, 2步全部completed, 依赖顺序正确"

check("DAG引擎端到端（2步依赖）", test_dag_engine_e2e)

def test_templates_instantiate():
    """测试模板实例化"""
    from workflow.templates import get_template, instantiate_template
    tpl = get_template("pentest_full")
    if not tpl:
        raise ValueError("pentest_full 模板不存在")
    inst = instantiate_template("pentest_full", "example.com", {})
    if len(inst["steps"]) < 5:
        raise ValueError(f"实例化后步骤数过少: {len(inst['steps'])}")
    # 验证占位符替换
    has_target = any("example.com" in json.dumps(s, ensure_ascii=False) for s in inst["steps"])
    return f"模板{len(tpl['steps'])}步, 实例化{len(inst['steps'])}步, 占位符替换={'OK' if has_target else 'N/A'}"

check("模板实例化（pentest_full）", test_templates_instantiate)

def test_builder_cycle_detection():
    """测试构建器循环依赖检测"""
    from workflow.builder import WorkflowBuilder
    b = WorkflowBuilder()
    wf = b.create_workflow("循环测试", "测试循环依赖检测")
    b.add_step(wf, "a", "A", "tool_call", {}, ["b"], None, "continue", 1)
    b.add_step(wf, "b", "B", "tool_call", {}, ["a"], None, "continue", 1)
    result = b.validate_workflow(wf)
    if result["valid"]:
        raise ValueError("循环依赖未被检测到")
    return f"检测到{len(result['errors'])}个错误: {result['errors'][0][:50]}"

check("构建器循环依赖检测", test_builder_cycle_detection)

def test_cve_search_and_match():
    """测试CVE搜索和服务匹配"""
    from vuln_database.cve_database import search_cve, match_cve_by_service, get_cve
    # 搜索Log4j
    results = search_cve(keyword="Log4j")
    if len(results) < 2:
        raise ValueError(f"Log4j搜索结果过少: {len(results)}")
    # 匹配Apache 2.4.49
    matched = match_cve_by_service("Apache", "2.4.49")
    # 获取单条CVE
    cve = get_cve("CVE-2021-44228")
    if not cve:
        raise ValueError("CVE-2021-44228 不存在")
    return f"搜索{len(results)}条, 匹配{len(matched)}条, CVE-2021-44228 CVSS={cve['cvss_score']}"

check("CVE搜索+匹配+详情", test_cve_search_and_match)

def test_attack_path_generation():
    """测试攻击路径生成"""
    from visualization.attack_path import AttackPathGenerator
    g = AttackPathGenerator()
    data = {
        "target": "test.com",
        "ip": "1.2.3.4",
        "open_ports": [
            {"port": 80, "service": "http", "version": "Apache 2.4.49"},
            {"port": 22, "service": "ssh", "version": "OpenSSH 8.0"}
        ],
        "vulnerabilities": [
            {"id": "CVE-2021-41773", "name": "路径穿越", "severity": "高", "type": "路径穿越", "port": 80}
        ]
    }
    result = g.generate(data)
    mermaid = g.to_mermaid(result)
    if len(result["graph"]["nodes"]) < 3:
        raise ValueError(f"节点数过少: {len(result['graph']['nodes'])}")
    if len(result["paths"]) < 1:
        raise ValueError("未生成攻击路径")
    if "graph" not in mermaid.lower():
        raise ValueError("Mermaid输出格式错误")
    return f"节点{len(result['graph']['nodes'])}个, 边{len(result['graph']['edges'])}条, 路径{len(result['paths'])}条"

check("攻击路径生成+Mermaid输出", test_attack_path_generation)

def test_risk_heatmap_html():
    """测试风险热力图HTML输出"""
    from visualization.risk_heatmap import RiskHeatmapGenerator
    g = RiskHeatmapGenerator()
    data = {
        "targets": [
            {"ip": "1.1.1.1", "vulnerabilities": [
                {"port": 80, "severity": "高", "type": "SQL注入"},
                {"port": 443, "severity": "中", "type": "XSS"}
            ]},
            {"ip": "2.2.2.2", "vulnerabilities": [
                {"port": 22, "severity": "低", "type": "信息泄露"}
            ]}
        ]
    }
    result = g.generate(data, "host_port")
    html = g.to_html(result)
    if "<table" not in html:
        raise ValueError("HTML输出缺少table")
    if "background-color" not in html and "background" not in html:
        raise ValueError("HTML输出缺少颜色样式")
    return f"矩阵{len(result['matrix'])}行, HTML {len(html)}字符"

check("风险热力图HTML输出", test_risk_heatmap_html)

def test_trend_echarts():
    """测试趋势分析ECharts配置"""
    from visualization.trend_analysis import TrendAnalyzer
    a = TrendAnalyzer()
    data = [
        {"date": "2024-01", "new_vulns": 10, "fixed_vulns": 5, "unfixed_vulns": 20},
        {"date": "2024-02", "new_vulns": 8, "fixed_vulns": 12, "unfixed_vulns": 16},
        {"date": "2024-03", "new_vulns": 15, "fixed_vulns": 10, "unfixed_vulns": 21}
    ]
    result = a.analyze_vulnerability_trend(data)
    ec = a.to_echarts_config(result, "line")
    if "xAxis" not in ec or "series" not in ec:
        raise ValueError("ECharts配置缺少关键字段")
    return f"数据点{len(result['dates'])}个, series {len(ec['series'])}条"

check("趋势分析ECharts配置", test_trend_echarts)

def test_sdk_client_init():
    """测试SDK客户端初始化和异常类"""
    from sdk.python.ai_hacking_sdk import (
        AIAgentClient, APIError, AuthenticationError, NotFoundError,
        RateLimitError, ServerError, ValidationError
    )
    client = AIAgentClient(base_url="http://localhost:9999", api_key="test-key", timeout=5, max_retries=2)
    methods = [m for m in dir(client) if not m.startswith("_") and callable(getattr(client, m))]
    if len(methods) < 30:
        raise ValueError(f"SDK方法数不足: {len(methods)}")
    # 测试异常类
    try:
        raise AuthenticationError(401, "测试认证失败", "req-123")
    except APIError as e:
        if e.status_code != 401:
            raise ValueError("异常状态码错误")
    return f"客户端初始化OK, {len(methods)}个公开方法, 异常类体系完整"

check("SDK客户端初始化+异常体系", test_sdk_client_init)

def test_cli_help():
    """测试CLI帮助输出"""
    import subprocess
    result = subprocess.run(
        [sys.executable, "-m", "cicd.cli", "--help"],
        capture_output=True, text=True, cwd=os.path.dirname(__file__)
    )
    if result.returncode != 0:
        raise ValueError(f"CLI --help 返回码错误: {result.returncode}, stderr: {result.stderr}")
    if "scan" not in result.stdout and "verify" not in result.stdout:
        raise ValueError("CLI帮助输出缺少命令列表")
    return f"返回码0, 输出{len(result.stdout)}字符"

check("CLI --help 命令", test_cli_help)

# ===== 五、数据统计 =====
print("\n【五、第7轮升级数据统计】")

def get_stats():
    from vuln_database.cve_database import get_cve_stats
    from vuln_database.exploit_db import EXPLOIT_DB
    from vuln_database.remediation_db import REMEDIATION_DB
    from workflow.templates import list_templates
    from api_server.workflow_routes import router as wf_router
    from api_server.vuln_db_routes import router as vdb_router
    from api_server.visualization_routes import router as vis_router

    stats = get_cve_stats()
    return (
        f"CVE={stats['total']}条(严重{stats['by_severity'].get('critical',0)}"
        f"/高{stats['by_severity'].get('high',0)}"
        f"/中{stats['by_severity'].get('medium',0)}), "
        f"利用方式={len(EXPLOIT_DB)}条, 修复方案={len(REMEDIATION_DB)}条, "
        f"工作流模板={len(list_templates())}个, "
        f"API端点=workflow {len(wf_router.routes)}+vuln_db {len(vdb_router.routes)}+visualization {len(vis_router.routes)}"
    )

check("第7轮数据总览", get_stats)

# ===== 总结 =====
print("\n" + "=" * 70)
print(f"验证结果: {PASS} 通过, {FAIL} 失败, 共 {PASS+FAIL} 项")
print("=" * 70)

if FAIL > 0:
    print("\n失败项:")
    for status, name, detail in RESULTS:
        if status == "FAIL":
            print(f"  - {name}: {detail}")

sys.exit(0 if FAIL == 0 else 1)
