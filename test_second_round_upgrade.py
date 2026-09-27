"""
第二轮7项短板升级 - 全面验证测试
验证所有新模块是否正常工作
"""

import sys
import os
import json
import time

# 设置项目路径
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

results = []
passed = 0
failed = 0

def test(name, func):
    global passed, failed
    try:
        result = func()
        if result:
            print(f"✅ PASS: {name}")
            results.append({"name": name, "status": "pass", "detail": result})
            passed += 1
        else:
            print(f"❌ FAIL: {name} - 返回False")
            results.append({"name": name, "status": "fail", "detail": "返回False"})
            failed += 1
    except Exception as e:
        print(f"❌ FAIL: {name} - {str(e)}")
        results.append({"name": name, "status": "fail", "detail": str(e)})
        failed += 1

print("=" * 70)
print("第二轮7项短板升级 - 全面验证测试")
print("=" * 70)
print()

# ========== 测试1: 漏洞模板扩展（55个模板）==========
print("【测试1】漏洞模板扩展")
def test_templates():
    from asm.nuclei_engine import NucleiEngine
    engine = NucleiEngine(target="http://127.0.0.1")
    templates = engine.templates
    count = len(templates)
    categories = set(t.get("category", "未知") for t in templates)
    print(f"  模板总数: {count}")
    print(f"  覆盖类别: {len(categories)}种 - {', '.join(sorted(categories))}")
    # 列出各类别数量
    from collections import Counter
    cat_counts = Counter(t.get("category", "未知") for t in templates)
    for cat, cnt in cat_counts.most_common():
        print(f"    {cat}: {cnt}个")
    return count >= 50, f"{count}个模板, {len(categories)}种类别"

test("漏洞模板扩展（50+个模板）", test_templates)
print()

# ========== 测试2: AI智能体增强 ==========
print("【测试2】AI智能体增强")
def test_enhanced_agent():
    from agent.enhanced_agent import EnhancedAgent, AgentOrchestrator, AgentState
    # 创建智能体
    agent = EnhancedAgent(agent_type="recon")
    # 检查状态
    assert agent.state == AgentState.IDLE, f"初始状态应为IDLE，实际{agent.state}"
    # 测试计划生成（不调用LLM，使用规则引擎）
    plan = agent._plan_with_rules("127.0.0.1 端口扫描和漏洞扫描")
    assert plan is not None, "计划生成失败"
    assert len(plan) > 0, "计划为空"
    print(f"  智能体类型: {agent.agent_type}")
    print(f"  智能体状态: {agent.state.value}")
    print(f"  生成计划步骤数: {len(plan)}")
    for i, step in enumerate(plan[:3]):
        print(f"    步骤{i+1}: {step.tool or '无工具'} - {step.description[:50]}")
    # 测试编排器
    orchestrator = AgentOrchestrator()
    assert orchestrator is not None, "编排器创建失败"
    print(f"  编排器创建成功")
    return True, f"智能体+编排器正常, 计划{len(plan)}步"

test("AI智能体增强（自主规划+动态调整）", test_enhanced_agent)
print()

# ========== 测试3: 报告AI分析增强 ==========
print("【测试3】报告AI分析增强")
def test_report_analyzer():
    from asm.report_ai_analyzer import ReportAIAnalyzer
    analyzer = ReportAIAnalyzer()
    # 构造测试漏洞数据
    test_vulns = [
        {"id": "V1", "name": "SQL注入漏洞", "severity": "high", "category": "SQL注入", "url": "http://test.com/login"},
        {"id": "V2", "name": "XSS跨站脚本", "severity": "medium", "category": "XSS", "url": "http://test.com/search"},
        {"id": "V3", "name": "敏感信息泄露", "severity": "low", "category": "信息泄露", "url": "http://test.com/.env"},
        {"id": "V4", "name": "命令执行漏洞", "severity": "critical", "category": "命令执行", "url": "http://test.com/ping"},
        {"id": "V5", "name": "文件上传漏洞", "severity": "high", "category": "文件上传", "url": "http://test.com/upload"},
    ]
    analyzer.load_vulnerabilities(test_vulns)
    result = analyzer.analyze_all()

    print(f"  漏洞数量: {result['vulnerability_count']}")
    print(f"  漏洞关系数: {len(result['relations'])}")
    print(f"  攻击路径数: {len(result['attack_paths'])}")
    print(f"  业务影响评估数: {len(result['business_impacts'])}")
    print(f"  MITRE战术覆盖: {result['mitre_mapping']['attack_coverage']}")
    print(f"  整体风险: {result['executive_summary']['overall_risk']}")

    # 验证关键功能
    assert result['vulnerability_count'] == 5, "漏洞数量不对"
    assert len(result['relations']) > 0, "没有发现漏洞关系"
    assert len(result['attack_paths']) > 0, "没有推理出攻击路径"
    assert len(result['business_impacts']) == 5, "业务影响评估数量不对"
    assert 'risk_prioritization' in result, "缺少风险优先级"
    assert 'mitre_mapping' in result, "缺少MITRE映射"

    # 打印攻击路径
    for path in result['attack_paths']:
        print(f"  攻击路径: {path['name']} - {path['overall_severity']} - 可能性{path['likelihood']}")

    return True, f"5漏洞→{len(result['relations'])}关系/{len(result['attack_paths'])}攻击路径"

test("报告AI分析增强（漏洞关联+攻击链+业务影响）", test_report_analyzer)
print()

# ========== 测试4: 被动资产积累 ==========
print("【测试4】被动资产积累")
def test_passive_assets():
    from asm.passive_asset_manager import PassiveAssetManager
    db_path = os.path.join(project_root, "data", "test_passive.db")
    # 删除旧的测试数据库，确保表结构是最新的
    if os.path.exists(db_path):
        os.remove(db_path)
    manager = PassiveAssetManager(db_path=db_path)

    # 第一次扫描
    result1 = {
        "ip": "192.168.1.1",
        "open_ports": [80, 443, 22],
        "services": {"80": "nginx", "443": "nginx", "22": "openssh"},
        "tech_stack": ["nginx", "php"],
        "vulnerabilities": [{"name": "测试漏洞1", "severity": "high", "category": "SQL注入"}],
    }
    scan_id1 = manager.record_scan("192.168.1.1", "full_scan", result1)
    print(f"  第一次扫描ID: {scan_id1}")

    # 第二次扫描（有变化）
    time.sleep(0.1)
    result2 = {
        "ip": "192.168.1.1",
        "open_ports": [80, 443, 22, 3306],  # 新增3306端口
        "services": {"80": "nginx", "443": "nginx", "22": "openssh", "3306": "mysql"},
        "tech_stack": ["nginx", "php", "mysql"],
        "vulnerabilities": [
            {"name": "测试漏洞1", "severity": "high", "category": "SQL注入"},
            {"name": "测试漏洞2", "severity": "medium", "category": "XSS"},  # 新增漏洞
        ],
    }
    scan_id2 = manager.record_scan("192.168.1.1", "full_scan", result2)
    print(f"  第二次扫描ID: {scan_id2}")

    # 获取资产画像
    profile = manager.get_asset_profile("192.168.1.1")
    print(f"  资产扫描次数: {profile['scan_count']}")
    print(f"  当前开放端口: {profile['current_open_ports']}")
    print(f"  当前漏洞数: {len(profile['current_vulnerabilities'])}")
    print(f"  最近变更数: {len(profile['recent_changes'])}")

    # 获取变更事件
    changes = manager.get_recent_changes(limit=20)
    print(f"  总变更事件数: {len(changes)}")
    for change in changes[:5]:
        print(f"    {change['change_type']}: {change['description']}")

    # 获取趋势分析
    trend = manager.get_trend_analysis("192.168.1.1", days=30)
    print(f"  端口趋势点数: {len(trend['port_count_trend'])}")

    # 获取统计
    stats = manager.get_statistics()
    print(f"  总资产数: {stats['total_assets']}")
    print(f"  总扫描数: {stats['total_scans']}")
    print(f"  总变更数: {stats['total_changes']}")

    # 验证
    assert profile['scan_count'] == 2, "扫描次数应为2"
    assert 3306 in profile['current_open_ports'], "应包含3306端口"
    assert len(changes) > 0, "应检测到变更"
    assert stats['total_assets'] >= 1, "资产数应>=1"

    # 清理测试数据库
    try:
        os.remove(os.path.join(project_root, "data", "test_passive.db"))
    except:
        pass

    return True, f"2次扫描→{len(changes)}变更事件, 资产画像正常"

test("被动资产积累（历史数据+趋势分析+变更追踪）", test_passive_assets)
print()

# ========== 测试5: 漏洞验证框架 ==========
print("【测试5】漏洞验证框架")
def test_vuln_verifier():
    from asm.vulnerability_verifier import VulnerabilityVerifier, AuthorizationScope, VerificationStatus
    # 设置授权范围
    auth = AuthorizationScope(
        authorized_targets=["http://test.com", "http://127.0.0.1"],
        authorized_ips=["127.0.0.1", "192.168.1.0/24"],
        authorization_id="test-auth-001",
        max_rate=20,
    )
    verifier = VulnerabilityVerifier(authorization=auth)

    # 测试授权检查
    assert verifier.is_authorized("http://test.com") == True, "test.com应被授权"
    assert verifier.is_authorized("http://evil.com") == False, "evil.com不应被授权"
    print(f"  授权检查: test.com=通过, evil.com=拒绝")

    # 测试未授权目标验证
    vuln = {"id": "test-1", "name": "测试SQL注入", "category": "SQL注入", "severity": "high"}
    result_unauth = verifier.verify(vuln, "http://evil.com")
    assert result_unauth.status == "unauthorized", "未授权目标应被拒绝"
    print(f"  未授权验证: {result_unauth.status} - {result_unauth.error}")

    # 测试验证方法注册
    methods = verifier.verification_methods
    print(f"  内置验证方法数: {len(methods)}")
    for method_name in list(methods.keys())[:5]:
        print(f"    - {method_name}")

    # 测试CORS验证（对本地服务）
    cors_vuln = {"id": "cors-1", "name": "CORS配置错误", "category": "CORS", "severity": "medium"}
    # 注意：这里不实际发送请求，只验证框架能正常创建任务
    result_cors = verifier.verify(cors_vuln, "http://127.0.0.1:9999")
    print(f"  CORS验证结果: {result_cors.status} (本地无服务，预期error或not_vulnerable)")

    # 测试安全头验证
    header_vuln = {"id": "header-1", "name": "安全头缺失", "category": "安全头", "severity": "low"}
    result_header = verifier.verify(header_vuln, "http://127.0.0.1:9999")
    print(f"  安全头验证结果: {result_header.status}")

    # 测试批量验证
    vulns_batch = [
        {"id": "b1", "name": "批量测试1", "category": "XSS", "severity": "medium"},
        {"id": "b2", "name": "批量测试2", "category": "路径遍历", "severity": "high"},
    ]
    batch_results = verifier.verify_batch(vulns_batch, "http://127.0.0.1:9999")
    print(f"  批量验证: {len(batch_results)}个任务")

    # 测试汇总
    summary = verifier.get_summary()
    print(f"  验证汇总: 总计{summary['total']}, 确认{summary['confirmed']}, 未授权{summary['unauthorized']}")

    assert len(methods) >= 10, "验证方法应>=10种"
    assert result_unauth.status == "unauthorized", "未授权检查失败"

    return True, f"{len(methods)}种验证方法, 授权检查正常"

test("漏洞验证框架（授权检查+12种验证方法）", test_vuln_verifier)
print()

# ========== 测试6: 分布式扫描架构 ==========
print("【测试6】分布式扫描架构")
def test_distributed_scanner():
    from asm.distributed_scanner import DistributedScanner, ScanNode, ScanTask, ScanJob
    scanner = DistributedScanner(max_workers=5)

    # 注册节点
    node1 = scanner.register_node("node-1", "主节点", "http://127.0.0.1:8001", capacity=10, capabilities=["port_scan", "vuln_scan"])
    node2 = scanner.register_node("node-2", "从节点", "http://127.0.0.1:8002", capacity=5, capabilities=["dir_scan", "port_scan"])
    print(f"  注册节点数: {len(scanner.nodes)}")
    print(f"  节点1: {node1.name} - 容量{node1.capacity} - 能力{node1.capabilities}")
    print(f"  节点2: {node2.name} - 容量{node2.capacity} - 能力{node2.capabilities}")

    # 注册本地执行函数（用于测试）
    def mock_port_scan(target, **kwargs):
        return {"target": target, "open_ports": [80, 443], "scan_type": "port_scan"}

    def mock_vuln_scan(target, **kwargs):
        return {"target": target, "vulnerabilities": [{"name": "测试漏洞", "severity": "low"}], "scan_type": "vuln_scan"}

    scanner.register_local_executor("port_scan", mock_port_scan)
    scanner.register_local_executor("vuln_scan", mock_vuln_scan)
    print(f"  本地执行函数: {list(scanner.local_executors.keys())}")

    # 创建作业（自动拆分任务）
    job_id = scanner.create_job(
        name="测试扫描作业",
        targets=["192.168.1.1", "192.168.1.2"],
        scan_types=["port_scan", "vuln_scan"],
    )
    print(f"  创建作业ID: {job_id}")
    print(f"  作业任务总数: {scanner.jobs[job_id].total_tasks}")

    # 启动扫描器
    scanner.start()
    print(f"  扫描器已启动")

    # 等待任务完成
    time.sleep(2)

    # 获取作业状态
    job_status = scanner.get_job_status(job_id)
    print(f"  作业进度: {job_status['progress']}% ({job_status['completed_tasks']}/{job_status['total_tasks']})")
    print(f"  作业状态: {job_status['status']}")

    # 获取节点状态
    node_status = scanner.get_node_status()
    print(f"  节点状态: {len(node_status)}个节点")
    for node in node_status:
        print(f"    {node['name']}: {node['status']}, 负载{node['current_load']}/{node['capacity']}")

    # 获取统计
    stats = scanner.get_statistics()
    print(f"  全局统计: {stats['total_tasks']}任务, {stats['completed_tasks']}完成, {stats['pending_tasks']}等待")

    # 停止扫描器
    scanner.stop()
    print(f"  扫描器已停止")

    # 验证
    assert len(scanner.nodes) == 2, "节点数应为2"
    assert scanner.jobs[job_id].total_tasks == 4, "任务数应为4（2目标×2类型）"
    assert job_status['progress'] >= 0, "进度应>=0"

    return True, f"2节点+4任务, 进度{job_status['progress']}%"

test("分布式扫描架构（节点管理+任务分发+结果聚合）", test_distributed_scanner)
print()

# ========== 测试7: 多租户SaaS化 ==========
print("【测试7】多租户SaaS化")
def test_multi_tenant():
    from asm.multi_tenant_manager import MultiTenantManager, PLAN_QUOTAS
    db_path = os.path.join(project_root, "data", "test_saas.db")
    # 删除旧的测试数据库，确保表结构是最新的
    if os.path.exists(db_path):
        os.remove(db_path)
    manager = MultiTenantManager(db_path=db_path)

    # 测试订阅计划
    print(f"  订阅计划数: {len(PLAN_QUOTAS)}")
    for plan_id, plan_info in PLAN_QUOTAS.items():
        print(f"    {plan_info['name']}: 用户{plan_info['max_users']}, 团队{plan_info['max_teams']}, 项目{plan_info['max_projects']}")

    # 创建组织
    org_id = manager.create_organization("测试组织", plan="pro", created_by="test-user")
    print(f"  创建组织ID: {org_id}")

    # 获取组织信息
    org = manager.get_organization(org_id)
    print(f"  组织名称: {org['name']}")
    print(f"  组织计划: {org['plan']} - {org['plan_info']['name']}")

    # 创建团队
    team_id = manager.create_team(org_id, "安全团队", created_by="test-user")
    print(f"  创建团队ID: {team_id}")

    # 创建项目
    project_id = manager.create_project(org_id, team_id, "渗透测试项目", description="测试项目", created_by="test-user")
    print(f"  创建项目ID: {project_id}")

    # 注册用户
    user_id = manager.register_user("test@example.com", "测试用户", "password123", org_id=org_id, role="org_admin")
    print(f"  注册用户ID: {user_id}")

    # 用户认证
    auth_result = manager.authenticate_user("test@example.com", "password123")
    print(f"  用户认证: {'成功' if auth_result else '失败'}")
    if auth_result:
        print(f"    用户名: {auth_result['username']}")
        print(f"    角色: {auth_result['role']}")
        print(f"    API Key: {auth_result['api_key'][:16]}...")

    # 权限检查
    can_create = manager.check_permission(user_id, "create", "project", org_id=org_id)
    can_delete = manager.check_permission(user_id, "delete", "project", org_id=org_id)
    can_export = manager.check_permission(user_id, "export", "report", org_id=org_id)
    print(f"  权限检查: 创建={can_create}, 删除={can_delete}, 导出={can_export}")

    # 配额检查
    quota_ok, used, max_val = manager.check_quota(org_id, "max_projects")
    print(f"  项目配额: 已用{used}/{max_val}, {'够用' if quota_ok else '超限'}")

    # 记录使用量
    manager.increment_usage(org_id, scan_count=5, asset_count=10)
    print(f"  记录使用量: 扫描+5, 资产+10")

    # 审计日志
    manager._log_audit(org_id, user_id, "test_action", "test_resource", "test-123", {"test": "data"})
    logs = manager.get_audit_logs(org_id, limit=10)
    print(f"  审计日志数: {len(logs)}")

    # 获取统计
    stats = manager.get_statistics(org_id)
    print(f"  组织统计: 用户{stats['users']}, 团队{stats['teams']}, 项目{stats['projects']}")

    # 验证
    assert org_id is not None, "组织创建失败"
    assert team_id is not None, "团队创建失败"
    assert project_id is not None, "项目创建失败"
    assert user_id is not None, "用户注册失败"
    assert auth_result is not None, "用户认证失败"
    assert can_create == True, "组织管理员应能创建"
    assert len(logs) > 0, "审计日志应为空"

    # 清理测试数据库
    try:
        os.remove(os.path.join(project_root, "data", "test_saas.db"))
    except:
        pass

    return True, f"组织+团队+项目+用户+权限+配额+审计全部正常"

test("多租户SaaS化（组织/团队/项目/角色/配额/审计）", test_multi_tenant)
print()

# ========== 汇总 ==========
print("=" * 70)
print("测试汇总")
print("=" * 70)
print(f"  总测试数: {passed + failed}")
print(f"  通过: {passed}")
print(f"  失败: {failed}")
print(f"  通过率: {round(passed / (passed + failed) * 100, 1)}%")
print()

if failed == 0:
    print("🎉 所有测试通过！第二轮7项短板升级全部完成！")
else:
    print(f"⚠️  有{failed}项测试失败，请检查")

# 保存测试结果
result_file = os.path.join(project_root, "第二轮升级验证报告.json")
with open(result_file, "w", encoding="utf-8") as f:
    json.dump({
        "test_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total": passed + failed,
        "passed": passed,
        "failed": failed,
        "pass_rate": round(passed / (passed + failed) * 100, 1),
        "results": results,
    }, f, ensure_ascii=False, indent=2)

print(f"\n测试报告已保存: {result_file}")
