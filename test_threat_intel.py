# -*- coding: utf-8 -*-
"""
威胁情报集成模块 - 自测脚本

验证内容：
    1. 模块导入
    2. 数据库表创建
    3. 数据初始化数量（IOC/Actor/狩猎规则）
    4. 核心方法调用（IOC匹配/Actor查询/狩猎启动）
    5. API路由导入
"""
import os
import sys
import json

# 确保项目根目录在path中
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

# 测试结果收集
test_results = []

def test(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    test_results.append({"name": name, "status": status, "detail": detail})
    print(f"  [{status}] {name}" + (f" - {detail}" if detail else ""))


print("=" * 60)
print("  威胁情报集成模块 - 自测")
print("=" * 60)
print()

# ==================== 1. 模块导入测试 ====================
print("【1. 模块导入测试】")

try:
    from threat_intel.ioc_manager import IOCManager
    test("导入 IOCManager", True)
except Exception as e:
    test("导入 IOCManager", False, str(e))

try:
    from threat_intel.threat_actor import ThreatActorManager
    test("导入 ThreatActorManager", True)
except Exception as e:
    test("导入 ThreatActorManager", False, str(e))

try:
    from threat_intel.sample_analyzer import SampleAnalyzer
    test("导入 SampleAnalyzer", True)
except Exception as e:
    test("导入 SampleAnalyzer", False, str(e))

try:
    from threat_intel.threat_hunting import ThreatHuntingManager
    test("导入 ThreatHuntingManager", True)
except Exception as e:
    test("导入 ThreatHuntingManager", False, str(e))

try:
    from threat_intel import ioc_manager, threat_actor, sample_analyzer, threat_hunting
    test("导入 threat_intel包", True)
except Exception as e:
    test("导入 threat_intel包", False, str(e))

print()

# ==================== 2. IOC管理器测试 ====================
print("【2. IOC管理器测试】")

try:
    ioc_mgr = IOCManager()
    test("初始化 IOCManager", True)
except Exception as e:
    test("初始化 IOCManager", False, str(e))
    ioc_mgr = None

if ioc_mgr:
    # IOC统计
    try:
        stats = ioc_mgr.get_ioc_stats()
        ioc_count = stats.get("total_iocs", 0)
        test("IOC总数 >= 500", ioc_count >= 500, f"当前: {ioc_count}")
        test("IOC来源数 >= 5", stats.get("sources_count", 0) >= 5, f"当前: {stats.get('sources_count')}")
        test("白名单数 >= 5", stats.get("whitelist_count", 0) >= 5, f"当前: {stats.get('whitelist_count')}")
    except Exception as e:
        test("IOC统计", False, str(e))

    # IOC列表查询
    try:
        result = ioc_mgr.list_iocs(page=1, page_size=5)
        test("IOC列表查询", result.get("total", 0) > 0, f"total={result.get('total')}")
    except Exception as e:
        test("IOC列表查询", False, str(e))

    # IOC搜索
    try:
        results = ioc_mgr.search_ioc("malware")
        test("IOC模糊搜索", len(results) >= 0, f"找到 {len(results)} 条")
    except Exception as e:
        test("IOC模糊搜索", False, str(e))

    # IOC批量匹配
    try:
        match_result = ioc_mgr.match_iocs([
            {"type": "ip", "value": "185.244.25.10"},
            {"type": "ip", "value": "8.8.8.8"},
            {"type": "domain", "value": "nonexistent-domain-xyz123.xyz"},
        ])
        matched = match_result.get("matched_count", 0)
        test("IOC批量匹配", matched >= 1, f"匹配 {matched}/3")
    except Exception as e:
        test("IOC批量匹配", False, str(e))

    # 白名单检查
    try:
        is_whitelisted = ioc_mgr.check_whitelist("8.8.8.8")
        test("白名单检查", is_whitelisted, "8.8.8.8 应在白名单")
    except Exception as e:
        test("白名单检查", False, str(e))

    # IOC来源列表
    try:
        sources = ioc_mgr.list_sources()
        test("IOC来源列表", len(sources) >= 5, f"共 {len(sources)} 个来源")
    except Exception as e:
        test("IOC来源列表", False, str(e))

print()

# ==================== 3. 威胁Actor测试 ====================
print("【3. 威胁Actor测试】")

try:
    actor_mgr = ThreatActorManager()
    test("初始化 ThreatActorManager", True)
except Exception as e:
    test("初始化 ThreatActorManager", False, str(e))
    actor_mgr = None

if actor_mgr:
    try:
        stats = actor_mgr.get_actor_stats()
        actor_count = stats.get("total_actors", 0)
        test("Actor总数 >= 50", actor_count >= 50, f"当前: {actor_count}")
    except Exception as e:
        test("Actor统计", False, str(e))

    try:
        result = actor_mgr.list_actors(page=1, page_size=5)
        test("Actor列表查询", result.get("total", 0) > 0, f"total={result.get('total')}")
    except Exception as e:
        test("Actor列表查询", False, str(e))

    try:
        results = actor_mgr.search_actors("Lazarus")
        test("Actor搜索", len(results) >= 1, f"找到 {len(results)} 个")
    except Exception as e:
        test("Actor搜索", False, str(e))

    try:
        # 获取第一个actor的TTP
        actors = actor_mgr.list_actors(page=1, page_size=1)
        if actors.get("items"):
            actor_id = actors["items"][0]["id"]
            ttp_result = actor_mgr.get_actor_ttps(actor_id)
            test("Actor TTP查询", "tactics" in ttp_result, f"战术数: {len(ttp_result.get('tactics', {}))}")
        else:
            test("Actor TTP查询", False, "无Actor数据")
    except Exception as e:
        test("Actor TTP查询", False, str(e))

print()

# ==================== 4. 样本分析器测试 ====================
print("【4. 样本分析器测试】")

try:
    analyzer = SampleAnalyzer()
    test("初始化 SampleAnalyzer", True)
except Exception as e:
    test("初始化 SampleAnalyzer", False, str(e))
    analyzer = None

if analyzer:
    # 分析一个模拟的可疑脚本
    try:
        malicious_script = b"""
        var shell = WScript.CreateObject("WScript.Shell");
        shell.Run("cmd.exe /c powershell -enc SQBFAFgA...");
        var url = "http://malware-c2.xyz/download.exe";
        """
        result = analyzer.analyze_sample(file_content=malicious_script, file_name="test.js")
        test("样本静态分析", result.get("verdict") in ("malicious", "suspicious"),
             f"verdict={result.get('verdict')}, score={result.get('score')}")
    except Exception as e:
        test("样本静态分析", False, str(e))

    # IOC提取测试
    try:
        sample_data = b"""
        IP: 185.244.25.10
        Domain: malware-c2.xyz
        URL: http://malware-c2.xyz/payload.exe
        """
        iocs = analyzer.extract_iocs(sample_data)
        test("IOC提取", len(iocs) >= 2, f"提取到 {len(iocs)} 个IOC")
    except Exception as e:
        test("IOC提取", False, str(e))

print()

# ==================== 5. 威胁狩猎测试 ====================
print("【5. 威胁狩猎测试】")

try:
    hunt_mgr = ThreatHuntingManager()
    test("初始化 ThreatHuntingManager", True)
except Exception as e:
    test("初始化 ThreatHuntingManager", False, str(e))
    hunt_mgr = None

if hunt_mgr:
    try:
        rules = hunt_mgr.list_rules(page=1, page_size=100)
        rule_count = rules.get("total", 0)
        test("狩猎规则数 >= 20", rule_count >= 20, f"当前: {rule_count}")
    except Exception as e:
        test("狩猎规则统计", False, str(e))

    try:
        result = hunt_mgr.start_hunting()
        test("启动狩猎任务", result.get("success", False),
             f"task_id={result.get('task_id')}, results={result.get('results_count')}")
        task_id = result.get("task_id")

        if task_id:
            # 查询状态
            import time
            time.sleep(0.5)
            status = hunt_mgr.get_hunting_status(task_id)
            test("狩猎状态查询", status is not None, f"status={status.get('status') if status else 'N/A'}")

            # 查询结果
            results = hunt_mgr.get_hunting_results(task_id, page=1, page_size=5)
            test("狩猎结果查询", "items" in results, f"total={results.get('total')}")

            # 生成报告
            report = hunt_mgr.generate_hunting_report(task_id)
            test("生成狩猎报告", "analysis" in report, f"total_results={report.get('total_results')}")
    except Exception as e:
        test("狩猎任务流程", False, str(e))

    try:
        dashboard = hunt_mgr.get_hunting_dashboard()
        test("狩猎仪表盘", "overview" in dashboard,
             f"rules={dashboard['overview'].get('total_rules')}")
    except Exception as e:
        test("狩猎仪表盘", False, str(e))

print()

# ==================== 6. API路由导入测试 ====================
print("【6. API路由导入测试】")

try:
    from api_server.threat_intel_routes import router
    test("导入 threat_intel_routes.router", True, f"prefix={router.prefix}")
    # 统计端点数量
    routes = [r for r in router.routes]
    test("API端点数量 >= 15", len(routes) >= 15, f"当前: {len(routes)} 个端点")
except Exception as e:
    test("导入 threat_intel_routes", False, str(e))

print()

# ==================== 7. 数据库表验证 ====================
print("【7. 数据库表验证】")

try:
    from utils.database import db
    conn = db._get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'ti_%'")
    tables = [row[0] for row in cursor.fetchall()]
    conn.close()
    test("ti_开头的表数量 >= 7", len(tables) >= 7, f"共 {len(tables)} 张: {', '.join(tables)}")
except Exception as e:
    test("数据库表查询", False, str(e))

print()

# ==================== 汇总 ====================
print("=" * 60)
passed = sum(1 for r in test_results if r["status"] == "PASS")
failed = sum(1 for r in test_results if r["status"] == "FAIL")
total = len(test_results)

print(f"  总计: {total} 项, 通过: {passed}, 失败: {failed}")
print("=" * 60)

if failed > 0:
    print("\n失败项详情:")
    for r in test_results:
        if r["status"] == "FAIL":
            print(f"  - {r['name']}: {r['detail']}")

sys.exit(0 if failed == 0 else 1)
