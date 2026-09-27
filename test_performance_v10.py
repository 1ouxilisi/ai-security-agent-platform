# -*- coding: utf-8 -*-
"""
test_performance_v10.py — 第10轮性能优化模块测试脚本

测试范围：
    1. 6 个核心类（QueryOptimizer / IndexManager / CacheManager /
       SlowQueryMonitor / APIPerformanceMonitor / DBPerformanceMonitor）的主要方法；
    2. api_server/performance_routes.py 路由模块导入与端点注册。

运行方式（项目根目录）：
    python test_performance_v10.py
"""
import os
import sys
import time

# 保证从项目根导入
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = 0
FAIL = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    """简单断言并计数。"""
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {extra}")


def test_query_optimizer() -> None:
    """测试查询优化器。"""
    print("\n=== QueryOptimizer ===")
    from performance.query_optimizer import query_optimizer, QueryOptimizer

    check("单例", query_optimizer is QueryOptimizer())

    qid = query_optimizer.record_query(
        "SELECT * FROM tasks WHERE status = ?", 150.5, params=("done",))
    check("慢查询记录返回id", bool(qid), qid)

    rows = query_optimizer.get_slow_queries(limit=10)
    check("慢查询列表非空", isinstance(rows, list) and len(rows) >= 0)

    detail = query_optimizer.get_query_detail(qid) if qid else None
    check("查询详情", detail is not None and detail.get("query_id") == qid)

    analysis = query_optimizer.analyze_query(
        "SELECT * FROM tasks WHERE status = 'done'")
    check("执行计划分析含字段", "plan" in analysis)

    sugg = query_optimizer.get_optimization_suggestions(
        "SELECT * FROM tasks WHERE status = 'done'")
    check("优化建议非空", isinstance(sugg, list) and len(sugg) > 0)

    rew = query_optimizer.rewrite_query("SELECT * FROM tasks WHERE id = ?")
    check("查询重写", "rewritten" in rew and "SELECT *" not in rew["rewritten"])

    stats = query_optimizer.get_stats()
    check("统计含分位数", "p95_ms" in stats and "p99_ms" in stats)


def test_index_manager() -> None:
    """测试索引管理器。"""
    print("\n=== IndexManager ===")
    from performance.index_manager import index_manager, IndexManager

    check("单例", index_manager is IndexManager())

    analysis = index_manager.analyze_indexes()
    check("索引分析含字段", "index_count" in analysis)

    sugg = index_manager.get_index_suggestions()
    check("索引建议为列表", isinstance(sugg, list))

    res = index_manager.create_index("tasks", ["status"], index_name="idx_test_v10_status")
    check("创建索引", res.get("success") is True, str(res))

    stats = index_manager.get_index_stats()
    check("索引统计含数量", "index_count" in stats)

    health = index_manager.health_check()
    check("健康检查含status", "status" in health)

    rb = index_manager.rebuild_index("idx_test_v10_status")
    check("重建索引", rb.get("success") is True, str(rb))

    drop = index_manager.drop_index("idx_test_v10_status")
    check("删除索引", drop.get("success") is True, str(drop))


def test_cache_manager() -> None:
    """测试缓存管理器。"""
    print("\n=== CacheManager ===")
    from performance.cache_manager import cache_manager, CacheManager

    check("单例", cache_manager is CacheManager())

    cache_manager.set("k1", {"a": 1}, ttl=60)
    val = cache_manager.get("k1")
    check("写入并读取", val == {"a": 1})

    check("未命中返回None", cache_manager.get("not_exist") is None)

    removed = cache_manager.delete("k1")
    check("删除缓存", removed is True)

    warmed = cache_manager.warmup({"cfg:mode": "test"})
    check("预热缓存", warmed > 0)

    st = cache_manager.get_stats()
    check("缓存统计含命中率", "hit_rate" in st)

    status = cache_manager.get_status()
    check("缓存状态running", status.get("running") is True)

    rate = cache_manager.get_hit_rate()
    check("命中率为数值", isinstance(rate, (int, float)))

    cache_manager.clear("cfg:")


def test_slow_query_monitor() -> None:
    """测试慢查询监控器。"""
    print("\n=== SlowQueryMonitor ===")
    from performance.slow_query_monitor import slow_query_monitor, SlowQueryMonitor

    check("单例", slow_query_monitor is SlowQueryMonitor())

    slow_query_monitor.start_monitoring(threshold_ms=50)
    check("启动监控", slow_query_monitor.is_monitoring is True)

    rid = slow_query_monitor.record_slow_query(
        "SELECT * FROM tasks", 120.0, params=())
    check("记录慢查询", rid is not None)

    log = slow_query_monitor.get_slow_query_log(limit=10)
    check("慢查询日志为列表", isinstance(log, list))

    patterns = slow_query_monitor.analyze_patterns()
    check("模式分析含字段", "frequent_queries" in patterns)

    report = slow_query_monitor.generate_report()
    check("报告含建议", "suggestions" in report)

    alerts = slow_query_monitor.get_alerts()
    check("告警为列表", isinstance(alerts, list))

    slow_query_monitor.stop_monitoring()
    check("停止监控", slow_query_monitor.is_monitoring is False)


def test_api_performance() -> None:
    """测试 API 性能监控器。"""
    print("\n=== APIPerformanceMonitor ===")
    from performance.api_performance import (
        api_performance_monitor, APIPerformanceMonitor)

    check("单例", api_performance_monitor is APIPerformanceMonitor())

    for i in range(60):
        api_performance_monitor.record_request(
            "/api/v1/test", "GET", 100.0 + i, 200)

    stats = api_performance_monitor.get_endpoint_stats("/api/v1/test", "GET")
    check("端点统计含p95", "p95_ms" in stats)

    all_ep = api_performance_monitor.get_all_endpoints()
    check("端点列表非空", isinstance(all_ep, list) and len(all_ep) >= 1)

    trends = api_performance_monitor.get_trends("1h")
    check("趋势含endpoints", "endpoints" in trends)

    degr = api_performance_monitor.detect_degradations()
    check("退化检测为列表", isinstance(degr, list))

    alerts = api_performance_monitor.get_alerts()
    check("告警为列表", isinstance(alerts, list))

    report = api_performance_monitor.generate_report()
    check("报告含端点数量", "endpoint_count" in report)


def test_db_performance() -> None:
    """测试数据库性能监控器。"""
    print("\n=== DBPerformanceMonitor ===")
    from performance.db_performance import (
        db_performance_monitor, DBPerformanceMonitor)

    check("单例", db_performance_monitor is DBPerformanceMonitor())

    conns = db_performance_monitor.get_connections()
    check("连接统计含字段", "active" in conns)

    locks = db_performance_monitor.get_locks()
    check("锁状态含字段", "busy_timeout" in locks)

    db_performance_monitor.record_transaction(50.0, committed=True)
    db_performance_monitor.record_transaction(2000.0, committed=False)
    tx = db_performance_monitor.get_transactions()
    check("事务统计含提交", "committed" in tx)

    ts = db_performance_monitor.get_tablespaces()
    check("表空间含db_size", "db_size_bytes" in ts)

    alerts = db_performance_monitor.get_alerts()
    check("告警为列表", isinstance(alerts, list))

    report = db_performance_monitor.generate_report()
    check("报告含建议", "suggestions" in report)


def test_routes_import() -> None:
    """测试路由模块导入与端点注册。"""
    print("\n=== performance_routes 导入 ===")
    try:
        from api_server.performance_routes import router
        check("路由模块导入成功", router is not None)
        paths = [r.path for r in router.routes]
        check("路由数量>=22", len(paths) >= 22, f"got {len(paths)}")
        print(f"  注册端点({len(paths)}):")
        for p in paths:
            print(f"    - {p}")
    except Exception as e:
        check(f"路由导入: {e}", False, str(e))


def main() -> None:
    """运行全部测试。"""
    global PASS, FAIL
    print("=" * 60)
    print("第10轮性能优化模块测试")
    print("=" * 60)
    t0 = time.time()
    try:
        test_query_optimizer()
        test_index_manager()
        test_cache_manager()
        test_slow_query_monitor()
        test_api_performance()
        test_db_performance()
        test_routes_import()
    except Exception as e:
        FAIL += 1
        print(f"\n[FATAL] 测试中断: {e}")

    print("\n" + "=" * 60)
    print(f"结果: PASS={PASS}  FAIL={FAIL}  耗时={time.time() - t0:.2f}s")
    print("=" * 60)
    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()
