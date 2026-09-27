# -*- coding: utf-8 -*-
"""
test_visualization_v10.py —— 第10轮数据可视化深化模块测试脚本

测试范围：
    1. 4 个核心单例类的主要方法
       - RealtimeDashboard（realtime_dashboard）
       - Topology3D（topology_3d）
       - AttackMap（attack_map）
       - CustomDashboard（custom_dashboard）
    2. visualization/__init__.py 新导出
    3. api_server/visualization_v2_routes 路由模块导入与端点计数

运行：python test_visualization_v10.py
"""

import os
import sys

# 项目根目录入 sys.path
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    """断言辅助。"""
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}  {detail}")


def test_realtime_dashboard() -> None:
    """测试 RealtimeDashboard 主要方法。"""
    print("\n== RealtimeDashboard ==")
    from visualization.realtime_dashboard import realtime_dashboard, RealtimeDashboard

    data = realtime_dashboard.get_realtime_data()
    check("get_realtime_data 返回 dict", isinstance(data, dict))
    check("含 status", "status" in data)
    check("含 attack_map", "attack_map" in data)

    alerts = realtime_dashboard.get_alerts(limit=20)
    check("get_alerts(20) 长度<=20", isinstance(alerts, list) and len(alerts) <= 20)
    if alerts:
        check("告警含 severity/color", "severity" in alerts[0] and "color" in alerts[0])

    metrics = realtime_dashboard.get_metrics()
    check("get_metrics 含 MTTD/MTTR/SLA",
          all(k in metrics for k in ("mttd_seconds", "mttr_minutes", "sla_compliance", "fix_rate")))

    trends = realtime_dashboard.get_trends(hours=24)
    check("get_trends 含 event/alert/flow",
          all(k in trends for k in ("event_trend", "alert_trend", "flow_trend")))

    amap = realtime_dashboard.get_attack_map_data()
    check("攻击地图含 points/paths", "points" in amap and "paths" in amap)

    top_s = realtime_dashboard.get_top_attack_sources(10)
    check("TOP来源长度=10", len(top_s) == 10)
    top_t = realtime_dashboard.get_top_attack_types(10)
    check("TOP类型长度=10", len(top_t) == 10)

    layout = realtime_dashboard.get_layout_config()
    check("布局含深色主题", layout.get("theme", {}).get("background") == "#0a0e17")

    refreshed = realtime_dashboard.refresh_data()
    check("refresh_data 返回状态", isinstance(refreshed, dict) and "event_count" in refreshed)


def test_topology_3d() -> None:
    """测试 Topology3D 主要方法。"""
    print("\n== Topology3D ==")
    from visualization.topology_3d import topology_3d, SUPPORTED_LAYOUTS

    check("支持 4 种布局", set(SUPPORTED_LAYOUTS) == {"force", "hierarchical", "circular", "grid"})

    tid = topology_3d.generate(layout="force", options={"node_count": 12})
    check("generate 返回 topology_id", isinstance(tid, str) and tid.startswith("topo-"))

    data = topology_3d.get_data(tid)
    check("get_data 含 nodes/links", data and "nodes" in data and "links" in data)
    check("节点含 position", data and "position" in data["nodes"][0])

    for lay in ("circular", "hierarchical", "grid"):
        tid2 = topology_3d.generate(layout=lay)
        d = topology_3d.get_data(tid2)
        check(f"布局 {lay} 生成", d is not None and len(d["nodes"]) > 0)

    j = topology_3d.export_json(tid)
    check("export_json 为 dict", isinstance(j, dict))
    svg = topology_3d.export_svg(tid)
    check("export_svg 含 <svg", isinstance(svg, str) and "<svg" in svg)
    html = topology_3d.export_html(tid)
    check("export_html 含 <html", isinstance(html, str) and "<html" in html)

    clusters = topology_3d.cluster_nodes(data["nodes"], "type")
    check("cluster_nodes 返回 dict", isinstance(clusters, dict) and len(clusters) > 0)


def test_attack_map() -> None:
    """测试 AttackMap 主要方法。"""
    print("\n== AttackMap ==")
    from visualization.attack_map import attack_map

    loc = attack_map.geolocate_ip("8.8.8.8")
    check("geolocate_ip 返回国家/经纬度", "country" in loc and "lat" in loc)
    loc_cn = attack_map.geolocate_ip("114.114.114.114")
    check("国内 IP 定位为中国", loc_cn["country"] == "中国")

    mid = attack_map.generate(map_type="world")
    check("generate 返回 map_id", isinstance(mid, str) and mid.startswith("amap-"))

    data = attack_map.get_map_data(mid)
    check("get_map_data 含 sources/paths/stats",
          data and all(k in data for k in ("sources", "paths", "stats")))

    srcs = attack_map.get_attack_sources(mid, 10)
    check("get_attack_sources(10)", isinstance(srcs, list) and len(srcs) <= 10)
    tgts = attack_map.get_attack_targets(mid, 10)
    check("get_attack_targets(10)", isinstance(tgts, list))
    paths = attack_map.get_attack_paths(mid)
    check("get_attack_paths 含 source/target",
          isinstance(paths, list) and all("source" in p and "target" in p for p in paths[:1]))
    stats = attack_map.get_stats(mid)
    check("get_stats 含 total/by_type", "total_attacks" in stats and "by_type" in stats)

    csv_out = attack_map.export_csv(mid)
    check("export_csv 含表头", "attack_type" in csv_out)
    html = attack_map.export_html(mid)
    check("export_html 含 <html", "<html" in html)


def test_custom_dashboard() -> None:
    """测试 CustomDashboard 主要方法。"""
    print("\n== CustomDashboard ==")
    from visualization.custom_dashboard import custom_dashboard

    tpls = custom_dashboard.get_templates()
    check("5 个模板", isinstance(tpls, list) and len(tpls) == 5)
    comps = custom_dashboard.get_components()
    check("组件库 >=10 个", isinstance(comps, list) and len(comps) >= 10)

    dash = custom_dashboard.create_dashboard("测试仪表盘", template="安全运营")
    did = dash["id"]
    check("create_dashboard 含 id/components", "id" in dash and "components" in dash)

    got = custom_dashboard.get_dashboard(did)
    check("get_dashboard 一致", got and got["id"] == did)

    updated = custom_dashboard.update_dashboard(did, {"name": "改名后的仪表盘"})
    check("update_dashboard 生效", updated and updated["name"] == "改名后的仪表盘")

    lst = custom_dashboard.list_dashboards()
    check("list_dashboards 含 total/items", "total" in lst and "items" in lst)

    share = custom_dashboard.share_dashboard(did, expires_in_days=7)
    check("share_dashboard 含 token", "share_token" in share)
    shared = custom_dashboard.get_shared_dashboard(share["share_token"])
    check("get_shared_dashboard 可取", shared is not None and shared["id"] == did)

    exp = custom_dashboard.export_dashboard(did, "json")
    check("export_dashboard json", isinstance(exp, dict) and exp["id"] == did)
    rendered = custom_dashboard.render_dashboard(did)
    check("render_dashboard 含 <html", "<html" in rendered)

    ok = custom_dashboard.delete_dashboard(did)
    check("delete_dashboard 成功", ok is True)


def test_package_init() -> None:
    """测试 visualization/__init__.py 新导出。"""
    print("\n== visualization/__init__.py ==")
    import visualization
    for name in ("realtime_dashboard", "topology_3d", "attack_map", "custom_dashboard"):
        check(f"导出单例 {name}", hasattr(visualization, name))
    # 既有导出仍在
    for name in ("AttackPathGenerator", "NetworkTopologyGenerator",
                 "RiskHeatmapGenerator", "TrendAnalyzer"):
        check(f"既有导出 {name} 保留", hasattr(visualization, name))


def test_routes_import() -> None:
    """测试路由模块可导入、端点数量正确。"""
    print("\n== visualization_v2_routes ==")
    try:
        from api_server.visualization_v2_routes import router
        check("路由模块导入成功", router is not None)
        paths = [r.path for r in router.routes]
        check("路由前缀 /api/v1/visualization-v2", all(
            p.startswith("/api/v1/visualization-v2") for p in paths))
        print(f"  路由端点共 {len(paths)} 个：")
        for p in paths:
            print(f"     - {p}")
    except Exception as e:
        check("路由模块导入成功", False, str(e))


def main() -> int:
    """主入口。"""
    print("=" * 60)
    print("第10轮 数据可视化深化模块 测试")
    print("=" * 60)
    try:
        test_realtime_dashboard()
    except Exception as e:
        check("RealtimeDashboard 无异常", False, str(e))
    try:
        test_topology_3d()
    except Exception as e:
        check("Topology3D 无异常", False, str(e))
    try:
        test_attack_map()
    except Exception as e:
        check("AttackMap 无异常", False, str(e))
    try:
        test_custom_dashboard()
    except Exception as e:
        check("CustomDashboard 无异常", False, str(e))
    try:
        test_package_init()
    except Exception as e:
        check("__init__ 无异常", False, str(e))
    try:
        test_routes_import()
    except Exception as e:
        check("路由导入无异常", False, str(e))

    print("\n" + "=" * 60)
    print(f"结果：PASS={PASS}  FAIL={FAIL}")
    print("=" * 60)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
