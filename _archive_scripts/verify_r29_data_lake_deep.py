#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证 data_lake_deep 模块"""
import sys
import os
import py_compile

ROOT = r"E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent"
os.chdir(ROOT)
sys.path.insert(0, ROOT)

errors = []

# 1. py_compile all .py files
files = [
    "data_lake_deep/__init__.py",
    "data_lake_deep/lake_architecture.py",
    "data_lake_deep/log_aggregation.py",
    "data_lake_deep/behavior_analysis.py",
    "data_lake_deep/ai_threat_detection.py",
    "data_lake_deep/data_mining.py",
    "data_lake_deep/data_lake_dashboard.py",
    "api_server/data_lake_deep_routes.py",
]

print("=" * 60)
print("1. py_compile 语法检查")
print("=" * 60)
for f in files:
    try:
        py_compile.compile(f, doraise=True)
        print(f"  PASS: {f}")
    except py_compile.PyCompileError as e:
        print(f"  FAIL: {f} — {e}")
        errors.append(f)

# 2. Independent import test
print()
print("=" * 60)
print("2. 模块独立 import 测试")
print("=" * 60)

modules = [
    "data_lake_deep",
    "data_lake_deep.lake_architecture",
    "data_lake_deep.log_aggregation",
    "data_lake_deep.behavior_analysis",
    "data_lake_deep.ai_threat_detection",
    "data_lake_deep.data_mining",
    "data_lake_deep.data_lake_dashboard",
]

for mod in modules:
    try:
        __import__(mod)
        print(f"  PASS: {mod}")
    except Exception as e:
        print(f"  FAIL: {mod} — {type(e).__name__}: {e}")
        errors.append(mod)

# 3. Count API endpoints
print()
print("=" * 60)
print("3. API 端点统计")
print("=" * 60)
with open("api_server/data_lake_deep_routes.py", "r", encoding="utf-8") as f:
    content = f.read()

import re
endpoints = re.findall(r'@router\.(get|post|put|delete|patch)\(', content)
print(f"  总端点数: {len(endpoints)}")
methods = {}
for m in endpoints:
    methods[m] = methods.get(m, 0) + 1
for k, v in sorted(methods.items()):
    print(f"    {k.upper()}: {v}")

# 4. HTML size
print()
print("=" * 60)
print("4. 前端 HTML 文件大小")
print("=" * 60)
html_size = os.path.getsize("api_server/data_lake_deep_console.html")
print(f"  HTML 大小: {html_size} bytes ({html_size/1024:.1f} KB)")
print(f"  要求 >15KB (15360 bytes): {'PASS' if html_size > 15360 else 'FAIL'}")

# 5. File listing
print()
print("=" * 60)
print("5. 交付文件清单")
print("=" * 60)
deliverables = [
    ("data_lake_deep/__init__.py", "包初始化"),
    ("data_lake_deep/lake_architecture.py", "数据湖架构"),
    ("data_lake_deep/log_aggregation.py", "日志聚合"),
    ("data_lake_deep/behavior_analysis.py", "行为分析UEBA"),
    ("data_lake_deep/ai_threat_detection.py", "AI威胁检测"),
    ("data_lake_deep/data_mining.py", "数据挖掘"),
    ("data_lake_deep/data_lake_dashboard.py", "控制台聚合层"),
    ("api_server/data_lake_deep_routes.py", "API路由"),
    ("api_server/data_lake_deep_console.html", "前端控制台"),
]
total_lines = 0
total_size = 0
for path, desc in deliverables:
    full = os.path.join(ROOT, path)
    if os.path.exists(full):
        with open(full, "r", encoding="utf-8") as f:
            lines = len(f.readlines())
        size = os.path.getsize(full)
        total_lines += lines
        total_size += size
        print(f"  {path:50s} {lines:5d} lines  {size:8d} bytes  ({desc})")
    else:
        print(f"  MISSING: {path}")
print(f"  {'TOTAL':50s} {total_lines:5d} lines  {total_size:8d} bytes")

# 6. Smoke test — functional demo
print()
print("=" * 60)
print("6. 功能冒烟测试")
print("=" * 60)

try:
    from data_lake_deep.lake_architecture import LakeArchitecture
    lake = LakeArchitecture()
    lake.initialize()
    # 真实数据接入
    result = lake.ingest_data("syslog", [
        {"src_ip": "192.168.1.1", "level": "info", "msg": "test"},
        {"src_ip": "192.168.1.2", "level": "warn", "msg": "test2"},
        {"src_ip": "192.168.1.1", "level": "info", "msg": "test"},  # duplicate
    ])
    assert result["records_received"] == 3
    assert result["duplicates_removed"] == 1
    print(f"  PASS: 数据接入+去重 — 接收{result['records_received']}条, 去重{result['duplicates_removed']}条")
except Exception as e:
    print(f"  FAIL: 数据接入 — {e}")
    errors.append("lake_ingest")

try:
    from data_lake_deep.log_aggregation import LogAggregationEngine
    log = LogAggregationEngine()
    parsed = log.parse_log('<134>Sep 16 10:30:00 host app[1234]: login failed for admin', "auto")
    print(f"  PASS: 日志解析 — parsed={parsed['parsed']}, fields={len(parsed['fields'])}")
except Exception as e:
    print(f"  FAIL: 日志解析 — {e}")
    errors.append("log_parse")

try:
    from data_lake_deep.behavior_analysis import BehaviorUEBAEngine
    ueba = BehaviorUEBAEngine()
    result = ueba.detect_anomaly("admin", {
        "event_type": "login", "hour": 3,
        "location": "Moscow", "device": "Unknown-Phone"
    })
    print(f"  PASS: 异常检测 — score={result['anomaly_score']}, level={result['risk_level']}, anomalies={result['anomalies_detected']}")
except Exception as e:
    print(f"  FAIL: 异常检测 — {e}")
    errors.append("ueba_detect")

try:
    from data_lake_deep.ai_threat_detection import AIThreatDetectionEngine
    ai = AIThreatDetectionEngine()
    result = ai.predict("if_login_anomaly", {"src_ip": "203.0.113.1", "user": "admin"})
    print(f"  PASS: AI推理 — score={result['anomaly_score']}, anomaly={result['is_anomaly']}, confidence={result['confidence']}")
except Exception as e:
    print(f"  FAIL: AI推理 — {e}")
    errors.append("ai_predict")

try:
    from data_lake_deep.data_mining import DataMiningEngine
    mining = DataMiningEngine()
    corr = mining.correlate_events()
    print(f"  PASS: 关联分析 — 分析{corr['events_analyzed']}事件, 发现{corr['correlations_found']}关联")
except Exception as e:
    print(f"  FAIL: 关联分析 — {e}")
    errors.append("mining_corr")

try:
    from data_lake_deep.data_lake_dashboard import DataLakeDashboard
    dash = DataLakeDashboard()
    overview = dash.get_overview()
    print(f"  PASS: 控制台聚合 — 模块数={len(overview['module_status'])}, KPI数={len(overview['kpi_cards'])}")
except Exception as e:
    print(f"  FAIL: 控制台聚合 — {e}")
    errors.append("dashboard")

# Summary
print()
print("=" * 60)
print("总结")
print("=" * 60)
if errors:
    print(f"  发现 {len(errors)} 个错误: {errors}")
else:
    print("  全部验证通过!")
print(f"  API 端点数: {len(endpoints)}")
print(f"  HTML 大小: {html_size/1024:.1f} KB")
print(f"  总代码行数: {total_lines}")
