#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_round15_supply_chain.py — 第15轮供应链安全模块验证脚本。"""
from __future__ import annotations
import os, sys, re

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)
sys.path.insert(0, ROOT)

files = [
    "supply_chain/__init__.py",
    "supply_chain/sbom_manager.py",
    "supply_chain/component_analyzer.py",
    "supply_chain/vulnerability_detector.py",
    "supply_chain/license_compliance.py",
    "supply_chain/supplier_risk.py",
    "supply_chain/supply_chain_workflow.py",
    "api_server/supply_chain_routes.py",
    "api_server/supply_chain_console.html",
]

print("=== 文件统计 ===")
for f in files:
    path = os.path.join(ROOT, f)
    if os.path.exists(path):
        size = os.path.getsize(path)
        with open(path, "r", encoding="utf-8") as fh:
            lines = sum(1 for _ in fh)
        print(f"  {f:55s} {lines:5d} lines  {size:8d} bytes")
    else:
        print(f"  {f:55s} MISSING!")

print()
print("=== Import 验证 ===")
for mod in [
    "supply_chain.sbom_manager",
    "supply_chain.component_analyzer",
    "supply_chain.vulnerability_detector",
    "supply_chain.license_compliance",
    "supply_chain.supplier_risk",
    "supply_chain.supply_chain_workflow",
]:
    try:
        __import__(mod)
        print(f"  {mod:55s} OK")
    except Exception as e:
        print(f"  {mod:55s} FAIL: {e}")

try:
    from supply_chain import (
        SBOMManager, ComponentAnalyzer, VulnerabilityDetector,
        LicenseComplianceChecker, SupplierRiskAssessor,
        get_supply_chain_workflow, SUPPLY_CHAIN_STEPS,
    )
    print(f"  {'supply_chain (package)':55s} OK, steps={len(SUPPLY_CHAIN_STEPS)}")
except Exception as e:
    print(f"  {'supply_chain (package)':55s} FAIL: {e}")

try:
    from api_server.supply_chain_routes import router
    print(f"  {'api_server.supply_chain_routes':55s} OK, routes={len(router.routes)}")
except Exception as e:
    print(f"  {'api_server.supply_chain_routes':55s} FAIL: {e}")

print()
print("=== API 端点数 ===")
with open(os.path.join(ROOT, "api_server/supply_chain_routes.py"), "r", encoding="utf-8") as f:
    content = f.read()
endpoints = re.findall(r"@router\.(get|post|put|delete|patch)\(", content)
print(f"  总端点数: {len(endpoints)}")
from collections import Counter
print(f"  按方法: {dict(Counter(endpoints))}")

print()
html_path = os.path.join(ROOT, "api_server/supply_chain_console.html")
html_size = os.path.getsize(html_path)
print(f"前端页面大小: {html_size} bytes ({html_size/1024:.1f} KB)")
print(f"前端 > 10KB: {html_size > 10240}")

print()
print("=== 功能快速冒烟测试 ===")
try:
    mgr = SBOMManager()
    sboms = mgr.list_sboms()
    print(f"  SBOMManager: {len(sboms)} sample SBOMs loaded")
except Exception as e:
    print(f"  SBOMManager FAIL: {e}")

try:
    det = VulnerabilityDetector()
    r = det.scan([{"name": "log4j-core", "version": "2.14.1", "ecosystem": "maven"}])
    print(f"  VulnerabilityDetector: {r['total_vulnerabilities']} vulns found")
except Exception as e:
    print(f"  VulnerabilityDetector FAIL: {e}")

try:
    lc = LicenseComplianceChecker()
    r = lc.check([{"name": "test", "license": "MIT"}, {"name": "test2", "license": "GPL-3.0"}])
    print(f"  LicenseComplianceChecker: risk={r['overall_risk']}, score={r['commercial_friendly_score']}")
except Exception as e:
    print(f"  LicenseComplianceChecker FAIL: {e}")

try:
    sa = SupplierRiskAssessor()
    r = sa.assess_suppliers()
    print(f"  SupplierRiskAssessor: {r['suppliers_assessed']} suppliers assessed")
except Exception as e:
    print(f"  SupplierRiskAssessor FAIL: {e}")

try:
    wf = get_supply_chain_workflow()
    r = wf.run_assessment({"scan_id": "test-smoke"})
    print(f"  Workflow: risk={r['overall_risk']}, score={r['overall_score']}")
except Exception as e:
    print(f"  Workflow FAIL: {e}")

print()
print("=== 验证完成 ===")
