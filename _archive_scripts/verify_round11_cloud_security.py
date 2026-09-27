# -*- coding: utf-8 -*-
"""第11轮云安全深化模块 import 验证脚本。"""
import sys
import os
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

files = [
    "cloud_security.aws_audit",
    "cloud_security.azure_audit",
    "cloud_security.aliyun_audit",
    "cloud_security.gcp_audit",
    "cloud_security.container_scanner",
    "cloud_security.k8s_security",
    "cloud_security.cloud_asset_discovery",
    "cloud_security.cloud_threat_detection",
]

ok = 0
for f in files:
    try:
        m = __import__(f, fromlist=["x"])
        if hasattr(m, "AWSAudit"):
            r = m.AWSAudit().run_audit()
            print(f"OK  {f}: rules={len(m.AWSAudit.RULES)}, findings={r['total_findings']}")
        elif hasattr(m, "AzureAudit"):
            r = m.AzureAudit().run_audit()
            print(f"OK  {f}: rules={len(m.AzureAudit.RULES)}, findings={r['total_findings']}")
        elif hasattr(m, "AliyunAudit"):
            r = m.AliyunAudit().run_audit()
            print(f"OK  {f}: rules={len(m.AliyunAudit.RULES)}, findings={r['total_findings']}")
        elif hasattr(m, "GCPAudit"):
            r = m.GCPAudit().run_audit()
            print(f"OK  {f}: rules={len(m.GCPAudit.RULES)}, findings={r['total_findings']}")
        elif hasattr(m, "ContainerScanner"):
            r = m.ContainerScanner(image="nginx:1.24").run_scan()
            print(f"OK  {f}: findings={r['total_findings']}")
        elif hasattr(m, "K8sSecurityAudit"):
            r = m.K8sSecurityAudit().run_audit()
            print(f"OK  {f}: rules={len(m.K8sSecurityAudit.RULES)}, findings={r['total_findings']}")
        elif hasattr(m, "CloudAssetDiscovery"):
            r = m.CloudAssetDiscovery().discover()
            print(f"OK  {f}: assets={r['total_assets']}, changes={len(r['changes'])}")
        elif hasattr(m, "CloudThreatDetection"):
            r = m.CloudThreatDetection().detect()
            print(f"OK  {f}: alerts={r['total_alerts']}, events={r['total_events']}")
        ok += 1
    except Exception as e:
        print(f"ERR {f}: {e}")
        traceback.print_exc()

print(f"--- {ok}/{len(files)} core modules OK ---")

# 验证 routes
try:
    from api_server import cloud_security_v2_routes
    routes = [r.path for r in cloud_security_v2_routes.router.routes]
    print(f"OK  api_server.cloud_security_v2_routes: {len(routes)} routes")
    for p in routes:
        print(f"    - {p}")
except Exception as e:
    print(f"ERR routes: {e}")
    traceback.print_exc()
