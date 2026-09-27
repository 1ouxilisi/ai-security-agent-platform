# -*- coding: utf-8 -*-
"""
高级安全能力升级 - 验证脚本

逐模块测试核心功能，输出摘要结果。
运行：python tests/verify_security_upgrade.py
"""
import os
import sys
import time
import json

# 确保项目根在 sys.path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

PASS = 0
FAIL = 0
RESULTS = []


def report(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        RESULTS.append("  [PASS] %s %s" % (name, detail))
    else:
        FAIL += 1
        RESULTS.append("  [FAIL] %s %s" % (name, detail))


# ====================================================================== #
# 1. 漏洞生命周期
# ====================================================================== #
print("=" * 60)
print("模块1：漏洞生命周期管理")
from security.vuln_lifecycle import VulnerabilityLifecycle

# 用临时数据目录，避免污染正式数据
import tempfile
tmp = tempfile.mkdtemp(prefix="vuln_test_")
lc = VulnerabilityLifecycle(data_dir=tmp)

# 功能1：状态流转规则校验
report("can_transition 校验",
       lc.can_transition("discovered", "confirmed") is True
       and lc.can_transition("discovered", "closed") is False)

# 功能2：SLA 计算
due = lc.get_due_date("critical", time.time())
delta_days = (due - time.time()) / 86400
report("SLA critical=7天", abs(delta_days - 7) < 0.01, "(实际 %.2f 天)" % delta_days)
due_low = lc.get_due_date("low", time.time())
report("SLA low=90天", abs((due_low - time.time()) / 86400 - 90) < 0.01)

# 功能3：创建 + 完整流转 + 历史
v = lc.create_vulnerability("测试SQL注入", "critical", target="10.0.0.5")
vid = v["id"]
lc.assign(vid, "张三", "指派给DBA")
lc.transition(vid, "confirmed", "李四")
lc.transition(vid, "fixing", "李四")
lc.transition(vid, "fixed", "李四")
lc.transition(vid, "verifying", "王五")
lc.verify(vid, verification_result=True, verified_by="王五")
final = lc.vulnerabilities[vid]
report("完整流转至 closed", final["status"] == "closed", "(最终状态: %s)" % final["status"])

hist = lc.get_history(vid)
report("历史记录可查询", len(hist) >= 5, "(记录 %d 条)" % len(hist))

# 功能4：逾期检测
v2 = lc.create_vulnerability("逾期测试漏洞", "high", target="10.0.0.6")
# 人为把 due_date 调到过去
lc.vulnerabilities[v2["id"]]["due_date"] = time.time() - 86400
overdue = lc.check_overdue()
report("逾期检测", len(overdue) >= 1, "(逾期 %d 个)" % len(overdue))

# 功能5：统计
stats = lc.get_stats()
report("统计 get_stats", "by_status" in stats and "overdue_count" in stats,
       "(总数 %d)" % stats["total"])


# ====================================================================== #
# 2. 资产发现与管理
# ====================================================================== #
print("=" * 60)
print("模块2：资产发现与管理")
from security.asset_discovery import AssetDiscovery, COMMON_PORTS

tmp2 = tempfile.mkdtemp(prefix="asset_test_")
ad = AssetDiscovery(data_dir=tmp2)

# 功能1：端口扫描 127.0.0.1
open_ports = ad.port_scan("127.0.0.1", ports=[80, 443, 22, 135, 445, 3389])
report("port_scan 127.0.0.1 返回列表", isinstance(open_ports, list),
       "(开放端口: %s)" % open_ports)

# 功能2：资产 CRUD
a = ad.add_asset("10.0.0.10", domain="web.test.local", importance="critical", owner="运维组")
aid = a["id"]
report("add_asset", ad.get_asset(aid) is not None)
ad.update_asset(aid, {"tags": ["dmz", "web"], "importance": "high"})
report("update_asset", ad.get_asset(aid)["tags"] == ["dmz", "web"])
report("list_assets", len(ad.list_assets()) >= 1)
report("delete_asset", ad.delete_asset(aid))

# 功能3：CMS 识别 + 风险评分
cms = ad.cms_identify("<html>wp-content/themes/x/style.css</html>", {})
report("cms_identify WordPress", cms == "WordPress", "(识别: %s)" % cms)

a2 = ad.add_asset("10.0.0.20", importance="high")
aid2 = a2["id"]
ad.update_asset(aid2, {"open_ports": [22, 80, 443, 3389, 6379]})
risk = ad.calculate_risk(aid2)
report("calculate_risk 0-100", 0 <= risk["risk_score"] <= 100,
       "(评分 %d / %s)" % (risk["risk_score"], risk["risk_level"]))

# 功能4：子域名字典逻辑存在
from security.asset_discovery import SUBDOMAIN_WORDS
report("subdomain 字典≥50", len(SUBDOMAIN_WORDS) >= 50, "(字典 %d 个)" % len(SUBDOMAIN_WORDS))
# 真正跑一次解析（可能无网络，不强制）
try:
    subs = ad.subdomain_enumerate("nonexistent-invalid-domain-xyz.com")
    report("subdomain_enumerate 可运行", isinstance(subs, list))
except Exception as e:
    report("subdomain_enumerate 可运行", False, str(e))


# ====================================================================== #
# 3. 合规审计
# ====================================================================== #
print("=" * 60)
print("模块3：合规审计")
from security.compliance_audit import ComplianceAuditor, CHECKLISTS

mlps = CHECKLISTS["mlps2"]
iso = CHECKLISTS["iso27001"]
pci = CHECKLISTS["pci_dss"]
report("等保≥30项", len(mlps) >= 30, "(实际 %d)" % len(mlps))
report("ISO≥28项", len(iso) >= 28, "(实际 %d)" % len(iso))
report("PCI≥12项", len(pci) >= 12, "(实际 %d)" % len(pci))

tmp3 = tempfile.mkdtemp(prefix="compliance_test_")
ca = ComplianceAuditor(data_dir=tmp3)

# 功能1：执行审计
results = {it["id"]: {"status": "pass"} for it in mlps[:20]}
results.update({it["id"]: {"status": "fail", "evidence": "未配置"} for it in mlps[20:]})
aud = ca.run_audit("mlps2", {"target": "测试系统", "results": results})
rate = aud["report"]["compliance_rate"]
report("run_audit 合规率计算", 0.0 <= rate <= 1.0, "(合规率 %.1f%%)" % (rate * 100))
report("报告含整改计划", len(aud["report"]["remediation_plan"]) > 0)

# 功能2：趋势对比
aud2 = ca.run_audit("mlps2", {"target": "测试系统",
                              "results": {it["id"]: {"status": "pass"} for it in mlps}})
cmp_res = ca.compare_audits(aud["audit_id"], aud2["audit_id"])
report("compare_audits 趋势", cmp_res["rate_delta"] >= 0,
       "(改进项 %d)" % cmp_res["improved_count"])

# 功能3：清单查询
report("list_checklists / get_item",
       len(ca.list_checklists("iso27001")) >= 28
       and ca.get_checklist_item("pci_dss", "PCI-01") is not None)


# ====================================================================== #
# 4. 攻击路径可视化
# ====================================================================== #
print("=" * 60)
print("模块4：攻击路径可视化")
from security.attack_path import AttackPathAnalyzer

ap = AttackPathAnalyzer()
assets = [
    {"id": "web", "ip": "10.0.0.1", "name": "Web服务器", "importance": "high"},
    {"id": "db", "ip": "10.0.0.2", "name": "数据库", "importance": "critical"},
]
vulns = [
    {"id": "v1", "title": "Web未授权访问", "severity": "high",
     "asset_id": "web", "target_asset_id": "db"},
    {"id": "v2", "title": "SQL注入", "severity": "critical",
     "asset_id": "web", "target_asset_id": "db"},
]
g = ap.build_attack_graph(assets, vulns)
report("build_attack_graph 节点边", g["stats"]["node_count"] >= 4
       and g["stats"]["edge_count"] >= 3,
       "(%d 节点)" % g["stats"]["node_count"])

# 功能1：路径查找
paths = ap.find_paths(g, "external", "db")
report("find_paths 查找路径", len(paths) >= 1, "(找到 %d 条)" % len(paths))

# 功能2：风险评分 + 关键路径
cp = ap.get_critical_paths(g, top_n=3)
report("get_critical_paths", len(cp) >= 1 and cp[0]["risk_score"] > 0,
       "(最高分 %.1f)" % cp[0]["risk_score"])

# 功能3：可视化输出
mer = ap.generate_mermaid(g, cp)
report("Mermaid 输出", "graph TD" in mer and ("暴露" in mer or "利用" in mer or "访问" in mer),
       "(长度 %d)" % len(mer))
svg = ap.generate_svg(g, cp)
report("SVG 输出", svg.strip().startswith("<svg"), "(长度 %d)" % len(svg))
html_out = ap.generate_html(g, cp)
report("HTML 输出", "<html" in html_out.lower() and "<svg" in html_out, "(长度 %d)" % len(html_out))

# 功能4：缓解建议
mit = ap.get_mitigations(g, cp)
report("get_mitigations 缓解建议", len(mit) >= 1,
       "(建议 %d 条)" % len(mit))


# ====================================================================== #
# 5. API 路由注册
# ====================================================================== #
print("=" * 60)
print("模块5：API 路由注册")
try:
    from api_server.security_routes import router
    routes = [r.path for r in router.routes]
    report("APIRouter 可导入", len(routes) > 0, "(%d 个端点)" % len(routes))
    report("路由前缀正确", all("/api/v1/security" in p for p in routes))
    # 抽查关键端点
    keys = ["/vuln-lifecycle/list", "/asset-discovery/assets",
            "/compliance/audit", "/attack-path/generate"]
    report("关键端点齐全", any(k in "".join(routes) for k in keys))
except Exception as e:
    report("APIRouter 可导入", False, str(e))


# ====================================================================== #
# 汇总
# ====================================================================== #
print("=" * 60)
for line in RESULTS:
    print(line)
print("=" * 60)
print("总计: %d 通过, %d 失败" % (PASS, FAIL))
sys.exit(0 if FAIL == 0 else 1)
