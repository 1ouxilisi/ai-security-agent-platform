# -*- coding: utf-8 -*-
"""方向3 云安全 Pro 演示脚本。"""
from __future__ import annotations
import json
import cloud_security_pro as csp

print("=" * 70)
print("方向3 云安全 Pro — 五阶段全流程演示")
print("=" * 70)

# 0. 凭证状态（不 mock）
print("\n[阶段0] 凭证/SDK 状态检测:")
for p in ("aws", "aliyun"):
    st = csp.detect_credential_status(p)
    print(f"  - {p}: sdk={st['sdk_installed']} cred={st['credentials_configured']}")
    print(f"    hint: {st['hint']}")

# 编排器全流程（无凭证时也应优雅降级，不 mock 资源）
orch = csp.get_orchestrator()
t = orch.run_full(provider="aws")
d = t.to_dict()

print("\n[阶段1] 资产发现:")
inv = d["inventory"]
print(f"  resource_count = {inv.get('resource_count')}")
print(f"  notes: {inv.get('notes')}")

print("\n[阶段2] 配置检查 (18条规则):")
cfg = d["config"]
print(f"  executed={cfg.get('executed')} findings={cfg.get('finding_count')}")
print(f"  by_severity={cfg.get('by_severity')}")

print("\n[阶段3] 风险评级:")
risk = d["risk"]
print(f"  score={risk.get('score')}/100 grade={risk.get('grade')} level={risk.get('level')}")

print("\n[阶段4] 漏洞检测:")
vuln = d["vuln"]
print(f"  executed={vuln.get('executed')} count={vuln.get('count')} db_size={vuln.get('db_size')}")

print("\n[阶段5] 合规审计:")
comp = d["compliance"]
print(f"  pass_rate={comp.get('pass_rate')}% frameworks={list(comp.get('frameworks',{}).keys())}")

print("\n[AI 分析]:")
ai = d["ai"]
print(f"  summary: {ai.get('summary')}")
print(f"  priorities: {len(ai.get('priorities',[]))} 项")
print(f"  attack_paths: {len(ai.get('attack_paths',[]))} 条")

print("\n[报告生成]:")
print(f"  path = {t.report_path}")
print(f"  markdown length = {len(t.report_markdown)} chars")
print(f"  html length = {len(t.report_html)} chars")

# 用一份带真实形态的样例资源再跑一次 AI/风险/报告（验证逻辑可处理有数据的情况）
print("\n" + "=" * 70)
print("附：注入一份形态化资源清单，验证评级/AI/报告逻辑可处理真实数据")
print("=" * 70)
sample_inv = {
    "credential_status": {"credentials_configured": True},
    "resource_count": 4,
    "by_type": {"ec2": 2, "rds": 1, "s3": 1},
    "resources": [
        {"resource_id": "i-0abc", "resource_type": "ec2", "state": "running",
         "name": "web", "region": "cn-north-1", "tags": {},
         "extra": {"public_ip": "1.2.3.4"}},
        {"resource_id": "mydb", "resource_type": "rds", "state": "available",
         "name": "mydb", "region": "cn-north-1", "tags": {},
         "extra": {"engine": "mysql", "engine_version": "5.7",
                   "publicly_accessible": True, "storage_encrypted": False,
                   "backup_retention": 0}},
        {"resource_id": "mybucket", "resource_type": "s3", "state": "",
         "name": "mybucket", "region": "", "tags": {},
         "extra": {"encryption": False, "versioning": "Suspended",
                   "policy_principal_star": True}},
    ],
    "security_groups": [
        {"group_id": "sg-1", "cidr_ip": "0.0.0.0/0", "from_port": 22, "to_port": 22},
        {"group_id": "sg-1", "cidr_ip": "0.0.0.0/0", "from_port": 6379, "to_port": 6379},
    ],
    "audit": {"enabled": False},
}
cc = csp.get_config_check_phase().run(sample_inv)
rr = csp.get_risk_rating_phase().rate(cc.findings, resource_count=4)
cp = csp.get_compliance_audit_phase().audit(cc.findings)
vv = csp.get_vuln_detect_phase().detect(sample_inv)
aii = csp.get_ai_analysis().analyze(sample_inv, cc.to_dict(), rr.to_dict(), vv, cp.to_dict())
print(f"  配置发现: {cc.to_dict().get('finding_count')} 条 -> {cc.to_dict().get('by_severity')}")
print(f"  风险评分: {rr.score}/100 grade={rr.grade} level={rr.level}")
print(f"  合规通过率: {cp.to_dict().get('pass_rate')}%")
print(f"  攻击路径: {len(aii['attack_paths'])} 条 -> {[p['name'] for p in aii['attack_paths']]}")

# 生成一份带数据的报告
rd = csp.report_generator.CloudReportData(
    task_id="demo001", provider="aws",
    started_at="2026-09-20 10:00:00", finished_at="2026-09-20 10:05:00",
    inventory=sample_inv, config=cc.to_dict(), risk=rr.to_dict(),
    vuln=vv, compliance=cp.to_dict(), ai=aii)
mp = csp.get_report_generator().save(rd, "md")
hp = csp.get_report_generator().save(rd, "html")
print(f"  MD 报告: {mp}")
print(f"  HTML 报告: {hp}")

print("\n[OK] 演示完成")
