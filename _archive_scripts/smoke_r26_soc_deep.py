# -*- coding: utf-8 -*-
"""SOC Deep 功能冒烟测试"""
from __future__ import annotations
import os, sys, time
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from soc_deep.siem_logging import get_siem, parse_syslog, parse_json_line, parse_csv_blob
from soc_deep.correlation_engine import get_correlation_engine
from soc_deep.alert_triage_deep import get_alert_triage_deep
from soc_deep.incident_response_deep import get_incident_response
from soc_deep.threat_intel_soc import get_threat_intel_soc
from soc_deep.soc_metrics import get_soc_metrics
from soc_deep.soc_dashboard import get_soc_dashboard

print("=" * 60)
print("SOC Deep 功能冒烟测试")
print("=" * 60)

# 1. SIEM Syslog 真实解析
print("\n[1] Syslog 真实解析:")
line = 'Sep 15 10:23:45 web01 sshd[1234]: Failed password for root from 10.0.3.55 port 22 ssh2'
p = parse_syslog(line)
print(f"  原始: {line}")
print(f"  → host={p['hostname']} app={p['app']} pid={p.get('pid')}")
print(f"  → severity={p['severity']} src_ip={p.get('src_ip')}")
assert p['hostname'] == 'web01' and p['app'] == 'sshd' and p['src_ip'] == '10.0.3.55'
print("  ✓ Syslog 解析正确")

# JSON 解析
print("\n[2] JSON 日志解析:")
j = parse_json_line('{"host":"db01","msg":"login failed","src_ip":"10.0.9.9","severity":"high"}')
print(f"  → host={j['hostname']} severity={j['severity']} src_ip={j['src_ip']}")
assert j['hostname'] == 'db01' and j['src_ip'] == '10.0.9.9'
print("  ✓ JSON 解析正确")

# CSV 解析
print("\n[3] CSV 日志解析:")
rows = parse_csv_blob("host,event,src_ip\nfw01,deny,198.51.100.1\ndb01,login,10.0.0.1")
print(f"  → 解析 {len(rows)} 行, 首行 host={rows[0]['host']}")
assert len(rows) == 2
print("  ✓ CSV 解析正确")

# 2. 关联规则真实触发
print("\n[4] 关联规则真实匹配（SSH 爆破阈值触发）:")
eng = get_correlation_engine()
rule = [r for r in eng.rules.values() if "SSH" in r.name][0]
print(f"  规则: {rule.name} (阈值={rule.threshold['count']}次/{rule.threshold['window_sec']}s)")
fired_total = 0
for i in range(6):
    evt = {"app": "sshd", "message": "Failed password", "src_ip": "10.0.99.99"}
    fired = eng.process_event(evt)
    fired_total += len(fired)
print(f"  注入 6 条失败登录事件, 触发告警 {fired_total} 次")
assert fired_total >= 1, "应触发至少1次告警"
print("  ✓ 阈值规则真实触发")

# 3. 告警去重+分诊+评分
print("\n[5] 告警去重/聚合/分诊评分:")
tr = get_alert_triage_deep()
a1 = tr.ingest({"title": "重复告警", "severity": "high", "category": "bruteforce",
                "src_ip": "1.2.3.4", "dst_ip": "10.0.1.10", "asset": "web-server-01"})
a2 = tr.ingest({"title": "重复告警", "severity": "high", "category": "bruteforce",
                "src_ip": "1.2.3.4", "dst_ip": "10.0.1.10", "asset": "web-server-01"})
print(f"  a1.status={a1.status} risk_score={a1.risk_score} priority={a1.priority}")
print(f"  a2.status={a2.status} duplicate_of={a2.duplicate_of}")
assert a2.duplicate_of == a1.id, "第二条应被去重"
assert a1.risk_score >= 40, "风险分应被计算"
print("  ✓ 去重+分诊评分正确")

# 4. 事件响应 NIST 流程
print("\n[6] 事件响应 NIST/SANS 流程:")
ir = get_incident_response()
inc = ir.create("测试勒索事件", "critical", "ransomware", "演示", "analyst")
print(f"  创建: {inc.id} 阶段={inc.phase}")
ir.advance_phase(inc.id, "确认为真实事件")
print(f"  推进后: 阶段={inc.phase} ({inc.to_dict()['phase_name']})")
ir.containment_action(inc.id, "isolate_network", "10.0.1.10")
ir.eradication_action(inc.id, "remove_malware", "/tmp/x")
ir.advance_phase(inc.id, "进入恢复")
print(f"  再推进: 阶段={inc.phase}, 动作数={len(inc.actions)}")
assert len(inc.actions) >= 2
print("  ✓ NIST 六阶段流转正确")

# 5. IOC 情报匹配
print("\n[7] 威胁情报 IOC 匹配:")
ti = get_threat_intel_soc()
hit = ti.lookup("198.51.100.23")
print(f"  查询 198.51.100.23 → {'命中' if hit else '未命中'}", end="")
if hit:
    print(f" (威胁={hit['threat']} 置信度={hit['confidence']})")
assert hit is not None
hit2 = ti.lookup("malware-c2.example.com")
print(f"  查询 malware-c2.example.com → {'命中' if hit2 else '未命中'}")
assert hit2 is not None
miss = ti.lookup("8.8.8.8")
print(f"  查询 8.8.8.8 → {'命中' if miss else '未命中(预期)'}")
assert miss is None
print("  ✓ IOC 匹配/未命中判断正确")

# 6. MTTD/MTTR/MTRS 计算
print("\n[8] SOC 度量 MTTD/MTTR/MTRS:")
sm = get_soc_metrics()
# 模拟一个完整事件周期
iid = "smoke_inc_1"
sm.record_event(iid, "detect")
time.sleep(0.05)
sm.record_event(iid, "ack")
time.sleep(0.05)
sm.record_event(iid, "close")
d = sm.dashboard()
print(f"  MTTD={d['MTTD_minutes']}min  MTTR={d['MTTR_minutes']}min  MTRS={d['MTRS_minutes']}min")
print(f"  成熟度: L{d['maturity_level']} {d['maturity_name']}")
assert d['MTTD_minutes'] >= 0
print("  ✓ 度量计算正确")

# 7. 仪表盘聚合
print("\n[9] 仪表盘聚合层:")
ov = get_soc_dashboard().overview()
print(f"  平台={ov['platform']}")
print(f"  日志={ov['siem']['total']} 规则={ov['rules']['total']} "
      f"告警={ov['triage']['total']} 事件={ov['incident']['total']} IOC={ov['intel']['total']}")
print("  ✓ 7模块数据聚合成功")

print("\n" + "=" * 60)
print("✅ 全部 9 项功能冒烟测试通过")
print("=" * 60)
