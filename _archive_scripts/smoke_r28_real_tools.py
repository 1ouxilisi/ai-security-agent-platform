# -*- coding: utf-8 -*-
"""R28 冒烟测试脚本"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from real_tools_deep import nmap_deep, sqlmap_deep, metasploit_deep, other_tools, tool_orchestration
from real_tools_deep.real_tools_dashboard import get_dashboard

# Nmap 命令构建
b = nmap_deep.NmapCommandBuilder()
b.add_target("192.168.1.1").set_scan_type("syn").set_port_range("1-1000").set_timing_template(3)
cmd = b.build()
print(f"[OK] Nmap命令构建: {cmd}")

# Nmap 模拟扫描
scanner = nmap_deep.get_scanner()
result = scanner.scan(["192.168.1.1"])
hosts = result.get("parsed", {}).get("hosts", [])
print(f"[OK] Nmap模拟扫描: {len(hosts)} 台主机")

# Nmap XML 解析
parsed = nmap_deep.NmapXMLParser.parse("")
h = len(parsed.get("hosts", []))
print(f"[OK] Nmap XML解析: hosts={h}")

# Nmap 报告生成
report = nmap_deep.get_report_generator().generate(result)
print(f"[OK] Nmap报告: risk={report['summary']['risk_label']}, ports={report['summary']['total_open_ports']}")

# SQLMap 命令构建
sb = sqlmap_deep.SQLMapCommandBuilder()
sb.set_target_url("http://t.com/?id=1").set_technique("BEUSTQ").set_level(1).set_risk(1).set_batch()
scmd = sb.build()
print(f"[OK] SQLMap命令构建: {scmd}")

# SQLMap 模拟扫描
ss = sqlmap_deep.get_scanner()
sresult = ss.scan("http://t.com/?id=1")
inj = sresult.get("parsed", {}).get("injection_found")
print(f"[OK] SQLMap模拟扫描: injection={inj}")

# MSF 模块搜索
client = metasploit_deep.get_client()
exploits = client.module_search("exploits")
print(f"[OK] MSF模块搜索: {len(exploits)} 个exploit")

# MSF 模拟利用
exp = client.execute_exploit(
    "exploit/windows/smb/ms17_010_eternalblue",
    {"RHOSTS": "10.0.0.1"}, "meterpreter/reverse_tcp")
print(f"[OK] MSF模拟利用: {exp.get('status')}")

# 其他工具
mgr = other_tools.get_manager()
versions = mgr.get_all_versions()
print(f"[OK] 其他工具版本: {list(versions.keys())}")

# 工作流
engine = tool_orchestration.get_engine()
inst = engine.create_instance("测试工作流", "recon_workflow", "192.168.1.1")
exec_result = engine.execute_instance(inst.instance_id)
print(f"[OK] 工作流执行: status={exec_result.get('status')}, progress={exec_result.get('progress')}%")

# Dashboard
dash = get_dashboard()
overview = dash.get_overview()
print(f"[OK] Dashboard总览: tools={list(overview.get('tools', {}).keys())}")

print("\n=== 全部冒烟测试通过 ===")
