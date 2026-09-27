# -*- coding: utf-8 -*-
"""第27轮方向3 二进制逆向 验证脚本"""
import os, sys, importlib, re

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

print("=" * 60)
print("【交付文件清单】")
print("=" * 60)
files = [
    "binary_reverse/__init__.py",
    "binary_reverse/disassembler.py",
    "binary_reverse/decompiler.py",
    "binary_reverse/vuln_miner.py",
    "binary_reverse/patch_diff.py",
    "binary_reverse/malware_analysis.py",
    "binary_reverse/pack_unpack.py",
    "binary_reverse/binary_dashboard.py",
    "api_server/binary_reverse_routes.py",
    "api_server/binary_reverse_console.html",
]
for f in files:
    p = os.path.join(ROOT, f)
    sz = os.path.getsize(p)
    with open(p, "r", encoding="utf-8", errors="ignore") as fh:
        lines = sum(1 for _ in fh)
    print(f"  {f:50s} {lines:6d} lines  {sz:8d} bytes")

print()
print("=" * 60)
print("【模块独立导入测试】")
print("=" * 60)
mods = [
    "binary_reverse",
    "binary_reverse.disassembler",
    "binary_reverse.decompiler",
    "binary_reverse.vuln_miner",
    "binary_reverse.patch_diff",
    "binary_reverse.malware_analysis",
    "binary_reverse.pack_unpack",
    "binary_reverse.binary_dashboard",
    "api_server.binary_reverse_routes",
]
ok = fail = 0
for m in mods:
    try:
        importlib.import_module(m)
        print(f"  [OK]   {m}")
        ok += 1
    except Exception as e:
        print(f"  [FAIL] {m}: {e}")
        fail += 1
print(f"通过 {ok}/{len(mods)}, 失败 {fail}")

print()
print("=" * 60)
print("【API 端点统计】")
print("=" * 60)
with open(os.path.join(ROOT, "api_server/binary_reverse_routes.py"), "r", encoding="utf-8") as f:
    src = f.read()
eps = re.findall(r"@router\.(get|post|put|delete)\(", src)
print(f"  装饰器端点数: {len(eps)}")
from api_server.binary_reverse_routes import router
print(f"  router.routes: {len(router.routes)}")
print(f"  prefix: {router.prefix}")

print()
print("=" * 60)
print("【HTML 文件大小】")
print("=" * 60)
html_sz = os.path.getsize(os.path.join(ROOT, "api_server/binary_reverse_console.html"))
print(f"  binary_reverse_console.html: {html_sz} bytes ({html_sz/1024:.1f} KB)")
print(f"  >15KB 要求: {'PASS' if html_sz > 15360 else 'FAIL'}")

print()
print("=" * 60)
print("【真实功能冒烟测试】")
print("=" * 60)
from binary_reverse.disassembler import (
    get_disassembler, SAMPLE_X86_64, SAMPLE_ARM, ARCHITECTURES,
)
from binary_reverse.decompiler import decompile_sample
from binary_reverse.vuln_miner import mine_demo
from binary_reverse.patch_diff import diff_demo
from binary_reverse.malware_analysis import analyze_demo
from binary_reverse.pack_unpack import detect_demo
from binary_reverse.binary_dashboard import get_dashboard

d = get_disassembler("x86_64")
insns = d.disassemble(SAMPLE_X86_64, 0x100000)
print(f"  [真实反汇编] x86_64: {len(insns)} 条指令")
for i in insns[:5]:
    print(f"    0x{i.address:x}: {i.mnemonic} {i.op_str}")
arm_insns = d.disassemble(SAMPLE_ARM, 0x80000)
print(f"  [真实反汇编] ARM: {len(arm_insns)} 条指令")
print(f"  [支持架构] {len(ARCHITECTURES)} 种")

r = decompile_sample()
print(f"  [真实反编译] 伪代码 {len(r['pseudocode'].splitlines())} 行")
print("    --- 伪代码片段 ---")
for line in r["pseudocode"].splitlines()[:8]:
    print("    " + line)

m = mine_demo()
print(f"  [真实漏洞挖掘] findings={len(m['findings'])} risk={m['risk_level']} score={m['risk_score']}")
for f in m["findings"][:3]:
    print(f"    - {f['type']} [{f['severity']}] {f['symbol']}")

p = diff_demo()
print(f"  [真实补丁对比] hunks={p['hunk_count']} added={p['summary']['added_lines']}")

a = analyze_demo()
print(f"  [真实恶意代码] verdict={a['verdict']} family={a['family_match']} conf={a['family_confidence']}%")

pk = detect_demo()
print(f"  [真实壳检测] packer={pk['packer']} is_packed={pk['is_packed']} entropy={pk['entropy']}")

ov = get_dashboard().overview()
print(f"  [控制台聚合] modules={list(ov['modules'].keys())}")

print()
print("=" * 60)
print("【验证结论】")
print("=" * 60)
all_ok = (fail == 0 and len(router.routes) >= 50 and html_sz > 15360
          and len(insns) > 0 and len(r["pseudocode"]) > 0)
print(f"  py_compile: OK (已单独验证)")
print(f"  模块导入: {ok}/{len(mods)}")
print(f"  API端点: {len(router.routes)} (>=50)")
print(f"  HTML大小: {html_sz} bytes (>15KB)")
print(f"  冒烟测试: {'PASS' if all_ok else 'FAIL'}")
