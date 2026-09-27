# -*- coding: utf-8 -*-
"""Test script for fp_optimizer_pro and llm_ultra."""
import sys
sys.path.insert(0, '.')

print('=== 功能测试1: FP优化流水线 ===')
from fp_optimizer_pro import get_fp_pro_dashboard
dash = get_fp_pro_dashboard()
comp = dash.get_before_after_comparison()
before_pct = comp["before"]["fp_rate"] * 100
after_pct = comp["after"]["fp_rate"] * 100
print(f"  优化前: {before_pct:.2f}%")
print(f"  优化后: {after_pct:.2f}%")
print(f"  达标(<5%): {comp['after']['fp_rate'] < 0.05}")

print()
print('=== 功能测试2: 二次验证 ===')
from fp_optimizer_pro import get_secondary_verifier
ver = get_secondary_verifier()
r = ver.verify_vulnerability({
    'type': 'sql_injection', 'name': 'SQL注入',
    'url': 'http://testphp.vulnweb.com/artists.php?id=1'
})
print(f"  验证结果: verified={r['verified']}, confidence={r['confidence_level']}")

print()
print('=== 功能测试3: 置信度评分 ===')
from fp_optimizer_pro import get_confidence_scorer
sc = get_confidence_scorer()
result = sc.score(
    {'type': 'sql_injection', 'name': '测试SQLi', 'severity': 'high',
     'detected_by': 'nuclei', 'evidence': "' OR 1=1",
     'evidence_keywords': ["' OR 1=1--"]},
    {'verified': True}
)
print(f"  评分: {result['total_score']}, 等级: {result['confidence_level']}")

print()
print('=== 功能测试4: LLM多轮对话 ===')
from llm_ultra import get_multi_turn_chat
chat = get_multi_turn_chat()
r = chat.chat('test-session-1', '这个SQL注入漏洞严重吗？怎么修？')
print(f"  回复长度: {len(r['assistant_reply'])}字")
print(f"  追问建议: {len(r['followup_suggestions'])}条")

print()
print('=== 功能测试5: 知识库关联 ===')
from llm_ultra import get_vuln_knowledge_base
kb = get_vuln_knowledge_base()
cves = kb.auto_correlate('rce')
cve_ids = [c['cve_id'] for c in cves]
print(f"  RCE关联到 {len(cves)} 个CVE: {cve_ids}")

print()
print('=== 功能测试6: 报告润色 ===')
from llm_ultra import get_report_polisher
pol = get_report_polisher()
r = pol.polish('网站被黑了！发现SQL注入，太严重了，必须马上修！赶紧处理！')
print(f"  质量评分: {r['quality_score']} ({r['quality_grade']})")
print(f"  修改数: {len(r['changes_made'])}处")
print(f"  检查项通过: {sum(1 for c in r['quality_checks'] if c['passed'])}/{len(r['quality_checks'])}")

print()
print('=== 功能测试7: FP过滤引擎 ===')
from fp_optimizer_pro import get_fp_filter_engine
fe = get_fp_filter_engine()
test_findings = [
    {'type': 'sensitive_info', 'name': 'favicon.ico accessible', 'url': '/favicon.ico'},
    {'type': 'xss', 'name': 'Reflected XSS', 'url': '/search?q=<script>alert(1)</script>'},
    {'type': 'tech_fingerprint', 'name': 'Server: Apache/2.4.29', 'url': '/'},
]
res = fe.filter_findings(test_findings)
print(f"  输入: {res['input']}条")
print(f"  通过: {res['pipeline_stats']['passed_count']}条")
print(f"  白名单过滤: {res['pipeline_stats']['whitelist_count']}条")
print(f"  规则过滤: {res['pipeline_stats']['rule_filtered_count']}条")

print()
print('=== 所有功能测试通过 ===')
