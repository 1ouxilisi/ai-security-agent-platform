# -*- coding: utf-8 -*-
import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

mods = [
    'report_engine',
    'report_engine.template_library',
    'report_engine.smart_generator',
    'report_engine.quality_checker',
    'report_engine.multi_format_export',
    'report_engine.collaboration_approval',
    'report_engine.report_analytics',
    'report_engine.report_workflow',
]
for m in mods:
    try:
        __import__(m)
        print('OK ', m)
    except Exception as e:
        print('ERR', m, e)

with open('api_server/report_engine_routes.py', 'r', encoding='utf-8') as f:
    src = f.read()
endpoints = re.findall(r'@router\.(get|post|put|delete|patch)\(', src)
print('endpoint_count =', len(endpoints))
for line in src.splitlines():
    m = re.match(r'@router\.(get|post|put|delete|patch)\("([^"]+)"', line)
    if m:
        print(' ', m.group(1).upper(), m.group(2))

paths = [
    'report_engine/__init__.py',
    'report_engine/template_library.py',
    'report_engine/smart_generator.py',
    'report_engine/quality_checker.py',
    'report_engine/multi_format_export.py',
    'report_engine/collaboration_approval.py',
    'report_engine/report_analytics.py',
    'report_engine/report_workflow.py',
    'api_server/report_engine_routes.py',
    'api_server/report_engine_console.html',
]
for p in paths:
    sz = os.path.getsize(p)
    with open(p, 'r', encoding='utf-8') as f:
        lines = sum(1 for _ in f)
    print(p, ':', sz, 'bytes,', lines, 'lines, abs=', os.path.abspath(p))
