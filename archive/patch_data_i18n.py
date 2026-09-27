# -*- coding: utf-8 -*-
"""Add static data-i18n attributes to titles/h1s of core pages."""
import os, re

ROOT = os.path.dirname(os.path.abspath(__file__))
SRV = os.path.join(ROOT, "api_server")

# page -> list of (regex, replacement)
PATCHES = {
    "workflow_console.html": [
        (r'<title>AI Hacking Agent - 工作流控制台 v7</title>',
         '<title data-i18n="page.workflow.title">AI Hacking Agent - 工作流控制台 v7</title>'),
        (r'<h1>AI Hacking Agent · 工作流控制台 v7</h1>',
         '<h1 data-i18n="page.workflow.title">AI Hacking Agent · 工作流控制台 v7</h1>'),
    ],
    "ai_assistant.html": [
        (r'<title>AI安全助手</title>',
         '<title data-i18n="page.assistant.title">AI安全助手</title>'),
        (r'<h1>AI安全助手</h1>',
         '<h1 data-i18n="page.assistant.title">AI安全助手</h1>'),
    ],
    "unified_console.html": [
        (r'<title>全域安全评估平台</title>',
         '<title data-i18n="page.unified.title">全域安全评估平台</title>'),
    ],
    "defense_console.html": [
        (r'<title>防御中心 - AI Hacking Agent</title>',
         '<title data-i18n="page.defense.title">防御中心 - AI Hacking Agent</title>'),
        (r'<h1>🛡 防御中心</h1>',
         '<h1 data-i18n="page.defense.title">🛡 防御中心</h1>'),
    ],
}

for fname, subs in PATCHES.items():
    p = os.path.join(SRV, fname)
    with open(p, "r", encoding="utf-8") as f:
        h = f.read()
    orig = h
    for pat, rep in subs:
        h2 = re.sub(pat, rep, h, count=1)
        if h2 == h:
            print(f"  WARN no match in {fname}: {pat[:50]}")
        h = h2
    if h != orig:
        with open(p, "w", encoding="utf-8") as f:
            f.write(h)
        print(f"  PATCHED {fname}")
    else:
        print(f"  SKIP {fname}")
