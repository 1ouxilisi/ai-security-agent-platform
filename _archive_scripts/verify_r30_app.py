# -*- coding: utf-8 -*-
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
for m in list(sys.modules.keys()):
    if m.startswith(("api_server", "web_pentest_full", "report_pro")):
        del sys.modules[m]
from api_server.app import app
routes = [getattr(r, "path", "") for r in app.routes]
print("total routes:", len(routes))
for p in ["/api/v1/web-pentest-full", "/api/v1/report-pro",
          "/web-pentest-full", "/report-pro"]:
    hit = any(p in x for x in routes)
    print(f"  {p}: {'OK' if hit else 'MISSING'}")

# 生成一份示例报告到 reports/
from report_pro.report_generator import ReportGenerator, ReportData
gen = ReportGenerator()
data = ReportData(
    title="示例安全评估报告 - demo.example.com",
    target="https://demo.example.com",
    findings=[
        {"name": "SQL注入", "severity": "critical", "cvss_score": 9.8,
         "cwe": "CWE-89", "url": "http://x/page?id=1",
         "impact": "可读取数据库", "repro": "加单引号触发错误",
         "fix": "参数化查询"},
        {"name": "信息泄露", "severity": "high", "cvss_score": 7.5,
         "cwe": "CWE-200", "url": "http://x/.git/HEAD",
         "impact": "源码泄露", "repro": "直接访问", "fix": "删除 .git"},
        {"name": "XSS", "severity": "medium", "cvss_score": 6.1,
         "cwe": "CWE-79", "url": "http://x/search?q=",
         "impact": "窃取会话", "repro": "提交 <script>alert(1)</script>",
         "fix": "输出编码"},
        {"name": "目录遍历", "severity": "low", "cvss_score": 3.5,
         "cwe": "CWE-22", "url": "http://x/file?path=",
         "impact": "读有限文件", "repro": "../../etc/passwd",
         "fix": "白名单"},
    ],
    assets=[
        {"name": "web-01", "critical": 1, "high": 1, "medium": 1, "low": 1},
        {"name": "web-02", "critical": 0, "high": 0, "medium": 1, "low": 0},
    ],
)
html = gen.generate_html(data)
out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "reports", f"{data.report_id}.html")
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w", encoding="utf-8") as f:
    f.write(html)
print("sample report:", out, os.path.getsize(out), "bytes")
