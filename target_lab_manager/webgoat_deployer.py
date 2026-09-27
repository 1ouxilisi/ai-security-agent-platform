# -*- coding: utf-8 -*-
"""
webgoat_deployer.py —— OWASP WebGoat 一键部署器

Docker: webgoat/webgoat
无 Docker: 本地 http.server 模拟 WebGoat 课程页。
"""

from __future__ import annotations

from .lab_manager import BaseDeployer


class WebGoatDeployer(BaseDeployer):
    lab_id = "webgoat"
    name = "OWASP WebGoat"
    docker_image = "webgoat/webgoat"
    default_port = 18083
    description = "交互式 Java 安全教学靶场，分课程讲解漏洞"
    vuln_types = ["SQLi", "XXE", "IDOR", "CSRF", "Deserialization", "Access Control"]

    def _mock_html(self) -> str:
        return """<!doctype html><html><head><meta charset="utf-8">
<title>WebGoat (Mock)</title><style>
body{background:#2d1b1b;color:#eee;font-family:Georgia,serif;max-width:560px;margin:60px auto}
.box{background:#3e2723;padding:26px;border:1px solid #6d4c41;border-radius:10px}
h2{color:#ffab40}
.lesson{padding:8px;border-bottom:1px solid #6d4c41}
</style></head><body><div class="box">
<h2>🐐 OWASP WebGoat (本地模拟)</h2>
<p>课程式安全教学靶场，用于演示一键部署。</p>
<div class="lesson">Lesson 1: HTTP Basics</div>
<div class="lesson">Lesson 2: SQL Injection (intro)</div>
<div class="lesson">Lesson 3: XSS</div>
<p style="color:#aaa;font-size:12px">Java 版若已安装会自动拉起；当前为 Python 模拟。仅限授权测试。</p>
</div></body></html>"""
