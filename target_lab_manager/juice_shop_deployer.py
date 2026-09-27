# -*- coding: utf-8 -*-
"""
juice_shop_deployer.py —— OWASP Juice Shop 一键部署器

Docker: bkimminich/juice-shop
无 Docker: 本地 http.server 模拟 Juice Shop 首页。
"""

from __future__ import annotations

from .lab_manager import BaseDeployer


class JuiceShopDeployer(BaseDeployer):
    lab_id = "juice-shop"
    name = "OWASP Juice Shop"
    docker_image = "bkimminich/juice-shop"
    default_port = 18082
    description = "现代 Web 安全练习场，覆盖 OWASP Top 10"
    vuln_types = ["SQLi", "XSS", "SSRF", "JWT", "Broken Auth", "Sensitive Data"]

    def _mock_html(self) -> str:
        return """<!doctype html><html><head><meta charset="utf-8">
<title>Juice Shop (Mock)</title><style>
body{background:#1a1a2e;color:#eee;font-family:Arial,sans-serif;max-width:560px;margin:60px auto}
.box{background:#16213e;padding:26px;border:1px solid #0f3460;border-radius:10px}
h2{color:#e94560}
.item{display:inline-block;width:120px;background:#0f3460;margin:6px;padding:12px;border-radius:8px}
</style></head><body><div class="box">
<h2>🍊 OWASP Juice Shop (本地模拟)</h2>
<p>电商风格靶场首页，用于演示一键部署。</p>
<div class="item">🍎 Apple Juice</div>
<div class="item">🍹 Mix Juice</div>
<div class="item">🥤 Soda</div>
<p style="color:#888;font-size:12px">Node.js 版若已安装会自动拉起；当前为 Python 模拟。仅限授权测试。</p>
</div></body></html>"""
