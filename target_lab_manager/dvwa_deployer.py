# -*- coding: utf-8 -*-
"""
dvwa_deployer.py —— DVWA 一键部署器

Docker: vulnerables/web-dvwa
无 Docker: 本地 http.server 模拟 DVWA 登录页。
"""

from __future__ import annotations

from typing import Any, Dict, List

from .lab_manager import BaseDeployer


class DVWADeployer(BaseDeployer):
    lab_id = "dvwa"
    name = "DVWA (Damn Vulnerable Web Application)"
    docker_image = "vulnerables/web-dvwa"
    default_port = 18081
    description = "经典 SQL 注入 / XSS / 命令注入 练习靶场"
    vuln_types = ["SQLi", "XSS", "Command Injection", "File Upload", "Brute Force"]

    def _mock_html(self) -> str:
        return """<!doctype html><html><head><meta charset="utf-8">
<title>DVWA (Mock)</title><style>
body{background:#1b1b1b;color:#eee;font-family:monospace;max-width:520px;margin:60px auto}
.box{background:#2a2a2a;padding:24px;border:1px solid #444;border-radius:8px}
input{width:100%;padding:8px;margin:6px 0;background:#111;color:#eee;border:1px solid #555}
button{width:100%;padding:10px;background:#d33;color:#fff;border:0;cursor:pointer}
</style></head><body><div class="box">
<h2>DVWA Login <small style="color:#888">(本地模拟)</small></h2>
<p>这是 DVWA 的本地模拟页面，用于演示一键部署流程。</p>
<input placeholder="username" value="admin">
<input placeholder="password" type="password" value="password">
<button>Login</button>
<p style="color:#888;font-size:12px">已自动配置数据库 · 仅限授权测试</p>
</div></body></html>"""
