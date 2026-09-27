# -*- coding: utf-8 -*-
"""
target_lab_real/simulated_lab.py — 无 Docker 时的模拟靶场

用 Python 内置 ThreadingHTTPServer 在后台线程起一个模拟页面，
明确标注"模拟模式"。
"""
from __future__ import annotations

import socket
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

from .lab_registry import get_lab


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def is_port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def alloc_port(preferred: Optional[int], start: int = 18080) -> int:
    cands = []
    if preferred:
        cands.append(preferred)
    cands.extend(range(start, start + 80))
    for p in cands:
        if is_port_free("127.0.0.1", p):
            return p
    return 0


class _MockHandler(BaseHTTPRequestHandler):
    page_html: str = "<h1>Mock</h1>"

    def _send(self) -> None:
        body = self.page_html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        self._send()

    def do_POST(self):  # noqa: N802
        self._send()

    def log_message(self, *args):  # noqa: A003
        pass


def _mock_html(lab_id: str) -> str:
    lab = get_lab(lab_id) or {}
    name = lab.get("name", lab_id)
    desc = lab.get("description", "")
    return f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>[模拟] {name}</title>
<style>body{{font-family:sans-serif;background:#1a1a2e;color:#eaeaea;padding:40px}}
.badge{{background:#d29922;color:#000;padding:4px 10px;border-radius:4px;font-weight:bold}}
pre{{background:#000;padding:10px;border-radius:4px}}</style></head>
<body><span class="badge">模拟模式（未检测到 Docker）</span>
<h1>{name}</h1><p>{desc}</p>
<h3>模拟登录</h3>
<form><input placeholder="用户名"><br><input placeholder="密码" type="password"><br>
<button>登录</button></form>
<h3>模拟漏洞点</h3>
<p><a href="/vuln?id=1">?id=1 SQL注入点</a></p>
<p><a href="/search?q=xss">?q=xss 反射型XSS</a></p>
<pre>这是一个由 Python http.server 渲染的模拟靶场页面。
真实靶场请安装 Docker 后重新部署：{lab.get('image','')}</pre>
</body></html>"""


class SimulatedLab:
    def __init__(self, lab_id: str, host: str, port: int) -> None:
        self.lab_id = lab_id
        self.host = host
        self.port = port
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.logs: List[str] = []

    def start(self) -> bool:
        _MockHandler.page_html = _mock_html(self.lab_id)
        try:
            self._httpd = ThreadingHTTPServer((self.host, self.port),
                                               _MockHandler)
        except OSError as e:
            self.logs.append(f"[{_now()}] 端口绑定失败: {e}")
            return False
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        daemon=True)
        self._thread.start()
        self.logs.append(f"[{_now()}] 模拟 {self.lab_id} 启动于 "
                         f"http://{self.host}:{self.port}")
        return True

    def stop(self) -> None:
        if self._httpd:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
                self.logs.append(f"[{_now()}] 模拟 {self.lab_id} 已停止")
            except Exception as e:  # noqa: BLE001
                self.logs.append(f"[{_now()}] 停止异常: {e}")
            self._httpd = None
            self._thread = None
