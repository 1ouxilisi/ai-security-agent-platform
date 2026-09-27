# -*- coding: utf-8 -*-
"""
range_deployer.py — 真实靶场一键部署。

优先 Docker 真实部署 10+ 靶场；无 Docker 时用 Python http.server 模拟
（明确标注为模拟）。靶场状态/日志/访问 URL 全部内存字典管理。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
import uuid
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

# 10+ 靶场目录
RANGES: Dict[str, Dict[str, Any]] = {
    "dvwa": {"name": "DVWA", "image": "vulnerables/web-dvwa",
             "port": 8081, "path": "/login.php",
             "desc": "Damn Vulnerable Web Application"},
    "juice_shop": {"name": "OWASP Juice Shop", "image": "bkimminich/juice-shop",
                   "port": 3000, "path": "/", "desc": "现代单页应用漏洞靶场"},
    "webgoat": {"name": "WebGoat", "image": "webgoat/webgoat",
                "port": 9090, "path": "/WebGoat", "desc": "OWASP 交互式教学靶场"},
    "metasploitable2": {"name": "Metasploitable2", "image": "tleemcjr/metasploitable2",
                        "port": 22, "path": "/", "desc": "经典多漏洞虚拟机"},
    "bwapp": {"name": "bWAPP", "image": "raesene/bwapp",
              "port": 8082, "path": "/login.php", "desc": "约 100+ Web 漏洞"},
    "mutillidae": {"name": "Mutillidae", "image": "citizenstig/nowasp",
                   "port": 8083, "path": "/mutillidae", "desc": "OWASP Mutillidae II"},
    "pikachu": {"name": "Pikachu", "image": "pikachu/pikachu",
                "port": 8084, "path": "/", "desc": "中文 Web 漏洞靶场"},
    "owasp_benchmark": {"name": "OWASP Benchmark", "image": "owasp/benchmark",
                        "port": 8085, "path": "/benchmark", "desc": "漏洞检测基准"},
    "nodegoat": {"name": "NodeGoat", "image": "bkimminich/nodegoat",
                 "port": 4000, "path": "/", "desc": "Node.js 漏洞靶场"},
    "vulhub": {"name": "Vulhub", "image": "vulhub/vulhub",
               "port": 8086, "path": "/", "desc": "多漏洞环境集合"},
}


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        out = subprocess.run(["docker", "info"], capture_output=True, text=True,
                             timeout=10,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return out.returncode == 0
    except Exception:
        return False


class RangeDeployer:
    """靶场部署器。"""

    def __init__(self) -> None:
        self._instances: Dict[str, Dict[str, Any]] = {}
        self._mock_servers: Dict[str, ThreadingHTTPServer] = {}

    def list_catalog(self) -> List[Dict[str, Any]]:
        return [{"id": k, **v} for k, v in RANGES.items()]

    def list_instances(self) -> List[Dict[str, Any]]:
        return sorted(self._instances.values(),
                      key=lambda x: x.get("started_at", ""), reverse=True)

    # ------------------------------------------------------------------ #
    def deploy(self, range_id: str) -> Dict[str, Any]:
        spec = RANGES.get(range_id)
        if not spec:
            return {"ok": False, "error": "未知靶场"}
        inst_id = f"range_{uuid.uuid4().hex[:8]}"
        use_docker = _docker_available()
        url = f"http://127.0.0.1:{spec['port']}{spec['path']}"
        inst = {
            "id": inst_id, "range_id": range_id, "name": spec["name"],
            "mode": "docker" if use_docker else "mock_http",
            "image": spec["image"] if use_docker else "",
            "status": "starting", "url": url, "port": spec["port"],
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "logs": [], "health": "unknown",
        }
        self._instances[inst_id] = inst

        if use_docker:
            inst["logs"].append(f"docker run -d -p {spec['port']}:80 {spec['image']}")
            try:
                subprocess.run(
                    ["docker", "run", "-d", "--name", f"hax_{inst_id}",
                     "-p", f"{spec['port']}:80", spec["image"]],
                    capture_output=True, text=True, timeout=60,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                inst["status"] = "running"
                inst["logs"].append("容器已启动（真实 Docker）")
            except Exception as e:
                inst["status"] = "failed"
                inst["logs"].append(f"Docker 启动失败，回退模拟：{e}")
                self._start_mock(inst, spec)
        else:
            inst["logs"].append("未检测到可用 Docker，启动 Python http.server 模拟页面")
            self._start_mock(inst, spec)

        self._health_check(inst, spec)
        return {"ok": True, "instance": inst}

    # ------------------------------------------------------------------ #
    def _start_mock(self, inst: Dict[str, Any], spec: Dict[str, Any]) -> None:
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "_mock_range")
        os.makedirs(root, exist_ok=True)
        html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>{spec['name']} (模拟)</title></head>
<body style="font-family:Microsoft YaHei;padding:40px;background:#111;color:#eee">
<h1 style="color:#ff5252">[模拟靶场] {spec['name']}</h1>
<p>这是一个由 Python http.server 提供的<strong>模拟</strong>靶场页面，
用于在无 Docker 环境下演示验证流程。</p>
<p>真实部署请安装 Docker 后重试。</p>
<hr><p>路径: {spec['path']} &nbsp;端口: {spec['port']}</p></body></html>"""
        with open(os.path.join(root, "index.html"), "w", encoding="utf-8") as f:
            f.write(html)
        try:
            handler = SimpleHTTPRequestHandler
            srv = ThreadingHTTPServer(("127.0.0.1", spec["port"]), handler)
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            self._mock_servers[inst["id"]] = srv
            inst["status"] = "running"
            inst["logs"].append(f"模拟 http.server 已监听 {spec['port']}")
        except Exception as e:
            inst["status"] = "failed"
            inst["logs"].append(f"模拟服务启动失败: {e}")

    def _health_check(self, inst: Dict[str, Any], spec: Dict[str, Any]) -> None:
        import urllib.request
        try:
            urllib.request.urlopen(inst["url"], timeout=5)
            inst["health"] = "healthy"
            inst["logs"].append("健康检查通过：可访问")
        except Exception as e:
            inst["health"] = "unreachable"
            inst["logs"].append(f"健康检查：{e}")

    # ------------------------------------------------------------------ #
    def stop(self, inst_id: str) -> Dict[str, Any]:
        inst = self._instances.get(inst_id)
        if not inst:
            return {"ok": False, "error": "实例不存在"}
        if inst["mode"] == "docker" and shutil.which("docker"):
            try:
                subprocess.run(["docker", "rm", "-f", f"hax_{inst_id}"],
                               capture_output=True, timeout=30,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            except Exception:
                pass
        srv = self._mock_servers.pop(inst_id, None)
        if srv:
            try:
                srv.shutdown()
            except Exception:
                pass
        inst["status"] = "stopped"
        inst["health"] = "stopped"
        inst["logs"].append("实例已停止")
        return {"ok": True, "instance": inst}

    def logs(self, inst_id: str) -> Dict[str, Any]:
        inst = self._instances.get(inst_id)
        if not inst:
            return {"ok": False, "error": "实例不存在"}
        return {"ok": True, "logs": inst["logs"], "status": inst["status"]}


_deployer: Optional[RangeDeployer] = None


def get_range_deployer() -> RangeDeployer:
    global _deployer
    if _deployer is None:
        _deployer = RangeDeployer()
    return _deployer
