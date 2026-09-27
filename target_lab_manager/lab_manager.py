# -*- coding: utf-8 -*-
"""
lab_manager.py —— 靶场统一管理器

负责：
  - 检测本机是否有 Docker（subprocess 调用 docker --version）
  - 无 Docker 时用 Python 内置 http.server 起一个模拟靶场页面
  - 统一管理 DVWA / Juice Shop / WebGoat 实例的 启动/停止/状态/日志
所有实例状态保存在内存字典中。
"""

from __future__ import annotations

import logging
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

NOTICE = "仅限授权环境：本地靶场仅用于授权安全测试 / 教学 / 演示。"


# ----------------------------------------------------------------------
# Docker 探测
# ----------------------------------------------------------------------
def detect_docker() -> Dict[str, Any]:
    """检测本机是否可用 docker。"""
    try:
        out = subprocess.run(
            ["docker", "--version"], capture_output=True, text=True,
            timeout=5,
        )
        ok = (out.returncode == 0)
        return {
            "available": ok,
            "version": out.stdout.strip() if ok else None,
            "message": out.stderr.strip() if not ok else "docker 可用",
        }
    except FileNotFoundError:
        return {"available": False, "version": None,
                "message": "未找到 docker 命令，将使用本地模拟模式"}
    except Exception as e:  # noqa: BLE001
        return {"available": False, "version": None, "message": f"docker 探测失败：{e}"}


def is_port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def _alloc_port(preferred: Optional[int], start: int = 18080) -> int:
    """从 preferred 或 start 开始找一个空闲端口。"""
    candidates = []
    if preferred:
        candidates.append(preferred)
    candidates.extend(range(start, start + 50))
    for p in candidates:
        if is_port_free("127.0.0.1", p):
            return p
    return 0


# ----------------------------------------------------------------------
# 模拟 HTTP 服务器（无 Docker 时使用）
# ----------------------------------------------------------------------
class _MockHandler(BaseHTTPRequestHandler):
    """通用模拟靶场请求处理器，内容由外部 HTML 决定。"""

    mock_html: str = "<h1>Mock Lab</h1>"
    lab_name: str = "mock"

    def _send(self):
        body = self.mock_html.encode("utf-8")
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
        pass  # 静音，避免污染 uvicorn 日志


class _MockServer:
    """在后台线程跑一个 http.server。"""

    def __init__(self, host: str, port: int, html: str, lab_name: str) -> None:
        self.host = host
        self.port = port
        self.html = html
        self.lab_name = lab_name
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.logs: List[str] = []

    def start(self) -> bool:
        _MockHandler.mock_html = self.html
        _MockHandler.lab_name = self.lab_name
        try:
            self._httpd = ThreadingHTTPServer((self.host, self.port),
                                              _MockHandler)
        except OSError as e:
            self.logs.append(f"[{_now()}] 端口 {self.port} 绑定失败：{e}")
            return False
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                       daemon=True)
        self._thread.start()
        self.logs.append(
            f"[{_now()}] 模拟 {self.lab_name} 已启动于 http://{self.host}:{self.port}")
        return True

    def stop(self) -> None:
        if self._httpd:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
                self.logs.append(f"[{_now()}] 模拟 {self.lab_name} 已停止")
            except Exception as e:  # noqa: BLE001
                self.logs.append(f"[{_now()}] 停止异常：{e}")
            self._httpd = None
            self._thread = None


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


# ----------------------------------------------------------------------
# 部署器基类
# ----------------------------------------------------------------------
class BaseDeployer:
    """靶场部署器基类。"""

    lab_id: str = "base"
    name: str = "Base"
    docker_image: str = ""
    default_port: int = 8080
    description: str = ""
    vuln_types: List[str] = []

    def __init__(self) -> None:
        self.instance_id: Optional[str] = None
        self.status: str = "stopped"     # stopped / starting / running / failed
        self.mode: str = "none"          # docker / mock
        self.host: str = "127.0.0.1"
        self.port: int = 0
        self.url: str = ""
        self.logs: List[str] = []
        self._proc: Optional[subprocess.Popen] = None
        self._mock: Optional[_MockServer] = None
        self.started_at: Optional[str] = None

    def _mock_html(self) -> str:
        return f"<h1>{self.name} (Mock)</h1>"

    def start(self, port: Optional[int] = None) -> Dict[str, Any]:
        self.logs.append(f"[{_now()}] 请求启动 {self.name} ...")
        self.status = "starting"
        docker = detect_docker()
        self.port = _alloc_port(port or self.default_port)
        if self.port == 0:
            self.status = "failed"
            self.logs.append(f"[{_now()}] 无可用端口")
            return {"success": False, "error": "无可用端口"}

        if docker["available"]:
            return self._start_docker()
        return self._start_mock()

    def _start_docker(self) -> Dict[str, Any]:
        try:
            cmd = [
                "docker", "run", "-d", "--rm",
                "-p", f"{self.port}:80",
                "--name", f"lab-{self.lab_id}-{uuid.uuid4().hex[:6]}",
                self.docker_image,
            ]
            self.logs.append(f"[{_now()}] 执行：{' '.join(cmd)}")
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True)
            # 等待 docker 拉取/启动（最多 8s，避免阻塞）
            try:
                out, _ = self._proc.communicate(timeout=8)
                self.logs.append(out.strip() or "(docker 已后台运行)")
            except subprocess.TimeoutExpired:
                self._proc.terminate()
                self.logs.append(f"[{_now()}] docker 启动超时，回退到模拟模式")
                return self._start_mock()
            self.mode = "docker"
            self.status = "running"
            self.url = f"http://{self.host}:{self.port}"
            self.started_at = _now()
            return {"success": True,
                    "data": self.info()}
        except Exception as e:  # noqa: BLE001
            self.logs.append(f"[{_now()}] docker 启动失败：{e}，回退模拟")
            return self._start_mock()

    def _start_mock(self) -> Dict[str, Any]:
        self._mock = _MockServer(self.host, self.port,
                                 self._mock_html(), self.name)
        ok = self._mock.start()
        if not ok:
            self.status = "failed"
            return {"success": False, "error": "模拟服务启动失败"}
        self.mode = "mock"
        self.status = "running"
        self.url = f"http://{self.host}:{self.port}"
        self.started_at = _now()
        return {"success": True, "data": self.info()}

    def stop(self) -> Dict[str, Any]:
        if self.status != "running":
            return {"success": False, "error": "实例未在运行"}
        if self._mock:
            self._mock.stop()
            self.logs.extend(self._mock.logs)
            self._mock = None
        if self._proc:
            try:
                self._proc.terminate()
                self.logs.append(f"[{_now()}] docker 容器已停止")
            except Exception as e:  # noqa: BLE001
                self.logs.append(f"[{_now()}] 停止 docker 失败：{e}")
            self._proc = None
        self.status = "stopped"
        self.url = ""
        self.started_at = None
        return {"success": True, "data": self.info()}

    def status_info(self) -> Dict[str, Any]:
        return self.info()

    def info(self) -> Dict[str, Any]:
        return {
            "lab_id": self.lab_id,
            "name": self.name,
            "mode": self.mode,
            "status": self.status,
            "url": self.url,
            "host": self.host,
            "port": self.port,
            "description": self.description,
            "vuln_types": self.vuln_types,
            "docker_image": self.docker_image,
            "started_at": self.started_at,
        }

    def get_logs(self, tail: int = 200) -> List[str]:
        if self._mock:
            return (self.logs + self._mock.logs)[-tail:]
        return self.logs[-tail:]


# ----------------------------------------------------------------------
# 统一管理器
# ----------------------------------------------------------------------
class LabManager:
    """管理所有靶场部署器实例。"""

    def __init__(self) -> None:
        self._deployers: Dict[str, BaseDeployer] = {}
        self._registry: Dict[str, Dict[str, BaseDeployer]] = {}

    def register(self, deployer: BaseDeployer) -> None:
        self._deployers[deployer.lab_id] = deployer

    def list_supported(self) -> List[Dict[str, Any]]:
        return [d.info() for d in self._deployers.values()]

    def start(self, lab_id: str, port: Optional[int] = None) -> Dict[str, Any]:
        d = self._deployers.get(lab_id)
        if not d:
            return {"success": False, "error": f"未知靶场 {lab_id}"}
        return d.start(port)

    def stop(self, lab_id: str) -> Dict[str, Any]:
        d = self._deployers.get(lab_id)
        if not d:
            return {"success": False, "error": f"未知靶场 {lab_id}"}
        return d.stop()

    def status(self, lab_id: str) -> Dict[str, Any]:
        d = self._deployers.get(lab_id)
        if not d:
            return {"success": False, "error": f"未知靶场 {lab_id}"}
        return {"success": True, "data": d.status_info()}

    def logs(self, lab_id: str) -> Dict[str, Any]:
        d = self._deployers.get(lab_id)
        if not d:
            return {"success": False, "error": f"未知靶场 {lab_id}"}
        return {"success": True, "data": {"lab_id": lab_id,
                                          "logs": d.get_logs()}}

    def status_all(self) -> Dict[str, Any]:
        return {
            "docker": detect_docker(),
            "instances": [d.info() for d in self._deployers.values()],
        }

    def quick_start_url(self, lab_id: str) -> Dict[str, Any]:
        """一键启动并直接返回可访问 URL（供 Web 渗透页面自动回填）。"""
        r = self.start(lab_id)
        if not r.get("success"):
            return r
        return {"success": True,
                "data": {"url": r["data"]["url"],
                         "lab_id": lab_id,
                         "status": r["data"]["status"]}}


_singleton: Optional[LabManager] = None


def get_lab_manager() -> LabManager:
    global _singleton
    if _singleton is None:
        m = LabManager()
        from .dvwa_deployer import DVWADeployer
        from .juice_shop_deployer import JuiceShopDeployer
        from .webgoat_deployer import WebGoatDeployer
        m.register(DVWADeployer())
        m.register(JuiceShopDeployer())
        m.register(WebGoatDeployer())
        _singleton = m
    return _singleton
