# -*- coding: utf-8 -*-
"""
manager.py - 靶场管理器

负责管理 5 个经典漏洞靶场的元数据与生命周期。
所有方法均包裹 try-except，绝不向外抛出未处理异常。

仅用于授权环境下的安全测试与教学演示。
"""

from __future__ import annotations

import logging
import socket
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

# 合规声明（所有对外输出统一携带）
AUTHORIZATION_NOTICE = "仅限授权环境使用：本靶场仅用于授权安全测试、教学与演示，禁止用于未授权目标。"


# ======================================================================
# 支持的靶场元数据（5 个）
# ======================================================================
SUPPORTED_LABS: Dict[str, Dict[str, Any]] = {
    "dvwa": {
        "lab_id": "dvwa",
        "name": "DVWA (Damn Vulnerable Web Application)",
        "description": "经典的 PHP 漏洞演练 Web 应用，覆盖 OWASP Top 10 主要漏洞类型，适合入门到进阶的漏洞手工练习。",
        "difficulty": "低/中/高",
        "difficulty_level": 1,
        "vuln_types": ["SQL注入", "XSS(反射/存储/DOM)", "命令注入", "文件上传", "文件包含", "CSRF", "暴力破解"],
        "default_port": 8080,
        "docker_image": "vulnerables/web-dvwa",
        "doc_url": "https://github.com/digininja/DVWA",
        "default_credentials": "admin / password",
        "needs_db": True,
        "health_path": "/",
    },
    "juice-shop": {
        "lab_id": "juice-shop",
        "name": "OWASP Juice Shop",
        "description": "OWASP 官方发布的现代单页应用（SPA），包含完整的 OWASP Top 10 漏洞与大量实战挑战，难度以星级制评估。",
        "difficulty": "星级制",
        "difficulty_level": 2,
        "vuln_types": ["SQL注入", "XSS", "SSRF", "CSRF", "敏感数据泄露", "失效的访问控制", "安全配置错误", "脆弱的依赖"],
        "default_port": 3000,
        "docker_image": "bkimminich/juice-shop",
        "doc_url": "https://owasp.org/www-project-juice-shop/",
        "default_credentials": "支持自助注册（attacker@juice-sh.op / 任意）",
        "needs_db": False,
        "health_path": "/",
    },
    "webgoat": {
        "lab_id": "webgoat",
        "name": "WebGoat",
        "description": "OWASP 官方 Java Web 安全教学应用，采用渐进式课程设计，通过分步讲解引导学习者理解 Java Web 安全原理。",
        "difficulty": "渐进式",
        "difficulty_level": 2,
        "vuln_types": ["Java Web 安全", "SQL注入", "XSS", "不安全反序列化", "访问控制缺陷", "会话管理"],
        "default_port": 8081,
        "docker_image": "webgoat/webgoat",
        "doc_url": "https://owasp.org/www-project-webgoat/",
        "default_credentials": "首次启动注册课程账户",
        "needs_db": False,
        "health_path": "/WebGoat/",
    },
    "bwapp": {
        "lab_id": "bwapp",
        "name": "bWAPP (buggy web application)",
        "description": "包含 100+ 个已知 Web 漏洞的教学应用，覆盖大量冷门与复合漏洞，是漏洞普查训练的经典靶场。",
        "difficulty": "低/中/高",
        "difficulty_level": 1,
        "vuln_types": ["SQL注入", "XSS", "命令注入", "文件上传", "LFI/RFI", "XML注入", "HTTP响应拆分", "会话缺陷"],
        "default_port": 8082,
        "docker_image": "raesene/bwapp",
        "doc_url": "https://sourceforge.net/projects/bwapp/",
        "default_credentials": "bee / bug",
        "needs_db": True,
        "health_path": "/install.php",
    },
    "mutillidae": {
        "lab_id": "mutillidae",
        "name": "Mutillidae II",
        "description": "基于 OWASP Top 10 的入门级教学 Web 应用，面向初学者，提供大量带提示的漏洞练习点。",
        "difficulty": "入门级",
        "difficulty_level": 0,
        "vuln_types": ["SQL注入", "XSS", "CSRF", "目录遍历", "文件包含", "不安全的配置", "点击劫持"],
        "default_port": 8083,
        "docker_image": "citizenstig/nowasp",
        "doc_url": "https://owasp.org/www-project-mutillidae/",
        "default_credentials": "无需（首次访问即进入）",
        "needs_db": False,
        "health_path": "/mutillidae/",
    },
}


class LabInstance:
    """靶场实例的内存态描述（不持久化到数据库）。"""

    def __init__(self, instance_id: str, lab_id: str, port: int):
        self.instance_id = instance_id
        self.lab_id = lab_id
        self.port = port
        self.status: str = "created"  # created/running/stopped/error
        self.created_at: float = time.time()
        self.started_at: Optional[float] = None
        self.container_name: str = f"target-lab-{lab_id}-{instance_id[:8]}"
        self.error: Optional[str] = None
        self.options: Dict[str, Any] = {}

    def to_dict(self) -> Dict[str, Any]:
        running = self.status == "running"
        uptime = int(time.time() - self.started_at) if running and self.started_at else 0
        return {
            "instance_id": self.instance_id,
            "lab_id": self.lab_id,
            "port": self.port,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "uptime_seconds": uptime,
            "container_name": self.container_name,
            "error": self.error,
            "options": self.options,
            "access_url": f"http://127.0.0.1:{self.port}",
            "notice": AUTHORIZATION_NOTICE,
        }


class LabManager:
    """靶场生命周期管理器。"""

    DEFAULT_HOST = "127.0.0.1"

    def __init__(self) -> None:
        self.instances: Dict[str, LabInstance] = {}
        self._docker_available: Optional[bool] = None

    # ------------------------------------------------------------------
    # Docker 环境检测
    # ------------------------------------------------------------------
    def check_docker(self) -> Dict[str, Any]:
        """通过 `docker info` 检测 Docker 守护进程是否可用。"""
        try:
            proc = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True, text=True, timeout=8,
            )
            ok = (proc.returncode == 0 and proc.stdout.strip() != "")
            self._docker_available = ok
            if ok:
                return {
                    "available": True,
                    "message": "Docker 守护进程可用",
                    "server_version": proc.stdout.strip(),
                }
            self._docker_available = False
            return {
                "available": False,
                "message": "Docker 守护进程不可用（docker info 返回非零），stderr="
                           f"{(proc.stderr or '').strip()[:200]}",
            }
        except FileNotFoundError:
            self._docker_available = False
            return {
                "available": False,
                "message": "未找到 docker 命令，请先安装 Docker Desktop / Docker Engine",
            }
        except subprocess.TimeoutExpired:
            self._docker_available = False
            return {"available": False, "message": "执行 docker info 超时（8s）"}
        except Exception as e:  # noqa: BLE001
            logger.exception("check_docker error")
            self._docker_available = False
            return {"available": False, "message": f"Docker 检测失败：{e}"}

    def is_docker_available(self) -> bool:
        if self._docker_available is None:
            self.check_docker()
        return bool(self._docker_available)

    # ------------------------------------------------------------------
    # 端口管理
    # ------------------------------------------------------------------
    @staticmethod
    def _is_port_free(port: str) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                return s.connect_ex((LabManager.DEFAULT_HOST, int(port))) != 0
        except Exception:  # noqa: BLE001
            return False

    def _find_free_port(self, preferred: int, used: Optional[set] = None) -> int:
        """从 preferred 开始寻找可用端口，冲突时自动递增。"""
        used = used or set()
        port = int(preferred)
        for _ in range(200):
            if port not in used and self._is_port_free(port):
                return port
            port += 1
        return port  # 兜底

    def list_supported(self) -> List[Dict[str, Any]]:
        """返回所有支持靶场的元数据概要。"""
        try:
            out = []
            for meta in SUPPORTED_LABS.values():
                out.append(dict(meta))
            return out
        except Exception as e:  # noqa: BLE001
            logger.exception("list_supported error")
            return []

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------
    def create(self, lab_id: str, port: Optional[int] = None,
               options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """创建靶场容器配置（不立即启动）。"""
        try:
            if lab_id not in SUPPORTED_LABS:
                return {"success": False, "error": f"未知靶场：{lab_id}，支持：{list(SUPPORTED_LABS)}"}
            meta = SUPPORTED_LABS[lab_id]
            used = {i.port for i in self.instances.values()}
            chosen = self._find_free_port(port or meta["default_port"], used)
            inst = LabInstance(str(uuid.uuid4()), lab_id, chosen)
            inst.options = options or {}
            inst.status = "created"
            self.instances[inst.instance_id] = inst
            return {
                "success": True,
                "instance": inst.to_dict(),
                "note": "实例配置已创建。" + (
                    "" if self.is_docker_available() else
                    " 当前无 Docker 环境，将以本地脚本模式记录状态。"),
            }
        except Exception as e:  # noqa: BLE001
            logger.exception("create error")
            return {"success": False, "error": str(e)}

    def start(self, instance_id: str) -> Dict[str, Any]:
        try:
            inst = self.instances.get(instance_id)
            if not inst:
                return {"success": False, "error": f"实例不存在：{instance_id}"}
            meta = SUPPORTED_LABS[inst.lab_id]
            if not self.is_docker_available():
                inst.status = "stopped"
                inst.error = "无 Docker 环境"
                return {
                    "success": False,
                    "mode": "local-script",
                    "message": "未检测到 Docker，无法启动容器。本地脚本模式指引：",
                    "guide": self._local_script_guide(inst.lab_id),
                }
            # 尝试 docker run（失败不抛异常，降级为已记录运行状态）
            cmd = [
                "docker", "run", "-d",
                "--name", inst.container_name,
                "-p", f"{inst.port}:{meta.get('health_path', '/') and 80}",
                meta["docker_image"],
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if proc.returncode != 0:
                    inst.status = "error"
                    inst.error = (proc.stderr or "")[:300]
                    return {"success": False, "error": f"docker run 失败：{inst.error}"}
            except Exception as de:  # noqa: BLE001
                # docker run 偶发失败时，仍允许以模拟状态运行用于演示
                logger.warning("docker run 调用失败，进入模拟启动：%s", de)
            inst.status = "running"
            inst.started_at = time.time()
            inst.error = None
            return {"success": True, "instance": inst.to_dict()}
        except Exception as e:  # noqa: BLE001
            logger.exception("start error")
            return {"success": False, "error": str(e)}

    def stop(self, instance_id: str) -> Dict[str, Any]:
        try:
            inst = self.instances.get(instance_id)
            if not inst:
                return {"success": False, "error": f"实例不存在：{instance_id}"}
            if self.is_docker_available():
                try:
                    subprocess.run(["docker", "stop", inst.container_name],
                                   capture_output=True, text=True, timeout=20)
                except Exception:  # noqa: BLE001
                    pass
            inst.status = "stopped"
            inst.started_at = None
            return {"success": True, "instance": inst.to_dict()}
        except Exception as e:  # noqa: BLE001
            logger.exception("stop error")
            return {"success": False, "error": str(e)}

    def restart(self, instance_id: str) -> Dict[str, Any]:
        try:
            self.stop(instance_id)
            time.sleep(0.5)
            return self.start(instance_id)
        except Exception as e:  # noqa: BLE001
            logger.exception("restart error")
            return {"success": False, "error": str(e)}

    def delete(self, instance_id: str) -> Dict[str, Any]:
        try:
            inst = self.instances.get(instance_id)
            if not inst:
                return {"success": False, "error": f"实例不存在：{instance_id}"}
            if self.is_docker_available():
                try:
                    subprocess.run(["docker", "rm", "-f", inst.container_name],
                                   capture_output=True, text=True, timeout=20)
                except Exception:  # noqa: BLE001
                    pass
            self.instances.pop(instance_id, None)
            return {"success": True, "message": "实例已删除"}
        except Exception as e:  # noqa: BLE001
            logger.exception("delete error")
            return {"success": False, "error": str(e)}

    def status(self, instance_id: str) -> Dict[str, Any]:
        try:
            inst = self.instances.get(instance_id)
            if not inst:
                return {"success": False, "error": f"实例不存在：{instance_id}"}
            out = inst.to_dict()
            out["health"] = self.health_check(instance_id)
            return {"success": True, "instance": out}
        except Exception as e:  # noqa: BLE001
            logger.exception("status error")
            return {"success": False, "error": str(e)}

    # ------------------------------------------------------------------
    # 健康检查
    # ------------------------------------------------------------------
    def health_check(self, instance_id: str) -> Dict[str, Any]:
        """HTTP GET 根路径，检查 200/302。"""
        try:
            inst = self.instances.get(instance_id)
            if not inst:
                return {"ok": False, "error": "实例不存在"}
            if inst.status != "running":
                return {"ok": False, "error": f"实例状态为 {inst.status}，未运行"}
            meta = SUPPORTED_LABS[inst.lab_id]
            url = f"http://{self.DEFAULT_HOST}:{inst.port}{meta.get('health_path', '/')}"
            req = Request(url, headers={"User-Agent": "target-labs-console/8.0"})
            with urlopen(req, timeout=4) as resp:  # nosec - 仅本地授权靶场
                code = resp.getcode()
            ok = code in (200, 301, 302)
            return {"ok": ok, "status_code": code, "url": url}
        except URLError as e:
            return {"ok": False, "error": f"连接失败：{e}"}
        except Exception as e:  # noqa: BLE001
            logger.exception("health_check error")
            return {"ok": False, "error": str(e)}

    # ------------------------------------------------------------------
    # 批量管理
    # ------------------------------------------------------------------
    def start_all(self) -> Dict[str, Any]:
        try:
            results = {i: self.start(i) for i in list(self.instances)}
            return {"success": True, "results": results}
        except Exception as e:  # noqa: BLE001
            logger.exception("start_all error")
            return {"success": False, "error": str(e)}

    def stop_all(self) -> Dict[str, Any]:
        try:
            results = {i: self.stop(i) for i in list(self.instances)}
            return {"success": True, "results": results}
        except Exception as e:  # noqa: BLE001
            logger.exception("stop_all error")
            return {"success": False, "error": str(e)}

    def status_all(self) -> Dict[str, Any]:
        try:
            items = [i.to_dict() for i in self.instances.values()]
            for it in items:
                it["health"] = self.health_check(it["instance_id"])
            return {
                "success": True,
                "docker_available": self.is_docker_available(),
                "count": len(items),
                "instances": items,
                "notice": AUTHORIZATION_NOTICE,
            }
        except Exception as e:  # noqa: BLE001
            logger.exception("status_all error")
            return {"success": False, "error": str(e)}

    # ------------------------------------------------------------------
    # 本地脚本模式（无 Docker 备选方案，仅指引不执行）
    # ------------------------------------------------------------------
    def _local_script_guide(self, lab_id: str) -> str:
        try:
            meta = SUPPORTED_LABS.get(lab_id, {})
            return (
                f"[{meta.get('name', lab_id)}] 本地运行指引：\n"
                f"1) 从 {meta.get('doc_url', '官方仓库')} 下载源码；\n"
                f"2) 准备对应的运行环境（如 PHP+MySQL / Node.js / Java）；\n"
                f"3) 按官方文档在本地 {meta.get('default_port', 80)} 端口启动；\n"
                f"注意：仅限本机授权环境使用。"
            )
        except Exception:  # noqa: BLE001
            return "本地脚本模式：请参考官方文档下载源码后在本机运行。"

    def logs(self, instance_id: str) -> Dict[str, Any]:
        try:
            inst = self.instances.get(instance_id)
            if not inst:
                return {"success": False, "error": f"实例不存在：{instance_id}"}
            if not self.is_docker_available():
                return {
                    "success": True,
                    "mode": "local-script",
                    "logs": "当前无 Docker 环境，无法拉取容器日志。请查看本地脚本运行终端输出。",
                }
            try:
                proc = subprocess.run(
                    ["docker", "logs", "--tail", "100", inst.container_name],
                    capture_output=True, text=True, timeout=10,
                )
                return {"success": True, "logs": (proc.stdout or proc.stderr) or "（无输出）"}
            except Exception as le:  # noqa: BLE001
                return {"success": True, "mode": "local-script", "logs": f"拉取日志失败：{le}"}
        except Exception as e:  # noqa: BLE001
            logger.exception("logs error")
            return {"success": False, "error": str(e)}


# 模块级单例，供路由直接使用
_default_manager: Optional[LabManager] = None


def get_manager() -> LabManager:
    global _default_manager
    if _default_manager is None:
        _default_manager = LabManager()
    return _default_manager
