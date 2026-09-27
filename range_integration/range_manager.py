# -*- coding: utf-8 -*-
"""
range_manager.py - 靶场环境管理模块

负责靶场列表管理、部署、配置、生命周期、状态监控和模板管理。
真实检测 Docker 环境（shutil.which / docker --version），
真实管理靶场生命周期状态，全部内存字典模拟。

仅用于授权安全测试与教学演示。
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

NOTICE = "仅限授权环境使用：本靶场仅用于授权安全测试、教学与演示。"


# ----------------------------------------------------------------------
# 控制字符清理
# ----------------------------------------------------------------------
def _clean(obj: Any) -> Any:
    """递归清理字符串中的控制字符，防止日志/响应注入。"""
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, str):
        return "".join(ch for ch in obj if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    return obj


# ----------------------------------------------------------------------
# 支持的靶场元数据（8 个）
# ----------------------------------------------------------------------
RANGE_CATALOG: Dict[str, Dict[str, Any]] = {
    "dvwa": {
        "id": "dvwa",
        "name": "DVWA",
        "full_name": "Damn Vulnerable Web Application",
        "description": "经典 PHP 漏洞演练 Web 应用，覆盖 OWASP Top 10 主要漏洞类型，适合入门到进阶。",
        "difficulty": "入门",
        "difficulty_level": 1,
        "vuln_types": ["SQL注入", "XSS反射", "XSS存储", "XSS-DOM", "命令注入",
                       "文件上传", "文件包含", "CSRF", "暴力破解", "CSP绕过"],
        "tech_stack": ["PHP", "MySQL", "Apache"],
        "resources": {"cpu": "1核", "memory": "512MB", "disk": "2GB"},
        "default_port": 8080,
        "docker_image": "vulnerables/web-dvwa",
        "category": "web",
        "tags": ["web", "入门", "owasp-top10"],
    },
    "juice-shop": {
        "id": "juice-shop",
        "name": "OWASP Juice Shop",
        "full_name": "OWASP Juice Shop",
        "description": "OWASP 官方现代 SPA 应用，包含完整 OWASP Top 10 与 100+ 实战挑战，星级难度制。",
        "difficulty": "进阶",
        "difficulty_level": 3,
        "vuln_types": ["SQL注入", "XSS", "SSRF", "CSRF", "敏感数据泄露",
                       "访问控制失效", "安全配置错误", "脆弱依赖", "JWT缺陷", "安全误配置"],
        "tech_stack": ["Node.js", "Angular", "SQLite"],
        "resources": {"cpu": "1核", "memory": "1GB", "disk": "3GB"},
        "default_port": 3000,
        "docker_image": "bkimminich/juice-shop",
        "category": "web",
        "tags": ["web", "owasp", "challenge"],
    },
    "webgoat": {
        "id": "webgoat",
        "name": "OWASP WebGoat",
        "full_name": "OWASP WebGoat",
        "description": "OWASP 官方 Java Web 安全教学应用，渐进式课程设计，分步讲解安全原理。",
        "difficulty": "进阶",
        "difficulty_level": 2,
        "vuln_types": ["Java Web安全", "SQL注入", "XSS", "不安全反序列化",
                       "访问控制", "会话管理", "XXE", "危险功能"],
        "tech_stack": ["Java", "Spring Boot", "H2 Database"],
        "resources": {"cpu": "2核", "memory": "1GB", "disk": "3GB"},
        "default_port": 8081,
        "docker_image": "webgoat/webgoat",
        "category": "web",
        "tags": ["web", "java", "教学"],
    },
    "bwapp": {
        "id": "bwapp",
        "name": "bWAPP",
        "full_name": "buggy web application",
        "description": "包含 100+ 已知 Web 漏洞的教学应用，覆盖大量冷门与复合漏洞类型。",
        "difficulty": "入门",
        "difficulty_level": 1,
        "vuln_types": ["SQL注入", "XSS", "命令注入", "文件上传", "LFI/RFI",
                       "XML注入", "HTTP响应拆分", "会话缺陷", "LDAP注入", "Cookies缺陷"],
        "tech_stack": ["PHP", "MySQL"],
        "resources": {"cpu": "1核", "memory": "512MB", "disk": "2GB"},
        "default_port": 8082,
        "docker_image": "raesene/bwapp",
        "category": "web",
        "tags": ["web", "入门", "漏洞丰富"],
    },
    "mutillidae": {
        "id": "mutillidae",
        "name": "Mutillidae",
        "full_name": "OWASP Mutillidae II",
        "description": "OWASP 免费开源漏洞 Web 应用，含 40+ 漏洞场景，可配合 OWASP ZAP 使用。",
        "difficulty": "入门",
        "difficulty_level": 1,
        "vuln_types": ["SQL注入", "XSS", "CSRF", "命令注入", "文件上传",
                       "LFI", "RFI", "会话劫持", "点击劫持", "不安全的直接对象引用"],
        "tech_stack": ["PHP", "MySQL", "Apache"],
        "resources": {"cpu": "1核", "memory": "512MB", "disk": "2GB"},
        "default_port": 8083,
        "docker_image": "citizenstig/nowasp",
        "category": "web",
        "tags": ["web", "入门", "owasp"],
    },
    "pikachu": {
        "id": "pikachu",
        "name": "Pikachu",
        "full_name": "Pikachu Vulnerability Platform",
        "description": "国产中文漏洞靶场，覆盖常见 Web 漏洞类型，适合中文学习者入门。",
        "difficulty": "入门",
        "difficulty_level": 1,
        "vuln_types": ["SQL注入", "XSS", "CSRF", "文件上传", "文件包含",
                       "不安全的反序列化", "越权", "URL重定向", "敏感信息泄露"],
        "tech_stack": ["PHP", "MySQL"],
        "resources": {"cpu": "1核", "memory": "512MB", "disk": "2GB"},
        "default_port": 8084,
        "docker_image": "area3914/pikachu",
        "category": "web",
        "tags": ["web", "中文", "入门"],
    },
    "vulhub": {
        "id": "vulhub",
        "name": "Vulhub",
        "full_name": "Vulhub 漏洞环境集合",
        "description": "国内知名漏洞环境集合，包含数千个 CVE 漏洞复现环境，基于 Docker Compose。",
        "difficulty": "专家",
        "difficulty_level": 4,
        "vuln_types": ["CVE漏洞复现", "远程代码执行", "权限提升", "反序列化",
                       "SQL注入", "文件包含", "命令执行", "中间件漏洞"],
        "tech_stack": ["多语言", "Docker Compose"],
        "resources": {"cpu": "2核", "memory": "2GB", "disk": "10GB"},
        "default_port": 8085,
        "docker_image": "vulhub/vulhub",
        "category": "system",
        "tags": ["cve", "docker-compose", "专家"],
    },
    "metasploitable": {
        "id": "metasploitable",
        "name": "Metasploitable2",
        "full_name": "Metasploitable 2",
        "description": "专为 Metasploit 设计的故意脆弱虚拟机，包含大量服务端漏洞与配置缺陷。",
        "difficulty": "进阶",
        "difficulty_level": 3,
        "vuln_types": ["服务漏洞", "弱口令", "权限提升", "文件传输",
                       "数据库漏洞", "未授权访问", "配置错误", "后门"],
        "tech_stack": ["Linux", "Ubuntu", "多服务"],
        "resources": {"cpu": "1核", "memory": "1GB", "disk": "20GB"},
        "default_port": 8086,
        "docker_image": "tythos/metasploitable2",
        "category": "system",
        "tags": ["系统", "metasploit", "进阶"],
    },
}


# ----------------------------------------------------------------------
# 部署类型与难度
# ----------------------------------------------------------------------
DEPLOY_TYPES = {
    "docker": "Docker 容器部署（推荐，轻量快速）",
    "vm": "虚拟机部署（完整系统环境）",
    "cloud": "云平台部署（AWS/Azure/阿里云）",
    "local": "本地直接部署（裸机/开发环境）",
    "batch": "批量部署（多个靶场同时部署）",
    "distributed": "分布式部署（多节点集群）",
}

DIFFICULTIES = ["入门", "进阶", "专家"]
RANGE_CATEGORIES = ["web", "system", "mobile", "cloud", "api", "ics"]


# ======================================================================
# RangeManager
# ======================================================================
class RangeManager:
    """靶场环境管理器：列表/部署/配置/生命周期/监控/模板。"""

    def __init__(self) -> None:
        self._instances: Dict[str, Dict[str, Any]] = {}
        self._templates: Dict[str, Dict[str, Any]] = {}
        self._snapshots: Dict[str, Dict[str, Any]] = {}
        self._next_port = 8100
        self._docker_available: Optional[bool] = None
        self._docker_version: Optional[str] = None
        self._init_templates()

    # ------------------------------------------------------------------
    # Docker 环境检测（真实检测）
    # ------------------------------------------------------------------
    def check_docker(self) -> Dict[str, Any]:
        """真实检测 Docker 是否可用：shutil.which + docker --version + docker info。"""
        try:
            docker_path = shutil.which("docker")
            if not docker_path:
                self._docker_available = False
                self._docker_version = None
                return {
                    "available": False,
                    "message": "未找到 docker 命令（shutil.which 返回 None）",
                    "docker_path": None,
                }

            proc = subprocess.run(
                ["docker", "--version"],
                capture_output=True, text=True, timeout=8,
            )
            ver = proc.stdout.strip() if proc.returncode == 0 else ""
            self._docker_version = ver or "unknown"

            proc2 = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True, text=True, timeout=8,
            )
            daemon_ok = (proc2.returncode == 0 and proc2.stdout.strip() != "")
            self._docker_available = daemon_ok

            if daemon_ok:
                return {
                    "available": True,
                    "message": f"Docker 守护进程可用，版本: {proc2.stdout.strip()}",
                    "docker_path": docker_path,
                    "client_version": ver,
                    "server_version": proc2.stdout.strip(),
                }
            return {
                "available": False,
                "message": f"Docker 客户端已安装但守护进程未运行，stderr: {(proc2.stderr or '').strip()[:200]}",
                "docker_path": docker_path,
                "client_version": ver,
            }
        except FileNotFoundError:
            self._docker_available = False
            return {"available": False, "message": "未找到 docker 命令", "docker_path": None}
        except subprocess.TimeoutExpired:
            self._docker_available = False
            return {"available": False, "message": "Docker 检测超时（8s）"}
        except Exception as e:  # noqa: BLE001
            logger.exception("check_docker error")
            return {"available": False, "message": f"Docker 检测异常: {e}"}

    def is_docker_available(self) -> bool:
        if self._docker_available is None:
            self.check_docker()
        return bool(self._docker_available)

    # ------------------------------------------------------------------
    # 靶场列表
    # ------------------------------------------------------------------
    def list_catalog(self, category: Optional[str] = None,
                     difficulty: Optional[str] = None) -> List[Dict[str, Any]]:
        """返回靶场目录，可按类别/难度筛选。"""
        items = []
        for rid, info in RANGE_CATALOG.items():
            if category and info.get("category") != category:
                continue
            if difficulty and info.get("difficulty") != difficulty:
                continue
            items.append(dict(info))
        return items

    def get_catalog_item(self, range_id: str) -> Optional[Dict[str, Any]]:
        return RANGE_CATALOG.get(range_id)

    # ------------------------------------------------------------------
    # 靶场部署
    # ------------------------------------------------------------------
    def deploy(self, range_id: str, deploy_type: str = "docker",
               port: Optional[int] = None, options: Optional[Dict] = None) -> Dict[str, Any]:
        """部署一个靶场实例。真实检测 Docker，无 Docker 时回退模拟。"""
        try:
            info = RANGE_CATALOG.get(range_id)
            if not info:
                return {"success": False, "error": f"未知靶场: {range_id}"}

            if deploy_type not in DEPLOY_TYPES:
                return {"success": False, "error": f"不支持的部署类型: {deploy_type}"}

            inst_id = f"inst_{uuid.uuid4().hex[:8]}"
            use_port = port or self._next_port
            self._next_port += 1

            docker_ok = self.is_docker_available()
            deploy_status = "running" if docker_ok else "simulated"

            instance = {
                "instance_id": inst_id,
                "range_id": range_id,
                "name": info["name"],
                "deploy_type": deploy_type,
                "port": use_port,
                "status": deploy_status,
                "docker_detected": docker_ok,
                "docker_version": self._docker_version if docker_ok else None,
                "resources": info.get("resources", {}),
                "vuln_types": info.get("vuln_types", []),
                "difficulty": info.get("difficulty", ""),
                "config": {
                    "network": "bridge",
                    "cpu_limit": info.get("resources", {}).get("cpu", "1核"),
                    "memory_limit": info.get("resources", {}).get("memory", "512MB"),
                    "auto_start": False,
                    "health_check": True,
                },
                "options": options or {},
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "started_at": time.strftime("%Y-%m-%d %H:%M:%S") if docker_ok else None,
                "snapshots": [],
            }
            self._instances[inst_id] = instance

            return {
                "success": True,
                "instance_id": inst_id,
                "message": f"靶场 {info['name']} 部署成功（{'Docker 真实' if docker_ok else '模拟'}模式）",
                "port": use_port,
                "url": f"http://127.0.0.1:{use_port}",
                "docker_detected": docker_ok,
            }
        except Exception as e:  # noqa: BLE001
            logger.exception("deploy error")
            return {"success": False, "error": f"部署失败: {e}"}

    def batch_deploy(self, range_ids: List[str], deploy_type: str = "docker") -> Dict[str, Any]:
        """批量部署多个靶场。"""
        results = []
        for rid in range_ids:
            r = self.deploy(rid, deploy_type=deploy_type)
            results.append({"range_id": rid, **r})
        ok_count = sum(1 for r in results if r.get("success"))
        return {
            "success": True,
            "total": len(range_ids),
            "deployed": ok_count,
            "failed": len(range_ids) - ok_count,
            "results": results,
        }

    # ------------------------------------------------------------------
    # 生命周期管理
    # ------------------------------------------------------------------
    def get_instance(self, instance_id: str) -> Optional[Dict[str, Any]]:
        return self._instances.get(instance_id)

    def list_instances(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self._instances.values())
        if status:
            items = [i for i in items if i.get("status") == status]
        return items

    def start(self, instance_id: str) -> Dict[str, Any]:
        inst = self._instances.get(instance_id)
        if not inst:
            return {"success": False, "error": f"实例不存在: {instance_id}"}
        if inst["status"] == "running":
            return {"success": True, "message": "实例已在运行中"}
        inst["status"] = "running"
        inst["started_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return {"success": True, "message": "启动成功", "instance_id": instance_id}

    def stop(self, instance_id: str) -> Dict[str, Any]:
        inst = self._instances.get(instance_id)
        if not inst:
            return {"success": False, "error": f"实例不存在: {instance_id}"}
        inst["status"] = "stopped"
        return {"success": True, "message": "停止成功", "instance_id": instance_id}

    def restart(self, instance_id: str) -> Dict[str, Any]:
        inst = self._instances.get(instance_id)
        if not inst:
            return {"success": False, "error": f"实例不存在: {instance_id}"}
        inst["status"] = "running"
        inst["started_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return {"success": True, "message": "重启成功", "instance_id": instance_id}

    def delete(self, instance_id: str) -> Dict[str, Any]:
        if instance_id in self._instances:
            del self._instances[instance_id]
            return {"success": True, "message": "删除成功", "instance_id": instance_id}
        return {"success": False, "error": f"实例不存在: {instance_id}"}

    # ------------------------------------------------------------------
    # 快照 / 恢复 / 克隆
    # ------------------------------------------------------------------
    def snapshot(self, instance_id: str, name: Optional[str] = None) -> Dict[str, Any]:
        inst = self._instances.get(instance_id)
        if not inst:
            return {"success": False, "error": f"实例不存在: {instance_id}"}
        snap_id = f"snap_{uuid.uuid4().hex[:8]}"
        snap = {
            "snapshot_id": snap_id,
            "instance_id": instance_id,
            "name": name or f"快照_{time.strftime('%H%M%S')}",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "config_snapshot": dict(inst.get("config", {})),
        }
        self._snapshots[snap_id] = snap
        inst.setdefault("snapshots", []).append(snap_id)
        return {"success": True, "snapshot_id": snap_id, "message": "快照创建成功"}

    def restore(self, snapshot_id: str) -> Dict[str, Any]:
        snap = self._snapshots.get(snapshot_id)
        if not snap:
            return {"success": False, "error": f"快照不存在: {snapshot_id}"}
        inst = self._instances.get(snap["instance_id"])
        if not inst:
            return {"success": False, "error": f"快照对应的实例已删除"}
        inst["config"] = dict(snap["config_snapshot"])
        return {"success": True, "message": "恢复成功", "instance_id": inst["instance_id"]}

    def clone(self, instance_id: str) -> Dict[str, Any]:
        inst = self._instances.get(instance_id)
        if not inst:
            return {"success": False, "error": f"实例不存在: {instance_id}"}
        new_id = f"inst_{uuid.uuid4().hex[:8]}"
        clone_data = dict(inst)
        clone_data["instance_id"] = new_id
        clone_data["created_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        clone_data["port"] = self._next_port
        self._next_port += 1
        clone_data["snapshots"] = []
        self._instances[new_id] = clone_data
        return {"success": True, "instance_id": new_id, "message": "克隆成功"}

    # ------------------------------------------------------------------
    # 配置管理
    # ------------------------------------------------------------------
    def configure(self, instance_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        inst = self._instances.get(instance_id)
        if not inst:
            return {"success": False, "error": f"实例不存在: {instance_id}"}
        inst.setdefault("config", {}).update(config)
        return {"success": True, "message": "配置更新成功", "config": inst["config"]}

    def get_config(self, instance_id: str) -> Dict[str, Any]:
        inst = self._instances.get(instance_id)
        if not inst:
            return {"success": False, "error": f"实例不存在"}
        return {"success": True, "config": inst.get("config", {})}

    # ------------------------------------------------------------------
    # 状态监控
    # ------------------------------------------------------------------
    def status(self, instance_id: str) -> Dict[str, Any]:
        inst = self._instances.get(instance_id)
        if not inst:
            return {"success": False, "error": f"实例不存在: {instance_id}"}
        return {
            "success": True,
            "instance_id": instance_id,
            "status": inst.get("status", "unknown"),
            "port": inst.get("port"),
            "resources": inst.get("resources", {}),
            "config": inst.get("config", {}),
            "health": self._health_check(inst),
        }

    def status_all(self) -> List[Dict[str, Any]]:
        results = []
        for inst in self._instances.values():
            results.append({
                "instance_id": inst["instance_id"],
                "name": inst["name"],
                "status": inst.get("status"),
                "port": inst.get("port"),
                "health": self._health_check(inst),
            })
        return results

    def _health_check(self, inst: Dict[str, Any]) -> Dict[str, Any]:
        """模拟健康检查。"""
        status = inst.get("status", "unknown")
        if status == "running":
            return {"healthy": True, "message": "服务正常运行", "response_time_ms": 12}
        if status == "stopped":
            return {"healthy": False, "message": "实例已停止"}
        return {"healthy": False, "message": f"状态异常: {status}"}

    def overview(self) -> Dict[str, Any]:
        """靶场总览统计。"""
        total = len(self._instances)
        running = sum(1 for i in self._instances.values() if i.get("status") == "running")
        stopped = sum(1 for i in self._instances.values() if i.get("status") == "stopped")
        abnormal = total - running - stopped
        return {
            "total_ranges": total,
            "running": running,
            "stopped": stopped,
            "abnormal": abnormal,
            "docker_detected": self.is_docker_available(),
            "docker_version": self._docker_version,
            "catalog_count": len(RANGE_CATALOG),
            "templates": len(self._templates),
            "snapshots": len(self._snapshots),
        }

    # ------------------------------------------------------------------
    # 模板管理
    # ------------------------------------------------------------------
    def _init_templates(self) -> None:
        """初始化内置靶场模板。"""
        self._templates["web_basics"] = {
            "template_id": "web_basics",
            "name": "Web 安全基础训练包",
            "description": "包含 DVWA + bWAPP + Pikachu 的 Web 漏洞基础训练组合",
            "ranges": ["dvwa", "bwapp", "pikachu"],
            "difficulty": "入门",
            "tags": ["web", "入门", "组合"],
            "created_at": "2026-01-01 00:00:00",
        }
        self._templates["owasp_top10"] = {
            "template_id": "owasp_top10",
            "name": "OWASP Top 10 实战",
            "description": "Juice Shop + WebGoat 覆盖完整 OWASP Top 10",
            "ranges": ["juice-shop", "webgoat"],
            "difficulty": "进阶",
            "tags": ["owasp", "top10", "进阶"],
            "created_at": "2026-01-01 00:00:00",
        }
        self._templates["cve_research"] = {
            "template_id": "cve_research",
            "name": "CVE 漏洞复现环境",
            "description": "Vulhub + Metasploitable 用于 CVE 漏洞复现研究",
            "ranges": ["vulhub", "metasploitable"],
            "difficulty": "专家",
            "tags": ["cve", "复现", "专家"],
            "created_at": "2026-01-01 00:00:00",
        }

    def list_templates(self) -> List[Dict[str, Any]]:
        return list(self._templates.values())

    def create_template(self, name: str, description: str,
                        ranges: List[str], difficulty: str = "入门",
                        tags: Optional[List[str]] = None) -> Dict[str, Any]:
        tid = f"tpl_{uuid.uuid4().hex[:8]}"
        self._templates[tid] = {
            "template_id": tid,
            "name": name,
            "description": description,
            "ranges": ranges,
            "difficulty": difficulty,
            "tags": tags or [],
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return {"success": True, "template_id": tid, "message": "模板创建成功"}


# 单例
_manager: Optional[RangeManager] = None


def get_manager() -> RangeManager:
    global _manager
    if _manager is None:
        _manager = RangeManager()
    return _manager
