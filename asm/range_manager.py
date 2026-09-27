"""
靶场集成模块
- 一键部署DVWA
- 一键部署Juice Shop
- 靶场管理（启动/停止/状态/删除）
- 靶场漏洞列表
"""

import subprocess
import time
import json
import os
from typing import Dict, List, Any, Optional


class RangeManager:
    """靶场管理器"""

    # 支持的靶场配置
    RANGE_CONFIGS = {
        "juice-shop": {
            "name": "OWASP Juice Shop",
            "description": "OWASP出品的现代化Web应用靶场，包含100+漏洞挑战",
            "image": "bkimminich/juice-shop:latest",
            "container_name": "juice-shop",
            "port": 3000,
            "internal_port": 3000,
            "difficulty_levels": ["Easy", "Medium", "Hard", "Insane"],
            "vulnerability_count": "100+",
            "category": "Web安全",
            "tags": ["OWASP", "Web", "XSS", "SQL注入", "认证绕过", "文件上传"]
        },
        "dvwa": {
            "name": "DVWA (Damn Vulnerable Web App)",
            "description": "经典的PHP/MySQL Web应用靶场，适合初学者练习",
            "image": "vulnerables/web-dvwa:latest",
            "container_name": "dvwa",
            "port": 8080,
            "internal_port": 80,
            "difficulty_levels": ["Low", "Medium", "High", "Impossible"],
            "vulnerability_count": 15,
            "category": "Web安全",
            "tags": ["PHP", "MySQL", "XSS", "SQL注入", "文件上传", "命令执行"]
        },
        "bwapp": {
            "name": "bWAPP (Buggy Web App)",
            "description": "包含100+漏洞的PHP靶场，覆盖各种Web漏洞类型",
            "image": "raesene/bwapp:latest",
            "container_name": "bwapp",
            "port": 8081,
            "internal_port": 80,
            "difficulty_levels": ["Low", "Medium", "High"],
            "vulnerability_count": "100+",
            "category": "Web安全",
            "tags": ["PHP", "MySQL", "XSS", "SQL注入", "XXE", "SSRF"]
        },
        "webgoat": {
            "name": "WebGoat",
            "description": "OWASP出品的Java Web应用安全教学靶场",
            "image": "webgoat/webgoat:latest",
            "container_name": "webgoat",
            "port": 8082,
            "internal_port": 8080,
            "difficulty_levels": ["Beginner", "Intermediate", "Advanced"],
            "vulnerability_count": "40+",
            "category": "Web安全",
            "tags": ["Java", "OWASP", "XSS", "SQL注入", "认证", "访问控制"]
        },
        "mutillidae": {
            "name": "Mutillidae II",
            "description": "OWASP出品的PHP靶场，包含大量漏洞和教程",
            "image": "citizenstig/nowasp:latest",
            "container_name": "mutillidae",
            "port": 8083,
            "internal_port": 80,
            "difficulty_levels": ["0", "1", "2", "3", "4", "5"],
            "vulnerability_count": "50+",
            "category": "Web安全",
            "tags": ["PHP", "OWASP", "XSS", "SQL注入", "文件包含", "命令执行"]
        }
    }

    def __init__(self):
        self.docker_available = self._check_docker()

    def _check_docker(self) -> bool:
        """检查Docker是否可用"""
        try:
            result = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False

    def list_ranges(self) -> Dict[str, Any]:
        """列出所有支持的靶场"""
        ranges = []
        for key, config in self.RANGE_CONFIGS.items():
            status = self.get_range_status(key)
            ranges.append({
                "id": key,
                "name": config["name"],
                "description": config["description"],
                "port": config["port"],
                "category": config["category"],
                "tags": config["tags"],
                "vulnerability_count": config["vulnerability_count"],
                "difficulty_levels": config["difficulty_levels"],
                "status": status["status"],
                "url": status.get("url", "")
            })
        return {
            "total": len(ranges),
            "docker_available": self.docker_available,
            "ranges": ranges
        }

    def get_range_status(self, range_id: str) -> Dict[str, Any]:
        """获取靶场状态"""
        if range_id not in self.RANGE_CONFIGS:
            return {"status": "unknown", "error": "靶场不存在"}

        config = self.RANGE_CONFIGS[range_id]
        container_name = config["container_name"]

        if not self.docker_available:
            return {"status": "docker_unavailable", "error": "Docker不可用"}

        try:
            result = subprocess.run(
                ["docker", "ps", "-a", "--filter", f"name={container_name}", "--format", "{{.Status}}|{{.Ports}}"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip():
                status_line = result.stdout.strip()
                parts = status_line.split("|")
                status = parts[0] if parts else "unknown"
                ports = parts[1] if len(parts) > 1 else ""

                if "Up" in status:
                    return {
                        "status": "running",
                        "container": container_name,
                        "port": config["port"],
                        "url": f"http://127.0.0.1:{config['port']}",
                        "details": status
                    }
                else:
                    return {
                        "status": "stopped",
                        "container": container_name,
                        "details": status
                    }
            else:
                return {"status": "not_deployed", "container": container_name}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def deploy_range(self, range_id: str, custom_port: Optional[int] = None) -> Dict[str, Any]:
        """部署靶场"""
        if range_id not in self.RANGE_CONFIGS:
            return {"success": False, "error": "靶场不存在"}

        if not self.docker_available:
            return {"success": False, "error": "Docker不可用，请先安装Docker Desktop"}

        config = self.RANGE_CONFIGS[range_id]
        container_name = config["container_name"]
        port = custom_port or config["port"]
        internal_port = config["internal_port"]

        # 检查是否已存在
        status = self.get_range_status(range_id)
        if status["status"] == "running":
            return {"success": True, "message": "靶场已在运行", "url": status["url"], "port": port}

        try:
            # 如果容器已存在但停止了，先删除
            if status["status"] == "stopped":
                subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, timeout=30)

            # 拉取镜像（如果不存在）
            image_check = subprocess.run(
                ["docker", "image", "inspect", config["image"]],
                capture_output=True, text=True, timeout=10
            )
            if image_check.returncode != 0:
                pull_result = subprocess.run(
                    ["docker", "pull", config["image"]],
                    capture_output=True, text=True, timeout=300
                )
                if pull_result.returncode != 0:
                    return {"success": False, "error": f"镜像拉取失败: {pull_result.stderr[:200]}"}

            # 启动容器
            run_result = subprocess.run(
                ["docker", "run", "-d", "--name", container_name, "-p", f"{port}:{internal_port}", config["image"]],
                capture_output=True, text=True, timeout=60
            )

            if run_result.returncode == 0:
                # 等待启动
                time.sleep(5)
                new_status = self.get_range_status(range_id)
                return {
                    "success": True,
                    "message": f"{config['name']} 部署成功",
                    "container_id": run_result.stdout.strip(),
                    "url": f"http://127.0.0.1:{port}",
                    "port": port,
                    "status": new_status["status"]
                }
            else:
                return {"success": False, "error": f"容器启动失败: {run_result.stderr[:200]}"}

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "操作超时"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def stop_range(self, range_id: str) -> Dict[str, Any]:
        """停止靶场"""
        if range_id not in self.RANGE_CONFIGS:
            return {"success": False, "error": "靶场不存在"}

        config = self.RANGE_CONFIGS[range_id]
        container_name = config["container_name"]

        try:
            result = subprocess.run(
                ["docker", "stop", container_name],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return {"success": True, "message": f"{config['name']} 已停止"}
            else:
                return {"success": False, "error": result.stderr[:200]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def start_range(self, range_id: str) -> Dict[str, Any]:
        """启动已停止的靶场"""
        if range_id not in self.RANGE_CONFIGS:
            return {"success": False, "error": "靶场不存在"}

        config = self.RANGE_CONFIGS[range_id]
        container_name = config["container_name"]

        try:
            result = subprocess.run(
                ["docker", "start", container_name],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                time.sleep(3)
                return {
                    "success": True,
                    "message": f"{config['name']} 已启动",
                    "url": f"http://127.0.0.1:{config['port']}"
                }
            else:
                return {"success": False, "error": result.stderr[:200]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def remove_range(self, range_id: str) -> Dict[str, Any]:
        """删除靶场容器"""
        if range_id not in self.RANGE_CONFIGS:
            return {"success": False, "error": "靶场不存在"}

        config = self.RANGE_CONFIGS[range_id]
        container_name = config["container_name"]

        try:
            result = subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return {"success": True, "message": f"{config['name']} 已删除"}
            else:
                return {"success": False, "error": result.stderr[:200]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_vulnerability_list(self, range_id: str) -> Dict[str, Any]:
        """获取靶场漏洞列表"""
        if range_id not in self.RANGE_CONFIGS:
            return {"success": False, "error": "靶场不存在"}

        config = self.RANGE_CONFIGS[range_id]

        # 预定义的漏洞列表
        vuln_lists = {
            "juice-shop": [
                {"id": "DOM XSS", "category": "XSS", "difficulty": "⭐", "description": "DOM型跨站脚本攻击"},
                {"id": "Reflected XSS", "category": "XSS", "difficulty": "⭐⭐", "description": "反射型跨站脚本攻击"},
                {"id": "Stored XSS", "category": "XSS", "difficulty": "⭐⭐⭐", "description": "存储型跨站脚本攻击"},
                {"id": "SQL Injection (Login)", "category": "SQL注入", "difficulty": "⭐⭐", "description": "登录表单SQL注入绕过"},
                {"id": "SQL Injection (Search)", "category": "SQL注入", "difficulty": "⭐⭐⭐", "description": "搜索功能SQL注入"},
                {"id": "Broken Authentication", "category": "认证", "difficulty": "⭐⭐", "description": "认证机制缺陷"},
                {"id": "Sensitive Data Exposure", "category": "信息泄露", "difficulty": "⭐⭐", "description": "敏感数据泄露"},
                {"id": "XML External Entities", "category": "XXE", "difficulty": "⭐⭐⭐", "description": "XML外部实体注入"},
                {"id": "Insecure Deserialization", "category": "反序列化", "difficulty": "⭐⭐⭐⭐", "description": "不安全的反序列化"},
                {"id": "File Upload", "category": "文件上传", "difficulty": "⭐⭐", "description": "任意文件上传"},
                {"id": "Path Traversal", "category": "目录遍历", "difficulty": "⭐⭐⭐", "description": "路径遍历漏洞"},
                {"id": "SSRF", "category": "SSRF", "difficulty": "⭐⭐⭐", "description": "服务端请求伪造"},
                {"id": "Open Redirect", "category": "重定向", "difficulty": "⭐", "description": "开放重定向"},
                {"id": "CSRF", "category": "CSRF", "difficulty": "⭐⭐", "description": "跨站请求伪造"},
                {"id": "Privilege Escalation", "category": "越权", "difficulty": "⭐⭐⭐", "description": "权限提升"}
            ],
            "dvwa": [
                {"id": "SQL Injection", "category": "SQL注入", "difficulty": "Low/Medium/High", "description": "SQL注入漏洞"},
                {"id": "SQL Injection (Blind)", "category": "SQL注入", "difficulty": "Low/Medium/High", "description": "盲注漏洞"},
                {"id": "XSS (Reflected)", "category": "XSS", "difficulty": "Low/Medium/High", "description": "反射型XSS"},
                {"id": "XSS (Stored)", "category": "XSS", "difficulty": "Low/Medium/High", "description": "存储型XSS"},
                {"id": "XSS (DOM)", "category": "XSS", "difficulty": "Low/Medium/High", "description": "DOM型XSS"},
                {"id": "Command Injection", "category": "命令执行", "difficulty": "Low/Medium/High", "description": "操作系统命令注入"},
                {"id": "File Upload", "category": "文件上传", "difficulty": "Low/Medium/High", "description": "文件上传漏洞"},
                {"id": "File Inclusion", "category": "文件包含", "difficulty": "Low/Medium/High", "description": "本地/远程文件包含"},
                {"id": "CSRF", "category": "CSRF", "difficulty": "Low/Medium/High", "description": "跨站请求伪造"},
                {"id": "Brute Force", "category": "暴力破解", "difficulty": "Low/Medium/High", "description": "登录暴力破解"},
                {"id": "CSP Bypass", "category": "CSP绕过", "difficulty": "Low/Medium/High", "description": "内容安全策略绕过"},
                {"id": "Insecure CAPTCHA", "category": "验证码", "difficulty": "Low/Medium/High", "description": "不安全的验证码"},
                {"id": "Weak Session IDs", "category": "会话", "difficulty": "Low/Medium/High", "description": "弱会话ID"},
                {"id": "Open HTTP Redirect", "category": "重定向", "difficulty": "Low/Medium/High", "description": "开放重定向"},
                {"id": "CORS", "category": "CORS", "difficulty": "Low/Medium/High", "description": "跨域资源共享配置错误"}
            ]
        }

        vulns = vuln_lists.get(range_id, [])
        return {
            "range": config["name"],
            "total_vulnerabilities": len(vulns),
            "vulnerabilities": vulns
        }
