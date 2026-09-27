"""
cli_engine安全工具集成模块，提供相关安全工具的封装和调用。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import asyncio
import json
import re
import shutil
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import log


class CLIToolEngine:
    """CLI工具集成引擎 - 统一管理所有专业安全工具"""

    # 支持的工具配置
    TOOL_CONFIGS = {
        "nmap": {
            "description": "网络扫描和安全审计工具",
            "check_cmd": ["nmap", "--version"],
            "version_pattern": r"Nmap version (\S+)",
            "default_args": ["-T4", "-Pn"],
        },
        "sqlmap": {
            "description": "自动化SQL注入检测和利用工具",
            "check_cmd": ["sqlmap", "--version"],
            "version_pattern": r"sqlmap/(\S+)",
            "default_args": ["--batch", "--random-agent"],
        },
        "nuclei": {
            "description": "基于模板的漏洞扫描器",
            "check_cmd": ["nuclei", "-version"],
            "version_pattern": r"(\d+\.\d+\.\d+)",
            "default_args": ["-silent"],
        },
        "gobuster": {
            "description": "目录/文件/DNS爆破工具",
            "check_cmd": ["gobuster", "version"],
            "version_pattern": r"v(\S+)",
            "default_args": ["-q"],
        },
        "ffuf": {
            "description": "快速Web模糊测试工具",
            "check_cmd": ["ffuf", "-V"],
            "version_pattern": r"(\S+)",
            "default_args": ["-s"],
        },
        "httpx": {
            "description": "HTTP服务探测和技术栈识别工具",
            "check_cmd": ["httpx", "-version"],
            "version_pattern": r"(\S+)",
            "default_args": ["-silent"],
        },
        "whatweb": {
            "description": "Web技术栈识别工具",
            "check_cmd": ["whatweb", "--version"],
            "version_pattern": r"WhatWeb (\S+)",
            "default_args": [],
        },
        "nikto": {
            "description": "Web服务器漏洞扫描器",
            "check_cmd": ["nikto", "-Version"],
            "version_pattern": r"(\S+)",
            "default_args": ["-nointeractive"],
        },
        "masscan": {
            "description": "大规模端口扫描工具",
            "check_cmd": ["masscan", "--version"],
            "version_pattern": r"(\S+)",
            "default_args": ["--rate=1000"],
        },
        "amass": {
            "description": "子域名枚举和攻击面测绘工具",
            "check_cmd": ["amass", "-version"],
            "version_pattern": r"(\S+)",
            "default_args": [],
        },
        "subfinder": {
            "description": "被动子域名发现工具",
            "check_cmd": ["subfinder", "-version"],
            "version_pattern": r"(\S+)",
            "default_args": ["-silent"],
        },
        "httpx-toolkit": {
            "description": "HTTP工具包（项目内置）",
            "check_cmd": None,  # 内置工具，不需要检测
            "version_pattern": None,
            "default_args": [],
        },
    }

    def __init__(self):
        """初始化CLIToolEngine实例。

        Args:
            self: 类实例。
        """
        self._tool_cache: Dict[str, Optional[str]] = {}
        self._version_cache: Dict[str, Optional[str]] = {}

    def is_available(self, tool_name: str) -> bool:
        """检测工具是否可用"""
        if tool_name in self._tool_cache:
            return self._tool_cache[tool_name] is not None

        config = self.TOOL_CONFIGS.get(tool_name)
        if not config:
            log.warning(f"未知工具: {tool_name}")
            self._tool_cache[tool_name] = None
            return False

        # 内置工具直接返回可用
        if config.get("check_cmd") is None:
            self._tool_cache[tool_name] = "builtin"
            return True

        try:
            path = shutil.which(tool_name)
            if path:
                self._tool_cache[tool_name] = path
                log.info(f"✅ 工具 {tool_name} 可用: {path}")
                return True
            else:
                self._tool_cache[tool_name] = None
                log.info(f"⚠️ 工具 {tool_name} 未安装")
                return False
        except Exception as e:
            log.warning(f"工具检测失败 {tool_name}: {e}")
            self._tool_cache[tool_name] = None
            return False

    def get_version(self, tool_name: str) -> Optional[str]:
        """获取工具版本"""
        if tool_name in self._version_cache:
            return self._version_cache[tool_name]

        if not self.is_available(tool_name):
            return None

        config = self.TOOL_CONFIGS.get(tool_name)
        if not config or not config.get("check_cmd"):
            return None

        try:
            import subprocess
            result = subprocess.run(
                config["check_cmd"],
                capture_output=True,
                text=True,
                timeout=10
            )
            output = result.stdout + result.stderr
            pattern = config.get("version_pattern", r"(\S+)")
            match = re.search(pattern, output)
            version = match.group(1) if match else "unknown"
            self._version_cache[tool_name] = version
            return version
        except Exception as e:
            log.warning(f"获取版本失败 {tool_name}: {e}")
            return None

    def get_available_tools(self) -> Dict[str, Dict]:
        """获取所有可用工具列表"""
        available = {}
        for tool_name in self.TOOL_CONFIGS:
            if self.is_available(tool_name):
                available[tool_name] = {
                    "description": self.TOOL_CONFIGS[tool_name]["description"],
                    "version": self.get_version(tool_name),
                    "path": self._tool_cache.get(tool_name),
                }
        return available

    async def execute(self, tool_name: str, args: List[str],
                      timeout: int = 300, env: Optional[Dict] = None,
                      cwd: Optional[str] = None) -> Dict:
        """
        执行CLI工具
        返回：{"success": bool, "stdout": str, "stderr": str, "returncode": int, "duration": float}
        """
        if not self.is_available(tool_name):
            return {
                "success": False,
                "error": f"工具 {tool_name} 未安装",
                "stdout": "",
                "stderr": "",
                "returncode": -1,
                "duration": 0,
            }

        config = self.TOOL_CONFIGS.get(tool_name, {})
        full_args = [tool_name] + config.get("default_args", []) + args

        log.info(f"执行工具: {' '.join(full_args)}")
        start_time = asyncio.get_event_loop().time()

        try:
            proc = await asyncio.create_subprocess_exec(
                *full_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=cwd,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return {
                    "success": False,
                    "error": f"执行超时（{timeout}秒）",
                    "stdout": "",
                    "stderr": "",
                    "returncode": -1,
                    "duration": timeout,
                }

            duration = asyncio.get_event_loop().time() - start_time
            stdout_str = stdout.decode("utf-8", errors="ignore")
            stderr_str = stderr.decode("utf-8", errors="ignore")

            result = {
                "success": proc.returncode == 0,
                "stdout": stdout_str,
                "stderr": stderr_str,
                "returncode": proc.returncode,
                "duration": round(duration, 2),
                "command": " ".join(full_args),
            }

            log.info(f"工具执行完成: {tool_name}, 返回码: {proc.returncode}, 耗时: {duration:.2f}秒")
            return result

        except FileNotFoundError:
            return {
                "success": False,
                "error": f"工具 {tool_name} 不存在",
                "stdout": "",
                "stderr": "",
                "returncode": -1,
                "duration": 0,
            }
        except Exception as e:
            log.error(f"工具执行异常 {tool_name}: {e}")
            return {
                "success": False,
                "error": str(e),
                "stdout": "",
                "stderr": "",
                "returncode": -1,
                "duration": 0,
            }

    # ========== 专用工具调用方法 ==========

    async def nmap_scan(self, target: str, ports: Optional[str] = None,
                         scan_type: str = "default", timeout: int = 120) -> Dict:
        """nmap端口扫描"""
        args = ["-T4", "-Pn"]
        if ports:
            args.extend(["-p", ports])
        if scan_type == "service":
            args.append("-sV")
        elif scan_type == "os":
            args.extend(["-O", "-sV"])
        elif scan_type == "aggressive":
            args.append("-A")
        args.extend(["-oX", "-", target])

        result = await self.execute("nmap", args, timeout=timeout)
        if not result["success"]:
            return result

        # 解析XML输出
        return self._parse_nmap_xml(result["stdout"], target)

    def _parse_nmap_xml(self, xml_content: str, target: str) -> Dict:
        """解析nmap XML输出"""
        try:
            root = ET.fromstring(xml_content)
            open_ports = []
            services = {}

            for host in root.findall(".//host"):
                for port in host.findall(".//port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        port_id = int(port.get("portid"))
                        open_ports.append(port_id)
                        service = port.find("service")
                        if service is not None:
                            services[port_id] = {
                                "name": service.get("name", "Unknown"),
                                "product": service.get("product", ""),
                                "version": service.get("version", ""),
                            }

            return {
                "success": True,
                "scanner": "nmap",
                "target": target,
                "open_ports": sorted(open_ports),
                "open_port_count": len(open_ports),
                "services": services,
                "raw_xml": xml_content[:5000],
            }
        except Exception as e:
            log.error(f"nmap XML解析失败: {e}")
            return {"success": False, "error": f"XML解析失败: {e}", "raw": xml_content[:2000]}

    async def sqlmap_scan(self, url: str, data: Optional[str] = None,
                           level: int = 1, risk: int = 1,
                           timeout: int = 300) -> Dict:
        """sqlmap SQL注入扫描"""
        args = ["-u", url, "--level", str(level), "--risk", str(risk),
                "--batch", "--random-agent", "--output-dir=/tmp/sqlmap_output"]

        if data:
            args.extend(["--data", data])

        result = await self.execute("sqlmap", args, timeout=timeout)
        return result

    async def nuclei_scan(self, target: str, templates: Optional[str] = None,
                          severity: Optional[str] = None,
                          timeout: int = 180) -> Dict:
        """nuclei漏洞扫描"""
        args = ["-u", target, "-silent", "-json"]
        if templates:
            args.extend(["-t", templates])
        if severity:
            args.extend(["-severity", severity])

        result = await self.execute("nuclei", args, timeout=timeout)
        if not result["success"]:
            return result

        # 解析JSON输出
        findings = []
        for line in result["stdout"].strip().split("\n"):
            if line.strip():
                try:
                    finding = json.loads(line)
                    findings.append({
                        "template": finding.get("template-id", ""),
                        "name": finding.get("info", {}).get("name", ""),
                        "severity": finding.get("info", {}).get("severity", "unknown"),
                        "url": finding.get("matched-at", ""),
                        "description": finding.get("info", {}).get("description", ""),
                    })
                except:
                    pass

        return {
            "success": True,
            "scanner": "nuclei",
            "target": target,
            "findings": findings,
            "finding_count": len(findings),
        }

    async def gobuster_dir(self, url: str, wordlist: str,
                            extensions: str = "php,html,txt",
                            timeout: int = 120) -> Dict:
        """gobuster目录爆破"""
        args = ["dir", "-u", url, "-w", wordlist, "-x", extensions, "-q"]
        result = await self.execute("gobuster", args, timeout=timeout)
        return result

    async def httpx_probe(self, target: str, timeout: int = 60) -> Dict:
        """httpx HTTP服务探测"""
        args = ["-u", target, "-silent", "-json", "-tech-detect", "-status-code"]
        result = await self.execute("httpx", args, timeout=timeout)
        return result

    def get_tool_help(self, tool_name: str) -> str:
        """获取工具帮助信息"""
        config = self.TOOL_CONFIGS.get(tool_name)
        if not config:
            return f"未知工具: {tool_name}"
        return f"{tool_name}: {config['description']}"


# 全局单例
cli_engine = CLIToolEngine()
