"""真实安全工具集成模块。

封装nmap、sqlmap、nuclei、masscan、nikto等专业安全工具的调用，
提供统一的Python接口，支持工具可用性检测、参数构建、结果解析。

注意：本模块仅用于授权的安全测试，使用前请确保已获得相关授权。
"""
import os
import re
import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from utils.logger import log


# 工具路径配置
_TOOLS_CONFIG = None
_CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "tools_config.json")


def _load_tools_config() -> Dict:
    """加载工具路径配置文件"""
    global _TOOLS_CONFIG
    if _TOOLS_CONFIG is not None:
        return _TOOLS_CONFIG
    
    default_config = {
        "tools": {},
        "settings": {"timeout": 300, "max_concurrent": 3}
    }
    
    try:
        if os.path.exists(_CONFIG_PATH):
            with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
                _TOOLS_CONFIG = json.load(f)
            log.info(f"工具配置已加载: {_CONFIG_PATH}")
        else:
            _TOOLS_CONFIG = default_config
            log.warning(f"工具配置文件不存在，使用默认配置: {_CONFIG_PATH}")
    except Exception as e:
        log.error(f"加载工具配置失败: {e}")
        _TOOLS_CONFIG = default_config
    
    return _TOOLS_CONFIG


def _get_tool_path(tool_name: str) -> Optional[str]:
    """从配置文件获取工具路径"""
    config = _load_tools_config()
    tool_config = config.get("tools", {}).get(tool_name, {})
    
    # 1. 优先使用自定义path
    custom_path = tool_config.get("path", "")
    if custom_path:
        expanded_path = os.path.expandvars(custom_path)
        if os.path.exists(expanded_path):
            return expanded_path
    
    # 2. 根据操作系统选择路径
    if os.name == "nt":  # Windows
        win_path = tool_config.get("windows_path", "")
        if win_path:
            expanded_path = os.path.expandvars(win_path)
            if os.path.exists(expanded_path):
                return expanded_path
    else:  # Linux/Mac
        linux_path = tool_config.get("linux_path", "")
        if linux_path and os.path.exists(linux_path):
            return linux_path
    
    return None


def _get_tool_wrapper(tool_name: str) -> Optional[str]:
    """获取工具的包装器（如python、perl）"""
    config = _load_tools_config()
    tool_config = config.get("tools", {}).get(tool_name, {})
    return tool_config.get("wrapper")


def _is_tool_enabled(tool_name: str) -> bool:
    """检查工具是否在配置中启用"""
    config = _load_tools_config()
    tool_config = config.get("tools", {}).get(tool_name, {})
    return tool_config.get("enabled", True)


@dataclass
class ToolResult:
    """工具执行结果"""
    tool_name: str
    success: bool
    command: str
    return_code: int
    stdout: str = ""
    stderr: str = ""
    parsed_data: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    execution_time: float = 0.0


class SecurityTool:
    """安全工具基类"""
    
    def __init__(self, name: str, binary: str, default_args: List[str] = None):
        self.name = name
        self.binary = binary
        self.default_args = default_args or []
        self._available = None
        self._tool_path = None
        self._wrapper = None
    
    def is_available(self) -> bool:
        """检查工具是否可用（优先使用配置文件路径）"""
        if self._available is not None:
            return self._available
        
        # 检查是否在配置中启用
        if not _is_tool_enabled(self.name):
            log.info(f"工具 {self.name} 在配置中未启用")
            self._available = False
            return False
        
        # 1. 优先从配置文件获取路径
        config_path = _get_tool_path(self.name)
        if config_path:
            self._tool_path = config_path
            self._wrapper = _get_tool_wrapper(self.name)
            log.info(f"工具 {self.name} 可用（配置路径）: {config_path}")
            self._available = True
            return True
        
        # 2. 检查系统PATH
        system_path = shutil.which(self.binary)
        if system_path:
            self._tool_path = system_path
            log.info(f"工具 {self.name} 可用（系统PATH）: {system_path}")
            self._available = True
            return True
        
        log.warning(f"工具 {self.name} 不可用，请安装或在 config/tools_config.json 中配置路径")
        self._available = False
        return False
    
    def _get_command(self, args: List[str]) -> List[str]:
        """构建完整命令（支持包装器）"""
        if self._wrapper:
            # 使用包装器（如 python sqlmap.py）
            return [self._wrapper, self._tool_path] + self.default_args + args
        elif self._tool_path:
            # 使用配置的完整路径
            return [self._tool_path] + self.default_args + args
        else:
            # 使用系统PATH中的命令
            return [self.binary] + self.default_args + args
    
    def run(self, args: List[str], timeout: int = 300, cwd: str = None) -> ToolResult:
        """执行工具"""
        import time
        full_command = self._get_command(args)
        command_str = " ".join(full_command)
        log.info(f"执行 {self.name}: {command_str}")
        
        start_time = time.time()
        try:
            process = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd
            )
            execution_time = time.time() - start_time
            
            result = ToolResult(
                tool_name=self.name,
                success=process.returncode == 0,
                command=command_str,
                return_code=process.returncode,
                stdout=process.stdout,
                stderr=process.stderr,
                execution_time=round(execution_time, 2)
            )
            
            if not result.success:
                result.error = process.stderr[:500]
                log.warning(f"{self.name} 执行失败 (code={process.returncode}): {result.error}")
            else:
                log.info(f"{self.name} 执行成功，耗时 {execution_time:.2f}s")
            
            return result
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            return ToolResult(
                tool_name=self.name,
                success=False,
                command=command_str,
                return_code=-1,
                error=f"执行超时 ({timeout}s)",
                execution_time=round(execution_time, 2)
            )
        except FileNotFoundError:
            return ToolResult(
                tool_name=self.name,
                success=False,
                command=command_str,
                return_code=-1,
                error=f"工具未找到: {self.binary}",
                execution_time=0
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                success=False,
                command=command_str,
                return_code=-1,
                error=str(e),
                execution_time=0
            )


class NmapTool(SecurityTool):
    """Nmap端口扫描工具"""
    
    def __init__(self):
        super().__init__("nmap", "nmap")
    
    def quick_scan(self, target: str, ports: str = "1-1000", timeout: int = 120) -> ToolResult:
        """快速端口扫描"""
        args = ["-sV", "-sC", "-p", ports, "--open", "-oX", "-", target]
        result = self.run(args, timeout=timeout)
        if result.success and result.stdout:
            result.parsed_data = self._parse_xml(result.stdout)
        return result
    
    def full_scan(self, target: str, timeout: int = 600) -> ToolResult:
        """全面扫描（所有端口+服务版本+脚本）"""
        args = ["-sV", "-sC", "-A", "-p-", "--open", "-oX", "-", target]
        result = self.run(args, timeout=timeout)
        if result.success and result.stdout:
            result.parsed_data = self._parse_xml(result.stdout)
        return result
    
    def os_detection(self, target: str, timeout: int = 120) -> ToolResult:
        """操作系统检测"""
        args = ["-O", "-oX", "-", target]
        result = self.run(args, timeout=timeout)
        if result.success and result.stdout:
            result.parsed_data = self._parse_xml(result.stdout)
        return result
    
    def _parse_xml(self, xml_content: str) -> Dict[str, Any]:
        """解析Nmap XML输出"""
        try:
            root = ET.fromstring(xml_content)
            hosts = []
            
            for host_elem in root.findall(".//host"):
                host_data = {"addresses": [], "ports": [], "os": None}
                
                # 地址
                for addr in host_elem.findall("address"):
                    host_data["addresses"].append({
                        "addr": addr.get("addr"),
                        "type": addr.get("addrtype")
                    })
                
                # 端口
                for port in host_elem.findall(".//port"):
                    port_data = {
                        "protocol": port.get("protocol"),
                        "portid": port.get("portid"),
                        "state": port.find("state").get("state") if port.find("state") is not None else "unknown",
                        "service": {},
                        "scripts": []
                    }
                    
                    service = port.find("service")
                    if service is not None:
                        port_data["service"] = {
                            "name": service.get("name"),
                            "product": service.get("product"),
                            "version": service.get("version"),
                            "extrainfo": service.get("extrainfo")
                        }
                    
                    for script in port.findall("script"):
                        port_data["scripts"].append({
                            "id": script.get("id"),
                            "output": script.get("output", "")[:200]
                        })
                    
                    if port_data["state"] == "open":
                        host_data["ports"].append(port_data)
                
                # OS检测
                os_elem = host_elem.find(".//osmatch")
                if os_elem is not None:
                    host_data["os"] = {
                        "name": os_elem.get("name"),
                        "accuracy": os_elem.get("accuracy")
                    }
                
                hosts.append(host_data)
            
            return {
                "scan_info": {
                    "scanner": root.get("scanner"),
                    "version": root.get("version"),
                    "args": root.get("args"),
                    "starttime": root.get("start")
                },
                "hosts": hosts,
                "total_open_ports": sum(len(h["ports"]) for h in hosts)
            }
        except Exception as e:
            log.error(f"Nmap XML解析失败: {e}")
            return {"error": str(e), "raw": xml_content[:1000]}


class SqlmapTool(SecurityTool):
    """SQLMap注入工具"""
    
    def __init__(self):
        super().__init__("sqlmap", "sqlmap")
    
    def scan_url(self, url: str, data: str = None, cookie: str = None, 
                  level: int = 3, risk: int = 2, timeout: int = 600) -> ToolResult:
        """扫描URL的SQL注入"""
        args = ["-u", url, "--batch", "--level", str(level), "--risk", str(risk)]
        
        if data:
            args.extend(["--data", data])
        if cookie:
            args.extend(["--cookie", cookie])
        
        # 输出JSON格式
        output_file = f"/tmp/sqlmap_{os.getpid()}.json"
        args.extend(["--output-dir", "/tmp", "--json"])
        
        result = self.run(args, timeout=timeout)
        if result.success:
            result.parsed_data = self._parse_output(result.stdout, result.stderr)
        return result
    
    def _parse_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """解析sqlmap输出"""
        output = stdout + stderr
        vulnerabilities = []
        
        # 检测注入类型
        injection_patterns = [
            (r"boolean-based blind", "Boolean-based blind SQL injection"),
            (r"error-based", "Error-based SQL injection"),
            (r"UNION query", "UNION query SQL injection"),
            (r"stacked queries", "Stacked queries SQL injection"),
            (r"time-based blind", "Time-based blind SQL injection"),
        ]
        
        for pattern, name in injection_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                vulnerabilities.append({"type": name, "evidence": "Detected in output"})
        
        # 提取数据库信息
        db_info = {}
        db_match = re.search(r"web application technology: (.+)", output)
        if db_match:
            db_info["web_tech"] = db_match.group(1).strip()
        
        backend_match = re.search(r"back-end DBMS: (.+)", output)
        if backend_match:
            db_info["backend_dbms"] = backend_match.group(1).strip()
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "database_info": db_info,
            "raw_output": output[:2000]
        }


class NucleiTool(SecurityTool):
    """Nuclei漏洞扫描工具"""
    
    def __init__(self):
        super().__init__("nuclei", "nuclei")
    
    def scan_target(self, target: str, templates: str = None, 
                    severity: str = None, timeout: int = 300) -> ToolResult:
        """扫描目标漏洞"""
        args = ["-u", target, "-json", "-silent"]
        
        if templates:
            args.extend(["-t", templates])
        if severity:
            args.extend(["-severity", severity])
        
        result = self.run(args, timeout=timeout)
        if result.success and result.stdout:
            result.parsed_data = self._parse_json_output(result.stdout)
        return result
    
    def _parse_json_output(self, output: str) -> Dict[str, Any]:
        """解析Nuclei JSON输出"""
        findings = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
                findings.append({
                    "template": finding.get("template-id"),
                    "name": finding.get("info", {}).get("name"),
                    "severity": finding.get("info", {}).get("severity"),
                    "description": finding.get("info", {}).get("description"),
                    "matched_at": finding.get("matched-at"),
                    "type": finding.get("type")
                })
            except json.JSONDecodeError:
                continue
        
        return {
            "total_findings": len(findings),
            "findings": findings,
            "by_severity": {
                sev: sum(1 for f in findings if f["severity"] == sev)
                for sev in ["critical", "high", "medium", "low", "info"]
            }
        }


class MasscanTool(SecurityTool):
    """Masscan高速端口扫描工具"""
    
    def __init__(self):
        super().__init__("masscan", "masscan")
    
    def quick_scan(self, target: str, ports: str = "1-65535", 
                   rate: int = 10000, timeout: int = 300) -> ToolResult:
        """高速端口扫描"""
        output_file = f"/tmp/masscan_{os.getpid()}.json"
        args = [target, "-p", ports, "--rate", str(rate), "-oJ", output_file]
        
        result = self.run(args, timeout=timeout)
        if result.success and os.path.exists(output_file):
            try:
                with open(output_file) as f:
                    result.parsed_data = json.load(f)
                os.remove(output_file)
            except Exception as e:
                result.parsed_data = {"error": str(e)}
        return result


class NiktoTool(SecurityTool):
    """Nikto Web漏洞扫描工具"""
    
    def __init__(self):
        super().__init__("nikto", "nikto")
    
    def scan_url(self, url: str, timeout: int = 300) -> ToolResult:
        """扫描Web服务器漏洞"""
        args = ["-h", url, "-Format", "json"]
        result = self.run(args, timeout=timeout)
        if result.success:
            result.parsed_data = {"raw_output": result.stdout[:2000]}
        return result


class ToolManager:
    """安全工具管理器"""
    
    # 工具安装指南
    INSTALL_GUIDES = {
        "nmap": {
            "windows": "下载地址: https://nmap.org/download.html\n安装后自动加入系统PATH",
            "linux": "sudo apt install nmap 或 sudo yum install nmap",
            "mac": "brew install nmap"
        },
        "sqlmap": {
            "windows": "方式1: git clone https://github.com/sqlmapproject/sqlmap.git\n方式2: 下载zip解压到 C:\\tools\\sqlmap\n然后运行 install_tools.bat 自动配置",
            "linux": "sudo apt install sqlmap 或 git clone https://github.com/sqlmapproject/sqlmap.git",
            "mac": "brew install sqlmap"
        },
        "nuclei": {
            "windows": "下载地址: https://github.com/projectdiscovery/nuclei/releases\n下载nuclei_Windows_x86_64.zip解压到 C:\\tools\\",
            "linux": "下载对应版本: https://github.com/projectdiscovery/nuclei/releases",
            "mac": "brew install nuclei"
        },
        "masscan": {
            "windows": "Windows预编译版较少，推荐使用WSL:\n1. wsl --install\n2. wsl sudo apt install masscan\n或在 config/tools_config.json 中配置 wsl_command",
            "linux": "sudo apt install masscan 或 sudo yum install masscan",
            "mac": "brew install masscan"
        },
        "nikto": {
            "windows": "需要先安装Perl (Strawberry Perl):\n1. 下载 https://strawberryperl.com/\n2. git clone https://github.com/sullo/nikto.git\n3. 运行 install_tools.bat 自动配置",
            "linux": "sudo apt install nikto",
            "mac": "brew install nikto"
        }
    }
    
    def __init__(self):
        self.tools = {
            "nmap": NmapTool(),
            "sqlmap": SqlmapTool(),
            "nuclei": NucleiTool(),
            "masscan": MasscanTool(),
            "nikto": NiktoTool(),
        }
    
    def get_tool(self, name: str) -> Optional[SecurityTool]:
        """获取工具实例"""
        return self.tools.get(name)
    
    def list_available_tools(self) -> List[Dict[str, Any]]:
        """列出所有可用工具"""
        available = []
        for name, tool in self.tools.items():
            is_avail = tool.is_available()
            available.append({
                "name": name,
                "binary": tool.binary,
                "available": is_avail,
                "path": tool._tool_path or (shutil.which(tool.binary) if is_avail else None),
                "wrapper": tool._wrapper,
                "enabled": _is_tool_enabled(name)
            })
        return available
    
    def get_tool_status(self) -> Dict[str, Any]:
        """获取工具状态概览"""
        tools = self.list_available_tools()
        return {
            "total_tools": len(tools),
            "available_tools": sum(1 for t in tools if t["available"]),
            "missing_tools": sum(1 for t in tools if not t["available"]),
            "tools": tools
        }
    
    def get_install_guide(self, tool_name: str) -> Optional[Dict[str, str]]:
        """获取工具安装指南"""
        return self.INSTALL_GUIDES.get(tool_name)
    
    def get_all_install_guides(self) -> Dict[str, Any]:
        """获取所有未安装工具的安装指南"""
        missing_tools = []
        for name, tool in self.tools.items():
            if not tool.is_available():
                guide = self.get_install_guide(name)
                missing_tools.append({
                    "name": name,
                    "guide": guide
                })
        return {
            "missing_count": len(missing_tools),
            "tools": missing_tools,
            "auto_install_script": "运行 install_tools.bat 可自动安装大部分工具"
        }
    
    def run_quick_diagnosis(self) -> Dict[str, Any]:
        """快速诊断工具环境"""
        status = self.get_tool_status()
        guides = self.get_all_install_guides()
        
        # 检查依赖环境
        dependencies = {
            "python": shutil.which("python") is not None,
            "git": shutil.which("git") is not None,
            "perl": shutil.which("perl") is not None,
        }
        
        return {
            "tool_status": status,
            "install_guides": guides,
            "dependencies": dependencies,
            "config_file": _CONFIG_PATH,
            "recommendation": self._get_recommendation(status, dependencies)
        }
    
    def _get_recommendation(self, status: Dict, dependencies: Dict) -> str:
        """生成安装建议"""
        if status["available_tools"] == status["total_tools"]:
            return "所有工具已安装，环境完整！"
        
        recommendations = []
        if not dependencies["perl"]:
            recommendations.append("安装 Strawberry Perl (nikto 依赖)")
        
        missing = [t["name"] for t in status["tools"] if not t["available"]]
        if missing:
            recommendations.append(f"安装缺失工具: {', '.join(missing)}")
            recommendations.append("运行 install_tools.bat 一键安装")
            recommendations.append("或在 config/tools_config.json 中手动配置工具路径")
        
        return "；".join(recommendations)


# 全局工具管理器实例
tool_manager = ToolManager()


# =============================================================================
# 以下为深化模块：sqlmap 批量/结果解析、nikto 插件化、masscan WSL/降级、
# Metasploit RPC 客户端（仅信息收集模块）以及统一工具调用门面 ToolIntegration。
# 注意：以上 NmapTool / SqlmapTool / NucleiTool / MasscanTool / NiktoTool /
# ToolManager 的既有实现保持不变，本节只做追加。
# =============================================================================

import sys as _sys
import time as _time
import tempfile as _tempfile

try:
    import requests as _requests
except Exception:  # pragma: no cover - requests 缺失时降级
    _requests = None


# ---------------------------------------------------------------------------
# 通用安装指引（Windows 优先，含国内镜像）
# ---------------------------------------------------------------------------
DEEP_INSTALL_GUIDES: Dict[str, str] = {
    "nmap": (
        "Windows: winget install Insecure.Nmap  或  官方下载 https://nmap.org/download.html\n"
        "国内镜像: https://mirrors.tuna.tsinghua.edu.cn/nmap/\n"
        "Linux: sudo apt install nmap  |  Mac: brew install nmap"
    ),
    "nuclei": (
        "Windows: 预编译二进制 https://github.com/projectdiscovery/nuclei/releases\n"
        "         国内加速: https://ghproxy.com/https://github.com/projectdiscovery/nuclei/releases\n"
        "         或: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n"
        "模板更新: nuclei -ut"
    ),
    "sqlmap": (
        "Windows: git clone https://github.com/sqlmapproject/sqlmap.git %USERPROFILE%\\tools\\sqlmap\n"
        "         国内镜像: https://gitee.com/mirrors/sqlmap.git\n"
        "         依赖 Python3；运行方式: python sqlmap.py [options]\n"
        "Linux: sudo apt install sqlmap"
    ),
    "nikto": (
        "Windows: 1) 先安装 Strawberry Perl https://strawberryperl.com/\n"
        "         2) git clone https://github.com/sullo/nikto.git %USERPROFILE%\\tools\\nikto\n"
        "         国内镜像: https://gitee.com/mirrors/nikto.git\n"
        "         3) 运行: perl nikto.pl -h <url>\n"
        "Linux: sudo apt install nikto"
    ),
    "masscan": (
        "Windows: 推荐 WSL ——  wsl --install  然后  wsl sudo apt install masscan\n"
        "         或使用预编译版: https://github.com/robertdavidgraham/masscan/releases\n"
        "Linux: sudo apt install masscan"
    ),
    "metasploit": (
        "Windows: 下载安装包 https://www.metasploit.com/download  或在 WSL 中:\n"
        "         curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfupdate | bash\n"
        "启动 RPC 服务: msfrpcd -P <强密码> -S -a 127.0.0.1 -p 55553\n"
        "本客户端仅允许 auxiliary/scanner 与 auxiliary/gather 信息收集模块。"
    ),
    "hashcat": (
        "Windows: 预编译二进制 https://hashcat.net/hashcat/  解压后加入 PATH\n"
        "Linux: sudo apt install hashcat"
    ),
    "dirsearch": (
        "Windows: git clone https://github.com/maurosoria/dirsearch.git %USERPROFILE%\\tools\\dirsearch\n"
        "         国内镜像: https://gitee.com/mirrors/dirsearch.git\n"
        "         然后: pip install -r requirements.txt   (清华镜像: -i https://pypi.tuna.tsinghua.edu.cn/simple)\n"
        "         运行: python dirsearch.py -u <url>"
    ),
}


def _unified_result(tool: str, status: str, result: Optional[Dict] = None,
                    error: str = "", duration_ms: int = 0,
                    install_guide: str = "") -> Dict[str, Any]:
    """构造统一工具调用返回格式。"""
    return {
        "tool": tool,
        "status": status,          # success / failed / unavailable
        "result": result or {},
        "error": error,
        "duration_ms": int(duration_ms),
        "install_guide": install_guide,
    }


def _run_capture(cmd: List[str], timeout: int = 300, cwd: Optional[str] = None) -> Dict[str, Any]:
    """跨平台执行命令并捕获输出，统一使用 utf-8 解码（errors=replace）。"""
    start = _time.time()
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            encoding="utf-8",
            errors="replace",
        )
        return {
            "rc": p.returncode,
            "stdout": p.stdout or "",
            "stderr": p.stderr or "",
            "duration_ms": int((_time.time() - start) * 1000),
            "exception": None,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "rc": -1,
            "stdout": e.stdout.decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or ""),
            "stderr": e.stderr.decode("utf-8", "replace") if isinstance(e.stderr, bytes) else (e.stderr or ""),
            "duration_ms": int((_time.time() - start) * 1000),
            "exception": f"timeout after {timeout}s",
        }
    except FileNotFoundError as e:
        return {"rc": -1, "stdout": "", "stderr": "", "duration_ms": 0, "exception": f"command not found: {e}"}
    except Exception as e:
        return {"rc": -1, "stdout": "", "stderr": "", "duration_ms": 0, "exception": str(e)}


def _which_all(name: str) -> Optional[str]:
    """在 PATH 中查找可执行文件（Windows 自动补 .exe/.cmd）。"""
    found = shutil.which(name)
    if found:
        return found
    if os.name == "nt":
        for ext in (".exe", ".cmd", ".bat"):
            found = shutil.which(name + ext)
            if found:
                return found
    return None


# ---------------------------------------------------------------------------
# sqlmap 深化：单 URL / 批量扫描 + 结果解析
# ---------------------------------------------------------------------------
def _sqlmap_command() -> Optional[List[str]]:
    """构造 sqlmap 启动命令。Windows 下用 python 调 sqlmap.py；Linux 下直接 sqlmap。"""
    path = _get_tool_path("sqlmap")
    if path and os.path.exists(path):
        if path.lower().endswith(".py"):
            wrapper = _get_tool_wrapper("sqlmap") or _sys.executable
            return [wrapper, path]
        return [path]
    if os.name == "nt":
        exe = _which_all("sqlmap")
        if exe:
            return [exe]
        # 退化：尝试当前工作目录下的 sqlmap.py
        candidate = os.path.join(_tempfile.gettempdir(), "..", "sqlmap.py")
        return None
    exe = _which_all("sqlmap")
    return [exe] if exe else None


def _parse_sqlmap_output(stdout: str, stderr: str) -> Dict[str, Any]:
    """解析 sqlmap 终端输出，提取注入点、数据库类型/用户/库/表。"""
    out = (stdout or "") + "\n" + (stderr or "")
    parsed: Dict[str, Any] = {
        "vulnerable": False,
        "injection_points": [],
        "backend_dbms": "",
        "current_user": "",
        "current_database": "",
        "databases": [],
        "tables": [],
        "techniques": [],
        "summary": out[-1500:],
    }

    for m in re.finditer(
        r"(GET|POST|Cookie|User-Agent|Referer)\s+parameter\s+'([^']+)'\s+is\s+([^.]*?)(?:inject|vulnerable)",
        out, re.IGNORECASE,
    ):
        parsed["injection_points"].append({
            "place": m.group(1),
            "parameter": m.group(2),
            "technique": m.group(3).strip(),
        })

    if re.search(r"is (?:vulnerable|injectable)", out, re.IGNORECASE) or parsed["injection_points"]:
        parsed["vulnerable"] = True

    m = re.search(r"back-end DBMS[^:]*:\s*(.+)", out)
    if m:
        parsed["backend_dbms"] = m.group(1).strip()
    m = re.search(r"current user[^:]*:\s*'?([^'\r\n]+)'?", out)
    if m:
        parsed["current_user"] = m.group(1).strip()
    m = re.search(r"current database[^:]*:\s*'?([^'\r\n]+)'?", out)
    if m:
        parsed["current_database"] = m.group(1).strip()

    db_block = re.search(r"available databases \[(\d+)\]:(.*?)(?=\n\s*$|\Z)", out, re.DOTALL)
    if db_block:
        for line in db_block.group(2).splitlines():
            line = line.strip()
            m2 = re.match(r"\[\*\]\s*'?([^'\]]+)'?", line)
            if m2:
                parsed["databases"].append(m2.group(1).strip())

    for m in re.finditer(r"Table:\s+([^\r\n]+)", out):
        t = m.group(1).strip().strip("'")
        if t and t not in parsed["tables"]:
            parsed["tables"].append(t)

    for tech in ["boolean-based blind", "error-based", "UNION query",
                 "stacked queries", "time-based blind", "inline query"]:
        if tech.lower() in out.lower():
            parsed["techniques"].append(tech)

    return parsed


def scan_sql_injection(url: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """对单个 URL 执行 sqlmap SQL 注入扫描。

    options 支持:
        level(1-5), risk(1-3), threads, batch(True), p(指定参数),
        cookie, data(POST 数据), dbs(枚举数据库), tables(枚举表),
        timeout(秒, 默认300), proxy, technique
    """
    opts = dict(options or {})
    cmd_base = _sqlmap_command()
    if not cmd_base:
        return _unified_result(
            "sqlmap", "unavailable",
            error="未找到 sqlmap（既未在 config/tools_config.json 配置路径，也不在 PATH 中）",
            install_guide=DEEP_INSTALL_GUIDES["sqlmap"],
        )

    args = ["-u", url, "--batch"]
    level = opts.get("level", 1)
    risk = opts.get("risk", 1)
    args += ["--level", str(max(1, min(5, int(level)))),
             "--risk", str(max(1, min(3, int(risk))))]
    if opts.get("threads"):
        args += ["--threads", str(opts["threads"])]
    if opts.get("p"):
        args += ["-p", str(opts["p"])]
    if opts.get("cookie"):
        args += ["--cookie", str(opts["cookie"])]
    if opts.get("data"):
        args += ["--data", str(opts["data"])]
    if opts.get("proxy"):
        args += ["--proxy", str(opts["proxy"])]
    if opts.get("technique"):
        args += ["--technique", str(opts["technique"])]
    if opts.get("dbs"):
        args.append("--dbs")
    if opts.get("tables"):
        args.append("--tables")

    out_dir = os.path.join(_tempfile.gettempdir(), "sqlmap_out")
    os.makedirs(out_dir, exist_ok=True)
    args += ["--output-dir", out_dir]

    timeout = int(opts.get("timeout", 300))
    cmd = cmd_base + args
    log.info(f"[sqlmap] 执行: {' '.join(cmd)}")
    res = _run_capture(cmd, timeout=timeout)
    duration = res["duration_ms"]

    if res["exception"] and "not found" in (res["exception"] or ""):
        return _unified_result("sqlmap", "unavailable", error=res["exception"],
                               duration_ms=duration, install_guide=DEEP_INSTALL_GUIDES["sqlmap"])

    parsed = _parse_sqlmap_output(res["stdout"], res["stderr"])
    ran_ok = res["rc"] == 0 and not res["exception"]
    status = "success" if (ran_ok or parsed["vulnerable"]) else "failed"
    return _unified_result(
        "sqlmap", status,
        result={"url": url, **parsed, "rc": res["rc"]},
        error=res["exception"] or (res["stderr"][-300:] if not parsed["vulnerable"] else ""),
        duration_ms=duration,
        install_guide="" if parsed["vulnerable"] else DEEP_INSTALL_GUIDES["sqlmap"],
    )


def scan_sql_injection_batch(urls: List[str], options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """对 URL 列表批量执行 sqlmap 扫描（串行）。"""
    if not urls:
        return _unified_result("sqlmap", "failed", error="urls 为空")
    results = []
    overall_ok = 0
    for i, u in enumerate(urls):
        log.info(f"[sqlmap-batch] ({i + 1}/{len(urls)}) {u}")
        r = scan_sql_injection(u, options)
        results.append(r)
        if r["status"] == "success":
            overall_ok += 1
    return _unified_result(
        "sqlmap", "success" if results else "failed",
        result={"total": len(urls), "succeeded": overall_ok, "per_url": results},
        duration_ms=sum(int(r.get("duration_ms", 0)) for r in results),
    )


# ---------------------------------------------------------------------------
# nikto 深化：插件/规避选项 + JSON 结果解析
# ---------------------------------------------------------------------------
def _nikto_command() -> Optional[List[str]]:
    path = _get_tool_path("nikto")
    if path and os.path.exists(path):
        wrapper = _get_tool_wrapper("nikto") or "perl"
        return [wrapper, path]
    if os.name == "nt":
        exe = _which_all("nikto")
        if exe:
            return [exe]
        if not _which_all("perl"):
            return None  # 没有 perl，也没有 nikto
        return ["perl", "nikto.pl"]
    exe = _which_all("nikto")
    return [exe] if exe else None


def _parse_nikto_output(stdout: str, stderr: str) -> Dict[str, Any]:
    """解析 nikto 输出（优先 JSON，否则按行解析）。"""
    raw = stdout or ""
    findings: List[Dict[str, Any]] = []
    fmt = "text"

    stripped = raw.strip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            data = json.loads(stripped)
            fmt = "json"
            items = data if isinstance(data, list) else data.get("items", [])
            for it in items:
                findings.append({
                    "osvdb": it.get("OSVDB") or it.get("id") or "",
                    "method": it.get("method", ""),
                    "url": it.get("url", ""),
                    "description": it.get("msg", it.get("description", "")),
                })
        except json.JSONDecodeError:
            fmt = "text"

    if fmt == "text":
        for line in raw.splitlines():
            line = line.strip()
            if not line.startswith("+"):
                continue
            m = re.search(r"OSVDB-?(\d+)", line)
            findings.append({
                "osvdb": m.group(1) if m else "",
                "method": "",
                "url": "",
                "description": line.lstrip("+ ").strip(),
            })

    return {"format": fmt, "total_findings": len(findings), "findings": findings,
            "raw_tail": (stderr or "")[-500:]}


def scan_web_server(url: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """使用 nikto 扫描 Web 服务器。

    options 支持: plugins(插件名), evasion(1-8 数字串), timeout(秒),
                  output_format(json/text), id(扫描 id)
    """
    opts = dict(options or {})
    perl_missing = os.name == "nt" and not _which_all("perl") and not _get_tool_path("nikto")
    if perl_missing:
        return _unified_result(
            "nikto", "unavailable",
            error="Windows 下未检测到 Perl 运行环境，nikto 需要 Strawberry Perl",
            install_guide=DEEP_INSTALL_GUIDES["nikto"],
        )

    cmd_base = _nikto_command()
    if not cmd_base:
        return _unified_result("nikto", "unavailable",
                               error="未找到 nikto（配置路径与 PATH 均未命中）",
                               install_guide=DEEP_INSTALL_GUIDES["nikto"])

    args = ["-h", url]
    out_fmt = opts.get("output_format", "json")
    if out_fmt == "json":
        args += ["-Format", "json"]
    if opts.get("plugins"):
        args += ["-Plugins", str(opts["plugins"])]
    if opts.get("evasion"):
        args += ["-evasion", str(opts["evasion"])]
    if opts.get("id"):
        args += ["-id", str(opts["id"])]

    timeout = int(opts.get("timeout", 300))
    cmd = cmd_base + args
    log.info(f"[nikto] 执行: {' '.join(cmd)}")
    res = _run_capture(cmd, timeout=timeout)

    if res["exception"] and "not found" in (res["exception"] or ""):
        return _unified_result("nikto", "unavailable", error=res["exception"],
                               duration_ms=res["duration_ms"],
                               install_guide=DEEP_INSTALL_GUIDES["nikto"])

    parsed = _parse_nikto_output(res["stdout"], res["stderr"])
    return _unified_result(
        "nikto", "success",
        result={"url": url, **parsed, "rc": res["rc"]},
        error=res["exception"] or "",
        duration_ms=res["duration_ms"],
    )


# ---------------------------------------------------------------------------
# masscan 深化：高速端口扫描，WSL 优先，失败降级 nmap
# ---------------------------------------------------------------------------
def _masscan_command() -> tuple:
    """返回 (cmd, backend) ；backend ∈ {native, wsl, None}。"""
    exe = _which_all("masscan") or _which_all("masscan.exe")
    if exe:
        return [exe], "native"
    if os.name == "nt" and _which_all("wsl"):
        probe = _run_capture(["wsl", "masscan", "--version"], timeout=15)
        if probe["rc"] == 0:
            return ["wsl", "masscan"], "wsl"
    return None, None


def _parse_masscan(stdout: str) -> Dict[str, Any]:
    """解析 masscan -oJ - 的 JSON 输出（可能为单个数组，或多个 JSON 对象行）。"""
    open_ports: List[Dict[str, Any]] = []
    text = (stdout or "").strip()
    if not text:
        return {"open_ports": open_ports, "total": 0}
    records = []
    try:
        data = json.loads(text)
        records = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("{"):
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    for rec in records:
        ip = rec.get("ip", "")
        for p in rec.get("ports", []) or []:
            open_ports.append({
                "ip": ip,
                "port": p.get("port"),
                "proto": p.get("proto", "tcp"),
                "reason": p.get("reason", ""),
            })
    return {"open_ports": open_ports, "total": len(open_ports)}


def scan_ports_fast(target: str, ports: str = "1-65535",
                    options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """使用 masscan 高速扫描端口；Windows 下自动走 WSL；不可用则降级 nmap。

    options 支持: rate(默认1000), interface, exclude, timeout(秒, 默认300)
    """
    opts = dict(options or {})
    rate = int(opts.get("rate", 1000))
    cmd, backend = _masscan_command()

    if cmd:
        args = [target, "-p", ports, "--rate", str(rate)]
        if opts.get("interface"):
            args += ["--interface", str(opts["interface"])]
        if opts.get("exclude"):
            args += ["--exclude", str(opts["exclude"])]
        args += ["-oJ", "-"]
        timeout = int(opts.get("timeout", 300))
        full = cmd + args
        log.info(f"[masscan:{backend}] 执行: {' '.join(full)}")
        res = _run_capture(full, timeout=timeout)
        if not (res["exception"] and "not found" in res["exception"]):
            parsed = _parse_masscan(res["stdout"])
            return _unified_result(
                "masscan", "success",
                result={"target": target, "ports": ports, "backend": backend, **parsed, "rc": res["rc"]},
                error=res["exception"] or "",
                duration_ms=res["duration_ms"],
            )

    # 降级：使用 nmap
    log.warning("[masscan] 不可用，降级到 nmap 进行端口扫描")
    nmap = NmapTool()
    if not nmap.is_available():
        return _unified_result(
            "masscan", "unavailable",
            error="masscan 不可用且降级 nmap 也未安装",
            result={"fallback": "nmap", "backend": "none"},
            install_guide=DEEP_INSTALL_GUIDES["masscan"] + "\n降级方案: " + DEEP_INSTALL_GUIDES["nmap"],
        )
    timeout = int(opts.get("timeout", 300))
    nr = nmap.quick_scan(target, ports=ports, timeout=timeout)
    return _unified_result(
        "masscan", "success" if nr.success else "failed",
        result={"target": target, "ports": ports, "backend": "nmap-fallback",
                "parsed": nr.parsed_data, "note": "masscan 不可用，已自动降级为 nmap"},
        error=nr.error,
        duration_ms=int((nr.execution_time or 0) * 1000),
        install_guide=DEEP_INSTALL_GUIDES["masscan"],
    )


# ---------------------------------------------------------------------------
# Metasploit RPC 客户端（仅信息收集模块）
# ---------------------------------------------------------------------------
class MetasploitClient:
    """通过 msfrpcd JSON-RPC 与 Metasploit 通信。

    合规约束：仅允许 auxiliary/scanner/* 与 auxiliary/gather/* 等信息收集模块，
    exploit/post/payload/auxiliary/admin 一律拒绝执行。
    """

    ALLOWED_PREFIXES = ("auxiliary/scanner/", "auxiliary/gather/")
    BLOCKED_PREFIXES = ("exploit/", "post/", "payload/", "auxiliary/admin/")

    def __init__(self, host: str = "127.0.0.1", port: int = 55553,
                 user: str = "msf", password: str = "msf", timeout: int = 10):
        self.host = host
        self.port = int(port)
        self.user = user
        self.password = password
        self.timeout = timeout
        self.base_url = f"http://{host}:{int(port)}/api/1.1/"
        self.token: Optional[str] = None
        self.connected = False
        self.last_error = ""

    # -- 底层 RPC ---------------------------------------------------------
    def _post(self, data) -> Dict[str, Any]:
        if _requests is None:
            return {"error": "Python requests 库未安装，请 pip install requests"}
        try:
            r = _requests.post(self.base_url, data=data, timeout=self.timeout)
            return r.json()
        except _requests.exceptions.ConnectionError as e:
            return {"error": f"连接 msfrpcd 失败 ({self.base_url}): {e}"}
        except Exception as e:
            return {"error": str(e)}

    def connect(self) -> bool:
        resp = self._post({"username": self.user, "password": self.password})
        if isinstance(resp, dict) and resp.get("result") == "success" and resp.get("token"):
            self.token = resp["token"]
            self.connected = True
            self.last_error = ""
        else:
            self.connected = False
            self.last_error = str(resp)
        return self.connected

    def _rpc(self, method: str, options=None) -> Dict[str, Any]:
        if not self.connected and not self.connect():
            return {"error": "未连接 msfrpcd: " + self.last_error}
        body = {"token": self.token, "method": method}
        if options is not None:
            body["options"] = options
        resp = self._post(body)
        # token 失效则重连一次
        if isinstance(resp, dict) and resp.get("error_message") == "Invalid Authentication Token.":
            self.connected = False
            if self.connect():
                body["token"] = self.token
                resp = self._post(body)
        return resp

    # -- 模块白名单 -------------------------------------------------------
    def _is_allowed(self, module_name: str) -> bool:
        if any(module_name.startswith(b) for b in self.BLOCKED_PREFIXES):
            return False
        return any(module_name.startswith(a) for a in self.ALLOWED_PREFIXES)

    # -- 公开 API ---------------------------------------------------------
    def search_modules(self, keyword: str, module_type: str = "auxiliary") -> List[Dict[str, Any]]:
        resp = self._rpc("module.search", keyword)
        if not isinstance(resp, dict):
            return []
        hits = resp.get("residuals") or resp.get("modules") or {}
        out: List[Dict[str, Any]] = []
        if isinstance(hits, dict):
            iterable = hits.items()
        elif isinstance(hits, list):
            iterable = [(h if isinstance(h, str) else h.get("fullname", ""),
                         h if isinstance(h, dict) else {}) for h in hits]
        else:
            iterable = []
        for name, desc in iterable:
            if not name or not name.startswith(module_type + "/"):
                continue
            if self._is_allowed(name):
                out.append({"name": name, "description": desc if isinstance(desc, str) else str(desc)})
        return out

    def execute_module(self, module_name: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self._is_allowed(module_name):
            return {
                "status": "blocked",
                "error": (f"模块 '{module_name}' 不是信息收集类模块；"
                          f"仅允许 {' / '.join(self.ALLOWED_PREFIXES)}*"),
            }
        options = options or {}
        if not self.connected and not self.connect():
            return {"status": "unavailable", "error": "未连接 msfrpcd: " + self.last_error,
                    "install_guide": DEEP_INSTALL_GUIDES["metasploit"]}
        body = [
            ("token", self.token),
            ("method", "module.execute"),
            ("options[0]", "auxiliary"),
            ("options[1]", module_name),
        ]
        for k, v in options.items():
            body.append((f"options[2][{k}]", str(v)))
        try:
            r = _requests.post(self.base_url, data=body, timeout=self.timeout)
            resp = r.json()
        except Exception as e:
            return {"status": "failed", "error": str(e)}
        if isinstance(resp, dict) and "job_id" in resp:
            return {"status": "queued", "job_id": resp["job_id"], "uuid": resp.get("uuid")}
        return {"status": "failed", "error": str(resp)}

    def get_job_status(self, job_id) -> Dict[str, Any]:
        resp = self._rpc("job.list")
        if not isinstance(resp, dict):
            return {"running": False, "error": str(resp)}
        jobs = resp.get("jobs", {})
        return {"running": str(job_id) in jobs, "job_id": str(job_id), "jobs": jobs}

    def list_sessions(self) -> Dict[str, Any]:
        resp = self._rpc("session.list")
        return resp if isinstance(resp, dict) else {"error": str(resp)}

    def get_session_info(self, session_id) -> Dict[str, Any]:
        sessions = self.list_sessions()
        info = sessions.get(str(session_id))
        if info is None:
            return {"session_id": str(session_id), "error": "session not found"}
        return {"session_id": str(session_id), **(info if isinstance(info, dict) else {"info": info})}


def _get_metasploit_client() -> MetasploitClient:
    cfg = _load_tools_config().get("tools", {}).get("metasploit", {})
    rpc = cfg.get("rpc", {}) if isinstance(cfg.get("rpc"), dict) else {}
    return MetasploitClient(
        host=rpc.get("msfrpcd_host", cfg.get("msfrpcd_host", "127.0.0.1")),
        port=rpc.get("msfrpcd_port", cfg.get("msfrpcd_port", 55553)),
        user=rpc.get("msfrpcd_user", cfg.get("msfrpcd_user", "msf")),
        password=rpc.get("msfrpcd_password", cfg.get("msfrpcd_password", "msf")),
    )


# ---------------------------------------------------------------------------
# 统一工具调用门面
# ---------------------------------------------------------------------------
class ToolIntegration:
    """统一工具调用入口：外部通过工具名 + 参数调用任意已集成工具。

    返回统一结构：
        {"tool": ..., "status": success|failed|unavailable,
         "result": {...}, "error": ..., "duration_ms": ..., "install_guide": ...}
    """

    def __init__(self):
        self.manager = ToolManager()

    # -- 高层封装 ---------------------------------------------------------
    def scan_sql_injection(self, url: str, options: Optional[Dict] = None) -> Dict[str, Any]:
        return scan_sql_injection(url, options)

    def scan_sql_injection_batch(self, urls: List[str], options: Optional[Dict] = None) -> Dict[str, Any]:
        return scan_sql_injection_batch(urls, options)

    def scan_web_server(self, url: str, options: Optional[Dict] = None) -> Dict[str, Any]:
        return scan_web_server(url, options)

    def scan_ports_fast(self, target: str, ports: str = "1-65535",
                        options: Optional[Dict] = None) -> Dict[str, Any]:
        return scan_ports_fast(target, ports, options)

    def metasploit(self) -> MetasploitClient:
        """返回 Metasploit RPC 客户端（懒连接）。"""
        return _get_metasploit_client()

    # -- 统一分发 ---------------------------------------------------------
    def call(self, tool: str, **kwargs) -> Dict[str, Any]:
        """按工具名统一调用。

        关键字参数:
            action: 工具子动作（scan / batch / search / execute / jobs / sessions）
            其余参数透传给对应工具函数。
        """
        tool = (tool or "").strip().lower()
        action = (kwargs.pop("action", "scan") or "scan").lower()
        start = _time.time()

        try:
            if tool in ("sqlmap",):
                if action in ("batch",):
                    return self.scan_sql_injection_batch(kwargs.get("urls") or [], kwargs)
                return self.scan_sql_injection(kwargs.get("url"), kwargs)
            if tool == "nikto":
                return self.scan_web_server(kwargs.get("url"), kwargs)
            if tool == "masscan":
                return self.scan_ports_fast(kwargs.get("target", ""),
                                            kwargs.get("ports", "1-65535"), kwargs)
            if tool == "nmap":
                nmap = NmapTool()
                if not nmap.is_available():
                    return _unified_result("nmap", "unavailable",
                                           error="nmap 未安装",
                                           install_guide=DEEP_INSTALL_GUIDES["nmap"])
                res = nmap.quick_scan(kwargs.get("target", ""),
                                      ports=kwargs.get("ports", "1-1000"),
                                      timeout=int(kwargs.get("timeout", 120)))
                return _unified_result("nmap", "success" if res.success else "failed",
                                       result=res.parsed_data, error=res.error,
                                       duration_ms=int((res.execution_time or 0) * 1000))
            if tool == "nuclei":
                nuclei = NucleiTool()
                if not nuclei.is_available():
                    return _unified_result("nuclei", "unavailable",
                                            error="nuclei 未安装",
                                            install_guide=DEEP_INSTALL_GUIDES["nuclei"])
                res = nuclei.scan_target(kwargs.get("target", ""),
                                         templates=kwargs.get("templates"),
                                         severity=kwargs.get("severity"),
                                         timeout=int(kwargs.get("timeout", 300)))
                return _unified_result("nuclei", "success" if res.success else "failed",
                                       result=res.parsed_data, error=res.error,
                                       duration_ms=int((res.execution_time or 0) * 1000))
            if tool == "metasploit":
                client = self.metasploit()
                if action == "search":
                    hits = client.search_modules(kwargs.get("keyword", ""),
                                                 kwargs.get("module_type", "auxiliary"))
                    return _unified_result("metasploit", "success", result={"modules": hits},
                                           duration_ms=int((_time.time() - start) * 1000))
                if action == "execute":
                    r = client.execute_module(kwargs.get("module_name", ""),
                                              kwargs.get("options", {}))
                    status = "failed" if r.get("status") in ("blocked", "failed") else "success"
                    return _unified_result("metasploit", status, result=r,
                                           error=r.get("error", ""),
                                           duration_ms=int((_time.time() - start) * 1000),
                                           install_guide=DEEP_INSTALL_GUIDES["metasploit"]
                                           if status != "success" else "")
                if action == "jobs":
                    return _unified_result("metasploit", "success",
                                           result=client.get_job_status(kwargs.get("job_id", "")),
                                           duration_ms=int((_time.time() - start) * 1000))
                if action == "sessions":
                    return _unified_result("metasploit", "success",
                                           result=client.list_sessions(),
                                           duration_ms=int((_time.time() - start) * 1000))
                return _unified_result("metasploit", "failed",
                                       error=f"未知 metasploit 动作: {action}",
                                       install_guide=DEEP_INSTALL_GUIDES["metasploit"])
            return _unified_result(tool, "failed",
                                   error=f"未集成的工具: {tool}",
                                   install_guide=DEEP_INSTALL_GUIDES.get(tool, ""))
        except Exception as e:
            log.exception(f"[ToolIntegration] {tool}/{action} 异常")
            return _unified_result(tool, "failed", error=str(e),
                                   duration_ms=int((_time.time() - start) * 1000))

    def list_tools(self) -> List[str]:
        return ["nmap", "sqlmap", "nuclei", "masscan", "nikto",
                "metasploit", "hashcat", "dirsearch"]


# 统一门面全局实例
tool_integration = ToolIntegration()



# =====================================================================
# 模块二 2.3：工具可用性增强（追加，不修改上方已有逻辑）
# =====================================================================

import os as _os_for_health
import shutil as _shutil_for_health
import subprocess as _subprocess_for_health
from datetime import datetime as _dt_for_health


# 每个主要工具的安装指引文本
TOOL_INSTALL_GUIDES: Dict[str, str] = {
    "nmap": "下载安装包 https://nmap.org/dist/ 或 choco install nmap，安装后确认 nmap --version。",
    "sqlmap": "pip install sqlmap -i https://pypi.tuna.tsinghua.edu.cn/simple，"
              "或 git clone https://gitee.com/mirrors/sqlmap.git。",
    "nuclei": "https://github.com/projectdiscovery/nuclei/releases 下载 Windows 二进制，"
              "放入 %USERPROFILE%\\tools\\ 并加入 PATH。",
    "nikto": "需要 Perl 环境；或在 WSL 中 sudo apt install nikto。",
    "masscan": "Windows 原生支持差，建议在 WSL 中 sudo apt install masscan。",
    "metasploit": "下载 https://www.metasploit.com/download 完整安装包，"
                  "仅允许 auxiliary/scanner 与 auxiliary/gather 模块。",
    "hashcat": "https://hashcat.net/hashcat/ 下载 Windows 版本。",
    "dirsearch": "git clone https://github.com/maurosoria/dirsearch 后用 python 运行。",
    "hydra": "WSL 中 sudo apt install hydra；Windows 需自行编译。",
}


def tool_is_available(tool_name: str,
                       exe_path: str = "",
                       version_args: Optional[List[str]] = None) -> bool:
    """检查工具是否真正可执行：路径存在 + --version 退出码为 0。"""
    try:
        exe = exe_path or _shutil_for_health.which(tool_name) or tool_name
        if not _os_for_health.path.exists(exe) and not _shutil_for_health.which(exe):
            return False
        args = version_args or ["--version"]
        proc = _subprocess_for_health.run(
            [exe] + list(args),
            capture_output=True, timeout=15,
            text=True,
        )
        # 有些工具 --version 返回非 0 但仍输出版本号
        out = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode == 0 or any(
            ch.isdigit() for ch in out)
    except Exception:
        return False


def tool_install_guide(tool_name: str) -> str:
    """返回指定工具的安装指引字符串。"""
    return TOOL_INSTALL_GUIDES.get(
        tool_name,
        f"工具 {tool_name} 未内置安装指引，请参考官方文档。")


# 为 ToolIntegration 的主要工具类补充 is_available / install_guide 增强函数
def _enhance_tool_class(cls):
    """给工具类动态挂上 is_available / install_guide 方法（monkey-patch）。"""
    if not hasattr(cls, "is_available"):
        def _is_avail(self, *a, **kw):  # type: ignore
            name = getattr(self, "name", cls.__name__)
            path = getattr(self, "path", "") or getattr(self, "exe", "")
            return tool_is_available(name, path)
        cls.is_available = _is_avail  # type: ignore[attr-defined]
    if not hasattr(cls, "install_guide"):
        def _guide(self, *a, **kw):  # type: ignore
            name = getattr(self, "name", cls.__name__)
            return tool_install_guide(name)
        cls.install_guide = _guide  # type: ignore[attr-defined]
    return cls


# 对项目中已存在的工具类做轻量增强（容错：找不到类就跳过）
for _candidate_name in (
    "NmapScanner", "SQLMapScanner", "NucleiScanner", "MasscanScanner",
    "NiktoScanner", "MetasploitClient", "HashCracker", "DirSearch",
):
    try:
        _cls = globals().get(_candidate_name)
        if _cls is not None:
            _enhance_tool_class(_cls)
    except Exception:
        pass


def _fallback_result(tool_name: str, reason: str) -> Dict[str, Any]:
    """工具不可用时的统一降级返回。"""
    return {
        "status": "fallback",
        "tool": tool_name,
        "message": f"工具不可用，已降级为基础检测：{reason}",
        "result": {"note": "降级为基础 socket/HTTP 探测，结果仅供参考"},
        "install_guide": tool_install_guide(tool_name),
    }


class ToolHealthChecker:
    """工具健康检查器：批量检测所有工具可用性，生成健康报告。"""

    def __init__(self, tools: Optional[List[str]] = None):
        self.tools = tools or [
            "nmap", "sqlmap", "nuclei", "masscan", "nikto",
            "metasploit", "hashcat", "dirsearch", "hydra",
        ]
        self._cache: Dict[str, Dict[str, Any]] = {}

    def check_all(self) -> Dict[str, Dict[str, Any]]:
        """检测所有工具可用性。"""
        self._cache = {}
        for name in self.tools:
            try:
                ok = tool_is_available(name)
                self._cache[name] = {
                    "tool": name,
                    "available": ok,
                    "checked_at": _dt_for_health.now().isoformat(),
                    "install_guide": tool_install_guide(name),
                }
            except Exception as e:
                self._cache[name] = {
                    "tool": name, "available": False,
                    "error": str(e),
                    "install_guide": tool_install_guide(name),
                }
        return self._cache

    def get_unavailable_tools(self) -> List[str]:
        """返回不可用工具名列表。"""
        if not self._cache:
            self.check_all()
        return [k for k, v in self._cache.items()
                if not v.get("available")]

    def get_health_report(self) -> Dict[str, Any]:
        """生成工具健康报告。"""
        if not self._cache:
            self.check_all()
        available = [k for k, v in self._cache.items() if v.get("available")]
        unavailable = self.get_unavailable_tools()
        return {
            "generated_at": _dt_for_health.now().isoformat(),
            "total": len(self._cache),
            "available_count": len(available),
            "unavailable_count": len(unavailable),
            "available": available,
            "unavailable": unavailable,
            "details": self._cache,
            "next_steps": [
                f"运行 install_tool('{u}') 或手动安装：{TOOL_INSTALL_GUIDES.get(u, '')}"
                for u in unavailable[:5]
            ],
        }


# 全局健康检查实例
tool_health_checker = ToolHealthChecker()
