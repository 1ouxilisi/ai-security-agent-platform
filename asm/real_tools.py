"""
真实工具链执行器 - 调用系统级安全工具
支持: Nmap / Nuclei / SQLMap / Nikto / Subfinder / Httpx
"""
import subprocess
import json
import os
import re
import time
from typing import Dict, List, Optional, Any
from datetime import datetime


class RealToolExecutor:
    """真实安全工具执行器"""

    TOOLS = {
        "nmap": {"path": r"C:\Program Files (x86)\Nmap\nmap.exe", "type": "binary"},
        "nuclei": {"path": r"C:\Users\ASUS\tools\nuclei.exe", "type": "binary"},
        "sqlmap": {"path": r"C:\Users\ASUS\tools\sqlmap.bat", "type": "batch"},
        "nikto": {"path": r"C:\Users\ASUS\tools\nikto.bat", "type": "batch"},
        "subfinder": {"path": r"C:\Users\ASUS\bin\subfinder.exe", "type": "binary"},
        "httpx": {"path": r"C:\Users\ASUS\AppData\Local\Doubao\User Data\sandbox_runtime\bases\c98c5042338ed152c6f10ecd8591889f\python\Scripts\httpx.exe", "type": "binary"},
    }

    @staticmethod
    def check_tools() -> Dict[str, Dict]:
        """检查所有工具是否可用"""
        result = {}
        for name, info in RealToolExecutor.TOOLS.items():
            path = info["path"]
            exists = os.path.exists(path)
            result[name] = {
                "path": path,
                "available": exists,
                "type": info["type"]
            }
        return result

    @staticmethod
    def _run(cmd: List[str], timeout: int = 120, cwd: str = None) -> Dict[str, Any]:
        """执行命令并返回结果"""
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                encoding="utf-8",
                errors="replace"
            )
            return {
                "success": proc.returncode == 0 or proc.returncode == 1,
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "command": " ".join(cmd)
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"超时({timeout}s)", "command": " ".join(cmd)}
        except Exception as e:
            return {"success": False, "error": str(e), "command": " ".join(cmd)}


class NmapRunner:
    """Nmap真实扫描"""

    def __init__(self, target: str, timeout: int = 180):
        self.target = target
        self.timeout = timeout
        self.exe = RealToolExecutor.TOOLS["nmap"]["path"]

    def quick_scan(self) -> Dict:
        """快速端口扫描 -F"""
        r = RealToolExecutor._run(
            [self.exe, "-sT", "-F", "-T4", "--open", "-oX", "-", self.target],
            timeout=min(self.timeout, 120)
        )
        return self._parse_xml(r)

    def detailed_scan(self) -> Dict:
        """详细扫描 -sV -sC -O"""
        r = RealToolExecutor._run(
            [self.exe, "-sT", "-sV", "-sC", "-T4", "--open", "-oX", "-", self.target],
            timeout=self.timeout
        )
        return self._parse_xml(r)

    def vuln_scan(self) -> Dict:
        """漏洞扫描 --script vuln"""
        r = RealToolExecutor._run(
            [self.exe, "-sT", "-sV", "--script", "vuln", "-T4", "--open", "-oX", "-", self.target],
            timeout=self.timeout * 2
        )
        return self._parse_xml(r)

    def _parse_xml(self, result: Dict) -> Dict:
        """解析Nmap XML输出"""
        if not result.get("success"):
            return {"error": result.get("error", "扫描失败"), "raw": result.get("stderr", "")}

        xml = result.get("stdout", "")
        open_ports = []
        hostnames = []
        os_match = ""

        # 解析端口
        port_pattern = r'<port protocol="(\w+)" portid="(\d+)">(.*?)</port>'
        for match in re.finditer(port_pattern, xml, re.DOTALL):
            proto = match.group(1)
            port = int(match.group(2))
            block = match.group(3)
            state_match = re.search(r'<state state="(\w+)"', block)
            service_match = re.search(r'<service name="([^"]*)"[^>]*product="([^"]*)"[^>]*version="([^"]*)"', block)
            state = state_match.group(1) if state_match else "unknown"
            if state == "open":
                svc = service_match.group(1) if service_match else "unknown"
                product = service_match.group(2) if service_match else ""
                version = service_match.group(3) if service_match else ""
                open_ports.append({
                    "port": port, "protocol": proto,
                    "service": svc, "product": product, "version": version
                })

        # 解析主机名
        for m in re.finditer(r'<hostname name="([^"]*)"', xml):
            hostnames.append(m.group(1))

        # 解析OS
        os_m = re.search(r'<osmatch name="([^"]*)"', xml)
        if os_m:
            os_match = os_m.group(1)

        # 解析漏洞脚本结果
        vulns = []
        for m in re.finditer(r'<script id="([^"]*)" output="([^"]*)"', xml):
            vulns.append({"script": m.group(1), "output": m.group(2)[:200]})

        return {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "open_ports": open_ports,
            "open_ports_count": len(open_ports),
            "hostnames": hostnames,
            "os": os_match,
            "scripts": vulns,
            "raw_size": len(xml)
        }


class NucleiRunner:
    """Nuclei真实漏洞扫描"""

    def __init__(self, target: str, timeout: int = 120):
        self.target = target
        self.timeout = timeout
        self.exe = RealToolExecutor.TOOLS["nuclei"]["path"]
        self.template_dir = r"C:\Users\ASUS\nuclei-templates"

    def scan(self, severity: str = "critical,high") -> Dict:
        """执行Nuclei扫描（离线模式，本地模板目录）"""
        if severity == "all":
            severity = "critical,high,medium,low,info"
        target_url = self.target if self.target.startswith("http") else f"http://{self.target}"
        cmd = [self.exe, "-u", target_url, "-severity", severity,
               "-jsonl", "-silent", "-timeout", "10", "-retries", "1",
               "-nc", "-duc"]
        import os as _os
        if _os.path.isdir(self.template_dir):
            cmd.extend(["-t", self.template_dir])
        r = RealToolExecutor._run(cmd, timeout=self.timeout)
        return self._parse_json(r)

    def _parse_json(self, result: Dict) -> Dict:
        """解析Nuclei JSONL输出"""
        if not result.get("success"):
            return {"error": result.get("error", "扫描失败"), "vulnerabilities": []}

        vulns = []
        for line in result.get("stdout", "").strip().split("\n"):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                vulns.append({
                    "template_id": item.get("template-id", ""),
                    "template_name": item.get("info", {}).get("name", ""),
                    "severity": item.get("info", {}).get("severity", "unknown"),
                    "host": item.get("host", ""),
                    "matched": item.get("matched-at", ""),
                    "description": item.get("info", {}).get("description", "")[:200],
                    "cve": item.get("info", {}).get("classification", {}).get("cve-id", []),
                    "cvss": item.get("info", {}).get("classification", {}).get("cvss-score", "")
                })
            except json.JSONDecodeError:
                continue

        severity_dist = {}
        for v in vulns:
            sev = v["severity"]
            severity_dist[sev] = severity_dist.get(sev, 0) + 1

        return {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": vulns,
            "total": len(vulns),
            "severity_distribution": severity_dist
        }


class SubfinderRunner:
    """Subfinder子域名枚举"""

    def __init__(self, domain: str, timeout: int = 60):
        self.domain = domain
        self.timeout = timeout
        self.exe = RealToolExecutor.TOOLS["subfinder"]["path"]

    def enumerate(self) -> Dict:
        r = RealToolExecutor._run(
            [self.exe, "-d", self.domain, "-silent", "-timeout", "30"],
            timeout=self.timeout
        )
        subs = []
        for line in r.get("stdout", "").strip().split("\n"):
            line = line.strip()
            if line and "." in line:
                subs.append(line)
        return {
            "domain": self.domain,
            "subdomains": subs,
            "total": len(subs)
        }


class HttpxRunner:
    """Httpx存活探测"""

    def __init__(self, targets: List[str], timeout: int = 60):
        self.targets = targets
        self.timeout = timeout
        self.exe = RealToolExecutor.TOOLS["httpx"]["path"]

    def probe(self) -> Dict:
        input_str = "\n".join(self.targets)
        try:
            proc = subprocess.run(
                [self.exe, "-silent", "-status-code", "-title", "-tech-detect", "-json"],
                input=input_str,
                capture_output=True, text=True, timeout=self.timeout,
                encoding="utf-8", errors="replace"
            )
            results = []
            for line in proc.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                    results.append({
                        "url": item.get("url", ""),
                        "status_code": item.get("status_code", 0),
                        "title": item.get("title", ""),
                        "tech": item.get("tech", []),
                        "webserver": item.get("webserver", "")
                    })
                except:
                    continue
            return {"alive": results, "total": len(results)}
        except Exception as e:
            return {"error": str(e), "alive": []}


class NiktoRunner:
    """Nikto Web服务器扫描"""

    def __init__(self, target: str, timeout: int = 120):
        self.target = target
        self.timeout = timeout
        self.exe = RealToolExecutor.TOOLS["nikto"]["path"]

    def scan(self) -> Dict:
        url = self.target if self.target.startswith("http") else f"http://{self.target}"
        r = RealToolExecutor._run(
            [self.exe, "-h", url, "-nointeract", "-output", "-"],
            timeout=self.timeout
        )
        findings = []
        for line in r.get("stdout", "").split("\n"):
            line = line.strip()
            if line and ("OSVDB" in line or "Server:" in line or "E/" in line or "+ " in line):
                findings.append(line[:200])
        return {"target": self.target, "findings": findings, "total": len(findings)}


class SqlmapRunner:
    """SQLMap SQL注入检测"""

    def __init__(self, target: str, timeout: int = 180):
        self.target = target
        self.timeout = timeout
        self.exe = RealToolExecutor.TOOLS["sqlmap"]["path"]

    def scan(self, data: str = "", level: int = 3, risk: int = 2) -> Dict:
        """执行SQL注入检测"""
        url = self.target if self.target.startswith("http") else f"http://{self.target}"
        cmd = [self.exe, "-u", url, "--batch", "--level", str(level),
               "--risk", str(risk), "--threads", "4", "--smart"]
        if data:
            cmd.extend(["--data", data])
        r = RealToolExecutor._run(cmd, timeout=self.timeout)
        output = r.get("stdout", "") + r.get("stderr", "")
        injectable = []
        for line in output.split(chr(10)):
            line = line.strip()
            if ("is vulnerable" in line.lower() or "sql injection" in line.lower()
                    or "parameter:" in line.lower() or "type:" in line.lower()):
                injectable.append(line[:200])
        return {
            "target": self.target,
            "injectable": injectable,
            "total": len(injectable),
            "vulnerable": len(injectable) > 0,
            "raw_output_tail": output[-500:] if output else ""
        }


class SqlmapRunner:
    """SQLMap SQL注入检测"""

    def __init__(self, target: str, timeout: int = 180):
        self.target = target
        self.timeout = timeout
        self.exe = RealToolExecutor.TOOLS["sqlmap"]["path"]

    def scan(self, data: str = "", level: int = 3, risk: int = 2) -> Dict:
        """执行SQL注入检测"""
        url = self.target if self.target.startswith("http") else f"http://{self.target}"
        cmd = [self.exe, "-u", url, "--batch", "--level", str(level),
               "--risk", str(risk), "--threads", "4", "--smart"]
        if data:
            cmd.extend(["--data", data])
        r = RealToolExecutor._run(cmd, timeout=self.timeout)
        output = r.get("stdout", "") + r.get("stderr", "")
        injectable = []
        for line in output.split(chr(10)):
            line = line.strip()
            if ("is vulnerable" in line.lower() or "sql injection" in line.lower()
                    or "parameter:" in line.lower() or "type:" in line.lower()):
                injectable.append(line[:200])
        return {
            "target": self.target,
            "injectable": injectable,
            "total": len(injectable),
            "vulnerable": len(injectable) > 0,
            "raw_output_tail": output[-500:] if output else ""
        }
