# -*- coding: utf-8 -*-
"""
asset_discovery.py — 子域名发现 + 存活检测模块。

工具：
- subfinder（真实子域名枚举）— 优先调用
- CT 日志回退（crt.sh API）— subfinder 不可用时
- HTTP 存活探测（requests）— 真实检测每个子域名
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import socket
import subprocess
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# 工具路径探测
# --------------------------------------------------------------------------- #
def _find_binary(names: List[str], extra_paths: List[str] | None = None) -> Optional[str]:
    """在 PATH 和常见位置查找可执行文件。"""
    # 先查 PATH
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    # 再查常见额外路径
    candidates = [
        os.path.join(os.path.expanduser("~"), "go", "bin"),
        os.path.join(os.path.expanduser("~"), "tools"),
        r"C:\Program Files (x86)\Nmap",
        r"C:\Program Files\Nmap",
        r"C:\tools",
    ]
    if extra_paths:
        candidates.extend(extra_paths)
    for d in candidates:
        for name in names:
            p = os.path.join(d, name)
            if os.path.isfile(p):
                return p
    return None


SUBFINDER_BIN = _find_binary(["subfinder", "subfinder.exe"])
HTTPX_BIN = _find_binary(["httpx", "httpx.exe"])

# --------------------------------------------------------------------------- #
# 任务存储（内存字典）
# --------------------------------------------------------------------------- #
_TASKS: Dict[str, Dict[str, Any]] = {}


def _task_id(domain: str) -> str:
    return f"recon_{int(time.time())}_{abs(hash(domain)) % 10000}"


# --------------------------------------------------------------------------- #
# 子域名发现
# --------------------------------------------------------------------------- #
class AssetDiscovery:
    """子域名发现 + 存活检测。"""

    def __init__(self) -> None:
        self.subfinder_bin = SUBFINDER_BIN
        self.httpx_bin = HTTPX_BIN

    # ------------------------------------------------------------------ #
    # 1. subfinder 真实子域名枚举
    # ------------------------------------------------------------------ #
    def discover_subdomains_subfinder(self, domain: str, timeout: int = 300) -> List[str]:
        """用 subfinder 真实枚举子域名。"""
        if not self.subfinder_bin:
            logger.warning("subfinder not found, falling back to CT logs")
            return self._discover_subdomains_ct(domain, timeout)

        try:
            cmd = [
                self.subfinder_bin,
                "-d", domain,
                "-silent",
                "-timeout", "30",
            ]
            logger.info("Running subfinder: %s", " ".join(cmd))
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, encoding="utf-8", errors="replace",
            )
            subdomains = [
                line.strip() for line in result.stdout.strip().splitlines()
                if line.strip() and domain in line
            ]
            # 去重
            subdomains = sorted(set(subdomains))
            logger.info("subfinder found %d subdomains for %s", len(subdomains), domain)
            return subdomains
        except subprocess.TimeoutExpired:
            logger.error("subfinder timed out after %ds", timeout)
            return self._discover_subdomains_ct(domain, timeout)
        except Exception as e:
            logger.exception("subfinder error: %s", e)
            return self._discover_subdomains_ct(domain, timeout)

    # ------------------------------------------------------------------ #
    # 2. CT 日志回退（crt.sh）
    # ------------------------------------------------------------------ #
    def _discover_subdomains_ct(self, domain: str, timeout: int = 60) -> List[str]:
        """通过 crt.sh Certificate Transparency 日志发现子域名。"""
        try:
            import requests
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            logger.info("Querying crt.sh for %s", domain)
            resp = requests.get(url, timeout=timeout)
            if resp.status_code != 200:
                logger.warning("crt.sh returned %d", resp.status_code)
                return []
            data = resp.json()
            subs = set()
            for entry in data:
                name = entry.get("name_value", "")
                for line in name.splitlines():
                    line = line.strip().lstrip("*.").strip()
                    if line and domain in line and not line.startswith("*"):
                        subs.add(line.lower())
            result = sorted(subs)
            logger.info("crt.sh found %d subdomains for %s", len(result), domain)
            return result
        except Exception as e:
            logger.exception("crt.sh error: %s", e)
            return []

    # ------------------------------------------------------------------ #
    # 3. 存活检测
    # ------------------------------------------------------------------ #
    def probe_live(self, subdomains: List[str], timeout: int = 10) -> List[Dict[str, Any]]:
        """用 requests 真实检测子域名存活，返回 {subdomain, ip, status_code, title, url}。"""
        try:
            import requests
        except ImportError:
            requests = None  # type: ignore

        results: List[Dict[str, Any]] = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36",
        }

        for sub in subdomains:
            entry: Dict[str, Any] = {
                "subdomain": sub,
                "ip": None,
                "status_code": None,
                "title": None,
                "url": None,
                "is_live": False,
                "tech": None,
            }
            # DNS 解析
            try:
                entry["ip"] = socket.gethostbyname(sub)
            except socket.gaierror:
                entry["ip"] = None
                results.append(entry)
                continue

            # HTTP 探测
            if requests is not None:
                for scheme in ("https", "http"):
                    try:
                        url = f"{scheme}://{sub}"
                        resp = requests.get(
                            url, headers=headers, timeout=timeout,
                            allow_redirects=True, verify=False,
                        )
                        entry["status_code"] = resp.status_code
                        entry["url"] = resp.url
                        entry["is_live"] = True
                        # 提取标题
                        m = re.search(
                            r"<title[^>]*>(.*?)</title>",
                            resp.text, re.IGNORECASE | re.DOTALL,
                        )
                        if m:
                            entry["title"] = m.group(1).strip()[:200]
                        # 简单技术栈识别
                        server = resp.headers.get("Server", "")
                        powered = resp.headers.get("X-Powered-By", "")
                        techs = []
                        if server:
                            techs.append(server)
                        if powered:
                            techs.append(powered)
                        if "nginx" in server.lower():
                            techs.append("Nginx")
                        if "apache" in server.lower():
                            techs.append("Apache")
                        if "cloudflare" in server.lower():
                            techs.append("Cloudflare")
                        entry["tech"] = ", ".join(techs) if techs else None
                        break  # HTTPS 成功就不再试 HTTP
                    except requests.RequestException:
                        continue
            results.append(entry)
        return results

    # ------------------------------------------------------------------ #
    # 4. 完整侦察流程
    # ------------------------------------------------------------------ #
    def run_recon(self, domain: str, task_id: Optional[str] = None) -> Dict[str, Any]:
        """执行完整资产侦察：子域名发现 → 存活检测。"""
        tid = task_id or _task_id(domain)
        _TASKS[tid] = {
            "task_id": tid,
            "domain": domain,
            "status": "running",
            "stage": "discovering",
            "started_at": time.time(),
            "subdomains": [],
            "live_hosts": [],
            "error": None,
        }

        try:
            # Step 1: 子域名发现
            subdomains = self.discover_subdomains_subfinder(domain)
            # 确保主域名也在列表中
            if domain not in subdomains:
                subdomains.insert(0, domain)
            _TASKS[tid]["subdomains"] = subdomains
            _TASKS[tid]["stage"] = "probing"

            # Step 2: 存活检测
            live_hosts = self.probe_live(subdomains)
            _TASKS[tid]["live_hosts"] = live_hosts
            _TASKS[tid]["status"] = "completed"
            _TASKS[tid]["stage"] = "done"
            _TASKS[tid]["finished_at"] = time.time()

        except Exception as e:
            logger.exception("Recon failed for %s", domain)
            _TASKS[tid]["status"] = "failed"
            _TASKS[tid]["error"] = str(e)

        return self.get_task(tid)

    # ------------------------------------------------------------------ #
    # 任务查询
    # ------------------------------------------------------------------ #
    def get_task(self, task_id: str) -> Dict[str, Any]:
        return _TASKS.get(task_id, {})

    def list_tasks(self) -> List[Dict[str, Any]]:
        return sorted(_TASKS.values(), key=lambda x: x.get("started_at", 0), reverse=True)

    def delete_task(self, task_id: str) -> bool:
        if task_id in _TASKS:
            del _TASKS[task_id]
            return True
        return False
