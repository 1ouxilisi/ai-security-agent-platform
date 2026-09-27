# -*- coding: utf-8 -*-
"""
auto_scanner.py - 自动扫描与验证模块

功能：
- 靶场自动扫描（端口/服务/漏洞/配置/弱口令）
- 漏洞自动验证（POC/EXP/数据获取/权限获取/影响评估）
- 扫描结果对比（多次对比/新漏洞/已修复/误报/漏报）
- 扫描策略管理（模板/强度/速度/范围/排除/调度）
- 扫描性能优化（并发/分布式/缓存/增量/断点续扫）
- 扫描质量保证（覆盖率/准确率/误报率/漏报率）

全部内存字典模拟，不依赖外部扫描器。
"""

from __future__ import annotations

import logging
import random
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

NOTICE = "仅限授权环境使用：所有扫描仅在授权靶场内进行。"


def _clean(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, str):
        return "".join(ch for ch in obj if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    return obj


# ----------------------------------------------------------------------
# 扫描策略模板
# ----------------------------------------------------------------------
SCAN_PROFILES: Dict[str, Dict[str, Any]] = {
    "quick": {
        "profile_id": "quick", "name": "快速扫描",
        "description": "仅常用端口和基础漏洞检查，耗时约 2 分钟",
        "ports": "top-100", "intensity": "low", "speed": "fast",
        "checks": ["port", "banner", "weak_password_basic"],
    },
    "standard": {
        "profile_id": "standard", "name": "标准扫描",
        "description": "全端口扫描 + 常用漏洞检测，耗时约 10 分钟",
        "ports": "top-1000", "intensity": "medium", "speed": "medium",
        "checks": ["port", "banner", "service", "vuln_basic", "weak_password", "config_check"],
    },
    "deep": {
        "profile_id": "deep", "name": "深度扫描",
        "description": "全端口 + 全部漏洞库 + 慢速探测，耗时约 30 分钟",
        "ports": "all-65535", "intensity": "high", "speed": "slow",
        "checks": ["port", "banner", "service", "vuln_full", "weak_password",
                   "config_check", "web_vuln", "api_vuln", "tls_check", "misconfig"],
    },
}

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                465, 587, 993, 995, 1433, 1521, 2049, 2181, 3306, 3389, 5432,
                5900, 5985, 6379, 8080, 8443, 8888, 9000, 9200, 11211, 27017]

VULN_LIBRARY = [
    {"id": "SQLI-001", "name": "SQL 注入", "severity": "高危", "cwe": "CWE-89"},
    {"id": "XSS-001", "name": "跨站脚本 XSS", "severity": "中危", "cwe": "CWE-79"},
    {"id": "RCE-001", "name": "远程代码执行", "severity": "严重", "cwe": "CWE-78"},
    {"id": "SSRF-001", "name": "服务端请求伪造", "severity": "高危", "cwe": "CWE-918"},
    {"id": "IDOR-001", "name": "不安全的直接对象引用", "severity": "高危", "cwe": "CWE-639"},
    {"id": "UPLOAD-001", "name": "任意文件上传", "severity": "严重", "cwe": "CWE-434"},
    {"id": "LFI-001", "name": "本地文件包含", "severity": "高危", "cwe": "CWE-98"},
    {"id": "CSRF-001", "name": "跨站请求伪造", "severity": "中危", "cwe": "CWE-352"},
    {"id": "DESER-001", "name": "不安全反序列化", "severity": "严重", "cwe": "CWE-502"},
    {"id": "INFO-001", "name": "敏感信息泄露", "severity": "中危", "cwe": "CWE-200"},
    {"id": "WEAKPW-001", "name": "弱口令", "severity": "高危", "cwe": "CWE-521"},
    {"id": "MISCONF-001", "name": "安全配置错误", "severity": "中危", "cwe": "CWE-16"},
]

WEAK_PASSWORDS = ["admin", "password", "123456", "root", "toor", "admin123",
                  "password123", "qwerty", "letmein", "welcome"]


# ======================================================================
# AutoScanner
# ======================================================================
class AutoScanner:
    """自动扫描与验证引擎。"""

    def __init__(self) -> None:
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._results: Dict[str, Dict[str, Any]] = {}
        self._history: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # 扫描任务管理
    # ------------------------------------------------------------------
    def start_scan(self, target: str, profile: str = "standard",
                   options: Optional[Dict] = None) -> Dict[str, Any]:
        """启动扫描任务（异步模拟）。"""
        try:
            prof = SCAN_PROFILES.get(profile, SCAN_PROFILES["standard"])
            task_id = f"scan_task_{uuid.uuid4().hex[:8]}"

            task = {
                "task_id": task_id,
                "target": target,
                "profile": profile,
                "profile_name": prof["name"],
                "status": "running",
                "progress": 0,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "options": options or {},
                "checks": prof["checks"],
            }
            self._tasks[task_id] = task

            # 模拟执行扫描
            self._execute_scan(task_id, target, prof)

            return {
                "success": True,
                "task_id": task_id,
                "message": f"扫描任务已启动，目标: {target}",
                "profile": prof["name"],
            }
        except Exception as e:  # noqa: BLE001
            logger.exception("start_scan error")
            return {"success": False, "error": f"扫描启动失败: {e}"}

    def _execute_scan(self, task_id: str, target: str,
                      profile: Dict[str, Any]) -> None:
        """模拟执行扫描逻辑（内存计算，不发起真实网络请求）。"""
        task = self._tasks.get(task_id)
        if not task:
            return

        # 端口扫描模拟
        open_ports = []
        for port in random.sample(COMMON_PORTS, k=random.randint(3, 8)):
            open_ports.append({
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": self._guess_service(port),
                "version": self._fake_version(port),
            })

        # 漏洞检测模拟
        vulns = []
        check_list = profile.get("checks", [])
        if "vuln_basic" in check_list or "vuln_full" in check_list:
            for v in random.sample(VULN_LIBRARY, k=random.randint(3, 7)):
                vulns.append({
                    **v,
                    "target": target,
                    "confirmed": random.choice([True, True, False]),
                    "description": f"在 {target} 上检测到 {v['name']} 的迹象",
                })

        # 弱口令检测模拟
        weak_found = []
        if "weak_password" in check_list:
            for port_info in open_ports[:3]:
                svc = port_info.get("service", "")
                if svc in ("ssh", "ftp", "mysql", "redis", "telnet"):
                    weak_found.append({
                        "service": svc,
                        "port": port_info["port"],
                        "found_weak": random.choice([True, False]),
                    })

        # 配置检查模拟
        config_issues = []
        if "config_check" in check_list:
            config_issues = [
                {"issue": "目录列表开启", "severity": "低", "port": 80},
                {"issue": "服务器版本信息泄露", "severity": "低", "port": 443},
            ]

        result = {
            "task_id": task_id,
            "target": target,
            "profile": profile["name"],
            "scan_time": round(random.uniform(12.5, 180.3), 1),
            "open_ports": open_ports,
            "open_ports_count": len(open_ports),
            "vulnerabilities": vulns,
            "vuln_count": len(vulns),
            "weak_passwords": weak_found,
            "config_issues": config_issues,
            "summary": {
                "critical": sum(1 for v in vulns if v["severity"] == "严重"),
                "high": sum(1 for v in vulns if v["severity"] == "高危"),
                "medium": sum(1 for v in vulns if v["severity"] == "中危"),
                "low": sum(1 for v in vulns if v["severity"] == "低危"),
            },
        }
        self._results[task_id] = result

        task["status"] = "completed"
        task["progress"] = 100
        task["completed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

        self._history.append({
            "task_id": task_id, "target": target,
            "vuln_count": len(vulns), "time": task["completed_at"],
        })

    @staticmethod
    def _guess_service(port: int) -> str:
        mapping = {21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http",
                   443: "https", 3306: "mysql", 5432: "postgresql", 6379: "redis",
                   8080: "http-proxy", 9200: "elasticsearch", 27017: "mongodb"}
        return mapping.get(port, "unknown")

    @staticmethod
    def _fake_version(port: int) -> str:
        versions = {22: "OpenSSH_8.9", 80: "Apache/2.4.52", 443: "nginx/1.18.0",
                    3306: "MySQL 8.0.32", 6379: "Redis 7.0.11"}
        return versions.get(port, "unknown")

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def get_task(self, task_id: str) -> Dict[str, Any]:
        t = self._tasks.get(task_id)
        if not t:
            return {"success": False, "error": "任务不存在"}
        return {"success": True, "task": t, "result": self._results.get(task_id)}

    def list_tasks(self) -> List[Dict[str, Any]]:
        return list(self._tasks.values())

    def get_result(self, task_id: str) -> Dict[str, Any]:
        r = self._results.get(task_id)
        if not r:
            return {"success": False, "error": "结果不存在"}
        return {"success": True, "result": r}

    # ------------------------------------------------------------------
    # 扫描对比
    # ------------------------------------------------------------------
    def compare_scans(self, task_id1: str, task_id2: str) -> Dict[str, Any]:
        r1 = self._results.get(task_id1)
        r2 = self._results.get(task_id2)
        if not r1 or not r2:
            return {"success": False, "error": "一个或两个扫描结果不存在"}

        v1_names = {v["name"] for v in r1.get("vulnerabilities", [])}
        v2_names = {v["name"] for v in r2.get("vulnerabilities", [])}

        new_vulns = list(v2_names - v1_names)
        fixed_vulns = list(v1_names - v2_names)
        common = list(v1_names & v2_names)

        return {
            "success": True,
            "scan_a": task_id1,
            "scan_b": task_id2,
            "new_vulnerabilities": new_vulns,
            "fixed_vulnerabilities": fixed_vulns,
            "common_vulnerabilities": common,
            "vuln_a_count": len(v1_names),
            "vuln_b_count": len(v2_names),
        }

    # ------------------------------------------------------------------
    # 策略模板
    # ------------------------------------------------------------------
    def list_profiles(self) -> List[Dict[str, Any]]:
        return list(SCAN_PROFILES.values())

    def get_profile(self, profile_id: str) -> Optional[Dict[str, Any]]:
        return SCAN_PROFILES.get(profile_id)

    # ------------------------------------------------------------------
    # 质量指标
    # ------------------------------------------------------------------
    def quality_metrics(self) -> Dict[str, Any]:
        """模拟扫描质量指标。"""
        total = len(self._results)
        if total == 0:
            return {"total_scans": 0, "coverage": 0, "accuracy": 0,
                    "false_positive_rate": 0, "false_negative_rate": 0}
        return {
            "total_scans": total,
            "coverage": round(random.uniform(85, 98), 1),
            "accuracy": round(random.uniform(90, 99), 1),
            "false_positive_rate": round(random.uniform(2, 8), 1),
            "false_negative_rate": round(random.uniform(1, 5), 1),
            "repeatability": round(random.uniform(95, 99.5), 1),
        }

    # ------------------------------------------------------------------
    # 调度
    # ------------------------------------------------------------------
    def schedule_scan(self, target: str, profile: str, cron_expr: str) -> Dict[str, Any]:
        """模拟定时扫描调度。"""
        sched_id = f"sched_{uuid.uuid4().hex[:8]}"
        return {
            "success": True,
            "schedule_id": sched_id,
            "target": target,
            "profile": profile,
            "cron": cron_expr,
            "message": "定时扫描任务已创建（模拟）",
        }


_scanner: Optional[AutoScanner] = None


def get_scanner() -> AutoScanner:
    global _scanner
    if _scanner is None:
        _scanner = AutoScanner()
    return _scanner
