#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
持续监控后台进程 - Continuous Monitor Worker
真正的后台定时扫描进程，独立线程运行
功能：
- 定期检查到期的监控目标
- 执行端口扫描
- 检测状态变更
- 生成告警
- 更新数据库
"""
import threading
import time
import json
import logging
from typing import Dict, Any, List, Optional

try:
    from enterprise.database import (
        get_due_monitor_targets, update_monitor_scan, get_monitor_targets
    )
except ImportError:
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from enterprise.database import (
        get_due_monitor_targets, update_monitor_scan, get_monitor_targets
    )

logger = logging.getLogger("monitor_worker")


class MonitorWorker:
    """持续监控工作进程"""

    def __init__(self, check_interval: int = 60):
        self.check_interval = check_interval  # 检查间隔（秒）
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._scan_count = 0
        self._alert_count = 0
        self._last_check = None

    def start(self):
        """启动监控工作进程"""
        if self._running:
            logger.warning("监控进程已在运行")
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="MonitorWorker")
        self._thread.start()
        logger.info("持续监控后台进程已启动")

    def stop(self):
        """停止监控工作进程"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("持续监控后台进程已停止")

    def _run(self):
        """主循环"""
        while self._running:
            try:
                self._last_check = time.time()
                due_targets = get_due_monitor_targets()
                if due_targets:
                    logger.info(f"发现 {len(due_targets)} 个到期监控目标")
                    for target in due_targets:
                        self._scan_target(target)
                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"监控进程异常: {e}")
                time.sleep(self.check_interval)

    def _scan_target(self, target: Dict[str, Any]):
        """扫描单个监控目标"""
        target_id = target["id"]
        target_host = target["target"]
        ports = target.get("ports", "1-1000")

        try:
            # 执行端口扫描（调用真实工具）
            scan_result = self._port_scan(target_host, ports)
            changes = self._detect_changes(target, scan_result)

            # 更新数据库
            update_monitor_scan(target_id, scan_result, changes)
            self._scan_count += 1

            if changes:
                self._alert_count += len(changes)
                logger.info(f"目标 {target_host} 发现 {len(changes)} 个变更")

        except Exception as e:
            logger.error(f"扫描目标 {target_host} 失败: {e}")

    def _port_scan(self, target: str, ports: str = "1-1000", timeout: int = 3) -> Dict[str, Any]:
        """执行端口扫描（使用socket实现，不依赖nmap）"""
        import socket
        start_time = time.time()
        open_ports = []
        services = {}

        # 解析端口范围
        port_list = self._parse_ports(ports)
        # 限制扫描端口数量，避免超时
        if len(port_list) > 100:
            port_list = port_list[:100]

        for port in port_list:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                    # 尝试识别服务
                    try:
                        service = socket.getservbyport(port)
                        services[str(port)] = service
                    except:
                        services[str(port)] = "unknown"
                sock.close()
            except:
                pass

        duration_ms = round((time.time() - start_time) * 1000, 2)
        return {
            "target": target,
            "ports": ports,
            "open_ports": open_ports,
            "services": services,
            "scan_time": time.time(),
            "duration_ms": duration_ms,
            "scanner": "socket_monitor"
        }

    def _parse_ports(self, ports_str: str) -> List[int]:
        """解析端口范围字符串"""
        ports = []
        for part in ports_str.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    start, end = part.split("-")
                    ports.extend(range(int(start), int(end) + 1))
                except:
                    pass
            else:
                try:
                    ports.append(int(part))
                except:
                    pass
        return ports

    def _detect_changes(self, target: Dict[str, Any], new_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """检测目标状态变更"""
        changes = []
        last_result_json = target.get("last_result_json")
        if not last_result_json:
            return changes

        try:
            last_result = json.loads(last_result_json)
            old_ports = set(last_result.get("open_ports", []))
            new_ports = set(new_result.get("open_ports", []))

            new_open = new_ports - old_ports
            new_closed = old_ports - new_ports

            if new_open:
                changes.append({
                    "type": "new_port_open",
                    "severity": "medium",
                    "target": target["target"],
                    "ports": list(new_open),
                    "message": f"新开放端口: {list(new_open)}",
                    "timestamp": time.time()
                })
            if new_closed:
                changes.append({
                    "type": "port_closed",
                    "severity": "info",
                    "target": target["target"],
                    "ports": list(new_closed),
                    "message": f"端口关闭: {list(new_closed)}",
                    "timestamp": time.time()
                })
        except:
            pass

        return changes

    def get_status(self) -> Dict[str, Any]:
        """获取监控进程状态"""
        return {
            "running": self._running,
            "scan_count": self._scan_count,
            "alert_count": self._alert_count,
            "last_check": self._last_check,
            "check_interval": self.check_interval,
            "active_targets": len(get_monitor_targets())
        }


# 全局单例
_monitor_worker: Optional[MonitorWorker] = None


def start_monitor_worker(check_interval: int = 60) -> MonitorWorker:
    """启动全局监控工作进程"""
    global _monitor_worker
    if _monitor_worker is None:
        _monitor_worker = MonitorWorker(check_interval)
        _monitor_worker.start()
    return _monitor_worker


def get_monitor_worker() -> Optional[MonitorWorker]:
    """获取全局监控工作进程"""
    return _monitor_worker
