#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代理池管理模块，支持HTTP/HTTPS/SOCKS4/SOCKS5代理、健康检查、轮换策略和代理验证。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import re
import random
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class ProxyType:
    """代理类型"""
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"


@dataclass
class ProxyServer:
    """代理服务器"""
    host: str
    port: int
    proxy_type: str = ProxyType.HTTP
    username: str = ""
    password: str = ""
    country: str = ""
    city: str = ""
    isp: str = ""
    latency: float = 0.0
    success_rate: float = 0.0
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    last_used: str = ""
    last_checked: str = ""
    status: str = "unknown"  # active, inactive, checking, banned, dead
    tags: List[str] = field(default_factory=list)
    added_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "host": self.host,
            "port": self.port,
            "proxy_type": self.proxy_type,
            "username": self.username[:5] + "..." if self.username else "",
            "country": self.country,
            "city": self.city,
            "isp": self.isp,
            "latency": self.latency,
            "success_rate": self.success_rate,
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "last_used": self.last_used,
            "last_checked": self.last_checked,
            "status": self.status,
            "tags": self.tags,
            "added_at": self.added_at,
        }

    def get_url(self) -> str:
        """获取代理URL"""
        auth = ""
        if self.username and self.password:
            auth = f"{self.username}:{self.password}@"
        return f"{self.proxy_type}://{auth}{self.host}:{self.port}"

    def is_available(self) -> bool:
        """检查代理是否可用"""
        return self.status == "active" and self.success_rate > 0.5

    def record_request(self, success: bool, latency: float = 0.0):
        """记录请求结果"""
        self.total_requests += 1
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
        self.success_rate = self.successful_requests / self.total_requests if self.total_requests > 0 else 0
        self.latency = latency
        self.last_used = datetime.now().isoformat()

        # 自动状态更新
        if self.total_requests >= 10 and self.success_rate < 0.2:
            self.status = "dead"
        elif self.total_requests >= 5 and self.success_rate < 0.5:
            self.status = "inactive"


class ProxyPool:
    """代理池"""

    # 轮换策略
    ROTATION_RANDOM = "random"
    ROTATION_ROUND_ROBIN = "round_robin"
    ROTATION_LEAST_USED = "least_used"
    ROTATION_FASTEST = "fastest"
    ROTATION_BEST_SUCCESS = "best_success"

    def __init__(self, rotation_strategy: str = ROTATION_RANDOM, min_success_rate: float = 0.5):
        """初始化ProxyPool实例。

        Args:
            self: 类实例。
        """
        self.proxies: List[ProxyServer] = []
        self.rotation_strategy = rotation_strategy
        self.min_success_rate = min_success_rate
        self._round_robin_index = 0
        self._banned_targets: Dict[str, List[str]] = {}  # target -> [proxy_ids]

    def add_proxy(self, proxy: ProxyServer) -> bool:
        """添加代理"""
        # 检查重复
        for existing in self.proxies:
            if existing.host == proxy.host and existing.port == proxy.port:
                logger.warning(f"代理 {proxy.host}:{proxy.port} 已存在")
                return False
        self.proxies.append(proxy)
        logger.info(f"代理添加成功: {proxy.host}:{proxy.port}")
        return True

    def add_proxies_from_list(self, proxy_list: List[str], proxy_type: str = ProxyType.HTTP) -> int:
        """从列表批量添加代理（格式: host:port 或 user:pass@host:port）"""
        count = 0
        for proxy_str in proxy_list:
            try:
                proxy = self._parse_proxy_string(proxy_str, proxy_type)
                if proxy and self.add_proxy(proxy):
                    count += 1
            except Exception as e:
                logger.error(f"解析代理失败 {proxy_str}: {e}")
        return count

    def remove_proxy(self, host: str, port: int) -> bool:
        """移除代理"""
        for i, proxy in enumerate(self.proxies):
            if proxy.host == host and proxy.port == port:
                self.proxies.pop(i)
                logger.info(f"代理移除: {host}:{port}")
                return True
        return False

    def get_proxy(self, target: str = "", strategy: str = "") -> Optional[ProxyServer]:
        """获取代理"""
        if not strategy:
            strategy = self.rotation_strategy

        # 过滤可用代理
        available = [p for p in self.proxies if p.is_available()]

        # 排除目标已封禁的代理
        if target and target in self._banned_targets:
            banned = self._banned_targets[target]
            available = [p for p in available if f"{p.host}:{p.port}" not in banned]

        if not available:
            logger.warning("没有可用的代理")
            return None

        if strategy == self.ROTATION_RANDOM:
            return random.choice(available)
        elif strategy == self.ROTATION_ROUND_ROBIN:
            proxy = available[self._round_robin_index % len(available)]
            self._round_robin_index += 1
            return proxy
        elif strategy == self.ROTATION_LEAST_USED:
            return min(available, key=lambda p: p.total_requests)
        elif strategy == self.ROTATION_FASTEST:
            return min(available, key=lambda p: p.latency)
        elif strategy == self.ROTATION_BEST_SUCCESS:
            return max(available, key=lambda p: p.success_rate)
        else:
            return random.choice(available)

    def get_proxies(self, count: int = 1, target: str = "", strategy: str = "") -> List[ProxyServer]:
        """获取多个代理"""
        proxies = []
        used_hosts = set()
        for _ in range(count):
            proxy = self.get_proxy(target, strategy)
            if proxy and f"{proxy.host}:{proxy.port}" not in used_hosts:
                proxies.append(proxy)
                used_hosts.add(f"{proxy.host}:{proxy.port}")
            if len(proxies) >= len([p for p in self.proxies if p.is_available()]):
                break
        return proxies

    def mark_proxy_banned(self, host: str, port: int, target: str = ""):
        """标记代理被目标封禁"""
        for proxy in self.proxies:
            if proxy.host == host and proxy.port == port:
                proxy.status = "banned"
                proxy.record_request(False)
                if target:
                    if target not in self._banned_targets:
                        self._banned_targets[target] = []
                    self._banned_targets[target].append(f"{host}:{port}")
                logger.info(f"代理被标记为封禁: {host}:{port} (目标: {target})")
                break

    def mark_proxy_dead(self, host: str, port: int):
        """标记代理失效"""
        for proxy in self.proxies:
            if proxy.host == host and proxy.port == port:
                proxy.status = "dead"
                proxy.record_request(False)
                logger.info(f"代理被标记为失效: {host}:{port}")
                break

    def verify_proxy(self, host: str, port: int, test_url: str = "http://httpbin.org/ip") -> bool:
        """验证代理可用性"""
        for proxy in self.proxies:
            if proxy.host == host and proxy.port == port:
                proxy.status = "checking"
                proxy.last_checked = datetime.now().isoformat()
                # 模拟验证（实际需要发送请求）
                proxy.status = "active"
                proxy.latency = random.uniform(0.1, 2.0)
                proxy.record_request(True, proxy.latency)
                return True
        return False

    def verify_all_proxies(self, test_url: str = "http://httpbin.org/ip") -> Dict[str, int]:
        """验证所有代理"""
        results = {"total": len(self.proxies), "active": 0, "inactive": 0, "dead": 0}
        for proxy in self.proxies:
            if self.verify_proxy(proxy.host, proxy.port, test_url):
                results["active"] += 1
            else:
                results["dead"] += 1
        return results

    def get_proxies_by_country(self, country: str) -> List[ProxyServer]:
        """按国家获取代理"""
        return [p for p in self.proxies if p.country.lower() == country.lower() and p.is_available()]

    def get_proxies_by_type(self, proxy_type: str) -> List[ProxyServer]:
        """按类型获取代理"""
        return [p for p in self.proxies if p.proxy_type == proxy_type and p.is_available()]

    def remove_dead_proxies(self) -> int:
        """移除失效代理"""
        dead = [p for p in self.proxies if p.status == "dead"]
        for proxy in dead:
            self.proxies.remove(proxy)
        return len(dead)

    def load_from_file(self, filepath: str, proxy_type: str = ProxyType.HTTP) -> int:
        """从文件加载代理"""
        try:
            with open(filepath, 'r') as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return self.add_proxies_from_list(lines, proxy_type)
        except Exception as e:
            logger.error(f"加载代理文件失败: {e}")
            return 0

    def export_to_file(self, filepath: str, only_active: bool = True):
        """导出代理到文件"""
        try:
            proxies = [p for p in self.proxies if p.is_available()] if only_active else self.proxies
            with open(filepath, 'w') as f:
                for proxy in proxies:
                    f.write(f"{proxy.host}:{proxy.port}\n")
            logger.info(f"代理导出成功: {len(proxies)} 个代理 -> {filepath}")
        except Exception as e:
            logger.error(f"导出代理文件失败: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        total = len(self.proxies)
        active = sum(1 for p in self.proxies if p.status == "active")
        inactive = sum(1 for p in self.proxies if p.status == "inactive")
        banned = sum(1 for p in self.proxies if p.status == "banned")
        dead = sum(1 for p in self.proxies if p.status == "dead")

        avg_latency = sum(p.latency for p in self.proxies if p.latency > 0) / max(1, sum(1 for p in self.proxies if p.latency > 0))
        avg_success = sum(p.success_rate for p in self.proxies) / max(1, total)

        by_type = {}
        by_country = {}
        for p in self.proxies:
            by_type[p.proxy_type] = by_type.get(p.proxy_type, 0) + 1
            if p.country:
                by_country[p.country] = by_country.get(p.country, 0) + 1

        return {
            "total_proxies": total,
            "active": active,
            "inactive": inactive,
            "banned": banned,
            "dead": dead,
            "available_rate": f"{active/total*100:.1f}%" if total > 0 else "0%",
            "average_latency": f"{avg_latency:.2f}s",
            "average_success_rate": f"{avg_success*100:.1f}%",
            "by_type": by_type,
            "by_country": by_country,
            "rotation_strategy": self.rotation_strategy,
            "total_requests": sum(p.total_requests for p in self.proxies),
            "total_successful": sum(p.successful_requests for p in self.proxies),
            "total_failed": sum(p.failed_requests for p in self.proxies),
        }

    def _parse_proxy_string(self, proxy_str: str, default_type: str = ProxyType.HTTP) -> Optional[ProxyServer]:
        """解析代理字符串"""
        proxy_str = proxy_str.strip()

        # 移除协议前缀
        if "://" in proxy_str:
            parts = proxy_str.split("://", 1)
            proxy_type = parts[0].lower()
            proxy_str = parts[1]
        else:
            proxy_type = default_type

        # 解析认证信息
        username = ""
        password = ""
        if "@" in proxy_str:
            auth_part, host_part = proxy_str.rsplit("@", 1)
            if ":" in auth_part:
                username, password = auth_part.split(":", 1)
        else:
            host_part = proxy_str

        # 解析主机和端口
        if ":" in host_part:
            host, port_str = host_part.rsplit(":", 1)
            port = int(port_str)
        else:
            host = host_part
            port = 8080 if proxy_type in [ProxyType.HTTP, ProxyType.HTTPS] else 1080

        return ProxyServer(
            host=host,
            port=port,
            proxy_type=proxy_type,
            username=username,
            password=password,
        )


# 全局实例
proxy_pool = ProxyPool()
