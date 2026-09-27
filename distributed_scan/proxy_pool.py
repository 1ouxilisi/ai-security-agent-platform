# -*- coding: utf-8 -*-
"""
proxy_pool.py — 代理池与 IP 轮换（第23轮升级 · 方向2）。

职责：
- 代理管理：HTTP/HTTPS/SOCKS4/SOCKS5 / 代理认证 / 分组 / 标签
- 代理检测：可用性 / 匿名度 / 速度 / 地理位置 / 稳定性
- 代理池：维护 / 健康检查 / 自动剔除 / 自动补充 / 评分 / 排序
- IP 轮换策略：按请求/按时间/按目标/随机/粘性会话/失败重试换 IP
- 请求限流：全局/per代理/per目标 / 令牌桶 / 漏桶 / 自适应
- 反检测：UA 轮换 / 请求头随机化 / 请求间隔随机化 / TLS 指纹 / 浏览器指纹

全部内存模拟，不建立真实 TCP 连接。
"""

from __future__ import annotations

import random
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


# ==================== 常量库 ====================

PROXY_TYPES = ["http", "https", "socks4", "socks5"]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]

REFERERS = ["https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/"]

COUNTRY_POOL = ["CN", "US", "JP", "SG", "DE", "FR", "HK", "KR", "GB", "RU"]


class TokenBucket:
    """令牌桶限流。"""

    def __init__(self, rate: float, capacity: float) -> None:
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last = time.time()
        self._lock = threading.Lock()

    def allow(self, amount: float = 1.0) -> bool:
        with self._lock:
            now = time.time()
            self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False


class LeakyBucket:
    """漏桶限流：恒定速率出水。"""

    def __init__(self, rate: float, capacity: float) -> None:
        self.rate = rate
        self.capacity = capacity
        self.water = 0.0
        self.last = time.time()
        self._lock = threading.Lock()

    def allow(self, amount: float = 1.0) -> bool:
        with self._lock:
            now = time.time()
            self.water = max(0.0, self.water - (now - self.last) * self.rate)
            self.last = now
            if self.water + amount <= self.capacity:
                self.water += amount
                return True
            return False


class ProxyPool:
    """代理池核心。"""

    def __init__(self) -> None:
        self.proxies: Dict[str, Dict[str, Any]] = {}
        self.groups: Dict[str, List[str]] = {"default": []}
        self.policy: Dict[str, Any] = {
            "rotation_strategy": "random",     # per_request/per_time/per_target/random/sticky/failover
            "rotation_interval": 60,           # 秒，per_time
            "sticky_ttl": 300,
            "min_score": 30,
            "auto_evict": True,
            "auto_refill": True,
            "global_rps": 50.0,
            "per_proxy_rps": 5.0,
            "per_target_rps": 10.0,
            "limiter_mode": "token_bucket",    # token_bucket / leaky / adaptive
        }
        self._global_bucket = TokenBucket(50, 50)
        self._proxy_buckets: Dict[str, TokenBucket] = {}
        self._target_buckets: Dict[str, LeakyBucket] = {}
        self._sticky: Dict[str, Dict[str, float]] = {}   # key -> {proxy_id, until}
        self.detection_log: List[Dict[str, Any]] = []
        self._seed_proxies()

    # ---------- 种子 ----------
    def _seed_proxies(self) -> None:
        for i in range(12):
            self.add_proxy(
                host=f"103.xx.{random.randint(1,254)}.{random.randint(1,254)}",
                port=random.choice([8080, 3128, 1080, 8000, 8888]),
                ptype=random.choice(PROXY_TYPES),
                group="default",
                tags={"isp": random.choice(["telecom", "unicom", "mobile"])},
            )

    # ---------- 代理 CRUD ----------
    def add_proxy(self, host: str, port: int, ptype: str = "http",
                  username: str = "", password: str = "",
                  group: str = "default",
                  tags: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        pid = f"px-{uuid.uuid4().hex[:8]}"
        proxy = {
            "id": pid, "host": host, "port": port, "type": ptype,
            "auth": {"username": username, "password": bool(password)},
            "group": group, "tags": tags or {},
            "status": "unchecked",          # unchecked/healthy/dead/slow
            "score": 50.0, "latency_ms": 0.0,
            "anonymity": "unknown",         # unknown/transparent/anonymous/elite
            "country": random.choice(COUNTRY_POOL),
            "success_count": 0, "fail_count": 0,
            "last_checked": None, "last_used": None,
            "created_at": datetime.now().isoformat(),
        }
        self.proxies[pid] = proxy
        self.groups.setdefault(group, []).append(pid)
        self._proxy_buckets[pid] = TokenBucket(self.policy["per_proxy_rps"],
                                               self.policy["per_proxy_rps"])
        return proxy

    def remove_proxy(self, pid: str) -> bool:
        if pid not in self.proxies:
            return False
        p = self.proxies.pop(pid)
        self.groups.get(p["group"], []).remove(pid)
        self._proxy_buckets.pop(pid, None)
        return True

    def list_proxies(self, group: Optional[str] = None,
                     status: Optional[str] = None) -> List[Dict[str, Any]]:
        out = []
        for p in self.proxies.values():
            if group and p["group"] != group:
                continue
            if status and p["status"] != status:
                continue
            item = dict(p)
            item["auth"].pop("password", None)
            out.append(item)
        out.sort(key=lambda x: x["score"], reverse=True)
        return out

    # ---------- 检测 ----------
    def detect_proxy(self, pid: str) -> Dict[str, Any]:
        p = self.proxies.get(pid)
        if not p:
            raise KeyError(f"代理不存在: {pid}")
        latency = round(random.uniform(20, 1800), 1)
        alive = latency < 1500
        anonymity = random.choice(["transparent", "anonymous", "elite", "elite"])
        p["latency_ms"] = latency
        p["anonymity"] = anonymity
        p["status"] = "healthy" if alive else "dead"
        p["last_checked"] = datetime.now().isoformat()
        # 评分：速度 + 匿名度 + 成功率
        speed_score = max(0.0, 100 - latency / 15.0)
        anon_score = {"transparent": 10, "anonymous": 50, "elite": 80,
                      "unknown": 30}.get(anonymity, 30)
        total = p["success_count"] + p["fail_count"]
        succ_rate = (p["success_count"] / max(1, total)) * 100
        p["score"] = round(speed_score * 0.4 + anon_score * 0.3 + succ_rate * 0.3, 1)
        self.detection_log.append({
            "time": datetime.now().isoformat(), "proxy_id": pid,
            "latency_ms": latency, "status": p["status"], "score": p["score"],
        })
        return dict(p)

    def health_check_all(self) -> Dict[str, Any]:
        healthy = dead = 0
        evicted = []
        for pid in list(self.proxies.keys()):
            r = self.detect_proxy(pid)
            if r["status"] == "healthy":
                healthy += 1
            else:
                dead += 1
                if self.policy["auto_evict"] and r["score"] < self.policy["min_score"]:
                    self.remove_proxy(pid)
                    evicted.append(pid)
        # 自动补充
        if self.policy["auto_refill"] and len(self.proxies) < 10:
            for _ in range(3):
                self._seed_one()
        return {"checked": healthy + dead, "healthy": healthy, "dead": dead,
                "evicted": evicted, "pool_size": len(self.proxies)}

    def _seed_one(self) -> None:
        self.add_proxy(
            host=f"104.xx.{random.randint(1,254)}.{random.randint(1,254)}",
            port=random.choice([8080, 3128, 1080]),
            ptype=random.choice(PROXY_TYPES), group="default",
        )

    # ---------- 轮换 ----------
    def acquire_proxy(self, target: str = "", sticky_key: str = "") -> Dict[str, Any]:
        """按策略取一个可用代理；含限流。"""
        # 全局限流
        if not self._global_bucket.allow(1.0):
            raise RuntimeError("全局限流触发")
        strategy = self.policy["rotation_strategy"]
        pool = [p for p in self.proxies.values() if p["status"] == "healthy"]
        if not pool:
            pool = list(self.proxies.values())
        if not pool:
            raise RuntimeError("代理池为空")

        chosen: Optional[Dict[str, Any]] = None
        if strategy == "sticky" and sticky_key:
            slot = self._sticky.get(sticky_key)
            if slot and slot["until"] > time.time():
                chosen = self.proxies.get(slot["proxy_id"])
        if chosen is None:
            if strategy == "per_request":
                chosen = random.choice(pool)
            elif strategy == "per_time":
                idx = int(time.time() / self.policy["rotation_interval"]) % len(pool)
                chosen = pool[idx]
            elif strategy == "per_target":
                idx = hash(target) % len(pool)
                chosen = pool[idx]
            elif strategy == "random":
                chosen = sorted(pool, key=lambda x: -x["score"])[0] if random.random() < 0.7 else random.choice(pool)
            else:  # failover / 默认按评分
                chosen = sorted(pool, key=lambda x: -x["score"])[0]
            if strategy == "sticky" and sticky_key:
                self._sticky[sticky_key] = {
                    "proxy_id": chosen["id"],
                    "until": time.time() + self.policy["sticky_ttl"],
                }
        # per-proxy 限流
        bucket = self._proxy_buckets.get(chosen["id"])
        if bucket and not bucket.allow(1.0):
            # 换一个
            alt = [p for p in pool if p["id"] != chosen["id"]]
            if alt:
                chosen = random.choice(alt)
        # per-target 限流
        tb = self._target_buckets.setdefault(target, LeakyBucket(
            self.policy["per_target_rps"], self.policy["per_target_rps"]))
        if not tb.allow(1.0):
            raise RuntimeError("目标级限流触发")
        chosen["last_used"] = datetime.now().isoformat()
        return dict(chosen)

    def report_usage(self, pid: str, success: bool) -> None:
        p = self.proxies.get(pid)
        if not p:
            return
        if success:
            p["success_count"] += 1
        else:
            p["fail_count"] += 1
            p["score"] = max(0.0, p["score"] - 5)
            if p["score"] < self.policy["min_score"] and self.policy["auto_evict"]:
                self.remove_proxy(pid)

    # ---------- 反检测 ----------
    def build_anti_detect_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": random.choice(["zh-CN,zh;q=0.9", "en-US,en;q=0.9",
                                              "zh-CN,en;q=0.8"]),
            "Referer": random.choice(REFERERS),
            "X-Request-Id": uuid.uuid4().hex[:12],
            "Via": f"1.1 proxy-{random.randint(1000,9999)}",
            "_jitter_delay_ms": random.randint(50, 400),
            "_tls_fingerprint": random.choice(["chrome-ja3-a", "firefox-ja3-b",
                                               "safari-ja3-c"]),
            "_browser_fingerprint": f"fp-{random.randint(100000,999999)}",
        }

    # ---------- 策略 / 统计 ----------
    def set_policy(self, **kw: Any) -> Dict[str, Any]:
        self.policy.update(kw)
        if "global_rps" in kw:
            self._global_bucket = TokenBucket(kw["global_rps"], kw["global_rps"])
        return dict(self.policy)

    def pool_stats(self) -> Dict[str, Any]:
        total = len(self.proxies)
        healthy = sum(1 for p in self.proxies.values() if p["status"] == "healthy")
        dead = sum(1 for p in self.proxies.values() if p["status"] == "dead")
        avg_score = round(
            sum(p["score"] for p in self.proxies.values()) / max(1, total), 1)
        return {
            "total": total, "healthy": healthy, "dead": dead,
            "unchecked": total - healthy - dead,
            "avg_score": avg_score,
            "groups": {g: len(ids) for g, ids in self.groups.items()},
            "policy": dict(self.policy),
            "countries": self._country_dist(),
        }

    def _country_dist(self) -> Dict[str, int]:
        dist: Dict[str, int] = {}
        for p in self.proxies.values():
            dist[p["country"]] = dist.get(p["country"], 0) + 1
        return dist


_POOL: Optional[ProxyPool] = None


def get_proxy_pool() -> ProxyPool:
    global _POOL
    if _POOL is None:
        _POOL = ProxyPool()
    return _POOL


__all__ = ["ProxyPool", "get_proxy_pool", "TokenBucket", "LeakyBucket",
           "PROXY_TYPES", "USER_AGENTS"]
