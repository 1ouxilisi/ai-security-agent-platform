# -*- coding: utf-8 -*-
"""
test_api_gateway_v10.py - 第 10 轮 API 网关深化模块测试脚本。

测试范围：
    1. 六大核心类（RateLimiter / CircuitBreaker / DegradationManager /
       APICache / APILogger / APIMonitor）的主要方法
    2. API 路由模块导入与端点注册数量

运行：
    python test_api_gateway_v10.py
"""

from __future__ import annotations

import os
import sys
import time
import traceback

# 项目根目录
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

PASS = 0
FAIL = 0
ERRORS = []


def check(name: str, cond: bool, detail: str = "") -> None:
    """断言助手。"""
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        ERRORS.append(f"{name}: {detail}")
        print(f"  [FAIL] {name} -> {detail}")


def section(title: str) -> None:
    print(f"\n=== {title} ===")


# ------------------------------------------------------------------ #
# 1. 限流器
# ------------------------------------------------------------------ #
def test_rate_limiter() -> None:
    section("1. RateLimiter 限流器")
    from api_gateway.rate_limiter import RateLimiter

    rl = RateLimiter()
    rl.set_policy("/test", "ip", requests_per_minute=5, burst=2)
    pol = rl.get_policy("/test", "ip")
    check("set_policy/get_policy", pol["requests_per_minute"] == 5, str(pol))

    # 白名单
    rl.add_whitelist("10.0.0.99", "ip")
    wl = rl.get_whitelist()
    check("add_whitelist/get_whitelist", "10.0.0.99" in wl.get("ip", []), str(wl))
    allowed = rl.is_allowed("10.0.0.99", "/test", "ip")
    check("白名单放行", allowed is True)
    rl.remove_whitelist("10.0.0.99", "ip")

    # 正常放行
    ok1 = rl.is_allowed("192.168.1.1", "/test", "ip")
    check("首次放行", ok1 is True)
    rem = rl.get_remaining("192.168.1.1", "/test")
    check("get_remaining 返回数值", isinstance(rem, int) and rem >= 0, str(rem))

    # 统计
    stats = rl.get_stats()
    check("get_stats 含关键字段",
          "total_blocked" in stats and "policies" in stats, str(list(stats.keys())))

    # 重置计数器
    rl.reset_counter("192.168.1.1")
    check("reset_counter 不抛异常", True)


# ------------------------------------------------------------------ #
# 2. 熔断器
# ------------------------------------------------------------------ #
def test_circuit_breaker() -> None:
    section("2. CircuitBreaker 熔断器")
    from api_gateway.circuit_breaker import (
        CircuitBreaker, CircuitBreakerError,
    )

    cb = CircuitBreaker()
    cb.set_config("/svc", failure_rate_threshold=0.5, min_requests=4,
                  open_timeout=1, time_window=60)

    # 正常调用
    result = cb.call("/svc", lambda: "ok")
    check("call 成功", result == "ok")

    # 连续失败触发熔断
    def _fail():
        raise RuntimeError("boom")

    opened = False
    for _ in range(6):
        try:
            cb.call("/svc", _fail)
        except (RuntimeError, CircuitBreakerError):
            pass
    try:
        cb.call("/svc", lambda: "should not run")
    except CircuitBreakerError:
        opened = True
    check("失败超阈值后熔断打开", opened, cb.get_state("/svc"))
    check("get_state 为 OPEN", cb.get_state("/svc") == "OPEN",
          cb.get_state("/svc"))

    # 半开超时后
    time.sleep(1.1)
    state = cb.get_state("/svc")
    check("超时后进入半开", state == "HALF_OPEN", state)

    # 半开成功 -> 关闭
    cb.call("/svc", lambda: "recovered")
    check("半开成功后关闭", cb.get_state("/svc") == "CLOSED",
          cb.get_state("/svc"))

    # record_success / record_failure / reset / stats
    cb.record_failure("/svc2")
    cb.record_success("/svc2")
    st = cb.get_stats("/svc2")
    check("get_stats(endpoint)", st["total_calls"] == 2, str(st))
    allst = cb.get_stats()
    check("get_stats(汇总) 含 endpoints", "endpoints" in allst, str(list(allst.keys())))
    cb.reset("/svc2")
    check("reset 后状态 CLOSED", cb.get_state("/svc2") == "CLOSED")
    cfg = cb.get_config("/svc")
    check("get_config", "failure_rate_threshold" in cfg, str(cfg))


# ------------------------------------------------------------------ #
# 3. 降级器
# ------------------------------------------------------------------ #
def test_degradation() -> None:
    section("3. DegradationManager 降级器")
    from api_gateway.degradation import DegradationManager

    dm = DegradationManager()
    dm.enable_degradation("/api/data", strategy="default",
                           data={"msg": "降级"}, reason="timeout")
    check("enable_degradation 后应降级",
          dm.should_degrade("/api/data") is True)
    resp = dm.get_degraded_response("/api/data")
    check("降级响应含 X-Degraded",
          resp.get("X-Degraded") == "true" and resp.get("degraded") is True,
          str(resp))
    check("降级端点列表", "/api/data" in dm.get_degraded_endpoints())
    dm.set_default_response("/api/data", {"cached": 1})
    check("set_default_response",
          dm.get_config("/api/data").get("default_response") == {"cached": 1})
    dm.disable_degradation("/api/data")
    check("disable 后不降级", dm.should_degrade("/api/data") is False)
    stats = dm.get_stats()
    check("get_stats", "total_degraded" in stats, str(list(stats.keys())))


# ------------------------------------------------------------------ #
# 4. 缓存器
# ------------------------------------------------------------------ #
def test_api_cache() -> None:
    section("4. APICache 缓存器")
    from api_gateway.api_cache import APICache

    cache = APICache()
    cache.clear()
    cache.set_policy("/users", ttl=300, strategy="LRU")
    pol = cache.get_policy("/users")
    check("set/get_policy", pol["ttl"] == 300 and pol["strategy"] == "LRU",
          str(pol))

    cache.set("/users", {"name": "alice"}, params={"id": 1})
    got = cache.get("/users", params={"id": 1})
    check("set/get 命中", got == {"name": "alice"}, str(got))
    miss = cache.get("/users", params={"id": 999})
    check("未命中返回 None", miss is None)

    # 预热
    warm = cache.warmup(["/api/v1/health"])
    check("warmup", warm["count"] >= 1, str(warm))

    # 失效
    n = cache.invalidate("/users")
    check("invalidate 按端点失效", n >= 1, str(n))
    removed = cache.invalidate_pattern("/api/*")
    check("invalidate_pattern 不抛异常", isinstance(removed, int))

    # 统计
    check("get_hit_rate", 0.0 <= cache.get_hit_rate() <= 1.0)
    check("get_cache_size", isinstance(cache.get_cache_size(), int))
    st = cache.get_stats()
    check("get_stats 含命中率", "hit_rate" in st, str(list(st.keys())))
    cache.clear()


# ------------------------------------------------------------------ #
# 5. 日志器
# ------------------------------------------------------------------ #
def test_api_logger() -> None:
    section("5. APILogger 日志器")
    from api_gateway.api_logger import APILogger, LEVEL_ALL

    lg = APILogger()
    lg.set_log_level(LEVEL_ALL)
    rid = lg.log_request({
        "endpoint": "/api/test", "method": "GET",
        "params": {"id": 1, "password": "secret123"},
        "headers": {"Authorization": "Bearer abcdef", "X-Api-Key": "key1"},
        "status_code": 200, "duration_ms": 12.5,
        "client_ip": "1.2.3.4", "user_id": "u1",
    })
    check("log_request 返回 request_id", bool(rid), str(rid))

    # 脱敏校验
    logs = lg.get_logs(page=1, page_size=10)
    check("get_logs 分页结构", "items" in logs and "total" in logs)
    items = logs["items"]
    if items:
        pwd = str(items[0].get("params", {}).get("password", ""))
        check("敏感字段脱敏", "secret123" not in pwd and "***" in pwd, pwd)

    check("get_recent_logs", isinstance(lg.get_recent_logs(5), list))
    st = lg.get_stats()
    check("get_stats", "total" in st, str(list(st.keys())))
    exp = lg.export_logs(fmt="json")
    check("export_logs", exp.get("format") == "json" and "path" in exp, str(exp))
    check("get_log_level", lg.get_log_level() == LEVEL_ALL)
    lg.clear_logs()


# ------------------------------------------------------------------ #
# 6. 监控器
# ------------------------------------------------------------------ #
def test_api_monitor() -> None:
    section("6. APIMonitor 监控器")
    from api_gateway.api_monitor import APIMonitor

    mon = APIMonitor()
    # 记录正常请求
    for _ in range(30):
        mon.record_metric("/svc/a", "GET", 50.0, 200)
    # 记录一些慢请求
    for _ in range(10):
        mon.record_metric("/svc/a", "GET", 1500.0, 200)
    # 错误请求
    for _ in range(5):
        mon.record_metric("/svc/b", "GET", 100.0, 500)

    st = mon.get_endpoint_stats("/svc/a")
    check("get_endpoint_stats 含百分位",
          "rt_p95" in st and "rt_p50" in st and "availability" in st,
          str(list(st.keys())))
    check("get_all_endpoints", "/svc/a" in mon.get_all_endpoints())
    tr = mon.get_trends("1h")
    check("get_trends", "endpoints" in tr and "throughput" in tr)
    avail = mon.get_availability()
    check("get_availability", "availability" in avail)
    mon.set_alert_threshold("/svc/a", rt_p95=100.0, error_rate=0.01)
    check("set/get_alert_threshold",
          mon.get_alert_threshold("/svc/a")["rt_p95"] == 100.0)
    alerts = mon.detect_anomalies()
    check("detect_anomalies 返回列表", isinstance(alerts, list))
    rep = mon.generate_report("24h")
    check("generate_report", "summary" in rep and "optimization_suggestions" in rep,
          str(list(rep.keys())))


# ------------------------------------------------------------------ #
# 7. 路由导入
# ------------------------------------------------------------------ #
def test_routes_import() -> None:
    section("7. API 路由导入与端点注册")
    try:
        from api_server.api_gateway_routes import router
        paths = [r.path for r in router.routes]
        methods = []
        for r in router.routes:
            methods.extend(getattr(r, "methods", []) or [])
        check("路由导入成功", router is not None)
        check("路由前缀正确",
              all(p.startswith("/api/v1/api-gateway") for p in paths),
              str(paths[:3]))
        print(f"  注册端点数: {len(paths)}")
        for p in paths:
            print(f"    - {p}")
        required = [
            "/rate-limit/config", "/rate-limit/stats",
            "/rate-limit/whitelist",
            "/circuit-breaker/status", "/circuit-breaker/config",
            "/circuit-breaker/stats",
            "/degradation/config", "/degradation/stats",
            "/cache/status", "/cache/stats", "/cache/clear", "/cache/warmup",
            "/logs", "/logs/stats", "/logs/export",
            "/monitor/endpoints", "/monitor/trends", "/monitor/alerts",
            "/monitor/report",
        ]
        missing = [r for r in required
                   if f"/api/v1/api-gateway{r}" not in paths]
        check("关键端点齐全", not missing, f"缺失: {missing}")
    except Exception as e:  # noqa: BLE001
        check("路由导入", False, f"{e}\n{traceback.format_exc()}")


def main() -> int:
    print("=" * 60)
    print("  API 网关深化模块 (v10-priority-5) 测试")
    print("=" * 60)
    tests = [
        test_rate_limiter,
        test_circuit_breaker,
        test_degradation,
        test_api_cache,
        test_api_logger,
        test_api_monitor,
        test_routes_import,
    ]
    for t in tests:
        try:
            t()
        except Exception as e:  # noqa: BLE001
            global FAIL
            FAIL += 1
            ERRORS.append(f"{t.__name__}: {e}")
            print(f"  [ERROR] {t.__name__} -> {e}\n{traceback.format_exc()}")

    print("\n" + "=" * 60)
    print(f"  结果: PASS={PASS}  FAIL={FAIL}")
    if ERRORS:
        print("  失败项:")
        for e in ERRORS:
            print(f"    - {e}")
    print("=" * 60)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
