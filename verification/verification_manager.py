#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
验证管理器（模块一：1.4）。

职责：
    - 接收验证任务（Web / 服务 / 版本匹配）
    - 队列 + 线程池并发执行（最多 3 并发）
    - 结果缓存 24 小时（key = md5(target+vuln_type)）
    - 统计数据持久化到 data/verification_stats.json
    - 生成验证报告

单例模式：直接 import verification_manager 使用。
"""

import hashlib
import json
import os
import queue
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict, Optional

try:
    from loguru import logger
except Exception:  # pragma: no cover
    import logging

    logger = logging.getLogger("verification_manager")

# 项目根目录
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_STATS_PATH = os.path.join(_PROJECT_ROOT, "data", "verification_stats.json")
_CACHE_TTL = 24 * 3600  # 24 小时


class VerificationManager:
    """验证管理器（单例）。"""

    _instance = None
    _instance_lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, max_workers: int = 3, cache_ttl: int = _CACHE_TTL):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True
        self.max_workers = max_workers
        self.cache_ttl = cache_ttl

        self._task_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._results: Dict[str, Dict[str, Any]] = {}
        self._cache: Dict[str, Dict[str, Any]] = {}  # key -> {result, ts}
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(max_workers=max_workers,
                                            thread_name_prefix="verify")
        self._stop = threading.Event()

        # 统计数据
        self._stats: Dict[str, int] = {
            "total": 0,
            "verified": 0,
            "possible": 0,
            "false_positive": 0,
            "unverifiable": 0,
        }
        self._load_stats()

        # 导入验证器（延迟导入避免循环依赖）
        from .web_vuln_verifier import WebVulnVerifier
        from .service_vuln_verifier import ServiceVulnVerifier
        self.web_verifier = WebVulnVerifier()
        self.service_verifier = ServiceVulnVerifier()

        # 启动后台消费者线程
        self._consumer_thread = threading.Thread(
            target=self._consume_loop, name="verify-consumer", daemon=True)
        self._consumer_thread.start()

    # ------------------------------------------------------------------
    # 统计持久化
    # ------------------------------------------------------------------
    def _load_stats(self) -> None:
        try:
            if os.path.exists(_STATS_PATH):
                with open(_STATS_PATH, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                if isinstance(saved, dict):
                    for k in self._stats:
                        self._stats[k] = int(saved.get(k, 0))
        except Exception as e:
            logger.warning(f"加载验证统计失败: {e}")

    def _save_stats(self) -> None:
        try:
            os.makedirs(os.path.dirname(_STATS_PATH), exist_ok=True)
            with open(_STATS_PATH, "w", encoding="utf-8") as f:
                json.dump(self._stats, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"保存验证统计失败: {e}")

    def _bump_stat(self, status: str) -> None:
        with self._lock:
            self._stats["total"] += 1
            if status in self._stats:
                self._stats[status] += 1
            self._save_stats()

    # ------------------------------------------------------------------
    # 缓存
    # ------------------------------------------------------------------
    @staticmethod
    def _cache_key(target: str, vuln_type: str) -> str:
        raw = f"{target}|{vuln_type}"
        return hashlib.md5(raw.encode("utf-8")).hexdigest()

    def _get_cache(self, target: str, vuln_type: str) -> Optional[Dict[str, Any]]:
        key = self._cache_key(target, vuln_type)
        with self._lock:
            entry = self._cache.get(key)
        if not entry:
            return None
        if time.time() - entry.get("ts", 0) > self.cache_ttl:
            with self._lock:
                self._cache.pop(key, None)
            return None
        return entry.get("result")

    def _set_cache(self, target: str, vuln_type: str,
                   result: Dict[str, Any]) -> None:
        key = self._cache_key(target, vuln_type)
        with self._lock:
            self._cache[key] = {"result": result, "ts": time.time()}

    # ------------------------------------------------------------------
    # 任务提交
    # ------------------------------------------------------------------
    def submit_verification(self, task_type: str, target: str,
                           vuln_type: str, **kwargs) -> str:
        """提交验证任务，返回 task_id。"""
        # 先查缓存
        cached = self._get_cache(target, vuln_type)
        task_id = uuid.uuid4().hex
        if cached is not None:
            cached_copy = dict(cached)
            cached_copy["task_id"] = task_id
            cached_copy["cached"] = True
            with self._lock:
                self._results[task_id] = cached_copy
            return task_id

        task = {
            "task_id": task_id,
            "task_type": task_type,
            "target": target,
            "vuln_type": vuln_type,
            "kwargs": kwargs,
            "submitted_at": time.time(),
        }
        self._task_queue.put(task)
        return task_id

    def get_result(self, task_id: str) -> Dict[str, Any]:
        """获取验证结果。未完成时返回 pending。"""
        with self._lock:
            res = self._results.get(task_id)
        if res is None:
            # 可能还在队列里
            return {"task_id": task_id, "status": "pending",
                    "message": "任务不存在或仍在队列中"}
        return res

    # ------------------------------------------------------------------
    # 后台消费
    # ------------------------------------------------------------------
    def _consume_loop(self) -> None:
        while not self._stop.is_set():
            try:
                task = self._task_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            except Exception:
                break
            try:
                future = self._executor.submit(self._execute_task, task)
                future.add_done_callback(
                    lambda fut, t=task: self._finalize(t, fut))
            except Exception as e:
                logger.exception(f"提交验证任务失败: {e}")
                with self._lock:
                    self._results[task["task_id"]] = {
                        "task_id": task["task_id"],
                        "status": "unverifiable",
                        "error": str(e),
                    }

    def _execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """根据 task_type 分发到具体验证器。"""
        task_type = task["task_type"]
        target = task["target"]
        vuln_type = task["vuln_type"]
        kw = task.get("kwargs", {}) or {}

        try:
            if task_type == "web":
                return self._run_web_verify(vuln_type, target, kw)
            if task_type == "service":
                return self._run_service_verify(vuln_type, target, kw)
            if task_type == "version_match":
                svc = kw.get("service", "")
                ver = kw.get("version", "")
                return self.service_verifier.match_version_vulnerabilities(svc, ver)
            return {
                "vuln_type": vuln_type,
                "status": "unverifiable",
                "confidence": 0.0,
                "evidence": f"未知 task_type: {task_type}",
                "details": {}, "target": target, "param": "",
                "timestamp": time.time(),
            }
        except Exception as e:
            return {
                "vuln_type": vuln_type,
                "status": "unverifiable",
                "confidence": 0.0,
                "evidence": f"验证执行异常: {e}",
                "details": {"error": str(e)},
                "target": target, "param": "",
                "timestamp": time.time(),
            }

    def _run_web_verify(self, vuln_type: str, url: str,
                        kw: Dict[str, Any]) -> Dict[str, Any]:
        param = kw.get("param", "")
        method = kw.get("method", "GET")
        if vuln_type == "sql_injection":
            return self.web_verifier.verify_sql_injection(url, param, method)
        if vuln_type == "xss":
            return self.web_verifier.verify_xss(url, param, method)
        if vuln_type == "path_traversal":
            return self.web_verifier.verify_path_traversal(url, param)
        if vuln_type == "ssrf":
            return self.web_verifier.verify_ssrf(url, param)
        if vuln_type == "command_injection":
            return self.web_verifier.verify_command_injection(url, param, method)
        if vuln_type == "file_upload":
            return self.web_verifier.verify_file_upload(
                url, kw.get("file_field", "file"))
        return {
            "vuln_type": vuln_type, "status": "unverifiable",
            "confidence": 0.0,
            "evidence": f"未知 Web 漏洞类型: {vuln_type}",
            "details": {}, "target": url, "param": param,
            "timestamp": time.time(),
        }

    def _run_service_verify(self, vuln_type: str, target: str,
                            kw: Dict[str, Any]) -> Dict[str, Any]:
        # target 形如 host:port 或 host
        host = kw.get("host") or target.split(":")[0]
        port = kw.get("port")
        if port is None and ":" in target:
            try:
                port = int(target.split(":")[1].split("/")[0])
            except Exception:
                port = 0
        port = int(port or 0)
        service = kw.get("service", "")

        if vuln_type == "weak_password":
            return self.service_verifier.verify_weak_password(
                host, port, service,
                username=kw.get("username", "admin"),
                password_list=kw.get("password_list"))
        if vuln_type == "unauthorized_access":
            return self.service_verifier.verify_unauthorized_access(
                host, port, service)
        if vuln_type == "anonymous_access":
            return self.service_verifier.verify_anonymous_access(
                host, port, service)
        if vuln_type == "default_credentials":
            return self.service_verifier.verify_default_credentials(
                host, port, service)
        if vuln_type == "version_cve_match":
            return self.service_verifier.match_version_vulnerabilities(
                kw.get("service", ""), kw.get("version", ""))
        return {
            "vuln_type": vuln_type, "status": "unverifiable",
            "confidence": 0.0,
            "evidence": f"未知服务漏洞类型: {vuln_type}",
            "details": {}, "target": f"{host}:{port}", "param": service,
            "timestamp": time.time(),
        }

    def _finalize(self, task: Dict[str, Any], future) -> None:
        try:
            result = future.result()
        except Exception as e:
            result = {
                "vuln_type": task["vuln_type"],
                "status": "unverifiable",
                "confidence": 0.0,
                "evidence": f"任务执行异常: {e}",
                "details": {"error": str(e)},
                "target": task["target"], "param": "",
                "timestamp": time.time(),
            }
        result["task_id"] = task["task_id"]
        result["task_type"] = task["task_type"]
        result["completed_at"] = datetime.now().isoformat()
        with self._lock:
            self._results[task["task_id"]] = result
        # 更新统计与缓存
        self._bump_stat(result.get("status", "unverifiable"))
        self._set_cache(task["target"], task["vuln_type"], result)

    # ------------------------------------------------------------------
    # 统计 / 报告
    # ------------------------------------------------------------------
    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self._stats["total"]
            verified = self._stats["verified"]
            fp = self._stats["false_positive"]
            possible = self._stats["possible"]
            unverifiable = self._stats["unverifiable"]
        denom = verified + fp
        fp_rate = round(fp / denom, 4) if denom > 0 else 0.0
        return {
            "total": total,
            "verified": verified,
            "possible": possible,
            "false_positive": fp,
            "unverifiable": unverifiable,
            "false_positive_rate": fp_rate,
            "queue_size": self._task_queue.qsize(),
            "cache_size": len(self._cache),
        }

    def generate_report(self, task_id: Optional[str] = None) -> Dict[str, Any]:
        """生成验证报告。"""
        with self._lock:
            results = list(self._results.values())
        if task_id:
            results = [r for r in results if r.get("task_id") == task_id]

        by_status: Dict[str, int] = {}
        for r in results:
            s = r.get("status", "unknown")
            by_status[s] = by_status.get(s, 0) + 1

        return {
            "generated_at": datetime.now().isoformat(),
            "task_id": task_id,
            "total_results": len(results),
            "by_status": by_status,
            "stats": self.get_stats(),
            "results": results,
        }

    def shutdown(self, wait: bool = False) -> None:
        """关闭后台线程。"""
        self._stop.set()
        try:
            self._executor.shutdown(wait=wait, cancel_futures=True)
        except Exception:
            pass


# 单例全局实例
verification_manager = VerificationManager()
