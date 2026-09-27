# -*- coding: utf-8 -*-
"""多租户管理引擎。

提供租户隔离、生命周期管理、配额管理与租户级配置。

数据布局::

    data/tenants/
        _meta/
            tenants.json      # 租户元信息
            usage.json        # 配额使用记录
        {tenant_id}/
            config.json       # 租户级配置
            assessments/      # 评估结果
            reports/          # 报告
            logs/             # 日志
            uploads/          # 上传文件
"""
import os
import json
import time
import copy
import threading
from typing import Any, Dict, List, Optional, Tuple

try:
    from utils.logger import log
except Exception:  # pragma: no cover
    import logging
    log = logging.getLogger("commercial.multi_tenant")


# 租户工作空间子目录
TENANT_SUBDIRS = ["assessments", "reports", "logs", "uploads"]

# 默认配额上限
DEFAULT_QUOTAS: Dict[str, int] = {
    "scan_count": 10,        # 每月扫描次数
    "storage_mb": 500,       # 存储 MB
    "api_calls_daily": 1000,  # 每日 API 调用
    "users": 1,              # 用户数
    "api_keys": 1,           # API Key 数
}

# 各计划预置配额（与 billing.PLANS 对齐，避免循环依赖在此内置一份）
PLAN_QUOTA_PRESETS: Dict[str, Dict[str, int]] = {
    "FREE": {"scan_count": 10, "users": 1, "api_keys": 1,
             "storage_mb": 500, "api_calls_daily": 500},
    "PRO": {"scan_count": 100, "users": 10, "api_keys": 5,
            "storage_mb": 10240, "api_calls_daily": 50000},
    "ENTERPRISE": {"scan_count": 10 ** 9, "users": 10 ** 9, "api_keys": 50,
                   "storage_mb": 102400, "api_calls_daily": 10 ** 9},
}

# 配额字段是否按周期重置（True=每日重置，False=每月重置）
_QUOTA_PERIOD_DAILY = {"api_calls_daily"}


class TenantManager:
    """多租户管理器（线程安全，可实例化/单例）。"""

    def __init__(self, base_dir: str = "data/tenants"):
        self.base_dir = base_dir
        self.meta_dir = os.path.join(base_dir, "_meta")
        self.tenants_file = os.path.join(self.meta_dir, "tenants.json")
        self.usage_file = os.path.join(self.meta_dir, "usage.json")

        self._tenants: Dict[str, Dict[str, Any]] = {}
        # usage 结构: {tenant_id: {quota_type: {"period": str, "used": int}}}
        self._usage: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self._lock = threading.RLock()

        os.makedirs(self.meta_dir, exist_ok=True)
        self._load()

    # ---------------- 持久化 ----------------

    def _load(self):
        if os.path.exists(self.tenants_file):
            try:
                with open(self.tenants_file, "r", encoding="utf-8") as f:
                    self._tenants = json.load(f)
            except Exception as e:
                log.warning(f"[multi_tenant] 加载 tenants.json 失败: {e}")
                self._tenants = {}
        if os.path.exists(self.usage_file):
            try:
                with open(self.usage_file, "r", encoding="utf-8") as f:
                    self._usage = json.load(f)
            except Exception as e:
                log.warning(f"[multi_tenant] 加载 usage.json 失败: {e}")
                self._usage = {}

    def _save_tenants(self):
        with open(self.tenants_file, "w", encoding="utf-8") as f:
            json.dump(self._tenants, f, ensure_ascii=False, indent=2)

    def _save_usage(self):
        with open(self.usage_file, "w", encoding="utf-8") as f:
            json.dump(self._usage, f, ensure_ascii=False, indent=2)

    # ---------------- 路径辅助 ----------------

    def get_tenant_path(self, tenant_id: str, subpath: str = "") -> str:
        """返回租户数据目录（可带子路径）的绝对路径。"""
        base = os.path.abspath(os.path.join(self.base_dir, tenant_id))
        if subpath:
            base = os.path.join(base, subpath)
        return base

    def _ensure_tenant_dirs(self, tenant_id: str):
        root = self.get_tenant_path(tenant_id)
        os.makedirs(root, exist_ok=True)
        for sub in TENANT_SUBDIRS:
            os.makedirs(os.path.join(root, sub), exist_ok=True)

    @staticmethod
    def _period_key(quota_type: str) -> str:
        now = time.time()
        if quota_type in _QUOTA_PERIOD_DAILY:
            return time.strftime("%Y-%m-%d", time.localtime(now))
        return time.strftime("%Y-%m", time.localtime(now))

    # ---------------- 租户生命周期 ----------------

    def create_tenant(self, tenant_id: str, name: str, plan: str = "FREE",
                      **kwargs) -> Dict[str, Any]:
        """创建租户，初始化目录结构与默认配置/配额。"""
        with self._lock:
            if tenant_id in self._tenants:
                raise ValueError(f"租户 {tenant_id} 已存在")

            quotas = dict(DEFAULT_QUOTAS)
            # 套用计划预置配额
            if plan in PLAN_QUOTA_PRESETS:
                quotas.update(PLAN_QUOTA_PRESETS[plan])
            quotas.update(kwargs.get("quotas") or {})

            tenant = {
                "tenant_id": tenant_id,
                "name": name,
                "plan": plan,
                "status": "active",
                "created_at": time.time(),
                "quotas": quotas,
                "config": {
                    "brand_name": name,
                    "report_template": "",
                    "tool_paths": {},
                    "notifications": {"email": "", "enabled": False},
                },
                "extra": {k: v for k, v in kwargs.items() if k not in ("quotas",)},
            }
            self._tenants[tenant_id] = tenant
            self._usage.setdefault(tenant_id, {})
            self._ensure_tenant_dirs(tenant_id)
            self._save_tenants()
            self._save_usage()
            log.info(f"[multi_tenant] 租户 {tenant_id}({name}) 创建成功, plan={plan}")
            return dict(tenant)

    def disable_tenant(self, tenant_id: str) -> bool:
        with self._lock:
            t = self._tenants.get(tenant_id)
            if not t:
                return False
            t["status"] = "disabled"
            self._save_tenants()
            return True

    def enable_tenant(self, tenant_id: str) -> bool:
        with self._lock:
            t = self._tenants.get(tenant_id)
            if not t:
                return False
            t["status"] = "active"
            self._save_tenants()
            return True

    def delete_tenant(self, tenant_id: str, delete_data: bool = False) -> bool:
        with self._lock:
            if tenant_id not in self._tenants:
                return False
            del self._tenants[tenant_id]
            self._usage.pop(tenant_id, None)
            self._save_tenants()
            self._save_usage()
            if delete_data:
                import shutil
                path = self.get_tenant_path(tenant_id)
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
            return True

    def get_tenant(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        t = self._tenants.get(tenant_id)
        return dict(t) if t else None

    def list_tenants(self) -> List[Dict[str, Any]]:
        return [dict(t) for t in self._tenants.values()]

    # ---------------- 配额 ----------------

    def update_quota(self, tenant_id: str, quota_type: str, value: int) -> bool:
        with self._lock:
            t = self._tenants.get(tenant_id)
            if not t:
                return False
            t.setdefault("quotas", {})[quota_type] = int(value)
            self._save_tenants()
            return True

    def _get_usage_record(self, tenant_id: str, quota_type: str) -> Dict[str, Any]:
        """获取当前周期的使用记录，周期切换时自动清零。"""
        tmap = self._usage.setdefault(tenant_id, {})
        rec = tmap.get(quota_type)
        period = self._period_key(quota_type)
        if not rec or rec.get("period") != period:
            rec = {"period": period, "used": 0}
            tmap[quota_type] = rec
        return rec

    def check_quota(self, tenant_id: str, quota_type: str,
                    amount: int = 1) -> Tuple[bool, int, int]:
        """检查配额。返回 (allowed, remaining, limit)。"""
        with self._lock:
            t = self._tenants.get(tenant_id)
            if not t:
                return False, 0, 0
            if t.get("status") != "active":
                return False, 0, 0
            limit = int(t.get("quotas", {}).get(quota_type, 0))
            rec = self._get_usage_record(tenant_id, quota_type)
            used = int(rec.get("used", 0))
            remaining = max(0, limit - used)
            allowed = (used + amount) <= limit
            return allowed, remaining, limit

    def record_usage(self, tenant_id: str, quota_type: str, amount: int = 1) -> int:
        """记录使用量，返回记录后的已用量。"""
        with self._lock:
            if tenant_id not in self._tenants:
                return 0
            rec = self._get_usage_record(tenant_id, quota_type)
            rec["used"] = int(rec.get("used", 0)) + int(amount)
            self._save_usage()
            return rec["used"]

    # ---------------- 租户级配置 ----------------

    def get_config(self, tenant_id: str, key: str, default: Any = None) -> Any:
        t = self._tenants.get(tenant_id)
        if not t:
            return default
        cfg = t.get("config", {})
        # 支持 brand_name / notifications.email 这类点号路径
        cur: Any = cfg
        for part in key.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return default
        return cur

    def set_config(self, tenant_id: str, key: str, value: Any) -> bool:
        with self._lock:
            t = self._tenants.get(tenant_id)
            if not t:
                return False
            cfg = t.setdefault("config", {})
            parts = key.split(".")
            cur = cfg
            for part in parts[:-1]:
                cur = cur.setdefault(part, {})
            cur[parts[-1]] = value
            self._save_tenants()
            return True

    # ---------------- 用量快照（供仪表盘） ----------------

    def usage_snapshot(self, tenant_id: str) -> Dict[str, Any]:
        """返回各配额的已用/上限/剩余。"""
        with self._lock:
            t = self._tenants.get(tenant_id)
            if not t:
                return {}
            out: Dict[str, Any] = {}
            for qtype, limit in t.get("quotas", {}).items():
                rec = self._get_usage_record(tenant_id, qtype)
                used = int(rec.get("used", 0))
                out[qtype] = {
                    "used": used,
                    "limit": int(limit),
                    "remaining": max(0, int(limit) - used),
                    "period": rec.get("period", ""),
                }
            return out


# 模块级单例
_default_manager: Optional[TenantManager] = None


def get_tenant_manager(base_dir: str = "data/tenants") -> TenantManager:
    global _default_manager
    if _default_manager is None:
        _default_manager = TenantManager(base_dir)
    return _default_manager
