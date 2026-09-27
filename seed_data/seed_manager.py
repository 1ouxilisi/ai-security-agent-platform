# -*- coding: utf-8 -*-
"""
seed_data/seed_manager.py — 种子数据统一管理器。

职责：
  - 统一管理漏洞库/知识库/工具模板/报告模板/KPI/合规控制项 6 大模块的
    导入/导出/重置/状态查看；
  - 支持按模块选择性导入；
  - 导入进度追踪（总条数/已导入/当前模块/百分比）；
  - 重复数据检测（基于唯一键，跳过或更新）；
  - 数据版本管理（版本号/更新日志/版本对比）；
  - 导入日志（时间/模块/条数/结果/错误）；
  - 内存模式（不写数据库，直接返回种子供 API 查询，默认）与数据库模式。

设计为管理/评估/检测视角，不提供攻击载荷。
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict, List, Optional

from seed_data import vulnerability_seeds as vs
from seed_data import knowledge_seeds as ks
from seed_data import tool_template_seeds as ts
from seed_data import report_kpi_compliance_seeds as rkcs

# --------------------------------------------------------------------------- #
# 模块注册表
# --------------------------------------------------------------------------- #
SEED_VERSION = "16.0.0"
SEED_CHANGELOG = [
    {"version": "16.0.0", "date": "2026-09-14",
     "note": "第16轮：漏洞库635+知识200+工具165+报告24/KPI340/合规530"},
    {"version": "15.0.0", "date": "2026-09-14",
     "note": "第15轮：供应链/SOAR/开发者中心/安全度量"},
]

# 模块名 -> (取数函数, 唯一键)
MODULES: Dict[str, Dict[str, Any]] = {
    "vulnerabilities": {
        "label": "漏洞库", "unique_key": "cve_id",
        "loader": vs.get_all, "stats": vs.stats,
        "filter": vs.filter_vulns,
    },
    "knowledge": {
        "label": "知识库", "unique_key": "title",
        "loader": ks.get_all, "stats": ks.stats,
        "filter": ks.filter_knowledge,
    },
    "tools": {
        "label": "工具模板", "unique_key": "name",
        "loader": ts.get_all, "stats": ts.stats,
        "filter": ts.filter_tools,
    },
    "reports": {
        "label": "报告模板", "unique_key": "name",
        "loader": rkcs.get_report_templates, "stats": lambda: {"total": len(rkcs.REPORT_TEMPLATES)},
        "filter": None,
    },
    "kpis": {
        "label": "KPI 指标库", "unique_key": "kpi_id",
        "loader": rkcs.get_kpis, "stats": lambda: {"total": len(rkcs.KPI_SEEDS)},
        "filter": None,
    },
    "compliance": {
        "label": "合规控制项", "unique_key": "control_id",
        "loader": rkcs.get_controls, "stats": rkcs.stats,
        "filter": rkcs.filter_controls,
    },
}


class SeedManager:
    """种子数据管理器（线程安全单例）。"""

    _instance: Optional["SeedManager"] = None
    _lock = threading.Lock()

    def __init__(self, mode: str = "memory") -> None:
        self.mode = mode  # memory | database
        self.version = SEED_VERSION
        # 已导入状态：module -> {imported: bool, count: int, imported_at, skipped, updated}
        self.state: Dict[str, Dict[str, Any]] = {
            m: {"imported": False, "count": 0, "imported_at": None,
                "skipped": 0, "updated": 0}
            for m in MODULES
        }
        # 内存模式下的导入缓存
        self._store: Dict[str, Dict[str, Dict[str, Any]]] = {
            m: {} for m in MODULES
        }
        # 导入日志
        self.import_logs: List[Dict[str, Any]] = []
        # 进度
        self.progress: Dict[str, Any] = {
            "running": False, "total": 0, "imported": 0,
            "current_module": None, "percent": 0, "message": "",
        }

    # ------------------------------------------------------------------ #
    # 单例
    # ------------------------------------------------------------------ #
    @classmethod
    def get_instance(cls, mode: str = "memory") -> "SeedManager":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(mode)
            return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        with cls._lock:
            cls._instance = None

    # ------------------------------------------------------------------ #
    # 状态
    # ------------------------------------------------------------------ #
    def module_status(self) -> List[Dict[str, Any]]:
        rows = []
        for m, meta in MODULES.items():
            total = len(meta["loader"]())
            st = self.state[m]
            rows.append({
                "module": m, "label": meta["label"],
                "unique_key": meta["unique_key"],
                "total_available": total,
                "imported_count": st["count"],
                "status": "imported" if st["imported"] else "not_imported",
                "imported_at": st["imported_at"],
                "skipped_duplicates": st["skipped"],
                "updated": st["updated"],
            })
        return rows

    def overall_status(self) -> Dict[str, Any]:
        mods = self.module_status()
        imported = sum(1 for m in mods if m["status"] == "imported")
        total_records = sum(m["imported_count"] for m in mods)
        return {
            "version": self.version,
            "mode": self.mode,
            "modules_total": len(mods),
            "modules_imported": imported,
            "total_records": total_records,
            "progress": self.progress,
            "modules": mods,
        }

    # ------------------------------------------------------------------ #
    # 导入
    # ------------------------------------------------------------------ #
    def import_module(self, module: str, on_duplicate: str = "skip") -> Dict[str, Any]:
        """导入单个模块。on_duplicate: skip | update。"""
        if module not in MODULES:
            return {"success": False, "error": f"未知模块: {module}"}
        meta = MODULES[module]
        rows = meta["loader"]()
        key = meta["unique_key"]
        skipped = 0
        updated = 0
        store = self._store[module]
        for r in rows:
            uk = r.get(key)
            if uk in store:
                if on_duplicate == "update":
                    store[uk] = r
                    updated += 1
                else:
                    skipped += 1
            else:
                store[uk] = r
        self.state[module].update({
            "imported": True, "count": len(store),
            "imported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "skipped": skipped, "updated": updated,
        })
        entry = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "module": module, "label": meta["label"],
            "total": len(rows), "imported": len(store),
            "skipped": skipped, "updated": updated,
            "result": "PASS", "error": None,
        }
        self.import_logs.append(entry)
        return {"success": True, "module": module, "result": entry}

    def import_all(self, modules: Optional[List[str]] = None,
                   on_duplicate: str = "skip") -> Dict[str, Any]:
        """导入全部或指定模块，带进度追踪。"""
        targets = modules or list(MODULES.keys())
        self.progress.update({
            "running": True, "total": len(targets), "imported": 0,
            "current_module": None, "percent": 0, "message": "开始导入",
        })
        results = []
        errors = []
        for i, m in enumerate(targets):
            self.progress["current_module"] = m
            self.progress["message"] = f"正在导入 {MODULES[m]['label']}"
            try:
                r = self.import_module(m, on_duplicate=on_duplicate)
                results.append(r)
            except Exception as e:  # noqa: BLE001
                errors.append({"module": m, "error": str(e)})
                self.import_logs.append({
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "module": m, "result": "FAIL", "error": str(e),
                })
            self.progress["imported"] = i + 1
            self.progress["percent"] = round((i + 1) / len(targets) * 100, 1)
            time.sleep(0.01)  # 让出 CPU，便于前端轮询进度
        self.progress.update({
            "running": False, "current_module": None,
            "message": "导入完成", "percent": 100.0,
        })
        return {
            "success": len(errors) == 0,
            "results": results, "errors": errors,
            "summary": self.overall_status(),
        }

    # ------------------------------------------------------------------ #
    # 重置 / 导出
    # ------------------------------------------------------------------ #
    def reset(self, modules: Optional[List[str]] = None) -> Dict[str, Any]:
        targets = modules or list(MODULES.keys())
        for m in targets:
            self._store[m].clear()
            self.state[m].update({
                "imported": False, "count": 0, "imported_at": None,
                "skipped": 0, "updated": 0,
            })
        self.import_logs.append({
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "module": ",".join(targets), "result": "RESET",
            "message": f"重置模块: {targets}",
        })
        return {"success": True, "reset_modules": targets}

    def export_module(self, module: str) -> Dict[str, Any]:
        if module not in MODULES:
            return {"success": False, "error": f"未知模块: {module}"}
        rows = list(self._store[module].values())
        return {
            "success": True, "module": module, "count": len(rows),
            "version": self.version, "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "data": rows,
        }

    def export_all(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "modules": {m: list(self._store[m].values()) for m in MODULES},
        }

    # ------------------------------------------------------------------ #
    # 查询（内存模式直接返回种子）
    # ------------------------------------------------------------------ #
    def query(self, module: str, **kwargs: Any) -> Dict[str, Any]:
        """查询模块数据。内存模式直接调用种子的 filter。"""
        if module not in MODULES:
            return {"success": False, "error": f"未知模块: {module}"}
        meta = MODULES[module]
        if meta.get("filter") is None:
            rows = meta["loader"]()
            limit = kwargs.get("limit") or 0
            offset = kwargs.get("offset") or 0
            if offset:
                rows = rows[offset:]
            if limit:
                rows = rows[:limit]
            return {"success": True, "items": rows,
                    "total": len(meta["loader"]())}
        return {"success": True, **meta["filter"](**kwargs)}

    # ------------------------------------------------------------------ #
    # 版本管理
    # ------------------------------------------------------------------ #
    def version_info(self) -> Dict[str, Any]:
        return {
            "current_version": self.version,
            "changelog": SEED_CHANGELOG,
            "module_counts": {m: len(meta["loader"]()) for m, meta in MODULES.items()},
        }

    def compare_version(self, other: str) -> Dict[str, Any]:
        """与指定版本对比（这里简化为返回当前版本各模块数量）。"""
        current = self.version_info()
        return {
            "compared_to": other,
            "current": self.version,
            "is_newer": self.version > other,
            "module_counts": current["module_counts"],
        }

    # ------------------------------------------------------------------ #
    # 日志
    # ------------------------------------------------------------------ #
    def logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(reversed(self.import_logs[-limit:]))


def get_manager() -> SeedManager:
    return SeedManager.get_instance()
