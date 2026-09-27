# -*- coding: utf-8 -*-
"""
api_routes.py — 威胁狩猎内部路由注册辅助。

提供模块级别的路由工厂函数，供 api_server/threat_hunt_routes.py 调用。
所有功能为检测/监控/分析/管理视角，不包含实际攻击代码。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 内存任务存储
# --------------------------------------------------------------------------- #
TASKS: Dict[str, Dict[str, Any]] = {}


def new_task(kind: str) -> str:
    task_id = uuid.uuid4().hex[:16]
    TASKS[task_id] = {
        "task_id": task_id, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return task_id


def finish_task(task_id: str, result: Any, error: Optional[str] = None) -> None:
    if task_id in TASKS:
        t = TASKS[task_id]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


def get_task(task_id: str) -> Optional[Dict[str, Any]]:
    return TASKS.get(task_id)


# --------------------------------------------------------------------------- #
# 全局引擎实例（单例）
# --------------------------------------------------------------------------- #
_engine_instances: Dict[str, Any] = {}


def get_engines() -> Dict[str, Any]:
    """获取所有引擎实例（懒加载单例）。"""
    if not _engine_instances:
        try:
            from threat_hunt.hunt_query_engine import HuntQueryEngine
            from threat_hunt.hypothesis_driven_hunt import (
                HypothesisManager, HuntProjectManager, HuntPlaybookManager, HuntFindingManager,
            )
            from threat_hunt.behavior_analysis import (
                BehaviorBaselineBuilder, EntityProfiler, AnomalyDetector,
                BehaviorChainAnalyzer, BehaviorScorer,
            )
            from threat_hunt.ioc_enrichment import (
                IOCManager, IOCEnricher, IOCRelationAnalyzer, IOCImportExport, IOCScorer,
            )
            from threat_hunt.hunt_data_manager import (
                DataSourceManager, CrossSourceSearcher, DataPipeline,
                DataQualityMonitor, HuntDataExporter,
            )
            from threat_hunt.hunt_report_metrics import (
                HuntReportGenerator, HuntMetricsCalculator, HuntKnowledgeBase,
                HuntMaturityAssessor, HuntDashboardData,
            )

            _engine_instances["query_engine"] = HuntQueryEngine()
            _engine_instances["hypothesis_mgr"] = HypothesisManager()
            _engine_instances["project_mgr"] = HuntProjectManager()
            _engine_instances["playbook_mgr"] = HuntPlaybookManager()
            _engine_instances["finding_mgr"] = HuntFindingManager()
            _engine_instances["baseline_builder"] = BehaviorBaselineBuilder()
            _engine_instances["profiler"] = EntityProfiler()
            _engine_instances["anomaly_detector"] = AnomalyDetector()
            _engine_instances["chain_analyzer"] = BehaviorChainAnalyzer()
            _engine_instances["scorer"] = BehaviorScorer()
            _engine_instances["ioc_mgr"] = IOCManager()
            _engine_instances["ioc_enricher"] = IOCEnricher()
            _engine_instances["ioc_relation"] = IOCRelationAnalyzer()
            _engine_instances["ioc_impexp"] = IOCImportExport()
            _engine_instances["ioc_scorer"] = IOCScorer()
            _engine_instances["source_mgr"] = DataSourceManager()
            _engine_instances["searcher"] = CrossSourceSearcher()
            _engine_instances["pipeline"] = DataPipeline()
            _engine_instances["quality_monitor"] = DataQualityMonitor()
            _engine_instances["exporter"] = HuntDataExporter()
            _engine_instances["report_gen"] = HuntReportGenerator()
            _engine_instances["metrics_calc"] = HuntMetricsCalculator()
            _engine_instances["kb"] = HuntKnowledgeBase()
            _engine_instances["maturity"] = HuntMaturityAssessor()
            _engine_instances["dashboard"] = HuntDashboardData()
        except Exception:
            # 模块加载失败时返回空实例
            _engine_instances["_load_error"] = True
    return _engine_instances


def is_loaded() -> bool:
    return not get_engines().get("_load_error", False)
