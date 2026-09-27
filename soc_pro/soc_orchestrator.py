# -*- coding: utf-8 -*-
"""
soc_orchestrator.py — SOC Pro 七阶段编排器。

阶段:
    1. log_collection    日志收集
    2. log_parsing       日志解析
    3. correlation       关联分析
    4. alert_generation  告警生成
    5. incident_response 事件响应
    6. threat_hunting    威胁狩猎
    7. postmortem        事件复盘
"""

from __future__ import annotations

import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional

from .log_collection_phase import get_log_collection_phase
from .log_parsing_phase import get_log_parsing_phase
from .correlation_phase import get_correlation_phase
from .alert_generation_phase import get_alert_generation_phase
from .incident_response_phase import get_incident_response_phase
from .threat_hunting_phase import get_threat_hunting_phase
from .postmortem_phase import get_postmortem_phase
from .ai_analysis import get_ai_analysis
from .realtime_push import get_realtime_push
from .report_generator import get_report_generator, REPORTS_DIR


STAGES = [
    ("log_collection",     "1.日志收集", 12),
    ("log_parsing",        "2.日志解析", 25),
    ("correlation",        "3.关联分析", 45),
    ("alert_generation",   "4.告警生成", 60),
    ("incident_response",  "5.事件响应", 75),
    ("threat_hunting",     "6.威胁狩猎", 88),
    ("postmortem",         "7.事件复盘", 100),
]


@dataclass
class SOCTask:
    task_id: str = ""
    name: str = ""
    status: str = "pending"
    stage: str = "init"
    progress: int = 0
    created_at: str = ""
    finished_at: Optional[str] = None
    error: Optional[str] = None
    results: Dict[str, Any] = field(default_factory=dict)
    log: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id, "name": self.name,
            "status": self.status, "stage": self.stage,
            "progress": self.progress,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "results": self.results,
            "log": self.log[-80:],
        }


class SOCOrchestrator:
    """七阶段编排器。"""

    def __init__(self) -> None:
        self.collect = get_log_collection_phase()
        self.parse = get_log_parsing_phase()
        self.corr = get_correlation_phase()
        self.alert = get_alert_generation_phase()
        self.ir = get_incident_response_phase()
        self.hunt = get_threat_hunting_phase()
        self.pm = get_postmortem_phase()
        self.ai = get_ai_analysis()
        self.rt = get_realtime_push()
        self.report = get_report_generator()
        self._tasks: Dict[str, SOCTask] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def create_task(self, name: str = "SOC 全流程巡检") -> SOCTask:
        t = SOCTask(
            task_id="soc_" + uuid.uuid4().hex[:10],
            name=name,
            created_at=datetime.now().isoformat(timespec="seconds"),
        )
        with self._lock:
            self._tasks[t.task_id] = t
        return t

    def list_tasks(self) -> list:
        with self._lock:
            return [t.to_dict() for t in self._tasks.values()][::-1]

    def get_task(self, task_id: str) -> Optional[SOCTask]:
        with self._lock:
            return self._tasks.get(task_id)

    # ------------------------------------------------------------------ #
    def _log(self, t: SOCTask, level: str, msg: str) -> None:
        t.log.append(f"[{datetime.now().strftime('%H:%M:%S')}] "
                     f"{level} {msg}")
        self.rt.emit_log(t.task_id, level, msg)

    def _think(self, t: SOCTask, thought: str) -> None:
        self.rt.emit_thought(t.task_id, thought)

    def _stage(self, t: SOCTask, key: str, label: str,
               overall: int) -> None:
        t.stage = key
        t.progress = overall
        self.rt.emit_progress(t.task_id, key, label, overall,
                              stage_progress=0)

    # ------------------------------------------------------------------ #
    def run_full(self, task_id: str) -> None:
        t = self._tasks.get(task_id)
        if t is None:
            return
        t.status = "running"
        try:
            # 阶段1 日志收集
            self._stage(t, "log_collection", STAGES[0][1], 8)
            self._log(t, "INFO", "启动日志收集（syslog/filebeat/logstash）")
            self._think(t, "正在接入多源日志，优先调用真实采集工具；"
                          "未安装则用内置模拟框架兜底")
            r1 = self.collect.start_collect(count=300)
            t.results["log_collection"] = r1
            self._log(t, "OK", f"采集 {r1['produced']} 条日志，"
                               f"覆盖 {len(r1['started_sources'])} 个源")

            # 阶段2 日志解析
            self._stage(t, "log_parsing", STAGES[1][1], 22)
            self._log(t, "INFO", "执行日志标准化 / Grok 提取 / 富化")
            self._think(t, "正在跑正则提取、IP 地理富化、威胁情报匹配")
            r2 = self.parse.parse_batch(limit=500)
            t.results["log_parsing"] = {k: v for k, v in r2.items()
                                        if k != "samples"}
            self._log(t, "OK", f"解析 {r2['total']} 条，"
                               f"平均质量 {r2['avg_quality']:.2f}")

            # 阶段3 关联分析
            self._stage(t, "correlation", STAGES[2][1], 42)
            self._log(t, "INFO", f"执行 {self.corr.stats()['rule_total']} "
                                 f"条 SIEM 规则")
            self._think(t, "正在窗口化计数，触发阈值命中")
            r3 = self.corr.correlate()
            t.results["correlation"] = r3
            self._log(t, "OK", f"命中 {r3['hits']} 条")

            # 阶段4 告警生成
            self._stage(t, "alert_generation", STAGES[3][1], 58)
            self._log(t, "INFO", "生成告警 / 去重 / 聚合 / 分配")
            r4 = self.alert.generate_from_hits()
            t.results["alert_generation"] = r4
            self._log(t, "OK", f"新建 {r4['created']}，合并 {r4['merged']}")
            for a in self.alert.list_alerts(limit=3):
                self.rt.emit_alert(task_id, a)

            # 阶段5 事件响应
            self._stage(t, "incident_response", STAGES[4][1], 72)
            self._log(t, "INFO", "SOAR 剧本编排 / 工单")
            self._think(t, "对 critical/high 告警自动触发剧本")
            tickets = []
            for a in self.alert.list_alerts(limit=5):
                if a["severity"] in ("critical", "high"):
                    tk = self.ir.create_ticket(
                        title=a["title"], alert_id=a["alert_id"],
                        priority=a["severity"])
                    tickets.append(tk["ticket_id"])
            t.results["incident_response"] = {
                "tickets": tickets,
                "stats": self.ir.stats(),
            }
            self._log(t, "OK", f"创建工单 {len(tickets)} 张")

            # 阶段6 威胁狩猎
            self._stage(t, "threat_hunting", STAGES[5][1], 85)
            self._log(t, "INFO", "运行预设狩猎查询 + IOC 匹配")
            hunt_summary = {}
            for qid in [q["qid"] for q in self.hunt.list_queries()][:5]:
                hunt_summary[qid] = self.hunt.run_query(qid)["finds"]
            t.results["threat_hunting"] = {
                "queries": hunt_summary,
                "report": self.hunt.hunting_report(),
            }
            self._log(t, "OK", f"狩猎查询完成，"
                               f"发现 "
                               f"{self.hunt.hunting_report()['total_finds']}")

            # 阶段7 复盘
            self._stage(t, "postmortem", STAGES[6][1], 98)
            self._log(t, "INFO", "构建时间线 / 根因 / 改进项")
            pm = self.pm.generate(title=t.name, incident=task_id)
            t.results["postmortem"] = pm
            t.results["report"] = self.report.generate("both")
            self._log(t, "OK", "复盘报告已生成")

            # AI 分析
            self._think(t, "正在用 AI 对告警降噪、推断攻击路径")
            ai = self.ai.batch_analyze(self.alert.list_alerts(limit=20))
            t.results["ai_analysis"] = {
                "noise_ratio": ai["noise_ratio"],
                "likely_attack": ai["likely_attack"],
                "false_positives": ai["false_positives"],
            }
            self.rt.emit_result(task_id, t.results)

            t.status = "done"
            t.finished_at = datetime.now().isoformat(timespec="seconds")
            self.rt.emit_progress(task_id, "done", "完成", 100,
                                 stage_progress=100, eta_seconds=0)
        except Exception as e:  # noqa: BLE001
            t.status = "error"
            t.error = str(e)
            self._log(t, "ERROR", f"任务失败: {e}")
        finally:
            t.progress = 100 if t.status == "done" else t.progress


_default: Optional[SOCOrchestrator] = None


def get_orchestrator() -> SOCOrchestrator:
    global _default
    if _default is None:
        _default = SOCOrchestrator()
    return _default
