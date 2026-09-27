# -*- coding: utf-8 -*-
"""
threat_intel_orchestrator.py — 方向2 威胁情报 Pro 八阶段编排器。

阶段:
    1. collection   IOC 收集
    2. management  IOC 管理（入库/去重/富化）
    3. matching    IOC 匹配（日志/流量/资产/邮件）
    4. actors      威胁 Actor 画像
    5. surface     攻击面管理
    6. darkweb     暗网监控
    7. analysis    情报分析 + AI
    8. sharing     STIX/TAXII 情报共享
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .ioc_collection_phase import get_collection_phase
from .ioc_management_phase import get_management_phase
from .ioc_matching_phase import get_matching_phase
from .threat_actor_phase import get_actor_phase
from .attack_surface_phase import get_attack_surface_phase
from .darkweb_monitor_phase import get_darkweb_phase
from .intel_analysis_phase import get_analysis_phase
from .intel_sharing_phase import get_sharing_phase
from .ai_analysis import get_ai_analyzer
from .report_generator import (
    ThreatIntelReportGenerator, ReportData, get_report_generator)
from .realtime_push import manager


REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports", "threat_intel_pro")

STAGES = [
    ("collection",  "IOC 收集",     12),
    ("management",  "IOC 管理",     25),
    ("matching",    "IOC 匹配",     40),
    ("actors",      "Actor 画像",   52),
    ("surface",     "攻击面",       65),
    ("darkweb",     "暗网监控",     78),
    ("analysis",    "情报分析",     90),
    ("sharing",     "情报共享",     100),
]


@dataclass
class IntelTask:
    task_id: str = ""
    target: str = ""
    status: str = "pending"
    stage: str = "init"
    progress: int = 0
    created_at: str = ""
    finished_at: Optional[str] = None
    error: Optional[str] = None
    # 八阶段产物
    collection: Dict[str, Any] = field(default_factory=dict)
    management: Dict[str, Any] = field(default_factory=dict)
    matching: Dict[str, Any] = field(default_factory=dict)
    actors: Dict[str, Any] = field(default_factory=dict)
    surface: Dict[str, Any] = field(default_factory=dict)
    darkweb: Dict[str, Any] = field(default_factory=dict)
    analysis: Dict[str, Any] = field(default_factory=dict)
    sharing: Dict[str, Any] = field(default_factory=dict)
    report_path: str = ""
    report_markdown: str = ""
    report_html: str = ""
    log: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id, "target": self.target,
            "status": self.status, "stage": self.stage,
            "progress": self.progress,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "collection": self.collection,
            "management": self.management,
            "matching": self.matching,
            "actors": self.actors,
            "surface": self.surface,
            "darkweb": self.darkweb,
            "analysis": self.analysis,
            "sharing": self.sharing,
            "report_path": self.report_path,
            "log": self.log[-100:],
        }


class ThreatIntelOrchestrator:
    """八阶段编排器。"""

    def __init__(self) -> None:
        self.collection = get_collection_phase()
        self.management = get_management_phase()
        self.matching = get_matching_phase()
        self.actors = get_actor_phase()
        self.surface = get_attack_surface_phase()
        self.darkweb = get_darkweb_phase()
        self.analysis = get_analysis_phase()
        self.sharing = get_sharing_phase()
        self.ai = get_ai_analyzer()
        self.reporter: ThreatIntelReportGenerator = get_report_generator()
        self._tasks: Dict[str, IntelTask] = {}

    # ------------------------------------------------------------------ #
    def create_task(self, target: str) -> IntelTask:
        tid = uuid.uuid4().hex[:16]
        t = IntelTask(
            task_id=tid, target=target,
            created_at=time.strftime("%Y-%m-%d %H:%M:%S"))
        self._tasks[tid] = t
        return t

    def get_task(self, task_id: str) -> Optional[IntelTask]:
        return self._tasks.get(task_id)

    def list_tasks(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in sorted(
            self._tasks.values(), key=lambda x: x.created_at,
            reverse=True)]

    # ------------------------------------------------------------------ #
    def _set_stage(self, t: IntelTask, key: str, label: str) -> None:
        for k, name, prog in STAGES:
            if k == key:
                t.stage = key
                t.progress = prog
                t.log.append(f"[*] 进入阶段: {label}")
                manager.push_threadsafe(f"intel:{t.task_id}",
                                        "stage", {"stage": key,
                                                  "label": label,
                                                  "progress": prog})
                return

    def _log(self, t: IntelTask, msg: str, level: str = "INFO") -> None:
        t.log.append(msg)
        manager.push_threadsafe(f"intel:{t.task_id}", "log",
                                {"msg": msg, "level": level})

    # ------------------------------------------------------------------ #
    def run_full(self, target: str,
                 task_id: Optional[str] = None) -> IntelTask:
        t = self._tasks.get(task_id) if task_id else None
        if t is None:
            t = self.create_task(target)
        t.status = "running"
        try:
            # 阶段1 收集
            self._set_stage(t, "collection", "IOC 收集")
            t.collection = self.collection.collect_all()
            self._log(t, f"[+] 收集完成: {t.collection.get('total_collected',0)} IOC, "
                         f"兜底={t.collection.get('builtin_fallback_used')}")

            # 阶段2 入库管理
            self._set_stage(t, "management", "IOC 管理")
            raw_items = [i.to_dict() for i in
                         self.collection._iocs.values()]  # noqa: SLF001
            ingest = self.management.ingest(raw_items)
            t.management = self.management.stats()
            t.management["ingest"] = ingest
            self._log(t, f"[+] 入库: +{ingest.get('added')}, 去重 {ingest.get('dedup')}, "
                         f"总 {t.management.get('total',0)}")

            # 阶段3 匹配（用内置样例日志/流量做演示匹配）
            self._set_stage(t, "matching", "IOC 匹配")
            demo_logs = [
                "Sep 20 10:00 sshd[123]: Failed password for root from "
                + (self.management.all_values_by_type("ip")[0]
                   if self.management.all_values_by_type("ip")
                   else "1.2.3.4"),
                "Sep 20 10:01 httpd: GET /login from "
                + (self.management.all_values_by_type("ip")[0]
                   if self.management.all_values_by_type("ip")
                   else "1.2.3.4"),
            ]
            mm = self.matching.match_logs(demo_logs, "demo-syslog")
            demo_flows = []
            for ip in self.management.all_values_by_type("ip")[:5]:
                demo_flows.append({"id": "f1", "src_ip": ip,
                                   "dst_ip": "10.0.0.1", "dst_port": 443})
            mt = self.matching.match_traffic(demo_flows)
            t.matching = {"log": mm, "traffic": mt,
                          "stats": self.matching.stats()}
            self._log(t, f"[+] 匹配命中: {t.matching['stats'].get('total_hits',0)}, "
                         f"告警 {t.matching['stats'].get('total_alerts',0)}")

            # 阶段4 Actor
            self._set_stage(t, "actors", "Actor 画像")
            t.actors = self.actors.stats()
            malware = [i.malware for i in
                       self.management._iocs.values() if i.malware]  # noqa: SLF001
            inferred = self.actors.infer_from_iocs(malware)
            t.actors["inferred"] = inferred
            self._log(t, f"[+] Actor 画像: {t.actors.get('total',0)}, "
                         f"推断 {len(inferred)}")

            # 阶段5 攻击面
            self._set_stage(t, "surface", "攻击面")
            if target and "." in target:
                try:
                    domain = target.replace("https://", "").replace(
                        "http://", "").split("/")[0]
                    t.surface = self.surface.map_domain(
                        domain, do_port_scan=False)
                except Exception as e:  # noqa: BLE001
                    t.surface = {"error": str(e)}
            else:
                t.surface = {"note": "未指定目标域名，跳过测绘",
                             "stats": self.surface.stats()}
            self._log(t, f"[+] 攻击面: {self.surface.stats().get('total_assets',0)} 资产")

            # 阶段6 暗网
            self._set_stage(t, "darkweb", "暗网监控")
            self.darkweb.configure(brands=[target] if target else [])
            t.darkweb = self.darkweb.scan(domain=target)
            self._log(t, f"[+] 暗网: {t.darkweb.get('hits',0)} 命中 "
                         f"(模拟)")

            # 阶段7 分析
            self._set_stage(t, "analysis", "情报分析")
            warns = self.analysis.generate_warnings(
                self.management.stats(),
                self.matching.stats(),
                self.darkweb.stats(),
                inferred)
            t.analysis = {
                "warnings": warns,
                "trend": self.analysis.predict_trends(),
                "industry": self.analysis.industry_distribution(
                    self.actors.stats()),
                "level": self.analysis.assess_level(
                    self.management.stats().get("total", 0),
                    self.management.stats().get(
                        "by_confidence", {}).get("critical", 0),
                    self.matching.stats().get("open_alerts", 0),
                    self.darkweb.stats().get("alerts", 0),
                    self.surface.stats().get("avg_score", 0)),
            }
            self._log(t, f"[+] 分析: {len(warns)} 预警, "
                         f"等级 {t.analysis['level']['level']}")

            # AI 综合分析
            iocs_dict = [i.to_dict() for i in
                         self.management._iocs.values()]  # noqa: SLF001
            ai_concl = self.ai.analyze_intel(
                iocs_dict,
                [h.to_dict() for h in self.matching._hits.values()],
                self.actors.list_actors()["items"],
                self.surface.stats())
            t.analysis["ai"] = ai_concl

            # 阶段8 共享
            self._set_stage(t, "sharing", "情报共享")
            bundle = self.sharing.export_bundle(iocs_dict[:50])
            t.sharing = {
                "stix_objects": bundle.get("object_count", 0),
                "taxii": self.sharing.taxii_discovery(),
                "groups": self.sharing.list_groups(),
            }
            self._log(t, f"[+] 共享: STIX 对象 {t.sharing['stix_objects']}")

            # 报告
            rd = ReportData(
                task_id=t.task_id, target=target,
                started_at=t.created_at,
                finished_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                ioc_stats=self.management.stats(),
                match_stats=self.matching.stats(),
                actor_stats=self.actors.stats(),
                surface=self.surface.stats(),
                darkweb=self.darkweb.stats(),
                warnings=warns,
                trend=t.analysis["trend"],
                ai_conclusion=ai_concl,
                iocs=iocs_dict[:30])
            os.makedirs(REPORTS_DIR, exist_ok=True)
            t.report_path = self.reporter.save(rd, "html")
            t.report_markdown = self.reporter.generate_markdown(rd)
            t.report_html = self.reporter.generate_html(rd)
            self._log(t, f"[+] 报告: {t.report_path}")

            t.status = "done"
            t.stage = "done"
            t.progress = 100
            t.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
            manager.push_threadsafe(f"intel:{t.task_id}",
                                    "done", {"task_id": t.task_id})
        except Exception as e:  # noqa: BLE001
            t.status = "error"
            t.error = f"{type(e).__name__}: {e}"
            self._log(t, f"[!] 失败: {t.error}", "ERROR")
            t.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return t


_default: Optional[ThreatIntelOrchestrator] = None


def get_orchestrator() -> ThreatIntelOrchestrator:
    global _default
    if _default is None:
        _default = ThreatIntelOrchestrator()
    return _default
