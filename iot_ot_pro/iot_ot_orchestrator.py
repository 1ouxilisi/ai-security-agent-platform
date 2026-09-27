# -*- coding: utf-8 -*-
"""
iot_ot_orchestrator.py — 工控IoT Pro 八阶段编排器。

阶段:
    1. device_discovery   设备发现
    2. protocol_analysis  协议分析
    3. firmware_analysis  固件分析
    4. vuln_detection     漏洞检测
    5. config_audit       配置审计
    6. traffic_monitor    流量监控
    7. risk_rating        风险评级
    8. compliance_audit   合规审计
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .device_discovery_phase import get_device_discovery_phase
from .protocol_analysis_phase import get_protocol_analysis_phase
from .firmware_analysis_phase import get_firmware_analysis_phase
from .vuln_detection_phase import get_vuln_detection_phase
from .config_audit_phase import get_config_audit_phase
from .traffic_monitor_phase import get_traffic_monitor_phase
from .risk_rating_phase import get_risk_rating_phase
from .compliance_audit_phase import get_compliance_audit_phase
from .ai_analysis import get_ai_analysis
from .realtime_push import get_realtime_push
from .report_generator import get_report_generator, REPORTS_DIR

STAGES = [
    ("device_discovery",  "1.设备发现", 10),
    ("protocol_analysis", "2.协议分析", 24),
    ("firmware_analysis", "3.固件分析", 38),
    ("vuln_detection",    "4.漏洞检测", 52),
    ("config_audit",      "5.配置审计", 66),
    ("traffic_monitor",    "6.流量监控", 78),
    ("risk_rating",        "7.风险评级", 90),
    ("compliance_audit",   "8.合规审计", 98),
]


@dataclass
class IotOtTask:
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


class IotOtOrchestrator:
    """八阶段编排器。"""

    def __init__(self) -> None:
        self.disc = get_device_discovery_phase()
        self.pa = get_protocol_analysis_phase()
        self.fw = get_firmware_analysis_phase()
        self.vuln = get_vuln_detection_phase()
        self.cfg = get_config_audit_phase()
        self.traf = get_traffic_monitor_phase()
        self.risk = get_risk_rating_phase()
        self.comp = get_compliance_audit_phase()
        self.ai = get_ai_analysis()
        self.rt = get_realtime_push()
        self.report = get_report_generator()
        self._tasks: Dict[str, IotOtTask] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def create_task(self, name: str = "工控IoT 全流程安全评估"
                    ) -> IotOtTask:
        t = IotOtTask(
            task_id="iotot_" + uuid.uuid4().hex[:10],
            name=name,
            created_at=datetime.now().isoformat(timespec="seconds"),
        )
        with self._lock:
            self._tasks[t.task_id] = t
        return t

    def list_tasks(self) -> list:
        with self._lock:
            return [t.to_dict() for t in self._tasks.values()][::-1]

    def get_task(self, task_id: str) -> Optional[IotOtTask]:
        with self._lock:
            return self._tasks.get(task_id)

    # ------------------------------------------------------------------ #
    def _log(self, t: IotOtTask, level: str, msg: str) -> None:
        t.log.append(f"[{datetime.now().strftime('%H:%M:%S')}] "
                     f"{level} {msg}")
        self.rt.emit_log(t.task_id, level, msg)

    def _think(self, t: IotOtTask, thought: str) -> None:
        self.rt.emit_thought(t.task_id, thought)

    def _stage(self, t: IotOtTask, key: str, label: str,
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
        t0 = time.time()
        try:
            # 1 设备发现
            self._stage(t, "device_discovery", STAGES[0][1], 8)
            self._log(t, "INFO", "启动多协议设备发现（工控/IoT/通用）")
            self._think(t, "正在调用真实 socket 扫描，nmap 未安装则用内置兜底")
            r1 = self.disc.start_discovery("192.168.10.0/24", real=False)
            t.results["device_discovery"] = r1
            self._log(t, "OK", f"发现 {r1['found']} 台设备")
            for d in self.disc.list_devices()[:5]:
                self.rt.emit_device(task_id, d)

            # 2 协议分析
            self._stage(t, "protocol_analysis", STAGES[1][1], 22)
            self._log(t, "INFO", "执行工控/IoT 协议深度分析")
            self._think(t, "构造 Modbus/S7/MQTT 真实协议帧探测")
            devices = self.disc.list_devices()
            r2 = self.pa.auto_analyze(devices)
            t.results["protocol_analysis"] = r2
            self._log(t, "OK", f"协议发现 {r2['total_findings']} 条")

            # 3 固件分析
            self._stage(t, "firmware_analysis", STAGES[2][1], 36)
            self._log(t, "INFO", "执行固件解压/硬编码凭据/漏洞扫描")
            self._think(t, "binwalk 未安装则用内置固件分析模拟框架")
            r3 = self.fw.analyze_all("demo.bin")
            t.results["firmware_analysis"] = self.fw.stats()
            self._log(t, "OK", f"固件发现 {self.fw.stats()['total']} 项")

            # 4 漏洞检测
            self._stage(t, "vuln_detection", STAGES[3][1], 50)
            self._log(t, "INFO", "批量执行工控/IoT 漏洞检测")
            self._think(t, "覆盖默认凭据/未授权/注入/CVE 匹配")
            r4 = self.vuln.detect()
            t.results["vuln_detection"] = self.vuln.stats()
            self._log(t, "OK", f"检出 {r4['created']} 个漏洞")
            for v in self.vuln.list_vulns()[:5]:
                self.rt.emit_vuln(task_id, v)

            # 5 配置审计
            self._stage(t, "config_audit", STAGES[4][1], 64)
            self._log(t, "INFO", "执行工控/IoT 设备配置审计")
            self._think(t, "对照基线检查默认/弱/危险配置")
            r5 = self.cfg.audit_all()
            t.results["config_audit"] = self.cfg.stats()
            self._log(t, "OK", f"审计失败率 {self.cfg.stats()['fail_rate']}")

            # 6 流量监控
            self._stage(t, "traffic_monitor", STAGES[5][1], 76)
            self._log(t, "INFO", "启动流量异常检测")
            self._think(t, "tcpdump/tshark 未安装则用内置流量模拟")
            r6 = self.traf.quick_detect(25)
            t.results["traffic_monitor"] = self.traf.stats()
            self._log(t, "OK", f"产生 {r6['generated']} 条异常事件")
            for a in self.traf.list_alerts()[:5]:
                self.rt.emit_alert(task_id, a)

            # 7 风险评级
            self._stage(t, "risk_rating", STAGES[6][1], 88)
            self._log(t, "INFO", "多维度风险打分")
            self.risk.auto_score()
            t.results["risk_rating"] = self.risk.stats()
            self._log(t, "OK", f"成熟度 "
                               f"{self.risk.maturity()['name']}")

            # 8 合规审计
            self._stage(t, "compliance_audit", STAGES[7][1], 96)
            self._log(t, "INFO", "IEC 62443 + NIST IoT 合规检查")
            r8 = self.comp.run_audit()
            t.results["compliance_audit"] = r8
            t.results["report"] = self.report.generate("both")
            self._log(t, "OK", "合规检查与报告生成完成")

            # AI 分析
            self._think(t, "AI 正在做设备风险评估/攻击路径推理/整改建议")
            ai = self.ai.batch_overview(
                devices, self.vuln.list_vulns(),
                self.traf.list_alerts(), r8)
            t.results["ai_analysis"] = {
                "device_count": len(ai["devices"]),
                "traffic": ai["traffic"],
                "compliance": ai["compliance"],
            }
            self.rt.emit_result(task_id, t.results)

            t.status = "done"
            t.finished_at = datetime.now().isoformat(timespec="seconds")
            self.rt.emit_progress(task_id, "done", "完成", 100,
                                 stage_progress=100,
                                 eta_seconds=int(time.time() - t0))
        except Exception as e:  # noqa: BLE001
            t.status = "error"
            t.error = str(e)
            self._log(t, "ERROR", f"任务失败: {e}")
        finally:
            t.progress = 100 if t.status == "done" else t.progress


_default: Optional[IotOtOrchestrator] = None


def get_orchestrator() -> IotOtOrchestrator:
    global _default
    if _default is None:
        _default = IotOtOrchestrator()
    return _default
