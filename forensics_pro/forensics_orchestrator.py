# -*- coding: utf-8 -*-
"""
forensics_orchestrator.py — 取证 Pro 八阶段编排器。

阶段:
    1. evidence_acquisition    证据获取
    2. evidence_preservation    证据保全
    3. disk_forensics           磁盘取证
    4. memory_forensics         内存取证（Volatility3）
    5. network_forensics        网络取证（Wireshark/tshark）
    6. log_forensics            日志取证
    7. malware_analysis         恶意软件分析（静态+动态）
    8. forensics_report         取证报告
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .evidence_acquisition_phase import get_evidence_acquisition_phase
from .evidence_preservation_phase import get_evidence_preservation_phase
from .disk_forensics_phase import get_disk_forensics_phase
from .memory_forensics_phase import get_memory_forensics_phase
from .network_forensics_phase import get_network_forensics_phase
from .log_forensics_phase import get_log_forensics_phase
from .malware_analysis_phase import get_malware_analysis_phase
from .forensics_report_phase import get_forensics_report_phase
from .ai_analysis import get_ai_analysis
from .realtime_push import get_realtime_push
from .report_generator import get_report_generator, REPORTS_DIR


STAGES = [
    ("evidence_acquisition",  "1.证据获取", 10),
    ("evidence_preservation", "2.证据保全", 22),
    ("disk_forensics",       "3.磁盘取证", 40),
    ("memory_forensics",     "4.内存取证", 58),
    ("network_forensics",    "5.网络取证", 72),
    ("log_forensics",        "6.日志取证", 82),
    ("malware_analysis",     "7.恶意软件分析", 92),
    ("forensics_report",     "8.取证报告", 100),
]


@dataclass
class ForensicsTask:
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


class ForensicsOrchestrator:
    """八阶段编排器。"""

    def __init__(self) -> None:
        self.acq = get_evidence_acquisition_phase()
        self.pres = get_evidence_preservation_phase()
        self.disk = get_disk_forensics_phase()
        self.mem = get_memory_forensics_phase()
        self.net = get_network_forensics_phase()
        self.log_p = get_log_forensics_phase()
        self.mw = get_malware_analysis_phase()
        self.rpt = get_forensics_report_phase()
        self.ai = get_ai_analysis()
        self.rt = get_realtime_push()
        self.report = get_report_generator()
        self._tasks: Dict[str, ForensicsTask] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def create_task(self, name: str = "数字取证全流程") -> ForensicsTask:
        t = ForensicsTask(
            task_id="for_" + uuid.uuid4().hex[:10],
            name=name,
            created_at=datetime.now().isoformat(timespec="seconds"),
        )
        with self._lock:
            self._tasks[t.task_id] = t
        return t

    def list_tasks(self) -> list:
        with self._lock:
            return [t.to_dict() for t in self._tasks.values()][::-1]

    def get_task(self, task_id: str) -> Optional[ForensicsTask]:
        with self._lock:
            return self._tasks.get(task_id)

    # ------------------------------------------------------------------ #
    def _log(self, t: ForensicsTask, level: str, msg: str) -> None:
        t.log.append(f"[{datetime.now().strftime('%H:%M:%S')}] "
                     f"{level} {msg}")
        self.rt.emit_log(t.task_id, level, msg)

    def _think(self, t: ForensicsTask, thought: str) -> None:
        self.rt.emit_thought(t.task_id, thought)

    def _stage(self, t: ForensicsTask, key: str, label: str,
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
            # 阶段1 证据获取
            self._stage(t, "evidence_acquisition", STAGES[0][1], 8)
            self._log(t, "INFO", "启动证据获取（磁盘/内存/网络/系统/日志）")
            self._think(t, "优先调用真实取证工具；未安装则内置模拟框架兜底")
            for et in ["disk", "memory", "network", "sysstate", "log"]:
                tk = self.acq.create_task(evidence_type=et)
                self.acq.run_acquisition(tk["task_id"])
            t.results["evidence_acquisition"] = self.acq.stats()
            self._log(t, "OK", f"采集 {t.results['evidence_acquisition']['evidence_total']} 份证据")

            # 阶段2 证据保全
            self._stage(t, "evidence_preservation", STAGES[1][1], 20)
            self._log(t, "INFO", "哈希校验 / 证据链 / 写保护 / NTP")
            self._think(t, "为每份证据建立保管链，计算 MD5/SHA256")
            for ev in self.acq.list_evidence()[:5]:
                ch = self.pres.create_chain(ev["evidence_id"])
                self.pres.verify_integrity(ch["chain_id"])
                self.pres.set_write_protect(ch["chain_id"], True)
            t.results["evidence_preservation"] = self.pres.stats()
            self._log(t, "OK", "证据链建立完成，写保护已启用")

            # 阶段3 磁盘取证
            self._stage(t, "disk_forensics", STAGES[2][1], 38)
            self._log(t, "INFO", "文件系统分析 / MFT / 注册表 / 浏览器")
            self._think(t, "扫描 $MFT 恢复删除文件，分析注册表和浏览器历史")
            t.results["disk_forensics"] = {
                "fs": self.disk.analyze_filesystem(),
                "recovered": self.disk.recover_deleted(),
                "registry": self.disk.registry_analysis(),
                "timeline": self.disk.build_timeline(),
            }
            self._log(t, "OK", "磁盘取证完成")

            # 阶段4 内存取证
            self._stage(t, "memory_forensics", STAGES[3][1], 56)
            self._log(t, "INFO", "Volatility3 插件分析")
            self._think(t, "跑 pslist/malfind/hashdump/mimikatz 等插件")
            t.results["memory_forensics"] = self.mem.run_all()
            self._log(t, "OK", "内存取证完成")

            # 阶段5 网络取证
            self._stage(t, "network_forensics", STAGES[4][1], 70)
            self._log(t, "INFO", "tshark 流量分析 / 异常检测 / IOC")
            self._think(t, "分析 pcap，检测端口扫描/C2/外泄")
            t.results["network_forensics"] = {
                "anomaly": self.net.anomaly_detect(),
                "intrusion": self.net.intrusion_detect(),
                "exfil": self.net.exfiltration_analysis(),
                "ioc": self.net.ioc_library(),
            }
            for a in self.net.list_alerts()[:3]:
                self.rt.emit_alert(task_id, a)
            self._log(t, "OK", f"发现 {len(self.net.list_alerts())} 条网络告警")

            # 阶段6 日志取证
            self._stage(t, "log_forensics", STAGES[5][1], 80)
            self._log(t, "INFO", "多源日志关联 / 攻击路径重建")
            self._think(t, "关联 SSH爆破+登录成功+powershell+mimikatz")
            t.results["log_forensics"] = {
                "attack_path": self.log_p.attack_path_reconstruct(),
                "behavior": self.log_p.user_behavior_analysis(),
                "correlation": self.log_p.correlation(),
            }
            self._log(t, "OK", "日志取证完成")

            # 阶段7 恶意软件分析
            self._stage(t, "malware_analysis", STAGES[6][1], 90)
            self._log(t, "INFO", "静态分析 + 动态行为")
            self._think(t, "哈希/字符串/导入表/YARA + 沙箱行为监控")
            sa = self.mw.static_analysis("suspicious.exe")
            t.results["malware_analysis"] = {
                "static": sa,
                "dynamic": self.mw.dynamic_analysis(sa["sample_id"]),
                "classify": self.mw.classify(sa["sample_id"]),
                "ioc": self.mw.extract_ioc(sa["sample_id"]),
            }
            self._log(t, "OK", "恶意软件分析完成")

            # 阶段8 取证报告
            self._stage(t, "forensics_report", STAGES[7][1], 98)
            self._log(t, "INFO", "生成取证分析报告")
            rpt = self.rpt.generate(case_name=t.name)
            t.results["forensics_report"] = {"report_id": rpt["report_id"]}
            t.results["report"] = self.report.generate("both")
            self._log(t, "OK", "取证报告已生成")

            # AI 分析
            self._think(t, "AI 关联证据，推断攻击路径与嫌疑人画像")
            ai = self.ai.batch_analyze(self.acq.list_evidence())
            t.results["ai_analysis"] = {
                "high_risk": ai["high_risk"],
                "suspect": self.ai.suspect_profile(),
                "correlation": self.ai.correlate_evidence(
                    self.acq.list_evidence()),
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


_default: Optional[ForensicsOrchestrator] = None


def get_orchestrator() -> ForensicsOrchestrator:
    global _default
    if _default is None:
        _default = ForensicsOrchestrator()
    return _default
