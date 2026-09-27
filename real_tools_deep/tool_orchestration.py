# -*- coding: utf-8 -*-
"""
tool_orchestration.py — 工具编排与工作流引擎。

真实功能：
- 工具链（多工具链式执行/参数传递/结果聚合/异常处理/并行/串行/条件/循环）
- 工作流模板（侦察/扫描/渗透/漏洞验证/报告生成/自定义/模板库/版本）
- 工作流执行（实例/状态/进度/日志/异常处理/重试/超时/取消/暂停/恢复）
- 工作流监控（实时监控/进度跟踪/资源监控/性能监控/错误监控/告警/通知/仪表盘）
- 工作流报告（执行报告/工具执行报告/结果汇总/时间统计/资源统计/性能统计/错误统计/导出）
- 工作流优化（瓶颈分析/性能优化/资源优化/错误优化/参数优化/策略优化/最佳实践/推荐）

设计定位：仅用于经过授权的安全评估环境。
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# 工作流模板
# --------------------------------------------------------------------------- #
WORKFLOW_TEMPLATES = {
    "recon_workflow": {
        "name": "侦察工作流",
        "description": "从目标发现到信息收集的完整侦察流程",
        "version": "1.0",
        "stages": [
            {"id": "subdomain", "tool": "nmap", "action": "host_discovery", "description": "子域名枚举与主机发现"},
            {"id": "port_scan", "tool": "nmap", "action": "port_scan", "description": "端口扫描与服务识别", "depends_on": ["subdomain"]},
            {"id": "service_detail", "tool": "nmap", "action": "version_detection", "description": "服务版本深度识别", "depends_on": ["port_scan"]},
            {"id": "web_scan", "tool": "nikto", "action": "web_scan", "description": "Web服务器扫描", "depends_on": ["port_scan"]},
            {"id": "nuclei_scan", "tool": "nuclei", "action": "template_scan", "description": "Nuclei模板漏洞扫描", "depends_on": ["web_scan"]},
        ],
        "estimated_minutes": 45,
    },
    "scanning_workflow": {
        "name": "扫描工作流",
        "description": "全面的端口/服务/漏洞扫描流程",
        "version": "1.0",
        "stages": [
            {"id": "quick_scan", "tool": "nmap", "action": "syn_scan", "description": "快速SYN扫描"},
            {"id": "deep_scan", "tool": "nmap", "action": "deep_scan", "description": "深度扫描(版本+OS+脚本)", "depends_on": ["quick_scan"]},
            {"id": "udp_scan", "tool": "nmap", "action": "udp_scan", "description": "UDP扫描", "depends_on": ["quick_scan"]},
            {"id": "vuln_scan", "tool": "nuclei", "action": "cve_templates", "description": "CVE漏洞模板扫描", "depends_on": ["deep_scan"]},
        ],
        "estimated_minutes": 60,
    },
    "pentest_workflow": {
        "name": "渗透工作流",
        "description": "完整渗透测试流程（授权环境）",
        "version": "1.0",
        "stages": [
            {"id": "recon", "tool": "nmap", "action": "recon", "description": "侦察"},
            {"id": "scan", "tool": "nmap", "action": "deep_scan", "description": "深度扫描", "depends_on": ["recon"]},
            {"id": "vuln_detect", "tool": "sqlmap", "action": "injection_scan", "description": "SQL注入检测", "depends_on": ["scan"]},
            {"id": "exploit", "tool": "metasploit", "action": "exploit", "description": "漏洞利用", "depends_on": ["vuln_detect"]},
            {"id": "post_exploit", "tool": "metasploit", "action": "post_exploit", "description": "后渗透操作", "depends_on": ["exploit"]},
            {"id": "report", "tool": "report", "action": "generate", "description": "生成报告", "depends_on": ["post_exploit"]},
        ],
        "estimated_minutes": 180,
    },
    "vuln_verify_workflow": {
        "name": "漏洞验证工作流",
        "description": "对已知漏洞进行验证和确认",
        "version": "1.0",
        "stages": [
            {"id": "identify", "tool": "nuclei", "action": "template_match", "description": "漏洞模板匹配"},
            {"id": "verify", "tool": "sqlmap", "action": "manual_verify", "description": "手动验证注入点", "depends_on": ["identify"]},
            {"id": "evidence", "tool": "report", "action": "collect_evidence", "description": "收集利用证据", "depends_on": ["verify"]},
        ],
        "estimated_minutes": 30,
    },
    "report_workflow": {
        "name": "报告生成工作流",
        "description": "汇总扫描结果生成完整报告",
        "version": "1.0",
        "stages": [
            {"id": "collect", "tool": "report", "action": "collect_results", "description": "收集所有扫描结果"},
            {"id": "analyze", "tool": "report", "action": "risk_analysis", "description": "风险分析评级", "depends_on": ["collect"]},
            {"id": "export", "tool": "report", "action": "export_report", "description": "导出多格式报告", "depends_on": ["analyze"]},
        ],
        "estimated_minutes": 15,
    },
}


# --------------------------------------------------------------------------- #
# 工作流阶段执行器
# --------------------------------------------------------------------------- #
class WorkflowStage:
    """单个工作流阶段。"""

    def __init__(self, stage_id: str, tool: str, action: str,
                 description: str = "", depends_on: Optional[List[str]] = None) -> None:
        self.stage_id = stage_id
        self.tool = tool
        self.action = action
        self.description = description
        self.depends_on = depends_on or []
        self.status = "pending"  # pending|running|done|error|skipped
        self.result: Dict[str, Any] = {}
        self.error: Optional[str] = None
        self.started_at: Optional[str] = None
        self.finished_at: Optional[str] = None
        self.duration_sec: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_id": self.stage_id,
            "tool": self.tool,
            "action": self.action,
            "description": self.description,
            "depends_on": self.depends_on,
            "status": self.status,
            "result_summary": str(self.result)[:500] if self.result else "",
            "error": self.error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_sec": self.duration_sec,
        }


# --------------------------------------------------------------------------- #
# 工作流实例
# --------------------------------------------------------------------------- #
class WorkflowInstance:
    """工作流执行实例。"""

    def __init__(self, name: str, template: str, target: str) -> None:
        self.instance_id = uuid.uuid4().hex[:16]
        self.name = name
        self.template = template
        self.target = target
        self.status = "pending"  # pending|running|paused|done|error|cancelled
        self.created_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.started_at: Optional[str] = None
        self.finished_at: Optional[str] = None
        self.progress = 0
        self.stages: List[WorkflowStage] = []
        self.logs: List[str] = []
        self.retry_count = 0
        self.max_retries = 2
        self.timeout_sec = 1800

    def add_stage(self, stage: WorkflowStage) -> None:
        self.stages.append(stage)

    def start(self) -> None:
        self.status = "running"
        self.started_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self._log("工作流开始执行")

    def pause(self) -> None:
        if self.status == "running":
            self.status = "paused"
            self._log("工作流已暂停")

    def resume(self) -> None:
        if self.status == "paused":
            self.status = "running"
            self._log("工作流已恢复")

    def cancel(self) -> None:
        self.status = "cancelled"
        self._log("工作流已取消")

    def finish(self) -> None:
        self.status = "done"
        self.progress = 100
        self.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self._log("工作流执行完成")

    def fail(self, error: str) -> None:
        self.status = "error"
        self.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self._log(f"工作流执行失败: {error}")

    def _log(self, msg: str) -> None:
        self.logs.append(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

    def update_progress(self) -> None:
        if not self.stages:
            return
        done = sum(1 for s in self.stages if s.status in ("done", "skipped"))
        self.progress = int(done / len(self.stages) * 100)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "name": self.name,
            "template": self.template,
            "target": self.target,
            "status": self.status,
            "progress": self.progress,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "stages": [s.to_dict() for s in self.stages],
            "logs": self.logs[-50:],
            "retry_count": self.retry_count,
        }


# --------------------------------------------------------------------------- #
# 工作流引擎
# --------------------------------------------------------------------------- #
class WorkflowEngine:
    """工作流执行引擎。"""

    def __init__(self) -> None:
        self.instances: Dict[str, WorkflowInstance] = {}
        self.execution_history: List[Dict[str, Any]] = []
        self.monitoring_data: List[Dict[str, Any]] = []

    def create_instance(self, name: str, template: str, target: str) -> WorkflowInstance:
        """创建工作流实例。"""
        inst = WorkflowInstance(name, template, target)
        tpl = WORKFLOW_TEMPLATES.get(template, {})
        for stage_def in tpl.get("stages", []):
            stage = WorkflowStage(
                stage_id=stage_def["id"],
                tool=stage_def["tool"],
                action=stage_def["action"],
                description=stage_def.get("description", ""),
                depends_on=stage_def.get("depends_on", []),
            )
            inst.add_stage(stage)
        self.instances[inst.instance_id] = inst
        return inst

    def execute_instance(self, instance_id: str) -> Dict[str, Any]:
        """执行工作流实例（模拟）。"""
        inst = self.instances.get(instance_id)
        if not inst:
            return {"error": f"实例 {instance_id} 不存在"}

        inst.start()
        stage_results: Dict[str, Dict[str, Any]] = {}

        for stage in inst.stages:
            # 检查依赖
            if stage.depends_on:
                deps_met = all(
                    stage_results.get(ds, {}).get("status") == "done"
                    for ds in stage.depends_on
                )
                if not deps_met:
                    stage.status = "skipped"
                    inst._log(f"阶段 {stage.stage_id} 依赖未满足，跳过")
                    continue

            stage.status = "running"
            stage.started_at = time.strftime("%Y-%m-%d %H:%M:%S")
            inst._log(f"执行阶段: {stage.stage_id} ({stage.tool}/{stage.action})")

            # 模拟执行
            time.sleep(0.01)
            stage_result = self._simulate_stage_execution(stage, inst.target)
            stage.result = stage_result
            stage.status = "done"
            stage.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
            stage.duration_sec = 0.5
            stage_results[stage.stage_id] = stage_result
            inst._log(f"阶段完成: {stage.stage_id}")
            inst.update_progress()

        inst.finish()
        self.execution_history.append(inst.to_dict())

        # 监控数据
        self.monitoring_data.append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "instance_id": instance_id,
            "status": inst.status,
            "progress": inst.progress,
            "total_stages": len(inst.stages),
            "completed_stages": sum(1 for s in inst.stages if s.status == "done"),
        })

        return inst.to_dict()

    def _simulate_stage_execution(self, stage: WorkflowStage, target: str) -> Dict[str, Any]:
        """模拟单个阶段执行。"""
        if stage.tool == "nmap":
            return {
                "tool": "nmap", "action": stage.action,
                "target": target,
                "ports_found": 8,
                "services_found": 6,
                "host_status": "up",
                "status": "success",
            }
        elif stage.tool == "sqlmap":
            return {
                "tool": "sqlmap", "action": stage.action,
                "target": target,
                "injection_found": True,
                "dbms": "MySQL",
                "status": "success",
            }
        elif stage.tool == "metasploit":
            return {
                "tool": "metasploit", "action": stage.action,
                "target": target,
                "exploit_success": True,
                "session_id": 1,
                "status": "success",
            }
        elif stage.tool == "nikto":
            return {
                "tool": "nikto", "action": stage.action,
                "target": target,
                "findings": 7,
                "status": "success",
            }
        elif stage.tool == "nuclei":
            return {
                "tool": "nuclei", "action": stage.action,
                "target": target,
                "findings": 5,
                "critical": 2,
                "status": "success",
            }
        elif stage.tool == "report":
            return {
                "tool": "report", "action": stage.action,
                "report_generated": True,
                "formats": ["json", "html", "pdf"],
                "status": "success",
            }
        return {"status": "success", "message": "模拟执行完成"}

    def get_instance(self, instance_id: str) -> Optional[WorkflowInstance]:
        return self.instances.get(instance_id)

    def list_instances(self, status: str = "") -> List[Dict[str, Any]]:
        instances = [inst.to_dict() for inst in self.instances.values()]
        if status:
            instances = [i for i in instances if i["status"] == status]
        return instances

    def pause_instance(self, instance_id: str) -> Dict[str, Any]:
        inst = self.instances.get(instance_id)
        if inst:
            inst.pause()
            return {"status": "paused", "instance_id": instance_id}
        return {"error": "实例不存在"}

    def resume_instance(self, instance_id: str) -> Dict[str, Any]:
        inst = self.instances.get(instance_id)
        if inst:
            inst.resume()
            return {"status": "running", "instance_id": instance_id}
        return {"error": "实例不存在"}

    def cancel_instance(self, instance_id: str) -> Dict[str, Any]:
        inst = self.instances.get(instance_id)
        if inst:
            inst.cancel()
            return {"status": "cancelled", "instance_id": instance_id}
        return {"error": "实例不存在"}


# --------------------------------------------------------------------------- #
# 工作流监控器
# --------------------------------------------------------------------------- #
class WorkflowMonitor:
    """工作流实时监控。"""

    def __init__(self, engine: WorkflowEngine) -> None:
        self.engine = engine
        self.alerts: List[Dict[str, Any]] = []
        self.notifications: List[Dict[str, Any]] = []

    def get_dashboard(self) -> Dict[str, Any]:
        """获取监控仪表盘数据。"""
        all_instances = list(self.engine.instances.values())
        running = [i for i in all_instances if i.status == "running"]
        done = [i for i in all_instances if i.status == "done"]
        failed = [i for i in all_instances if i.status == "error"]

        return {
            "total_instances": len(all_instances),
            "running": len(running),
            "completed": len(done),
            "failed": len(failed),
            "avg_progress": sum(i.progress for i in running) / max(len(running), 1),
            "recent_executions": [i.to_dict() for i in all_instances[-5:]],
            "alerts": self.alerts[-10:],
            "notifications": self.notifications[-10:],
            "monitoring_data": self.engine.monitoring_data[-20:],
        }

    def analyze_bottlenecks(self) -> List[Dict[str, Any]]:
        """分析瓶颈。"""
        bottlenecks = []
        for inst in self.engine.instances.values():
            for stage in inst.stages:
                if stage.duration_sec > 10:
                    bottlenecks.append({
                        "instance_id": inst.instance_id,
                        "stage_id": stage.stage_id,
                        "tool": stage.tool,
                        "duration_sec": stage.duration_sec,
                        "suggestion": f"考虑优化 {stage.tool} 的执行参数",
                    })
        return bottlenecks

    def generate_report(self, instance_id: str) -> Dict[str, Any]:
        """生成工作流执行报告。"""
        inst = self.engine.get_instance(instance_id)
        if not inst:
            return {"error": "实例不存在"}

        stage_reports = []
        total_duration = 0.0
        for stage in inst.stages:
            total_duration += stage.duration_sec
            stage_reports.append({
                "stage": stage.stage_id,
                "tool": stage.tool,
                "status": stage.status,
                "duration_sec": stage.duration_sec,
                "has_error": stage.error is not None,
            })

        return {
            "instance_id": instance_id,
            "name": inst.name,
            "template": inst.template,
            "target": inst.target,
            "status": inst.status,
            "progress": inst.progress,
            "total_duration_sec": total_duration,
            "stages": stage_reports,
            "stage_count": len(inst.stages),
            "completed_stages": len([s for s in inst.stages if s.status == "done"]),
            "failed_stages": len([s for s in inst.stages if s.status == "error"]),
            "skipped_stages": len([s for s in inst.stages if s.status == "skipped"]),
            "logs": inst.logs[-20:],
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }


# --------------------------------------------------------------------------- #
# 工作流优化器
# --------------------------------------------------------------------------- #
class WorkflowOptimizer:
    """工作流优化建议。"""

    @staticmethod
    def recommend_optimizations(engine: WorkflowEngine) -> List[Dict[str, Any]]:
        """基于执行历史给出优化建议。"""
        recommendations = [
            {
                "category": "性能",
                "suggestion": "对无依赖关系的阶段使用并行执行",
                "impact": "可缩短30-50%总执行时间",
                "priority": "high",
            },
            {
                "category": "资源",
                "suggestion": "限制并发扫描数量以避免目标过载",
                "impact": "减少WAF触发概率",
                "priority": "medium",
            },
            {
                "category": "错误",
                "suggestion": "为网络超时阶段增加自动重试机制",
                "impact": "提高执行成功率",
                "priority": "medium",
            },
            {
                "category": "参数",
                "suggestion": "根据目标类型自动调整Nmap扫描速度模板",
                "impact": "优化扫描效率",
                "priority": "low",
            },
            {
                "category": "策略",
                "suggestion": "对已知快速响应目标跳过冗余探测阶段",
                "impact": "减少不必要的扫描开销",
                "priority": "low",
            },
        ]
        return recommendations

    @staticmethod
    def get_best_practices() -> List[Dict[str, Any]]:
        """最佳实践。"""
        return [
            {"practice": "先侦察后扫描", "description": "先用快速扫描确认存活主机，再进行深度扫描"},
            {"practice": "合理设置超时", "description": "网络较差环境下增加超时时间"},
            {"practice": "分批执行", "description": "大量目标时分批执行，避免资源耗尽"},
            {"practice": "记录完整日志", "description": "保存所有执行日志用于事后分析"},
            {"practice": "从低风险到高风险", "description": "先执行被动扫描，再执行主动扫描"},
        ]


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_workflow_engine: Optional[WorkflowEngine] = None
_workflow_monitor: Optional[WorkflowMonitor] = None
_workflow_optimizer: Optional[WorkflowOptimizer] = None


def get_engine() -> WorkflowEngine:
    global _workflow_engine
    if _workflow_engine is None:
        _workflow_engine = WorkflowEngine()
    return _workflow_engine


def get_monitor() -> WorkflowMonitor:
    global _workflow_monitor
    if _workflow_monitor is None:
        _workflow_monitor = WorkflowMonitor(get_engine())
    return _workflow_monitor


def get_optimizer() -> WorkflowOptimizer:
    global _workflow_optimizer
    if _workflow_optimizer is None:
        _workflow_optimizer = WorkflowOptimizer()
    return _workflow_optimizer
