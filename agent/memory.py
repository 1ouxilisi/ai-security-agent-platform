"""
memory智能体模块，提供相关AI驱动的安全分析和决策功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import json
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict
from utils.logger import log
from utils.helpers import generate_id


@dataclass
class TaskStep:
    """任务步骤"""
    step_id: str
    step_number: int
    description: str
    tool_name: Optional[str] = None
    tool_args: Optional[Dict] = None
    result: Optional[Any] = None
    status: str = "pending"  # pending / running / completed / failed / skipped
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    error: Optional[str] = None


@dataclass
class Finding:
    """安全发现/漏洞"""
    finding_id: str
    type: str  # vulnerability / info / warning
    severity: str  # critical / high / medium / low / info
    title: str
    description: str
    evidence: Optional[str] = None
    target: Optional[str] = None
    tool: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    recommendations: Optional[str] = None


@dataclass
class AgentMemory:
    """智能体记忆"""
    task_id: str
    task_description: str
    target: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    # 任务规划
    plan: List[TaskStep] = field(default_factory=list)
    current_step_index: int = 0

    # 执行历史
    history: List[Dict] = field(default_factory=list)

    # 安全发现
    findings: List[Finding] = field(default_factory=list)

    # 收集的信息
    collected_data: Dict[str, Any] = field(default_factory=dict)

    # 状态
    status: str = "initialized"  # initialized / planning / executing / reporting / completed / failed
    error: Optional[str] = None

    def add_step(self, description: str, tool_name: Optional[str] = None, tool_args: Optional[Dict] = None) -> TaskStep:
        """添加任务步骤"""
        step = TaskStep(
            step_id=generate_id("step"),
            step_number=len(self.plan) + 1,
            description=description,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        self.plan.append(step)
        self.updated_at = time.time()
        log.info(f"添加步骤 #{step.step_number}: {description}")
        return step

    def start_step(self, step_index: int) -> Optional[TaskStep]:
        """开始执行步骤"""
        if 0 <= step_index < len(self.plan):
            step = self.plan[step_index]
            step.status = "running"
            step.started_at = time.time()
            self.current_step_index = step_index
            self.updated_at = time.time()
            log.info(f"开始步骤 #{step.step_number}: {step.description}")
            return step
        return None

    def complete_step(self, step_index: int, result: Any = None) -> Optional[TaskStep]:
        """完成步骤"""
        if 0 <= step_index < len(self.plan):
            step = self.plan[step_index]
            step.status = "completed"
            step.result = result
            step.completed_at = time.time()
            self.updated_at = time.time()
            log.info(f"完成步骤 #{step.step_number}: {step.description}")
            return step
        return None

    def fail_step(self, step_index: int, error: str) -> Optional[TaskStep]:
        """步骤失败"""
        if 0 <= step_index < len(self.plan):
            step = self.plan[step_index]
            step.status = "failed"
            step.error = error
            step.completed_at = time.time()
            self.updated_at = time.time()
            log.error(f"步骤失败 #{step.step_number}: {step.description} - {error}")
            return step
        return None

    def add_finding(self, type: str, severity: str, title: str, description: str,
                     evidence: Optional[str] = None, target: Optional[str] = None,
                     tool: Optional[str] = None, recommendations: Optional[str] = None) -> Finding:
        """添加安全发现"""
        finding = Finding(
            finding_id=generate_id("finding"),
            type=type,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            target=target,
            tool=tool,
            recommendations=recommendations,
        )
        self.findings.append(finding)
        self.updated_at = time.time()
        log.warning(f"发现 [{severity.upper()}] {title}")
        return finding

    def add_history(self, role: str, content: str, metadata: Optional[Dict] = None):
        """添加对话历史"""
        entry = {
            "role": role,
            "content": content,
            "timestamp": time.time(),
            "metadata": metadata or {},
        }
        self.history.append(entry)
        self.updated_at = time.time()

    def set_collected_data(self, key: str, value: Any):
        """设置收集的数据"""
        self.collected_data[key] = value
        self.updated_at = time.time()

    def get_current_step(self) -> Optional[TaskStep]:
        """获取当前步骤"""
        if 0 <= self.current_step_index < len(self.plan):
            return self.plan[self.current_step_index]
        return None

    def get_next_pending_step(self) -> Optional[TaskStep]:
        """获取下一个待执行步骤"""
        for step in self.plan:
            if step.status == "pending":
                return step
        return None

    def get_statistics(self) -> Dict:
        """获取任务统计"""
        total = len(self.plan)
        completed = sum(1 for s in self.plan if s.status == "completed")
        failed = sum(1 for s in self.plan if s.status == "failed")
        pending = sum(1 for s in self.plan if s.status == "pending")
        running = sum(1 for s in self.plan if s.status == "running")

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            if f.severity in severity_counts:
                severity_counts[f.severity] += 1

        duration = time.time() - self.created_at

        return {
            "task_id": self.task_id,
            "status": self.status,
            "total_steps": total,
            "completed_steps": completed,
            "failed_steps": failed,
            "pending_steps": pending,
            "running_steps": running,
            "progress": f"{completed}/{total}" if total > 0 else "0/0",
            "findings_count": len(self.findings),
            "findings_by_severity": severity_counts,
            "duration_seconds": round(duration, 2),
            "target": self.target,
        }

    def to_dict(self) -> Dict:
        """序列化为字典"""
        return {
            "task_id": self.task_id,
            "task_description": self.task_description,
            "target": self.target,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status,
            "error": self.error,
            "plan": [asdict(s) for s in self.plan],
            "findings": [asdict(f) for f in self.findings],
            "collected_data": self.collected_data,
            "statistics": self.get_statistics(),
        }

    def save(self, filepath: str):
        """保存记忆到文件"""
        from utils.helpers import save_json
        save_json(self.to_dict(), filepath)
