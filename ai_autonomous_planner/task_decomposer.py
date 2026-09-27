# -*- coding: utf-8 -*-
"""
task_decomposer.py — 任务拆解器。

把用户的自然语言目标（例如“帮我渗透这个网站”）自动拆解成一组带依赖关系的
子任务，并给出每个子任务的目标、前置依赖、预期产出与优先级。

设计要点：
    - 纯内存字典存储，不依赖外部服务；
    - 提供“Web 渗透”“主机渗透”“API 安全测试”等模板化拆解方案，
      同时支持从目标文本中做轻量意图识别，选择最合适的拆解模板；
    - 子任务之间以 DAG（有向无环图）表达依赖，供 planner_engine 调度。
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 数据模型
# --------------------------------------------------------------------------- #
@dataclass
class SubTask:
    """单个子任务。"""

    task_id: str
    parent_goal_id: str
    name: str
    description: str
    category: str            # recon / enum / vuln / analysis / report
    depends_on: List[str] = field(default_factory=list)
    priority: int = 3         # 1 最高
    status: str = "pending"  # pending / running / done / failed / skipped
    expected_output: str = ""
    created_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    result_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DecomposedGoal:
    """一次完整的任务拆解结果。"""

    goal_id: str
    raw_goal: str
    target: str
    template: str
    subtasks: List[SubTask] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "goal_id": self.goal_id,
            "raw_goal": self.raw_goal,
            "target": self.target,
            "template": self.template,
            "created_at": self.created_at,
            "subtasks": [s.to_dict() for s in self.subtasks],
            "stats": {
                "total": len(self.subtasks),
                "done": sum(1 for s in self.subtasks if s.status == "done"),
                "failed": sum(1 for s in self.subtasks if s.status == "failed"),
                "pending": sum(1 for s in self.subtasks if s.status == "pending"),
                "running": sum(1 for s in self.subtasks if s.status == "running"),
            },
        }


# --------------------------------------------------------------------------- #
# 拆解模板
# --------------------------------------------------------------------------- #
# 每个模板返回一个 (name, description, category, depends_on, priority, expected_output) 元组列表
_TEMPLATE_WEB = [
    ("端口与服务探测", "对目标进行端口扫描与服务指纹识别，开放面测绘", "recon", [], 1,
     "开放端口清单 + 服务指纹"),
    ("目录与资产枚举", "枚举 Web 目录、虚拟主机、备份文件与敏感路径", "enum", ["端口与服务探测"], 2,
     "目录树 + 敏感文件清单"),
    ("技术栈指纹识别", "识别中间件、框架、CMS 与前端技术栈版本", "recon", ["端口与服务探测"], 2,
     "技术栈指纹报告"),
    ("认证与会话分析", "分析登录/注册/会话机制，识别弱认证点", "enum", ["技术栈指纹识别"], 3,
     "认证面清单"),
    ("注入类漏洞检测", "检测 SQL 注入、命令注入、ORM 注入等", "vuln", ["目录与资产枚举"], 3,
     "注入点列表"),
    ("XSS 漏洞检测", "检测反射型/存储型/DOM 型 XSS", "vuln", ["目录与资产枚举"], 3,
     "XSS 点列表"),
    ("目录遍历/文件包含", "检测路径穿越与本地/远程文件包含", "vuln", ["目录与资产枚举"], 3,
     "遍历/LFI/RFI 点"),
    ("访问控制与越权", "检测水平/垂直越权、未授权访问", "vuln", ["认证与会话分析"], 3,
     "越权测试结果"),
    ("AI 风险分析", "AI 对所有发现做关联分析、误报过滤与优先级排序", "analysis",
     ["注入类漏洞检测", "XSS 漏洞检测", "目录遍历/文件包含", "访问控制与越权"], 2,
     "AI 分析结论"),
    ("渗透报告生成", "汇总资产、漏洞、验证结果与修复建议", "report", ["AI 风险分析"], 1,
     "完整渗透报告"),
]

_TEMPLATE_HOST = [
    ("存活主机探测", "ICMP/TCP 存活探测，确定在线主机范围", "recon", [], 1,
     "存活主机清单"),
    ("端口与服务枚举", "全端口扫描 + 服务版本探测", "enum", ["存活主机探测"], 1,
     "端口/服务矩阵"),
    ("系统与服务指纹", "操作系统识别与服务版本指纹", "enum", ["端口与服务枚举"], 2,
     "OS/服务指纹"),
    ("弱口令与默认凭据", "对常见服务做凭据爆破（授权范围内）", "vuln", ["端口与服务枚举"], 3,
     "弱口令命中记录"),
    ("已知漏洞匹配", "按服务版本匹配 CVE / EXP 库", "vuln", ["系统与服务指纹"], 2,
     "候选 CVE 列表"),
    ("提权路径分析", "结合服务与系统信息分析潜在提权链", "analysis", ["已知漏洞匹配"], 2,
     "提权路径假设"),
    ("主机渗透报告", "汇总主机风险与验证证据", "report", ["提权路径分析"], 1,
     "主机侧报告"),
]

_TEMPLATE_API = [
    ("接口测绘", "从 OpenAPI/Swagger/流量中枚举全部接口", "recon", [], 1,
     "接口清单"),
    ("参数提取", "提取每个接口的入参、出参与鉴权方式", "enum", ["接口测绘"], 2,
     "参数模型"),
    ("鉴权绕过测试", "测试 Token 缺失/篡改/越权", "vuln", ["参数提取"], 2,
     "鉴权绕过结果"),
    ("注入与批量赋值", "测试 SQL 注入、NoSQL 注入、Mass Assignment", "vuln", ["参数提取"], 3,
     "注入点列表"),
    ("速率限制与业务逻辑", "测试限流绕过与业务逻辑缺陷", "vuln", ["鉴权绕过测试"], 3,
     "逻辑缺陷记录"),
    ("API 风险分析", "AI 对接口风险做聚合评级", "analysis",
     ["注入与批量赋值", "速率限制与业务逻辑"], 2,
     "API 风险结论"),
    ("API 测试报告", "输出 API 安全测试报告", "report", ["API 风险分析"], 1,
     "API 报告"),
]


_TEMPLATES: Dict[str, List[tuple]] = {
    "web": _TEMPLATE_WEB,
    "host": _TEMPLATE_HOST,
    "api": _TEMPLATE_API,
}


# --------------------------------------------------------------------------- #
# 拆解器
# --------------------------------------------------------------------------- #
class TaskDecomposer:
    """把自然语言目标拆解为带依赖的子任务 DAG。"""

    def __init__(self) -> None:
        self._goals: Dict[str, DecomposedGoal] = {}

    # ------------------------------------------------------------------ #
    # 意图识别
    # ------------------------------------------------------------------ #
    def detect_template(self, goal: str) -> str:
        """根据目标文本选择拆解模板。"""
        g = goal.lower()
        if any(k in g for k in ["api", "接口", "openapi", "swagger", "rest"]):
            return "api"
        if any(k in g for k in ["主机", "服务器", "内网", "主机渗透", "端口"]):
            return "host"
        # 默认走 Web 模板（最常见）
        return "web"

    @staticmethod
    def extract_target(goal: str) -> str:
        """从目标文本中粗略提取目标 URL / 主机。"""
        m = re.search(r"https?://[^\s，。,]+", goal)
        if m:
            return m.group(0).rstrip("/")
        m = re.search(r"([a-zA-Z0-9\-_]+\.)+[a-zA-Z]{2,}(:\d+)?", goal)
        if m:
            return m.group(0)
        return ""

    # ------------------------------------------------------------------ #
    # 核心拆解
    # ------------------------------------------------------------------ #
    def decompose(self, goal: str, target: str = "",
                  template: str = "") -> DecomposedGoal:
        """拆解一个自然语言目标为子任务 DAG。"""
        goal_id = "goal_" + uuid.uuid4().hex[:10]
        if not target:
            target = self.extract_target(goal) or "https://target.example.com"
        if not template:
            template = self.detect_template(goal)
        rows = _TEMPLATES.get(template, _TEMPLATE_WEB)

        # 先创建子任务（按名称索引），再回填依赖
        created: Dict[str, SubTask] = {}
        subtasks: List[SubTask] = []
        for name, desc, category, deps, prio, expected in rows:
            st = SubTask(
                task_id=f"{goal_id}_{len(subtasks)+1:02d}",
                parent_goal_id=goal_id,
                name=name,
                description=desc,
                category=category,
                priority=prio,
                expected_output=expected,
            )
            created[name] = st
            subtasks.append(st)

        # 回填 depends_on（按子任务 id 引用）
        for name, _, _, deps, _, _ in rows:
            st = created[name]
            st.depends_on = [created[d].task_id for d in deps if d in created]

        dg = DecomposedGoal(
            goal_id=goal_id,
            raw_goal=goal,
            target=target,
            template=template,
            subtasks=subtasks,
        )
        self._goals[goal_id] = dg
        return dg

    # ------------------------------------------------------------------ #
    # 查询 / 状态更新
    # ------------------------------------------------------------------ #
    def get_goal(self, goal_id: str) -> Optional[DecomposedGoal]:
        return self._goals.get(goal_id)

    def list_goals(self) -> List[Dict[str, Any]]:
        return [g.to_dict() for g in self._goals.values()]

    def update_subtask(self, goal_id: str, subtask_id: str,
                       status: str = "", result_summary: str = "") -> bool:
        dg = self._goals.get(goal_id)
        if dg is None:
            return False
        for s in dg.subtasks:
            if s.task_id == subtask_id:
                if status:
                    s.status = status
                if result_summary:
                    s.result_summary = result_summary
                if status in ("done", "failed", "skipped"):
                    s.finished_at = time.time()
                return True
        return False

    def next_ready_subtask(self, goal_id: str) -> Optional[SubTask]:
        """返回下一个可执行的子任务（依赖全部已终态、且未开始）。

        依赖已“完成/失败/跳过”均视为可继续——上游失败不阻塞下游
        （分析/报告仍可基于已有数据产出）。
        """
        dg = self._goals.get(goal_id)
        if dg is None:
            return None
        # 依赖已到达终态（done/failed/skipped）即可执行
        terminal_ids = {s.task_id for s in dg.subtasks
                        if s.status in ("done", "failed", "skipped")}
        candidates = [
            s for s in dg.subtasks
            if s.status == "pending" and all(d in terminal_ids for d in s.depends_on)
        ]
        if not candidates:
            return None
        # 按优先级排序（数字小优先）
        candidates.sort(key=lambda s: (s.priority, s.created_at))
        return candidates[0]

    def is_complete(self, goal_id: str) -> bool:
        dg = self._goals.get(goal_id)
        if dg is None:
            return True
        return all(s.status in ("done", "failed", "skipped") for s in dg.subtasks)

    def stats(self) -> Dict[str, Any]:
        return {
            "goals_total": len(self._goals),
            "templates": list(_TEMPLATES.keys()),
        }


# 单例
decomposer = TaskDecomposer()
