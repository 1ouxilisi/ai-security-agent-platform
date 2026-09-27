# -*- coding: utf-8 -*-
"""
thinking_visualizer.py — AI 思考过程可视化。

记录 AI 在每一步的“思考步骤”，包括：
    - 当前观察到的事实（observation）
    - 做出的决策（decision）
    - 决策的理由与依据（reasoning / evidence）
    - 预期下一步（next_expectation）

对外提供时间线、节点树、当前正在思考的“思考气泡”等可视化所需数据结构。
纯内存存储，所有数据可序列化为 JSON。
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class ThoughtStep:
    """一个 AI 思考步骤。"""

    step_id: str
    session_id: str
    seq: int
    phase: str                 # recon / enum / vuln / analysis / report / meta
    observation: str           # AI 观察到的事实
    reasoning: str             # 为什么这么判断
    evidence: List[str]        # 依据（可多条）
    decision: str              # 决策动作
    expectation: str          # 预期下一步/结果
    confidence: float = 0.0    # 0~1
    timestamp: float = field(default_factory=time.time)
    emotion: str = "neutral"    # neutral / curious / concerned / confident

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ThoughtSession:
    """一次自主渗透会话的思考流。"""

    session_id: str
    target: str
    steps: List[ThoughtStep] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target": self.target,
            "created_at": self.created_at,
            "step_count": len(self.steps),
            "latest": self.steps[-1].to_dict() if self.steps else None,
            "timeline": [s.to_dict() for s in self.steps],
        }


class ThinkingVisualizer:
    """记录并聚合 AI 思考步骤，供前端可视化。"""

    def __init__(self) -> None:
        self._sessions: Dict[str, ThoughtSession] = {}

    # ------------------------------------------------------------------ #
    def create_session(self, target: str) -> ThoughtSession:
        sid = "think_" + uuid.uuid4().hex[:10]
        sess = ThoughtSession(session_id=sid, target=target)
        self._sessions[sid] = sess
        return sess

    def add_step(self, session_id: str, *, phase: str,
                 observation: str, reasoning: str,
                 decision: str, expectation: str,
                 evidence: Optional[List[str]] = None,
                 confidence: float = 0.7,
                 emotion: str = "neutral") -> Optional[ThoughtStep]:
        sess = self._sessions.get(session_id)
        if sess is None:
            return None
        step = ThoughtStep(
            step_id=f"{session_id}_s{len(sess.steps)+1:03d}",
            session_id=session_id,
            seq=len(sess.steps) + 1,
            phase=phase,
            observation=observation,
            reasoning=reasoning,
            evidence=evidence or [],
            decision=decision,
            expectation=expectation,
            confidence=max(0.0, min(1.0, confidence)),
            emotion=emotion,
        )
        sess.steps.append(step)
        return step

    # ------------------------------------------------------------------ #
    def get_session(self, session_id: str) -> Optional[ThoughtSession]:
        return self._sessions.get(session_id)

    def list_sessions(self, limit: int = 50) -> List[Dict[str, Any]]:
        items = sorted(self._sessions.values(),
                       key=lambda s: s.created_at, reverse=True)
        return [
            {
                "session_id": s.session_id,
                "target": s.target,
                "created_at": s.created_at,
                "step_count": len(s.steps),
                "latest": s.steps[-1].to_dict() if s.steps else None,
            }
            for s in items[:limit]
        ]

    def get_timeline(self, session_id: str) -> List[Dict[str, Any]]:
        s = self._sessions.get(session_id)
        return [st.to_dict() for st in s.steps] if s else []

    def latest_thought(self, session_id: str) -> Optional[Dict[str, Any]]:
        s = self._sessions.get(session_id)
        if not s or not s.steps:
            return None
        return s.steps[-1].to_dict()

    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        total = sum(len(s.steps) for s in self._sessions.values())
        return {
            "sessions": len(self._sessions),
            "total_steps": total,
            "phases": ["recon", "enum", "vuln", "analysis", "report", "meta"],
        }


# 内置一些“思考样例句式”，让 AI 决策话术更自然（模拟推理）
SAMPLE_THOUGHTS: Dict[str, List[str]] = {
    "recon": [
        "我刚拿到目标，先做端口与服务探测，确认攻击面。",
        "开放了 80/443，说明是 Web 服务，下一步走 Web 资产枚举。",
    ],
    "enum": [
        "目录枚举发现了 /admin 与 /.git 泄露，值得深挖。",
        "技术栈指纹指向 Nginx + ThinkPHP，对应 CVE 库有候选。",
    ],
    "vuln": [
        "我发现了 SQL 注入点，下一步应该尝试获取数据。",
        "这个参数回显了数据库错误，存在注入嫌疑，准备利用。",
        "XSS 测试未回显，转向目录遍历方向继续验证。",
    ],
    "analysis": [
        "把所有命中点做关联，SQLi 与越权组合可能构成完整链路。",
        "按可利用性与影响面排序，这个发现应定为高危。",
    ],
    "report": [
        "证据已收集齐全，开始生成结构化报告。",
        "报告包含资产、漏洞、验证证据与修复建议。",
    ],
}


visualizer = ThinkingVisualizer()
