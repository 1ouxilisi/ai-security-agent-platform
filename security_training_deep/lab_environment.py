#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_training_deep/lab_environment.py — 实验环境深度。

覆盖六大子域：
    1. 实验管理：实验创建/分配/开始/结束/提交/评分
    2. 靶场环境：靶场创建/配置/启动/停止/快照/恢复
    3. 环境管理：资源池/网络隔离/镜像管理/配额管理
    4. 实验指导：指导文档/步骤提示/错误反馈/操作验证
    5. 实验评估：自动评分/人工评分/结果分析/能力映射
    6. 实验沙箱：代码执行沙箱/命令沙箱/隔离环境/资源限制
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
LAB_DIFFICULTY: Dict[str, str] = {
    "easy": "简单", "medium": "中等", "hard": "困难", "expert": "专家",
}

LAB_STATUS: Dict[str, str] = {
    "not_started": "未开始", "in_progress": "进行中", "submitted": "已提交",
    "graded": "已评分", "closed": "已关闭",
}

RANGE_STATUS: Dict[str, str] = {
    "stopped": "已停止", "starting": "启动中", "running": "运行中",
    "stopping": "停止中", "error": "异常",
}

LAB_CATEGORIES: Dict[str, str] = {
    "web_pentest": "Web渗透", "network_pentest": "网络渗透",
    "forensics": "取证分析", "reverse": "逆向工程",
    "malware_analysis": "恶意代码分析", "crypto": "密码学",
    "cloud_pentest": "云渗透", "mobile_pentest": "移动安全",
}

SANDBOX_LIMITS: Dict[str, Any] = {
    "max_cpu": "2核", "max_memory": "4GB", "max_disk": "20GB",
    "max_runtime_minutes": 60, "network": "隔离",
}


# --------------------------------------------------------------------------- #
# 实验管理
# --------------------------------------------------------------------------- #
class LabManager:
    """实验管理：创建/分配/开始/结束/提交。"""

    def __init__(self) -> None:
        self.labs: Dict[str, Dict[str, Any]] = {}
        self.assignments: Dict[str, Dict[str, Any]] = {}
        self._seed_default_labs()

    def _seed_default_labs(self) -> None:
        defaults = [
            ("SQL注入漏洞利用", "web_pentest", "medium", "通过DVWA靶场练习SQL注入攻击及防御。"),
            ("XSS跨站脚本实战", "web_pentest", "easy", "反射型/存储型/DOM型XSS漏洞挖掘与利用。"),
            ("Windows提权实验", "network_pentest", "hard", "利用服务配置错误进行Windows权限提升。"),
            ("内存取证分析", "forensics", "hard", "使用Volatility分析内存镜像中的恶意进程。"),
            ("简单密码学破解", "crypto", "easy", "基础加密算法识别与破解实验。"),
        ]
        for title, cat, diff, desc in defaults:
            lid = f"lab_{uuid.uuid4().hex[:8]}"
            self.labs[lid] = {
                "id": lid, "title": title, "category": cat, "difficulty": diff,
                "description": desc, "duration_minutes": 45,
                "objectives": ["掌握核心概念", "完成实操任务", "理解防御思路"],
                "hints": [], "steps": [],
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "attempt_count": 0, "avg_score": 0.0,
            }

    def create_lab(self, data: Dict[str, Any]) -> Dict[str, Any]:
        lid = f"lab_{uuid.uuid4().hex[:8]}"
        lab = {
            "id": lid, "title": data.get("title", "未命名实验"),
            "category": data.get("category", "web_pentest"),
            "difficulty": data.get("difficulty", "medium"),
            "description": data.get("description", ""),
            "duration_minutes": int(data.get("duration_minutes", 45)),
            "objectives": data.get("objectives", []),
            "hints": data.get("hints", []),
            "steps": data.get("steps", []),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "attempt_count": 0, "avg_score": 0.0,
        }
        self.labs[lid] = lab
        return lab

    def get_lab(self, lab_id: str) -> Optional[Dict[str, Any]]:
        return self.labs.get(lab_id)

    def list_labs(self, category: str = "", difficulty: str = "") -> List[Dict[str, Any]]:
        results = list(self.labs.values())
        if category:
            results = [l for l in results if l["category"] == category]
        if difficulty:
            results = [l for l in results if l["difficulty"] == difficulty]
        return results

    def assign_lab(self, lab_id: str, user: str) -> Optional[Dict[str, Any]]:
        if lab_id not in self.labs:
            return None
        aid = f"asg_{uuid.uuid4().hex[:8]}"
        assignment = {
            "id": aid, "lab_id": lab_id, "user": user,
            "status": "not_started", "started_at": None,
            "submitted_at": None, "score": None,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.assignments[aid] = assignment
        return assignment

    def start_lab(self, assignment_id: str) -> Optional[Dict[str, Any]]:
        a = self.assignments.get(assignment_id)
        if not a:
            return None
        a["status"] = "in_progress"
        a["started_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return a

    def submit_lab(self, assignment_id: str, answer: str = "") -> Optional[Dict[str, Any]]:
        a = self.assignments.get(assignment_id)
        if not a:
            return None
        a["status"] = "submitted"
        a["submitted_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        a["answer"] = answer
        return a


# --------------------------------------------------------------------------- #
# 靶场环境
# --------------------------------------------------------------------------- #
class RangeEnvironment:
    """靶场环境：创建/启动/停止/快照。"""

    def __init__(self) -> None:
        self.ranges: Dict[str, Dict[str, Any]] = {}
        self._seed_default_ranges()

    def _seed_default_ranges(self) -> None:
        defaults = [
            ("DVWA Web靶场", "web_pentest", "owasp/dvwa:latest"),
            ("Metasploitable2", "network_pentest", "metasploitable2:latest"),
            ("FlareVM逆向环境", "reverse", "remnux/flarevm:latest"),
            ("Kali攻击机", "offensive", "kali-linux:latest"),
        ]
        for name, rtype, image in defaults:
            rid = f"rng_{uuid.uuid4().hex[:8]}"
            self.ranges[rid] = {
                "id": rid, "name": name, "type": rtype, "image": image,
                "status": "stopped", "ip": None,
                "snapshots": [], "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }

    def create_range(self, name: str, rtype: str, image: str) -> Dict[str, Any]:
        rid = f"rng_{uuid.uuid4().hex[:8]}"
        r = {
            "id": rid, "name": name, "type": rtype, "image": image,
            "status": "stopped", "ip": None,
            "snapshots": [], "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.ranges[rid] = r
        return r

    def start_range(self, range_id: str) -> Optional[Dict[str, Any]]:
        r = self.ranges.get(range_id)
        if not r:
            return None
        r["status"] = "running"
        r["ip"] = f"10.0.{len(r['id']) % 255}.{len(r['id']) % 250 + 2}"
        return r

    def stop_range(self, range_id: str) -> Optional[Dict[str, Any]]:
        r = self.ranges.get(range_id)
        if not r:
            return None
        r["status"] = "stopped"
        r["ip"] = None
        return r

    def take_snapshot(self, range_id: str, name: str = "") -> Optional[Dict[str, Any]]:
        r = self.ranges.get(range_id)
        if not r:
            return None
        sid = f"snap_{uuid.uuid4().hex[:8]}"
        snap = {
            "id": sid, "name": name or f"快照_{len(r['snapshots']) + 1}",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        r["snapshots"].append(snap)
        return snap

    def list_ranges(self, rtype: str = "", status: str = "") -> List[Dict[str, Any]]:
        results = list(self.ranges.values())
        if rtype:
            results = [r for r in results if r["type"] == rtype]
        if status:
            results = [r for r in results if r["status"] == status]
        return results


# --------------------------------------------------------------------------- #
# 环境管理（资源池/配额）
# --------------------------------------------------------------------------- #
class EnvironmentManager:
    """环境管理：资源池/配额/镜像。"""

    def __init__(self) -> None:
        self.resource_pool: Dict[str, Any] = {
            "total_cpu_cores": 128, "used_cpu_cores": 0,
            "total_memory_gb": 512, "used_memory_gb": 0,
            "total_disk_gb": 2048, "used_disk_gb": 512,
            "active_ranges": 0,
        }
        self.quotas: Dict[str, Dict[str, Any]] = {}
        self.images: List[Dict[str, Any]] = [
            {"id": "img_001", "name": "Ubuntu 22.04", "size_gb": 8, "category": "base"},
            {"id": "img_002", "name": "Kali Linux", "size_gb": 15, "category": "offensive"},
            {"id": "img_003", "name": "DVWA", "size_gb": 2, "category": "vulnerable"},
        ]

    def get_resource_status(self) -> Dict[str, Any]:
        p = self.resource_pool
        return {
            **p,
            "cpu_usage_pct": round(p["used_cpu_cores"] / p["total_cpu_cores"] * 100, 1),
            "memory_usage_pct": round(p["used_memory_gb"] / p["total_memory_gb"] * 100, 1),
            "disk_usage_pct": round(p["used_disk_gb"] / p["total_disk_gb"] * 100, 1),
        }

    def set_quota(self, team: str, cpu: int, memory_gb: int, disk_gb: int) -> Dict[str, Any]:
        q = {"team": team, "cpu_cores": cpu, "memory_gb": memory_gb, "disk_gb": disk_gb}
        self.quotas[team] = q
        return q

    def list_images(self) -> List[Dict[str, Any]]:
        return self.images


# --------------------------------------------------------------------------- #
# 实验指导
# --------------------------------------------------------------------------- #
class LabGuide:
    """实验指导：步骤提示/错误反馈/操作验证。"""

    def __init__(self, lab_mgr: LabManager) -> None:
        self.lab_mgr = lab_mgr

    def get_hints(self, lab_id: str) -> List[Dict[str, Any]]:
        lab = self.lab_mgr.get_lab(lab_id)
        if not lab:
            return []
        return [
            {"step": i + 1, "hint": h, "reveal_after_minutes": i * 10}
            for i, h in enumerate(lab.get("hints", []))
        ]

    def validate_step(self, lab_id: str, step_index: int, user_input: str) -> Dict[str, Any]:
        # 模拟验证：检查输入是否非空且包含关键字
        lab = self.lab_mgr.get_lab(lab_id)
        if not lab:
            return {"valid": False, "message": "实验不存在"}
        # 简单模拟：如果输入包含 "success" 或 "flag" 关键字则视为通过
        is_valid = bool(user_input and len(user_input.strip()) > 3)
        return {
            "valid": is_valid,
            "step": step_index,
            "message": "验证通过" if is_valid else "请再尝试，检查输入是否正确",
            "hint": "" if is_valid else "提示：仔细观察目标响应中的关键信息",
        }


# --------------------------------------------------------------------------- #
# 实验评估
# --------------------------------------------------------------------------- #
class LabEvaluator:
    """实验评估：自动评分/结果分析/能力映射。"""

    def __init__(self, lab_mgr: LabManager) -> None:
        self.lab_mgr = lab_mgr
        self.evaluations: Dict[str, Dict[str, Any]] = {}

    def auto_grade(self, assignment_id: str) -> Optional[Dict[str, Any]]:
        a = self.lab_mgr.assignments.get(assignment_id)
        if not a:
            return None
        # 模拟自动评分：基于提交时间和答案长度
        answer = a.get("answer", "")
        base_score = 60
        if len(answer) > 50:
            base_score += 15
        if len(answer) > 200:
            base_score += 10
        if "flag" in answer.lower() or "success" in answer.lower():
            base_score += 15
        score = min(100, base_score)
        a["score"] = score
        a["status"] = "graded"
        eval_result = {
            "assignment_id": assignment_id,
            "score": score,
            "max_score": 100,
            "grade": "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F",
            "feedback": "完成度良好" if score >= 80 else "需要加强练习",
            "strengths": ["基础操作完成", "理解核心概念"],
            "improvements": ["深入理解攻击原理", "尝试更多绕过技巧"],
            "evaluated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.evaluations[assignment_id] = eval_result
        # update lab avg score
        lab = self.lab_mgr.get_lab(a["lab_id"])
        if lab:
            lab["attempt_count"] += 1
            lab["avg_score"] = round((lab["avg_score"] * (lab["attempt_count"] - 1) + score) / lab["attempt_count"], 1)
        return eval_result

    def get_evaluation(self, assignment_id: str) -> Optional[Dict[str, Any]]:
        return self.evaluations.get(assignment_id)


# --------------------------------------------------------------------------- #
# 实验沙箱
# --------------------------------------------------------------------------- #
class LabSandbox:
    """实验沙箱：隔离执行环境/资源限制。"""

    def __init__(self) -> None:
        self.sandboxes: Dict[str, Dict[str, Any]] = {}
        self.execution_logs: List[Dict[str, Any]] = []

    def create_sandbox(self, user: str, lab_id: str) -> Dict[str, Any]:
        sid = f"sbx_{uuid.uuid4().hex[:8]}"
        sbx = {
            "id": sid, "user": user, "lab_id": lab_id,
            "status": "running", "limits": SANDBOX_LIMITS.copy(),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "expires_at": None,
        }
        self.sandboxes[sid] = sbx
        return sbx

    def execute_in_sandbox(self, sandbox_id: str, command: str) -> Dict[str, Any]:
        sbx = self.sandboxes.get(sandbox_id)
        if not sbx:
            return {"success": False, "error": "沙箱不存在"}
        # 模拟命令执行（安全沙箱，不实际执行）
        log_entry = {
            "sandbox_id": sandbox_id, "command": command,
            "executed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "output": f"[沙箱模拟] 命令 '{command[:50]}...' 已在隔离环境执行",
            "exit_code": 0,
        }
        self.execution_logs.append(log_entry)
        return {"success": True, "output": log_entry["output"], "exit_code": 0}

    def destroy_sandbox(self, sandbox_id: str) -> bool:
        if sandbox_id in self.sandboxes:
            self.sandboxes[sandbox_id]["status"] = "destroyed"
            return True
        return False

    def list_sandboxes(self, user: str = "") -> List[Dict[str, Any]]:
        results = list(self.sandboxes.values())
        if user:
            results = [s for s in results if s["user"] == user]
        return results


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_lab_manager: Optional[LabManager] = None
_range_env: Optional[RangeEnvironment] = None
_env_manager: Optional[EnvironmentManager] = None
_lab_guide: Optional[LabGuide] = None
_lab_evaluator: Optional[LabEvaluator] = None
_lab_sandbox: Optional[LabSandbox] = None


def get_lab_manager() -> LabManager:
    global _lab_manager
    if _lab_manager is None:
        _lab_manager = LabManager()
    return _lab_manager


def get_range_env() -> RangeEnvironment:
    global _range_env
    if _range_env is None:
        _range_env = RangeEnvironment()
    return _range_env


def get_env_manager() -> EnvironmentManager:
    global _env_manager
    if _env_manager is None:
        _env_manager = EnvironmentManager()
    return _env_manager


def get_lab_guide() -> LabGuide:
    global _lab_guide
    if _lab_guide is None:
        _lab_guide = LabGuide(get_lab_manager())
    return _lab_guide


def get_lab_evaluator() -> LabEvaluator:
    global _lab_evaluator
    if _lab_evaluator is None:
        _lab_evaluator = LabEvaluator(get_lab_manager())
    return _lab_evaluator


def get_lab_sandbox() -> LabSandbox:
    global _lab_sandbox
    if _lab_sandbox is None:
        _lab_sandbox = LabSandbox()
    return _lab_sandbox
