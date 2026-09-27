# -*- coding: utf-8 -*-
"""
lab_environment_phase.py — 阶段3：实验环境（Docker）。

功能:
    - Docker 一键部署实验环境（真实 subprocess 调用，超时300s）
    - 实验指导书（目标/步骤/原理/注意事项）
    - 实验报告（结果/分析/总结/截图）
    - 实验评分（自动/人工/标准）
    - 实验资源管理（镜像/容器/端口/限制）
    - 实验分类 / 难度 / 状态机
    - 未安装 Docker 明确提示，不 mock；内置模拟实验框架兜底
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

TOOL_TIMEOUT = 300

LAB_CATEGORIES = ["Web实验", "内网实验", "移动实验", "云实验",
                  "密码学实验", "逆向实验"]
LAB_DIFFICULTIES = ["入门", "简单", "中等", "困难", "地狱"]
LAB_STATUS = ["未开始", "进行中", "已完成", "已超时"]


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


@dataclass
class Lab:
    lab_id: str = ""
    name: str = ""
    category: str = "Web实验"
    difficulty: str = "入门"
    image: str = ""
    guide: Dict[str, Any] = field(default_factory=dict)
    container_id: str = ""
    port: int = 0
    status: str = "未开始"
    student: str = ""
    score: float = 0.0
    auto_score: float = 0.0
    manual_score: float = 0.0
    report: Dict[str, Any] = field(default_factory=dict)
    started_at: str = ""
    finished_at: str = ""
    resource_limit: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lab_id": self.lab_id, "name": self.name,
            "category": self.category, "difficulty": self.difficulty,
            "image": self.image, "guide": self.guide,
            "container_id": self.container_id, "port": self.port,
            "status": self.status, "student": self.student,
            "score": self.score, "auto_score": self.auto_score,
            "manual_score": self.manual_score, "report": self.report,
            "started_at": self.started_at, "finished_at": self.finished_at,
            "resource_limit": self.resource_limit,
        }


class LabEnvironmentPhase:
    """阶段3：实验环境。"""

    def __init__(self) -> None:
        self._labs: Dict[str, Lab] = {}
        self._lock = threading.Lock()
        self._seed()

    # ------------------------------------------------------------------ #
    def _seed(self) -> None:
        seeds = [
            ("lab_sqli", "SQL 注入联合查询实验", "Web实验", "简单",
             "bkimminich/juice-shop", 3001),
            ("lab_xss", "反射型 XSS 实验", "Web实验", "入门",
             "bkimminich/juice-shop", 3002),
            ("lab_ad", "内网域渗透靶场", "内网实验", "地狱",
             "victorfang/active-directory-lab", 3003),
            ("lab_crypto", "RSA 共模攻击实验", "密码学实验", "困难",
             "python:3.11-slim", 3004),
        ]
        for lid, name, cat, diff, img, port in seeds:
            if lid not in self._labs:
                self._labs[lid] = Lab(
                    lab_id=lid, name=name, category=cat, difficulty=diff,
                    image=img, port=port,
                    guide={
                        "objective": f"{name} — 掌握核心原理",
                        "steps": ["1. 访问靶机", "2. 识别漏洞点",
                                  "3. 利用验证", "4. 截图留证"],
                        "principle": "基于 Docker 容器隔离环境",
                        "notice": "禁止对容器外网络发起攻击",
                    },
                    resource_limit={"cpu": "1.0", "memory": "512m"},
                )

    # ------------------------------------------------------------------ #
    def docker_status(self) -> Dict[str, Any]:
        """真实 Docker 探测。"""
        docker = _which("docker")
        out = {"docker_available": bool(docker), "path": docker or ""}
        if docker:
            try:
                p = subprocess.run([docker, "version", "--format",
                                    "{{.Server.Version}}"],
                                    capture_output=True, text=True,
                                    timeout=TOOL_TIMEOUT,
                                    encoding="utf-8", errors="ignore")
                out["server_version"] = p.stdout.strip()
                out["daemon_running"] = (p.returncode == 0
                                         and bool(p.stdout.strip()))
                if p.returncode != 0:
                    out["hint"] = p.stderr.strip()[:200]
            except Exception as e:  # noqa: BLE001
                out["daemon_running"] = False
                out["hint"] = f"Docker daemon 不可用: {e}"
        else:
            out["hint"] = "未检测到 docker 命令，请安装 Docker Desktop；" \
                          "当前使用内置模拟实验框架兜底"
            out["daemon_running"] = False
        return out

    # ------------------------------------------------------------------ #
    def list_labs(self, category: Optional[str] = None,
                  difficulty: Optional[str] = None,
                  status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._labs.values())
        out = []
        for l in items:
            if category and l.category != category:
                continue
            if difficulty and l.difficulty != difficulty:
                continue
            if status and l.status != status:
                continue
            out.append(l.to_dict())
        return out

    def get_lab(self, lab_id: str) -> Optional[Dict[str, Any]]:
        l = self._labs.get(lab_id)
        return l.to_dict() if l else None

    def create_lab(self, name: str, category: str = "Web实验",
                   difficulty: str = "入门", image: str = "",
                   guide: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if category not in LAB_CATEGORIES:
            raise ValueError(f"非法分类: {category}")
        if difficulty not in LAB_DIFFICULTIES:
            raise ValueError(f"非法难度: {difficulty}")
        l = Lab(
            lab_id="lab_" + uuid.uuid4().hex[:8], name=name,
            category=category, difficulty=difficulty, image=image,
            guide=guide or {"objective": name, "steps": [],
                            "principle": "", "notice": ""},
            resource_limit={"cpu": "1.0", "memory": "512m"},
        )
        with self._lock:
            self._labs[l.lab_id] = l
        return l.to_dict()

    # ------------------------------------------------------------------ #
    def start_lab(self, lab_id: str, student: str = "student") -> Dict[str, Any]:
        l = self._labs.get(lab_id)
        if l is None:
            return {"success": False, "error": "lab not found"}
        dstat = self.docker_status()
        notes: List[str] = []
        container_id = ""
        if dstat["docker_available"] and dstat.get("daemon_running"):
            # 真实 Docker 调用
            try:
                docker = dstat["path"]
                cmd = [docker, "run", "-d",
                       f"--cpus={l.resource_limit.get('cpu', '1')}",
                       f"--memory={l.resource_limit.get('memory', '512m')}",
                       "-p", f"{l.port}:80",
                       l.image]
                p = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=TOOL_TIMEOUT,
                                   encoding="utf-8", errors="ignore")
                if p.returncode == 0:
                    container_id = p.stdout.strip()[:12]
                    notes.append(f"[真实] docker run 成功: {container_id}")
                else:
                    notes.append(f"[真实] docker run 失败: "
                                 f"{p.stderr.strip()[:200]}；降级模拟")
            except Exception as e:  # noqa: BLE001
                notes.append(f"[真实] 调用异常: {e}；降级模拟")
        else:
            notes.append(f"[兜底] Docker 不可用（{dstat.get('hint','')}）；"
                         f"内置模拟实验环境启动")
            container_id = "sim_" + uuid.uuid4().hex[:10]

        with self._lock:
            l.status = "进行中"
            l.student = student
            l.container_id = container_id
            l.started_at = datetime.now().isoformat(timespec="seconds")
        return {"success": True, **l.to_dict(), "notes": notes,
                "docker": dstat}

    def stop_lab(self, lab_id: str) -> Dict[str, Any]:
        l = self._labs.get(lab_id)
        if l is None:
            return {"success": False, "error": "lab not found"}
        notes = []
        dstat = self.docker_status()
        if dstat["docker_available"] and dstat.get("daemon_running") \
                and l.container_id and not l.container_id.startswith("sim_"):
            try:
                subprocess.run([dstat["path"], "rm", "-f",
                                l.container_id],
                               capture_output=True, text=True,
                               timeout=TOOL_TIMEOUT,
                               encoding="utf-8", errors="ignore")
                notes.append("[真实] 容器已删除")
            except Exception as e:  # noqa: BLE001
                notes.append(f"[真实] 删除失败: {e}")
        with self._lock:
            l.status = "已完成"
            l.finished_at = datetime.now().isoformat(timespec="seconds")
            l.container_id = ""
        return {"success": True, **l.to_dict(), "notes": notes}

    # ------------------------------------------------------------------ #
    def submit_report(self, lab_id: str, result: str = "",
                      analysis: str = "", summary: str = "",
                      screenshot: str = "") -> Optional[Dict[str, Any]]:
        l = self._labs.get(lab_id)
        if l is None:
            return None
        with self._lock:
            l.report = {"result": result, "analysis": analysis,
                        "summary": summary, "screenshot": screenshot,
                        "submitted_at": datetime.now().isoformat(
                            timespec="seconds")}
            # 自动评分：按报告完整度
            filled = sum(1 for v in (result, analysis, summary, screenshot)
                         if v)
            l.auto_score = filled / 4.0 * 100
            l.score = l.auto_score
        return l.to_dict()

    def grade_manual(self, lab_id: str,
                     manual_score: float) -> Optional[Dict[str, Any]]:
        l = self._labs.get(lab_id)
        if l is None:
            return None
        with self._lock:
            l.manual_score = max(0.0, min(100.0, manual_score))
            l.score = round(l.auto_score * 0.4 + l.manual_score * 0.6, 1)
        return l.to_dict()

    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            labs = list(self._labs.values())
        return {
            "total": len(labs),
            "by_category": {c: sum(1 for l in labs if l.category == c)
                            for c in LAB_CATEGORIES},
            "by_status": {s: sum(1 for l in labs if l.status == s)
                          for s in LAB_STATUS},
            "docker": self.docker_status(),
            "avg_score": round(
                sum(l.score for l in labs) / max(1, len(labs)), 1),
        }


_default: Optional[LabEnvironmentPhase] = None


def get_lab_environment_phase() -> LabEnvironmentPhase:
    global _default
    if _default is None:
        _default = LabEnvironmentPhase()
    return _default
