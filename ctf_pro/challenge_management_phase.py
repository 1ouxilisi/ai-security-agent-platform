# -*- coding: utf-8 -*-
"""
challenge_management_phase.py — 阶段2：题目管理（8 大题型）。

8 大题型:
    - Web: SQL注入/XSS/文件上传/命令注入/SSRF/反序列化/逻辑漏洞
    - Reverse: 逆向工程/脱壳/算法分析/反调试
    - Pwn: 栈溢出/堆溢出/格式化字符串/UAF/ROP
    - Crypto: RSA/AES/哈希/数字签名/椭圆曲线/格密码
    - Misc: 隐写/编码/取证/流量分析/脑洞
    - Forensics: 磁盘取证/内存取证/网络取证/日志取证
    - Mobile: APK逆向/Frida/动态调试/组件安全
    - Blockchain: 智能合约漏洞/DeFi攻击/钱包安全

难度分级: 入门/简单/中等/困难/地狱
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

# 8 大题型与子知识点
CHALLENGE_CATEGORIES: Dict[str, List[str]] = {
    "Web": ["SQL注入", "XSS", "文件上传", "命令注入", "SSRF",
            "反序列化", "逻辑漏洞", "CSRF", "XXE", "模板注入SSTI"],
    "Reverse": ["逆向工程", "脱壳", "算法分析", "反调试",
                "ARM逆向", "MFC逆向", "Ollvm混淆"],
    "Pwn": ["栈溢出", "堆溢出", "格式化字符串", "Use-After-Free",
            "ROP", "整数溢出", "竞态条件", "堆风水"],
    "Crypto": ["RSA", "AES", "哈希", "数字签名", "椭圆曲线",
               "格密码", "古典密码", "侧信道"],
    "Misc": ["隐写", "编码", "取证", "流量分析", "脑洞",
             "压缩包", "图片隐写", "二维码"],
    "Forensics": ["磁盘取证", "内存取证", "网络取证", "日志取证",
                  "注册表取证", "时间线分析"],
    "Mobile": ["APK逆向", "Frida", "动态调试", "组件安全",
               "SO层逆向", "脱壳"],
    "Blockchain": ["智能合约漏洞", "DeFi攻击", "钱包安全",
                   "重入", "整数溢出", "权限绕过"],
}

DIFFICULTIES = ("入门", "简单", "中等", "困难", "地狱")
DIFFICULTY_SCORE = {"入门": 100, "简单": 200, "中等": 350,
                    "困难": 500, "地狱": 800}
CHALLENGE_STATUSES = ("draft", "published", "offline")


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


@dataclass
class Attachment:
    name: str = ""
    url: str = ""
    size: int = 0
    kind: str = ""   # source/image/pcap/doc/binary/wallet

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "url": self.url,
                "size": self.size, "kind": self.kind}


@dataclass
class ChallengeVersion:
    version: int = 1
    note: str = ""
    changed_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"version": self.version, "note": self.note,
                "changed_at": self.changed_at}


@dataclass
class Challenge:
    chal_id: str = ""
    title: str = ""
    category: str = "Web"
    subcategory: str = ""
    description: str = ""
    difficulty: str = "简单"
    base_score: int = 200
    dynamic_score: bool = True
    tags: List[str] = field(default_factory=list)
    hints: List[Dict[str, Any]] = field(default_factory=list)
    flag: str = ""                       # 标准答案 flag（动态题可为空模板）
    flag_template: str = ""              # 如 flag_{md5(team_id)}
    attachments: List[Attachment] = field(default_factory=list)
    status: str = "draft"
    competition_id: str = ""
    versions: List[ChallengeVersion] = field(default_factory=list)
    created_at: str = ""

    def to_dict(self, include_flag: bool = False) -> Dict[str, Any]:
        d = {
            "chal_id": self.chal_id, "title": self.title,
            "category": self.category,
            "subcategory": self.subcategory,
            "description": self.description,
            "difficulty": self.difficulty,
            "base_score": self.base_score,
            "dynamic_score": self.dynamic_score,
            "tags": self.tags,
            "hints": self.hints,
            "attachments": [a.to_dict() for a in self.attachments],
            "status": self.status,
            "competition_id": self.competition_id,
            "versions": [v.to_dict() for v in self.versions],
            "created_at": self.created_at,
        }
        if include_flag:
            d["flag"] = self.flag
            d["flag_template"] = self.flag_template
        return d


class ChallengeManagementPhase:
    """阶段2：题目管理。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._chals: Dict[str, Challenge] = {}

    # ------------------------------------------------------------------ #
    def create_challenge(self, title: str, category: str = "Web",
                         subcategory: str = "",
                         description: str = "",
                         difficulty: str = "简单",
                         base_score: int = 0,
                         tags: Optional[List[str]] = None,
                         flag: str = "",
                         flag_template: str = "",
                         competition_id: str = "",
                         dynamic_score: bool = True) -> Dict[str, Any]:
        if not title:
            raise ValueError("题目标题不能为空")
        if category not in CHALLENGE_CATEGORIES:
            raise ValueError(f"非法题型: {category}")
        if difficulty not in DIFFICULTIES:
            raise ValueError(f"非法难度: {difficulty}")
        c = Challenge(
            chal_id="chal_" + uuid.uuid4().hex[:10],
            title=title, category=category,
            subcategory=subcategory, description=description,
            difficulty=difficulty,
            base_score=base_score or DIFFICULTY_SCORE[difficulty],
            dynamic_score=dynamic_score,
            tags=tags or [], flag=flag, flag_template=flag_template,
            competition_id=competition_id,
            created_at=_now(),
        )
        c.versions.append(ChallengeVersion(
            version=1, note="初始创建", changed_at=_now()))
        with self._lock:
            self._chals[c.chal_id] = c
        return c.to_dict(include_flag=True)

    def get_challenge(self, chal_id: str,
                      include_flag: bool = False
                      ) -> Optional[Dict[str, Any]]:
        c = self._chals.get(chal_id)
        if c is None:
            return None
        return c.to_dict(include_flag=include_flag)

    def list_challenges(self, category: str = "",
                        difficulty: str = "",
                        status: str = "",
                        competition_id: str = "",
                        include_flag: bool = False
                        ) -> List[Dict[str, Any]]:
        out = []
        for c in self._chals.values():
            if category and c.category != category:
                continue
            if difficulty and c.difficulty != difficulty:
                continue
            if status and c.status != status:
                continue
            if competition_id and c.competition_id != competition_id:
                continue
            out.append(c.to_dict(include_flag=include_flag))
        return sorted(out, key=lambda x: x["created_at"], reverse=True)

    def update_challenge(self, chal_id: str,
                         patch: Dict[str, Any],
                         note: str = "") -> Dict[str, Any]:
        c = self._chals.get(chal_id)
        if c is None:
            raise KeyError(f"题目不存在: {chal_id}")
        editable = ("title", "description", "difficulty", "base_score",
                    "tags", "flag", "flag_template", "subcategory",
                    "dynamic_score", "status")
        for k in editable:
            if k in patch:
                setattr(c, k, patch[k])
        new_v = (c.versions[-1].version + 1) if c.versions else 1
        c.versions.append(ChallengeVersion(
            version=new_v, note=note or "更新", changed_at=_now()))
        return c.to_dict(include_flag=True)

    def change_status(self, chal_id: str,
                      status: str) -> Dict[str, Any]:
        if status not in CHALLENGE_STATUSES:
            raise ValueError(f"非法状态: {status}")
        c = self._chals.get(chal_id)
        if c is None:
            raise KeyError(f"题目不存在: {chal_id}")
        c.status = status
        return c.to_dict()

    # ------------------------------------------------------------------ #
    def add_attachment(self, chal_id: str, name: str, url: str,
                       size: int = 0, kind: str = "") -> Dict[str, Any]:
        c = self._chals.get(chal_id)
        if c is None:
            raise KeyError(f"题目不存在: {chal_id}")
        a = Attachment(name=name, url=url, size=size, kind=kind)
        c.attachments.append(a)
        return a.to_dict()

    def add_hint(self, chal_id: str, content: str,
                 cost: int = 0) -> Dict[str, Any]:
        c = self._chals.get(chal_id)
        if c is None:
            raise KeyError(f"题目不存在: {chal_id}")
        h = {"hint_id": "hint_" + uuid.uuid4().hex[:6],
             "content": content, "cost": cost,
             "unlocked": False, "created_at": _now()}
        c.hints.append(h)
        return h

    # ------------------------------------------------------------------ #
    def taxonomy(self) -> Dict[str, Any]:
        """题型/难度维度统计。"""
        by_cat: Dict[str, int] = {}
        by_diff: Dict[str, int] = {}
        for c in self._chals.values():
            by_cat[c.category] = by_cat.get(c.category, 0) + 1
            by_diff[c.difficulty] = by_diff.get(c.difficulty, 0) + 1
        return {"categories": CHALLENGE_CATEGORIES,
                "count_by_category": by_cat,
                "count_by_difficulty": by_diff,
                "total": len(self._chals)}

    def stats(self) -> Dict[str, Any]:
        t = self.taxonomy()
        published = sum(1 for c in self._chals.values()
                        if c.status == "published")
        return {"total": len(self._chals),
                "published": published,
                "by_category": t["count_by_category"],
                "by_difficulty": t["count_by_difficulty"]}


_default: Optional[ChallengeManagementPhase] = None


def get_challenge_phase() -> ChallengeManagementPhase:
    global _default
    if _default is None:
        _default = ChallengeManagementPhase()
    return _default
