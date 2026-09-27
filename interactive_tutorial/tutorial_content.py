# -*- coding: utf-8 -*-
"""
tutorial_content.py — 教程内容管理。

能力：
  - 教程创建（标题/描述/分类/难度/时长/目标/前置知识/标签/封面/版本）
  - 教程结构（章节/小节/步骤/知识点/示例/练习/测验/项目/总结）
  - 内容编辑器（富文本/Markdown/代码块/终端模拟/浏览器模拟/截图/视频/动画/交互组件）
  - 教程模板（快速开始/功能介绍/场景实战/最佳实践/故障排查/认证考试/模板变量/模板版本）
  - 教程分类（入门/基础/进阶/高级/专家/按功能/按场景/按角色/按行业）
  - 教程版本（版本号/变更记录/版本对比/历史版本/回滚/发布/草稿/审核）

全部内存字典模拟；不依赖数据库。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------- #
# 常量库
# --------------------------------------------------------------------------- #
DIFFICULTY_LEVELS = ["入门", "基础", "进阶", "高级", "专家"]
CATEGORY_BY_FUNCTION = ["Web安全", "渗透测试", "逆向工程", "漏洞分析", "应急响应",
                        "安全运维", "代码审计", "云安全", "移动安全", "工控安全"]
CATEGORY_BY_SCENARIO = ["CTF夺旗", "红蓝对抗", "护网行动", "合规审计", "日常巡检", "应急演练"]
CATEGORY_BY_ROLE = ["渗透测试工程师", "安全分析师", "蓝队工程师", "安全运维", "安全管理", "开发人员"]
CATEGORY_BY_INDUSTRY = ["金融", "政务", "能源", "制造", "互联网", "医疗", "教育"]
CONTENT_BLOCK_TYPES = ["richtext", "markdown", "code", "terminal", "browser",
                       "screenshot", "video", "animation", "interactive", "quiz"]
TEMPLATE_TYPES = ["quickstart", "feature", "scenario", "best_practice",
                  "troubleshooting", "certification"]
TUTORIAL_STATUS = ["draft", "reviewing", "published", "archived", "offline"]


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _rid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


# --------------------------------------------------------------------------- #
# 内存存储
# --------------------------------------------------------------------------- #
class ContentStore:
    """教程内容仓库（单例内存字典）。"""

    def __init__(self) -> None:
        self.tutorials: Dict[str, Dict[str, Any]] = {}
        self.chapters: Dict[str, Dict[str, Any]] = {}
        self.blocks: Dict[str, Dict[str, Any]] = {}
        self.templates: Dict[str, Dict[str, Any]] = {}
        self.versions: Dict[str, List[Dict[str, Any]]] = {}
        self._seed()

    # ---------------- 种子数据 ---------------- #
    def _seed(self) -> None:
        tpl_specs = [
            ("quickstart", "快速开始模板", "10分钟上手新工具的标准结构"),
            ("feature", "功能介绍模板", "单功能点深度讲解"),
            ("scenario", "场景实战模板", "面向真实业务场景的演练"),
            ("best_practice", "最佳实践模板", "行业经验沉淀"),
            ("troubleshooting", "故障排查模板", "问题定位到解决全流程"),
            ("certification", "认证考试模板", "备考与模拟测验"),
        ]
        for key, name, desc in tpl_specs:
            tid = _rid("tpl")
            self.templates[tid] = {
                "id": tid, "type": key, "name": name, "description": desc,
                "variables": ["{{TUTORIAL_TITLE}}", "{{TARGET}}", "{{TOOL}}",
                              "{{SCENARIO}}", "{{DURATION}}"],
                "chapters": [
                    {"title": "概述", "blocks": ["richtext"]},
                    {"title": "环境准备", "blocks": ["terminal", "code"]},
                    {"title": "核心步骤", "blocks": ["browser", "terminal"]},
                    {"title": "实战练习", "blocks": ["interactive", "quiz"]},
                    {"title": "总结", "blocks": ["markdown"]},
                ],
                "version": "1.0.0", "created_at": _now(), "updated_at": _now(),
            }
        # 内置示例教程
        tid = _rid("tut")
        self.tutorials[tid] = {
            "id": tid, "title": "Web渗透测试快速入门", "version": "1.0.0",
            "description": "从HTTP协议到SQL注入的交互式入门教程",
            "category": "Web安全", "difficulty": "入门", "duration_min": 120,
            "goals": ["理解HTTP请求结构", "识别常见注入点", "手工验证SQL注入"],
            "prerequisites": ["基础网络知识"], "tags": ["Web", "注入", "入门"],
            "cover": "/static/covers/web101.png", "status": "published",
            "rating": 4.8, "learner_count": 1280, "created_at": _now(),
            "updated_at": _now(), "chapter_ids": [],
        }
        self.versions[tid] = [{
            "version": "1.0.0", "status": "published", "changelog": "初版发布",
            "created_at": _now(), "author": "system",
        }]


STORE = ContentStore()


# --------------------------------------------------------------------------- #
# 教程 CRUD
# --------------------------------------------------------------------------- #
def create_tutorial(payload: Dict[str, Any]) -> Dict[str, Any]:
    tid = _rid("tut")
    tut = {
        "id": tid,
        "title": payload.get("title", "未命名教程"),
        "description": payload.get("description", ""),
        "category": payload.get("category", "Web安全"),
        "difficulty": payload.get("difficulty", "入门"),
        "duration_min": int(payload.get("duration_min", 30)),
        "goals": list(payload.get("goals", [])),
        "prerequisites": list(payload.get("prerequisites", [])),
        "tags": list(payload.get("tags", [])),
        "cover": payload.get("cover", ""),
        "version": "1.0.0",
        "status": "draft",
        "rating": 0.0,
        "learner_count": 0,
        "created_at": _now(),
        "updated_at": _now(),
        "chapter_ids": [],
    }
    STORE.tutorials[tid] = tut
    STORE.versions[tid] = [{
        "version": "1.0.0", "status": "draft", "changelog": "创建草稿",
        "created_at": _now(), "author": payload.get("author", "author"),
    }]
    return tut


def list_tutorials(category: Optional[str] = None, difficulty: Optional[str] = None,
                   keyword: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
    out = list(STORE.tutorials.values())
    if category:
        out = [t for t in out if t["category"] == category]
    if difficulty:
        out = [t for t in out if t["difficulty"] == difficulty]
    if status:
        out = [t for t in out if t["status"] == status]
    if keyword:
        kw = keyword.lower()
        out = [t for t in out if kw in t["title"].lower()
               or kw in t["description"].lower()]
    return out


def get_tutorial(tid: str) -> Optional[Dict[str, Any]]:
    return STORE.tutorials.get(tid)


def update_tutorial(tid: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    t = STORE.tutorials.get(tid)
    if not t:
        return None
    for k in ("title", "description", "category", "difficulty", "duration_min",
              "goals", "prerequisites", "tags", "cover", "status"):
        if k in payload:
            t[k] = payload[k]
    t["updated_at"] = _now()
    return t


def delete_tutorial(tid: str) -> bool:
    if tid in STORE.tutorials:
        del STORE.tutorials[tid]
        STORE.versions.pop(tid, None)
        return True
    return False


# --------------------------------------------------------------------------- #
# 章节 / 内容块
# --------------------------------------------------------------------------- #
def add_chapter(tid: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    t = STORE.tutorials.get(tid)
    if not t:
        return None
    cid = _rid("ch")
    ch = {
        "id": cid, "tutorial_id": tid,
        "title": payload.get("title", "新章节"),
        "order": int(payload.get("order", len(t["chapter_ids"]) + 1)),
        "summary": payload.get("summary", ""),
        "block_ids": [], "created_at": _now(), "updated_at": _now(),
    }
    STORE.chapters[cid] = ch
    t["chapter_ids"].append(cid)
    return ch


def list_chapters(tid: str) -> List[Dict[str, Any]]:
    t = STORE.tutorials.get(tid)
    if not t:
        return []
    out = [STORE.chapters[c] for c in t["chapter_ids"] if c in STORE.chapters]
    return sorted(out, key=lambda x: x["order"])


def add_block(cid: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    ch = STORE.chapters.get(cid)
    if not ch:
        return None
    bid = _rid("blk")
    btype = payload.get("type", "markdown")
    blk = {
        "id": bid, "chapter_id": cid, "type": btype,
        "title": payload.get("title", ""),
        "content": payload.get("content", ""),
        "language": payload.get("language", ""),
        "interactive_config": payload.get("interactive_config", {}),
        "order": int(payload.get("order", len(ch["block_ids"]) + 1)),
        "created_at": _now(),
    }
    STORE.blocks[bid] = blk
    ch["block_ids"].append(bid)
    return blk


def list_blocks(cid: str) -> List[Dict[str, Any]]:
    ch = STORE.chapters.get(cid)
    if not ch:
        return []
    out = [STORE.blocks[b] for b in ch["block_ids"] if b in STORE.blocks]
    return sorted(out, key=lambda x: x["order"])


# --------------------------------------------------------------------------- #
# 模板
# --------------------------------------------------------------------------- #
def list_templates(ttype: Optional[str] = None) -> List[Dict[str, Any]]:
    out = list(STORE.templates.values())
    if ttype:
        out = [t for t in out if t["type"] == ttype]
    return out


def apply_template(tid: str, tpl_id: str, variables: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """把模板章节结构套用到指定教程，变量替换。"""
    t = STORE.tutorials.get(tid)
    tpl = STORE.templates.get(tpl_id)
    if not t or not tpl:
        return None
    created = []
    for i, ch_def in enumerate(tpl["chapters"], start=1):
        title = ch_def["title"]
        for k, v in (variables or {}).items():
            title = title.replace("{{" + k + "}}", str(v))
        ch = add_chapter(tid, {"title": title, "order": i,
                               "summary": tpl["description"]})
        if ch:
            created.append(ch["id"])
    return {"tutorial_id": tid, "template_id": tpl_id,
            "created_chapters": created, "variables_applied": variables or {}}


# --------------------------------------------------------------------------- #
# 版本管理
# --------------------------------------------------------------------------- #
def list_versions(tid: str) -> List[Dict[str, Any]]:
    return STORE.versions.get(tid, [])


def new_version(tid: str, version: str, changelog: str, author: str = "author") -> Optional[Dict[str, Any]]:
    t = STORE.tutorials.get(tid)
    if not t:
        return None
    rec = {"version": version, "status": "draft", "changelog": changelog,
           "created_at": _now(), "author": author}
    STORE.versions.setdefault(tid, []).append(rec)
    t["version"] = version
    t["updated_at"] = _now()
    return rec


def compare_versions(tid: str, v1: str, v2: str) -> Dict[str, Any]:
    vers = {v["version"]: v for v in STORE.versions.get(tid, [])}
    a, b = vers.get(v1), vers.get(v2)
    if not a or not b:
        return {"error": "版本不存在"}
    return {"tutorial_id": tid, "from": a, "to": b,
            "diff": [f"{v1} -> {v2}: {b.get('changelog', '')}"]}


def rollback_version(tid: str, version: str) -> Optional[Dict[str, Any]]:
    t = STORE.tutorials.get(tid)
    if not t:
        return None
    target = next((v for v in STORE.versions.get(tid, []) if v["version"] == version), None)
    if not target:
        return None
    t["version"] = version
    t["updated_at"] = _now()
    return {"tutorial_id": tid, "rolled_back_to": version,
            "status": t["status"]}


def publish_tutorial(tid: str) -> Optional[Dict[str, Any]]:
    t = STORE.tutorials.get(tid)
    if not t:
        return None
    t["status"] = "published"
    t["updated_at"] = _now()
    for v in STORE.versions.get(tid, []):
        if v["version"] == t["version"]:
            v["status"] = "published"
    return t


# --------------------------------------------------------------------------- #
# 分类字典
# --------------------------------------------------------------------------- #
def taxonomy() -> Dict[str, Any]:
    return {
        "difficulty": DIFFICULTY_LEVELS,
        "by_function": CATEGORY_BY_FUNCTION,
        "by_scenario": CATEGORY_BY_SCENARIO,
        "by_role": CATEGORY_BY_ROLE,
        "by_industry": CATEGORY_BY_INDUSTRY,
        "block_types": CONTENT_BLOCK_TYPES,
        "template_types": TEMPLATE_TYPES,
        "status": TUTORIAL_STATUS,
    }
