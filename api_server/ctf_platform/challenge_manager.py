# -*- coding: utf-8 -*-
"""ctf_platform.challenge_manager — 题目与靶场管理模块。

设计定位：CTF 安全训练与教育平台的题目生命周期管理。
全部数据保存在内存字典中，不依赖任何数据库；支持题目 CRUD、分类标签、
Docker 风格靶场生命周期模拟、静态/动态 Flag、版本与审核。
"""

from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from typing import Any, Dict, List, Optional


CATEGORIES = [
    {"key": "Web", "name": "Web 安全", "color": "#3b82f6"},
    {"key": "Pwn", "name": "二进制漏洞利用", "color": "#ef4444"},
    {"key": "Reverse", "name": "逆向工程", "color": "#a855f7"},
    {"key": "Crypto", "name": "密码学", "color": "#10b981"},
    {"key": "Misc", "name": "杂项", "color": "#f59e0b"},
    {"key": "Forensics", "name": "取证分析", "color": "#06b6d4"},
    {"key": "Mobile", "name": "移动安全", "color": "#ec4899"},
    {"key": "Blockchain", "name": "区块链安全", "color": "#8b5cf6"},
    {"key": "IoT", "name": "物联网安全", "color": "#14b8a6"},
    {"key": "AI", "name": "AI 安全", "color": "#f97316"},
]

DIFFICULTIES = [
    {"key": "easy", "name": "入门", "score_base": 100, "color": "#22c55e"},
    {"key": "medium", "name": "进阶", "score_base": 300, "color": "#eab308"},
    {"key": "hard", "name": "高级", "score_base": 500, "color": "#f97316"},
    {"key": "expert", "name": "专家", "score_base": 800, "color": "#ef4444"},
]

STATUSES = ["draft", "reviewing", "published", "offline", "archived"]

_RANDOM_TOPICS = [
    "SQL 注入", "XSS", "SSRF", "文件上传", "反序列化", "缓冲区溢出",
    "ROP", "堆利用", "异或", "Base64", "RSA", "AES", "流量分析",
    "内存取证", "APK 逆向", "智能合约重入", "固件分析", "提示注入",
]


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


class ChallengeManager:
    """题目与靶场管理。"""

    def __init__(self) -> None:
        self.challenges: Dict[str, Dict[str, Any]] = {}
        self.containers: Dict[str, Dict[str, Any]] = {}
        self.versions: Dict[str, List[Dict[str, Any]]] = {}
        self.reviews: Dict[str, List[Dict[str, Any]]] = []
        self.flags: Dict[str, Dict[str, str]] = {}  # user -> challenge -> flag
        self._seed()

    # ------------------------------------------------------------------ #
    # 种子数据
    # ------------------------------------------------------------------ #
    def _seed(self) -> None:
        demo = [
            ("Web 入门：登录绕过", "Web", "easy", 100,
             "给出一个简单登录页，提示万能密码。"),
            ("SSRF 内网探测", "Web", "medium", 300,
             "通过 URL 抓取功能访问内网元数据服务。"),
            ("栈溢出入门", "Pwn", "easy", 100,
             "32 位二进制，栈上覆盖返回地址。"),
            ("RSA 共模攻击", "Crypto", "medium", 300,
             "两组密文使用相同模数不同指数。"),
            ("Flask Session 伪造", "Web", "hard", 500,
             "已知 secret_key 即可伪造 session。"),
            ("Android 抓包与脱壳", "Mobile", "medium", 300,
             "分析加固 APK，提取 flag。"),
            ("区块链重入", "Blockchain", "expert", 800,
             "EVM 智能合约重入漏洞。"),
            ("PCAP 流量取证书", "Forensics", "easy", 100,
             "从 pcap 中提取 HTTP 传输的 flag。"),
            ("异或加密文件", "Misc", "easy", 100,
             "单字节异或，频率分析。"),
            ("AI 提示注入", "AI", "hard", 500,
             "通过间接提示注入泄露系统提示。"),
        ]
        for idx, (name, cat, diff, score, desc) in enumerate(demo, 1):
            cid = f"chal_{1000 + idx}"
            ch = {
                "id": cid,
                "title": name,
                "category": cat,
                "difficulty": diff,
                "score": score,
                "description": desc,
                "flag": f"flag{{demo_{hashlib.md5(cid.encode()).hexdigest()[:8]}}}",
                "dynamic_flag": False,
                "hints": [{"order": 1, "content": "先观察输入与回显。", "penalty": 20}],
                "attachments": [{"name": f"{cid}.zip", "size_kb": 128}],
                "writeup": "示例 Writeup 见赛后发布。",
                "author": "demo_author",
                "source": "internal",
                "status": "published",
                "tags": [_RANDOM_TOPICS[idx % len(_RANDOM_TOPICS)]],
                "cve_refs": [],
                "tool_refs": ["Burp Suite", "Ghidra"],
                "depends_on": [],
                "quality_score": 4.5,
                "solves": 0,
                "submits": 0,
                "created_at": _now(),
                "updated_at": _now(),
                "version": 1,
            }
            self.challenges[cid] = ch
            self.versions[cid] = [{
                "version": 1, "changed_by": "demo_author",
                "changed_at": _now(), "note": "初始版本",
            }]

    # ------------------------------------------------------------------ #
    # 题目 CRUD
    # ------------------------------------------------------------------ #
    def list_challenges(self, category: Optional[str] = None,
                        difficulty: Optional[str] = None,
                        status: Optional[str] = None,
                        keyword: Optional[str] = None) -> Dict[str, Any]:
        items = list(self.challenges.values())
        if category:
            items = [c for c in items if c["category"] == category]
        if difficulty:
            items = [c for c in items if c["difficulty"] == difficulty]
        if status:
            items = [c for c in items if c["status"] == status]
        if keyword:
            kw = keyword.lower()
            items = [c for c in items
                     if kw in c["title"].lower() or kw in c["description"].lower()]
        return {
            "total": len(items),
            "challenges": [{
                "id": c["id"], "title": c["title"], "category": c["category"],
                "difficulty": c["difficulty"], "score": c["score"],
                "status": c["status"], "tags": c["tags"],
                "solves": c["solves"], "submits": c["submits"],
                "author": c["author"], "version": c["version"],
            } for c in items],
            "categories": CATEGORIES,
            "difficulties": DIFFICULTIES,
        }

    def get_challenge(self, cid: str) -> Optional[Dict[str, Any]]:
        return self.challenges.get(cid)

    def create_challenge(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        cid = _uid("chal")
        diff = payload.get("difficulty", "easy")
        base = next((d["score_base"] for d in DIFFICULTIES if d["key"] == diff), 100)
        ch = {
            "id": cid,
            "title": payload.get("title", "未命名题目"),
            "category": payload.get("category", "Misc"),
            "difficulty": diff,
            "score": int(payload.get("score", base)),
            "description": payload.get("description", ""),
            "flag": payload.get("flag", f"flag{{{secrets.token_hex(4)}}}"),
            "dynamic_flag": bool(payload.get("dynamic_flag", False)),
            "hints": payload.get("hints", []),
            "attachments": payload.get("attachments", []),
            "writeup": payload.get("writeup", ""),
            "author": payload.get("author", "admin"),
            "source": payload.get("source", "internal"),
            "status": "draft",
            "tags": payload.get("tags", []),
            "cve_refs": payload.get("cve_refs", []),
            "tool_refs": payload.get("tool_refs", []),
            "depends_on": payload.get("depends_on", []),
            "quality_score": float(payload.get("quality_score", 3.0)),
            "solves": 0, "submits": 0,
            "created_at": _now(), "updated_at": _now(), "version": 1,
        }
        self.challenges[cid] = ch
        self.versions[cid] = [{
            "version": 1, "changed_by": ch["author"],
            "changed_at": _now(), "note": "初始版本",
        }]
        return ch

    def update_challenge(self, cid: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ch = self.challenges.get(cid)
        if not ch:
            return None
        for k in ("title", "description", "flag", "score", "category",
                  "difficulty", "writeup", "tags", "hints", "attachments",
                  "cve_refs", "tool_refs", "depends_on"):
            if k in payload:
                ch[k] = payload[k]
        ch["version"] += 1
        ch["updated_at"] = _now()
        self.versions.setdefault(cid, []).append({
            "version": ch["version"],
            "changed_by": payload.get("changed_by", ch["author"]),
            "changed_at": _now(),
            "note": payload.get("note", "更新"),
        })
        return ch

    def delete_challenge(self, cid: str) -> bool:
        if cid in self.challenges:
            del self.challenges[cid]
            self.versions.pop(cid, None)
            return True
        return False

    # ------------------------------------------------------------------ #
    # 审核与发布
    # ------------------------------------------------------------------ #
    def submit_review(self, cid: str, reviewer: str, opinion: str,
                      action: str = "approve") -> Optional[Dict[str, Any]]:
        ch = self.challenges.get(cid)
        if not ch:
            return None
        record = {
            "challenge_id": cid, "reviewer": reviewer, "opinion": opinion,
            "action": action, "reviewed_at": _now(),
        }
        self.reviews.append(record)
        if action == "approve":
            ch["status"] = "published"
        elif action == "reject":
            ch["status"] = "draft"
        elif action == "offline":
            ch["status"] = "offline"
        return record

    def list_reviews(self) -> List[Dict[str, Any]]:
        return list(self.reviews)

    def list_versions(self, cid: str) -> List[Dict[str, Any]]:
        return self.versions.get(cid, [])

    # ------------------------------------------------------------------ #
    # 在线靶场（Docker 容器化模拟）
    # ------------------------------------------------------------------ #
    def start_container(self, cid: str, user: str) -> Dict[str, Any]:
        ch = self.challenges.get(cid)
        if not ch:
            return {"error": "题目不存在"}
        cid2 = _uid("ctf")
        port = 20000 + (secrets.randbelow(1500))
        container = {
            "container_id": cid2,
            "challenge_id": cid,
            "user": user,
            "image": f"ctf/{ch['category'].lower()}:latest",
            "status": "running",
            "port_mapping": {"host": port, "container": 80},
            "resources": {"cpu": "0.5", "memory": "512Mi", "disk": "100Mi"},
            "started_at": _now(),
            "expires_at": time.strftime("%Y-%m-%d %H:%M:%S",
                                        time.localtime(time.time() + 1800)),
            "health": "healthy",
            "access_url": f"http://lab.internal:{port}",
        }
        self.containers[cid2] = container
        if ch["dynamic_flag"]:
            self._assign_dynamic_flag(cid, user, cid2)
        return container

    def stop_container(self, container_id: str) -> bool:
        c = self.containers.get(container_id)
        if not c:
            return False
        c["status"] = "stopped"
        c["stopped_at"] = _now()
        return True

    def list_containers(self, user: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.containers.values())
        if user:
            items = [c for c in items if c["user"] == user]
        return items

    def health_check(self, container_id: str) -> Dict[str, Any]:
        c = self.containers.get(container_id)
        if not c:
            return {"error": "容器不存在"}
        c["health"] = "healthy" if c["status"] == "running" else "stopped"
        return c

    def gc_expired(self) -> int:
        now = time.time()
        freed = 0
        for c in self.containers.values():
            if c["status"] != "running":
                continue
            try:
                exp = time.mktime(time.strptime(c["expires_at"], "%Y-%m-%d %H:%M:%S"))
            except Exception:
                continue
            if exp < now:
                c["status"] = "expired"
                freed += 1
        return freed

    # ------------------------------------------------------------------ #
    # 动态 Flag
    # ------------------------------------------------------------------ #
    def _assign_dynamic_flag(self, cid: str, user: str, container_id: str) -> str:
        raw = f"{cid}|{user}|{secrets.token_hex(8)}"
        flag = f"flag{{{hashlib.sha256(raw.encode()).hexdigest()[:16]}}}"
        self.flags.setdefault(user, {})[cid] = flag
        self.flags.setdefault("__container__", {})[container_id] = flag
        return flag

    def get_dynamic_flag(self, cid: str, user: str) -> Optional[str]:
        return self.flags.get(user, {}).get(cid)

    def rotate_flag(self, cid: str, user: str) -> Optional[str]:
        if cid not in self.challenges:
            return None
        return self._assign_dynamic_flag(cid, user, _uid("ctf"))

    # ------------------------------------------------------------------ #
    # 统计
    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        by_cat: Dict[str, int] = {}
        by_diff: Dict[str, int] = {}
        for c in self.challenges.values():
            by_cat[c["category"]] = by_cat.get(c["category"], 0) + 1
            by_diff[c["difficulty"]] = by_diff.get(c["difficulty"], 0) + 1
        return {
            "total": len(self.challenges),
            "by_category": by_cat,
            "by_difficulty": by_diff,
            "published": sum(1 for c in self.challenges.values() if c["status"] == "published"),
            "running_containers": sum(1 for c in self.containers.values() if c["status"] == "running"),
            "total_containers": len(self.containers),
            "pending_reviews": len([r for r in self.reviews if r["action"] not in ("approve", "reject")]),
        }


_manager_singleton: Optional[ChallengeManager] = None


def get_challenge_manager() -> ChallengeManager:
    global _manager_singleton
    if _manager_singleton is None:
        _manager_singleton = ChallengeManager()
    return _manager_singleton
