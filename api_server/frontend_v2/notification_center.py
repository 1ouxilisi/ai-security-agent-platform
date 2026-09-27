# -*- coding: utf-8 -*-
"""
notification_center.py — 实时通知与活动流后端。

通知管理 / 类型 / 未读计数 / 活动流 / 通知设置。
前端通过轮询 /notifications 与 /activity 获取最新数据，模拟实时推送。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .common import now_str, new_id, paginate


NOTIFICATIONS: Dict[str, Dict[str, Any]] = {}
ACTIVITY: List[Dict[str, Any]] = []

SETTINGS: Dict[str, Any] = {
    "types": {
        "task_done": True, "task_failed": True,
        "security_alert": True, "system": True, "update": False,
    },
    "channels": {"web": True, "email": False, "sms": False},
    "quiet_hours": {"enabled": False, "start": "23:00", "end": "08:00"},
}

VALID_TYPES = {"task_done", "task_failed", "security_alert", "system", "update"}


def _seed() -> None:
    if NOTIFICATIONS:
        return
    seeds = [
        ("task_done", "任务完成：Web 主站漏洞扫描", "shop.example.com 扫描完成，发现 202 项发现。", False),
        ("security_alert", "高危告警：Redis 未授权访问", "db-master-01:6379 暴露公网，请立即处置。", False),
        ("task_failed", "任务失败：API 接口评估", "目标连接超时，已终止。", False),
        ("system", "系统升级完成", "前端控制台已升级至 v2.0，新增交互面板。", True),
        ("update", "新版本提示", "frontend_v2 模块已发布更新。", True),
        ("task_done", "任务完成：暗网泄露监控", "未发现新增泄露凭证。", True),
        ("security_alert", "中危告警：弱口令策略", "jump-bastion 允许弱口令登录。", False),
    ]
    for i, (t, title, body, read) in enumerate(seeds):
        nid = f"ntf_{700+i}"
        NOTIFICATIONS[nid] = {
            "id": nid, "type": t, "title": title, "body": body,
            "read": read, "created_at": now_str(),
        }
    acts = [
        ("task", "任务 task_seed_1000 完成", "shop.example.com"),
        ("vuln", "新增高危漏洞：Jenkins 未授权控制台", "jenkins-ci"),
        ("system", "配置备份完成", "nightly"),
        ("user", "分析师 alice 更新漏洞状态为 fixed", "vuln_300"),
        ("task", "任务 task_seed_1005 开始执行", "backend/requirements.txt"),
        ("vuln", "误报标记：过期 TLS 证书", "old-blog"),
        ("system", "缓存预热完成", "assets/vulns"),
    ]
    for i, (kind, title, ref) in enumerate(acts):
        ACTIVITY.append({
            "id": new_id("act"), "kind": kind, "title": title, "ref": ref,
            "created_at": now_str(),
        })


_seed()


def list_notifications(ntype: str = "", unread_only: bool = False,
                       page: int = 1, page_size: int = 20) -> Dict[str, Any]:
    items = list(NOTIFICATIONS.values())
    if ntype and ntype != "all":
        items = [n for n in items if n["type"] == ntype]
    if unread_only:
        items = [n for n in items if not n["read"]]
    items.sort(key=lambda x: x["created_at"], reverse=True)
    return paginate(items, page, page_size, "created_at", "desc")


def create_notification(ntype: str, title: str,
                         body: str = "") -> Dict[str, Any]:
    if ntype not in VALID_TYPES:
        raise ValueError(f"非法通知类型: {ntype}")
    nid = new_id("ntf")
    n = {"id": nid, "type": ntype, "title": title, "body": body,
         "read": False, "created_at": now_str()}
    NOTIFICATIONS[nid] = n
    return n


def mark_read(nid: str) -> Optional[Dict[str, Any]]:
    n = NOTIFICATIONS.get(nid)
    if not n:
        return None
    n["read"] = True
    return n


def mark_all_read() -> int:
    count = 0
    for n in NOTIFICATIONS.values():
        if not n["read"]:
            n["read"] = True
            count += 1
    return count


def delete_notification(nid: str) -> bool:
    return NOTIFICATIONS.pop(nid, None) is not None


def clear_all() -> int:
    n = len(NOTIFICATIONS)
    NOTIFICATIONS.clear()
    return n


def unread_count() -> Dict[str, int]:
    out: Dict[str, int] = {t: 0 for t in VALID_TYPES}
    out["total"] = 0
    for n in NOTIFICATIONS.values():
        if not n["read"]:
            out[n["type"]] = out.get(n["type"], 0) + 1
            out["total"] += 1
    return out


def list_activity(kind: str = "", limit: int = 50) -> List[Dict[str, Any]]:
    items = list(ACTIVITY)
    if kind and kind != "all":
        items = [a for a in items if a["kind"] == kind]
    items.sort(key=lambda x: x["created_at"], reverse=True)
    return items[:limit]


def push_activity(kind: str, title: str, ref: str = "") -> Dict[str, Any]:
    a = {"id": new_id("act"), "kind": kind, "title": title, "ref": ref,
         "created_at": now_str()}
    ACTIVITY.insert(0, a)
    return a


def get_settings() -> Dict[str, Any]:
    return dict(SETTINGS)


def update_settings(patch: Dict[str, Any]) -> Dict[str, Any]:
    for k, v in patch.items():
        if k in SETTINGS and isinstance(v, dict):
            SETTINGS[k].update(v)
        elif k in SETTINGS:
            SETTINGS[k] = v
    return get_settings()
