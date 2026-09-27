# -*- coding: utf-8 -*-
"""
data_crud.py — 数据管理 CRUD 后端。

实体：assets / vulns / tasks / reports / knowledge_base
支持增删改查、批量操作、高级筛选、分页、导入导出、行内编辑、数据验证。
"""
from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict, List, Optional

from .common import now_str, new_id, paginate, apply_filters, search_in


# --------------------------------------------------------------------------- #
# 数据存储
# --------------------------------------------------------------------------- #
DB: Dict[str, Dict[str, Dict[str, Any]]] = {
    "assets": {},
    "vulns": {},
    "tasks": {},
    "reports": {},
    "knowledge_base": {},
}

REQUIRED_FIELDS = {
    "assets": ["name", "ip_or_domain"],
    "vulns": ["title", "severity"],
    "tasks": ["name"],
    "reports": ["title"],
    "knowledge_base": ["title", "category"],
}

ENTITY_LABELS = {
    "assets": "资产", "vulns": "漏洞", "tasks": "任务",
    "reports": "报告", "knowledge_base": "知识库",
}


def _seed() -> None:
    if DB["assets"]:
        return
    assets = [
        ("api.example.com", "api.example.com", "web", "prod", "active", "10.0.3.21"),
        ("shop.example.com", "shop.example.com", "web", "prod", "active", "10.0.3.22"),
        ("db-master-01", "10.0.5.10", "database", "prod", "active", "10.0.5.10"),
        ("jenkins-ci", "ci.example.internal", "ci", "staging", "active", "10.0.6.4"),
        ("jump-bastion", "bastion.example.com", "infra", "prod", "active", "10.0.1.2"),
        ("old-blog", "blog.example.com", "web", "prod", "deprecated", "10.0.3.30"),
        ("k8s-master", "k8s.internal", "container", "prod", "active", "10.0.7.1"),
        ("backup-nas", "nas.internal", "storage", "prod", "active", "10.0.9.2"),
    ]
    for i, (name, host, atype, env, status, ip) in enumerate(assets):
        aid = f"asset_{200+i}"
        DB["assets"][aid] = {"id": aid, "name": name, "ip_or_domain": host,
                             "type": atype, "env": env, "status": status,
                             "ip": ip, "owner": "sec-team",
                             "created_at": now_str(), "updated_at": now_str()}

    vulns = [
        ("SQL 注入(登录接口)", "critical", "sql_injection", "high", "shop.example.com"),
        ("反射型 XSS(搜索)", "high", "xss", "open", "blog.example.com"),
        ("未授权访问(Redis)", "critical", "misconfig", "open", "db-master-01"),
        ("Jenkins 未授权控制台", "high", "misconfig", "in_progress", "jenkins-ci"),
        ("弱口令(admin)", "medium", "weak_password", "open", "jump-bastion"),
        ("过期 TLS 证书", "low", "tls", "fixed", "old-blog"),
    ]
    for i, (title, sev, vtype, st, asset) in enumerate(vulns):
        vid = f"vuln_{300+i}"
        DB["vulns"][vid] = {"id": vid, "title": title, "severity": sev,
                            "vuln_type": vtype, "status": st, "asset": asset,
                            "cvss": {"critical": 9.5, "high": 7.4,
                                     "medium": 5.3, "low": 3.1}.get(sev, 5.0),
                            "discovered_at": now_str(), "updated_at": now_str()}

    tasks = [
        ("周度 Web 巡检", "web_vuln_scan", "done", "shop.example.com"),
        ("API 回归测试", "api_security", "done", "api.example.com"),
        ("暗网泄露排查", "darkweb_monitor", "running", "corp.example.com"),
        ("供应链依赖扫描", "supply_chain", "pending", "backend/"),
    ]
    for i, (name, sc, st, tgt) in enumerate(tasks):
        tid = f"crud_task_{400+i}"
        DB["tasks"][tid] = {"id": tid, "name": name, "scenario": sc,
                            "status": st, "target": tgt,
                            "created_at": now_str(), "updated_at": now_str()}

    reports = [
        ("2026-Q3 Web 安全报告", "web", "done", 82),
        ("API 评估季度报告", "api", "done", 68),
        ("基线审计月报", "audit", "draft", 75),
    ]
    for i, (title, sc, st, score) in enumerate(reports):
        rid = f"crud_rep_{500+i}"
        DB["reports"][rid] = {"id": rid, "title": title, "category": sc,
                              "status": st, "risk_score": score,
                              "created_at": now_str(), "updated_at": now_str()}

    kbs = [
        ("如何修复 SQL 注入", "guideline", "sql,web", "使用参数化查询，避免拼接 SQL。"),
        ("XSS 防御清单", "guideline", "xss,web", "输出编码 + CSP + HttpOnly。"),
        ("CIS 基线检查脚本", "tool", "baseline,linux", "提供 ansible playbook 一键检测。"),
        ("应急响应 SOP", "sop", "incident", "发现入侵后断网、取证、上报流程。"),
        ("暗网监控接入指引", "guide", "threat", "配置关键词与告警阈值。"),
        ("供应链扫描使用手册", "guide", "supply", "如何接入 lockfile 与审批流。"),
    ]
    for i, (title, cat, tags, body) in enumerate(kbs):
        kid = f"kb_{600+i}"
        DB["knowledge_base"][kid] = {"id": kid, "title": title, "category": cat,
                                     "tags": tags, "content": body,
                                     "author": "sec-team",
                                     "created_at": now_str(), "updated_at": now_str()}


_seed()


def _validate_entity(entity: str) -> None:
    if entity not in DB:
        raise ValueError(f"未知实体: {entity}，可选 {sorted(DB.keys())}")


def _validate_payload(entity: str, data: Dict[str, Any]) -> None:
    for f in REQUIRED_FIELDS.get(entity, []):
        if f not in data or data[f] in (None, ""):
            raise ValueError(f"必填字段缺失: {f}")


# --------------------------------------------------------------------------- #
# CRUD
# --------------------------------------------------------------------------- #
def list_items(entity: str, page: int = 1, page_size: int = 20,
               q: str = "", filters: Optional[Dict[str, Any]] = None,
               sort_by: str = "created_at", sort_dir: str = "desc") -> Dict[str, Any]:
    _validate_entity(entity)
    items = list(DB[entity].values())
    items = apply_filters(items, filters or {})
    search_fields = ["title", "name", "status", "category", "severity", "tags"]
    items = search_in(items, q, search_fields)
    return paginate(items, page, page_size, sort_by, sort_dir)


def get_item(entity: str, item_id: str) -> Optional[Dict[str, Any]]:
    _validate_entity(entity)
    return DB[entity].get(item_id)


def create_item(entity: str, data: Dict[str, Any]) -> Dict[str, Any]:
    _validate_entity(entity)
    _validate_payload(entity, data)
    iid = data.get("id") or new_id(entity[:3])
    if iid in DB[entity]:
        raise ValueError(f"ID 已存在: {iid}（唯一性检查失败）")
    rec = dict(data)
    rec["id"] = iid
    rec["created_at"] = now_str()
    rec["updated_at"] = now_str()
    DB[entity][iid] = rec
    return rec


def update_item(entity: str, item_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    _validate_entity(entity)
    rec = DB[entity].get(item_id)
    if not rec:
        return None
    rec.update({k: v for k, v in data.items() if k != "id"})
    rec["updated_at"] = now_str()
    return rec


def patch_field(entity: str, item_id: str, field: str,
                value: Any) -> Optional[Dict[str, Any]]:
    rec = update_item(entity, item_id, {field: value})
    return rec


def delete_item(entity: str, item_id: str) -> bool:
    _validate_entity(entity)
    return DB[entity].pop(item_id, None) is not None


def batch_delete(entity: str, ids: List[str]) -> Dict[str, int]:
    _validate_entity(entity)
    removed = 0
    for i in ids:
        if DB[entity].pop(i, None) is not None:
            removed += 1
    return {"removed": removed, "requested": len(ids)}


def batch_update(entity: str, ids: List[str],
                 patch: Dict[str, Any]) -> Dict[str, int]:
    _validate_entity(entity)
    updated = 0
    for i in ids:
        rec = DB[entity].get(i)
        if rec:
            rec.update(patch)
            rec["updated_at"] = now_str()
            updated += 1
    return {"updated": updated, "requested": len(ids)}


def export_data(entity: str, fmt: str = "json") -> Dict[str, Any]:
    _validate_entity(entity)
    rows = list(DB[entity].values())
    if fmt == "csv":
        buf = io.StringIO()
        if rows:
            keys = sorted({k for r in rows for k in r.keys()})
            w = csv.DictWriter(buf, fieldnames=keys)
            w.writeheader()
            for r in rows:
                w.writerow(r)
        content = buf.getvalue()
    else:
        content = json.dumps(rows, ensure_ascii=False, indent=2)
    return {"entity": entity, "format": fmt, "count": len(rows),
            "filename": f"{entity}_export.{fmt}", "content": content}


def import_data(entity: str, content: str, fmt: str = "json") -> Dict[str, Any]:
    _validate_entity(entity)
    added = 0
    errors: List[str] = []
    if fmt == "csv":
        buf = io.StringIO(content)
        reader = csv.DictReader(buf)
        rows = list(reader)
    else:
        rows = json.loads(content)
        if isinstance(rows, dict):
            rows = [rows]
    for r in rows:
        try:
            create_item(entity, r)
            added += 1
        except Exception as e:  # noqa: BLE001
            errors.append(str(e))
    return {"added": added, "errors": errors[:10],
            "total_rows": len(rows)}
