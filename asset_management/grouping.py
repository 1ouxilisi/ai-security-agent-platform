# -*- coding: utf-8 -*-
"""
asset_management.grouping - 资产分组管理器

功能：
    - 树形分组（parent_id 层级）
    - 分组成员管理、自动分组（类型/部门/位置/重要性/风险评级/标签）
    - 分组统计（资产数/漏洞数/平均风险/修复率）
    - 批量扫描 / 批量报告（生成扫描任务占位）

数据库表：am_groups, am_group_members
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.database import db
from utils.logger import log


def _now() -> str:
    return datetime.now().isoformat()


class GroupingManager:
    """资产分组管理器"""

    def __init__(self) -> None:
        """初始化并建表。"""
        self._ensure_tables()

    def _ensure_tables(self) -> None:
        """创建分组表与分组成员表。"""
        conn = db._get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS am_groups (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    parent_id TEXT,
                    owner TEXT,
                    scan_policy TEXT,
                    alert_policy TEXT,
                    report_policy TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS am_group_members (
                    group_id TEXT,
                    asset_id TEXT,
                    joined_at TEXT,
                    PRIMARY KEY (group_id, asset_id)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_am_grp_parent ON am_groups(parent_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_am_gm_asset ON am_group_members(asset_id)")
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"创建分组表失败: {e}")
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 分组 CRUD
    # ------------------------------------------------------------------ #
    def list_groups(self) -> Dict[str, Any]:
        """列出分组，支持树形结构（按 parent_id 层级）。"""
        conn = db._get_connection()
        try:
            rows = conn.execute("SELECT * FROM am_groups ORDER BY created_at ASC").fetchall()
        finally:
            conn.close()
        groups = {}
        for r in rows:
            d = dict(r)
            for jf in ("scan_policy", "alert_policy", "report_policy"):
                if d.get(jf):
                    try:
                        d[jf] = json.loads(d[jf])
                    except Exception:
                        pass
            d["children"] = []
            groups[d["id"]] = d
        # 组装树
        roots = []
        for g in groups.values():
            pid = g.get("parent_id")
            if pid and pid in groups:
                groups[pid]["children"].append(g)
            else:
                roots.append(g)
        return {"total": len(groups), "tree": roots, "flat": list(groups.values())}

    def create_group(self, name: str, description: str = "",
                     parent_id: Optional[str] = None, owner: str = "",
                     scan_policy: Optional[Dict] = None,
                     alert_policy: Optional[Dict] = None,
                     report_policy: Optional[Dict] = None) -> Dict[str, Any]:
        """创建分组。"""
        gid = f"am-grp-{uuid.uuid4().hex[:10]}"
        now = _now()
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO am_groups
                    (id, name, description, parent_id, owner, scan_policy,
                     alert_policy, report_policy, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (gid, name, description, parent_id, owner,
                  json.dumps(scan_policy or {}, ensure_ascii=False),
                  json.dumps(alert_policy or {}, ensure_ascii=False),
                  json.dumps(report_policy or {}, ensure_ascii=False), now, now))
            conn.commit()
            return {"success": True, "id": gid}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def update_group(self, group_id: str, **fields) -> Dict[str, Any]:
        """更新分组。"""
        allowed = {"name", "description", "parent_id", "owner",
                   "scan_policy", "alert_policy", "report_policy"}
        sets, params = [], []
        for k, v in fields.items():
            if k in allowed and v is not None:
                if k in ("scan_policy", "alert_policy", "report_policy"):
                    v = json.dumps(v, ensure_ascii=False)
                sets.append(f"{k}=?")
                params.append(v)
        if not sets:
            return {"success": False, "error": "无更新字段"}
        sets.append("updated_at=?")
        params.append(_now())
        params.append(group_id)
        conn = db._get_connection()
        try:
            cur = conn.execute(
                f"UPDATE am_groups SET {', '.join(sets)} WHERE id=?", params)
            conn.commit()
            if cur.rowcount == 0:
                return {"success": False, "error": "分组不存在"}
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def delete_group(self, group_id: str) -> Dict[str, Any]:
        """删除分组（同时处理子组与成员）。"""
        conn = db._get_connection()
        try:
            # 收集所有子孙组
            to_delete = self._collect_descendants(group_id, conn)
            for gid in to_delete:
                conn.execute("DELETE FROM am_group_members WHERE group_id=?", (gid,))
                conn.execute("DELETE FROM am_groups WHERE id=?", (gid,))
            conn.commit()
            return {"success": True, "deleted_groups": len(to_delete)}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    @staticmethod
    def _collect_descendants(group_id: str, conn) -> List[str]:
        """递归收集所有子孙分组 ID。"""
        result = [group_id]
        stack = [group_id]
        while stack:
            cur = stack.pop()
            children = conn.execute(
                "SELECT id FROM am_groups WHERE parent_id=?", (cur,)).fetchall()
            for c in children:
                result.append(c["id"])
                stack.append(c["id"])
        return result

    # ------------------------------------------------------------------ #
    # 成员管理
    # ------------------------------------------------------------------ #
    def get_group_assets(self, group_id: str) -> Dict[str, Any]:
        """获取分组成员列表。"""
        conn = db._get_connection()
        try:
            rows = conn.execute("""
                SELECT a.*, m.joined_at FROM am_group_members m
                LEFT JOIN assets a ON a.id = m.asset_id
                WHERE m.group_id=?
            """, (group_id,)).fetchall()
            items = [dict(r) for r in rows]
            return {"group_id": group_id, "total": len(items), "items": items}
        finally:
            conn.close()

    def add_asset_to_group(self, group_id: str, asset_id: str) -> Dict[str, Any]:
        """把资产加入分组。"""
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT OR IGNORE INTO am_group_members (group_id, asset_id, joined_at)
                VALUES (?, ?, ?)
            """, (group_id, asset_id, _now()))
            conn.commit()
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def remove_asset_from_group(self, group_id: str, asset_id: str) -> Dict[str, Any]:
        """从分组移除资产。"""
        conn = db._get_connection()
        try:
            conn.execute("DELETE FROM am_group_members WHERE group_id=? AND asset_id=?",
                         (group_id, asset_id))
            conn.commit()
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 自动分组
    # ------------------------------------------------------------------ #
    def auto_group(self, key: str = "asset_type") -> Dict[str, Any]:
        """按类型/部门/位置/重要性/风险评级自动分组。"""
        valid_keys = {"asset_type", "department", "location",
                      "importance", "risk_level"}
        if key not in valid_keys:
            return {"success": False, "error": f"不支持的分组维度: {key}"}
        conn = db._get_connection()
        try:
            rows = conn.execute("SELECT * FROM assets").fetchall()
        finally:
            conn.close()

        groups_map: Dict[str, List[str]] = {}
        for r in rows:
            d = dict(r)
            if key == "risk_level":
                score = d.get("risk_score") or 0
                val = ("critical" if score > 90 else "high" if score >= 70
                       else "medium" if score >= 40 else "low")
            else:
                val = d.get(key) or "unknown"
            groups_map.setdefault(str(val), []).append(d["id"])

        created = 0
        for val, asset_ids in groups_map.items():
            gname = f"auto_{key}_{val}"
            # 避免重复创建
            conn = db._get_connection()
            try:
                exists = conn.execute("SELECT id FROM am_groups WHERE name=?",
                                      (gname,)).fetchone()
                if exists:
                    gid = exists["id"]
                else:
                    gid = f"am-grp-{uuid.uuid4().hex[:10]}"
                    conn.execute("""
                        INSERT INTO am_groups (id, name, description, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?)
                    """, (gid, gname, f"自动按{key}分组: {val}", _now(), _now()))
                for aid in asset_ids:
                    conn.execute("""
                        INSERT OR IGNORE INTO am_group_members (group_id, asset_id, joined_at)
                        VALUES (?, ?, ?)
                    """, (gid, aid, _now()))
                conn.commit()
                created += 1
            except Exception as e:  # pragma: no cover
                log.warning(f"自动分组 {gname} 失败: {e}")
            finally:
                conn.close()
        return {"success": True, "dimension": key, "groups_created": created,
                "buckets": {k: len(v) for k, v in groups_map.items()}}

    # ------------------------------------------------------------------ #
    # 统计 / 批量操作
    # ------------------------------------------------------------------ #
    def get_group_stats(self, group_id: str) -> Dict[str, Any]:
        """分组统计：资产数/漏洞数/平均风险评级/修复率。"""
        conn = db._get_connection()
        try:
            members = conn.execute("""
                SELECT asset_id FROM am_group_members WHERE group_id=?
            """, (group_id,)).fetchall()
            asset_ids = [m["asset_id"] for m in members]
            asset_count = len(asset_ids)
            # 平均风险
            avg_risk = 0.0
            level_dist: Dict[str, int] = {}
            vuln_count = 0
            fixed_count = 0
            if asset_ids:
                ph = ",".join("?" for _ in asset_ids)
                rows = conn.execute(
                    f"SELECT risk_score FROM assets WHERE id IN ({ph})", asset_ids).fetchall()
                scores = [r["risk_score"] or 0 for r in rows]
                avg_risk = round(sum(scores) / len(scores), 2) if scores else 0.0
                for s in scores:
                    lv = "critical" if s > 90 else "high" if s >= 70 else "medium" if s >= 40 else "low"
                    level_dist[lv] = level_dist.get(lv, 0) + 1
                # 关联漏洞（按 IP/域名）
                ip_rows = conn.execute(
                    f"SELECT ip, domain FROM assets WHERE id IN ({ph})", asset_ids).fetchall()
                targets = []
                for r in ip_rows:
                    if r["ip"]:
                        targets.append(r["ip"])
                    if r["domain"]:
                        targets.append(r["domain"])
                if targets:
                    tph = ",".join("?" for _ in targets)
                    try:
                        vrows = conn.execute(
                            f"SELECT status FROM vulnerabilities WHERE target IN ({tph})",
                            targets).fetchall()
                        for v in vrows:
                            vuln_count += 1
                            if (v["status"] or "").lower() in ("fixed", "closed", "resolved"):
                                fixed_count += 1
                    except Exception:
                        pass
            fix_rate = round((fixed_count / vuln_count * 100), 1) if vuln_count else 0.0
            return {
                "group_id": group_id, "asset_count": asset_count,
                "vuln_count": vuln_count, "fixed_count": fixed_count,
                "fix_rate_percent": fix_rate,
                "avg_risk_score": avg_risk, "level_distribution": level_dist,
            }
        finally:
            conn.close()

    def batch_scan(self, group_id: str) -> Dict[str, Any]:
        """批量扫描分组成员（生成扫描任务占位，不真实执行）。"""
        members = self.get_group_assets(group_id)
        targets = [a.get("ip") or a.get("domain") for a in members.get("items", []) if a]
        task_id = f"am-scan-{uuid.uuid4().hex[:10]}"
        log.info(f"批量扫描任务已创建: {task_id}, 目标数={len(targets)}")
        return {"success": True, "task_id": task_id, "group_id": group_id,
                "targets": len(targets), "target_ips": targets[:50]}

    def batch_report(self, group_id: str) -> Dict[str, Any]:
        """批量生成分组报告（占位）。"""
        stats = self.get_group_stats(group_id)
        report_id = f"am-rpt-{uuid.uuid4().hex[:10]}"
        return {"success": True, "report_id": report_id, "group_id": group_id,
                "summary": stats, "generated_at": _now()}


# 全局单例
grouping_manager = GroupingManager()
