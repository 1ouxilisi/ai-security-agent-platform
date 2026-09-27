# -*- coding: utf-8 -*-
"""
asset_management.change_detection - 资产变更检测器

功能：
    - 定期扫描资产快照，与基线对比，检测 8 类变更：
      new_asset / removed_asset / ip_change / port_change /
      service_change / os_change / config_change / risk_change
    - 变更审批（新增互联网暴露资产 / 开放高危端口等重要变更需审批）
    - 基线管理、变更统计、检测到变更自动写入 alerts 表

数据库表：am_changes, am_baselines
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.database import db
from utils.logger import log

CHANGE_TYPES = [
    "new_asset", "removed_asset", "ip_change", "port_change",
    "service_change", "os_change", "config_change", "risk_change",
]

# 需要审批的重要变更
_REQUIRE_APPROVAL = {"new_asset", "port_change", "ip_change"}
# 高危端口
_HIGH_RISK_PORTS = {21, 23, 135, 139, 445, 1433, 3306, 3389, 6379, 8080, 9200, 27017}


def _now() -> str:
    return datetime.now().isoformat()


class ChangeDetectionManager:
    """资产变更检测器"""

    def __init__(self) -> None:
        """初始化并建表。"""
        self._ensure_tables()

    def _ensure_tables(self) -> None:
        """创建变更记录表与资产基线表。"""
        conn = db._get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS am_changes (
                    id TEXT PRIMARY KEY,
                    asset_id TEXT,
                    change_type TEXT,
                    before_value TEXT,
                    after_value TEXT,
                    detected_at TEXT,
                    approved_by TEXT,
                    approved_at TEXT,
                    status TEXT DEFAULT 'pending',
                    description TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS am_baselines (
                    id TEXT PRIMARY KEY,
                    asset_id TEXT,
                    baseline_name TEXT,
                    snapshot TEXT,
                    created_at TEXT,
                    created_by TEXT,
                    is_active INTEGER DEFAULT 1
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_am_chg_type ON am_changes(change_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_am_chg_status ON am_changes(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_am_chg_asset ON am_changes(asset_id)")
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"创建变更检测表失败: {e}")
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 快照工具
    # ------------------------------------------------------------------ #
    @staticmethod
    def _current_snapshot() -> Dict[str, Dict[str, Any]]:
        """读取当前 assets 表，生成 asset_id -> 快照字典。"""
        conn = db._get_connection()
        try:
            rows = conn.execute("SELECT * FROM assets").fetchall()
        except Exception:
            return {}
        finally:
            conn.close()
        snap = {}
        for r in rows:
            d = dict(r)
            snap[d["id"]] = {
                "ip": d.get("ip"),
                "domain": d.get("domain"),
                "asset_type": d.get("asset_type"),
                "open_ports_count": d.get("open_ports_count") or 0,
                "risk_score": d.get("risk_score") or 0,
                "importance": d.get("importance"),
                "exposure_level": d.get("exposure_level"),
                "updated_at": d.get("updated_at"),
            }
        return snap

    # ------------------------------------------------------------------ #
    # 基线
    # ------------------------------------------------------------------ #
    def list_baselines(self) -> List[Dict[str, Any]]:
        """列出所有基线。"""
        conn = db._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM am_baselines ORDER BY created_at DESC").fetchall()
            items = []
            for r in rows:
                d = dict(r)
                if d.get("snapshot"):
                    try:
                        d["snapshot"] = json.loads(d["snapshot"])
                    except Exception:
                        pass
                items.append(d)
            return items
        finally:
            conn.close()

    def create_baseline(self, baseline_name: str,
                         created_by: str = "system",
                         asset_id: Optional[str] = None) -> Dict[str, Any]:
        """创建资产基线快照。"""
        snap = self._current_snapshot()
        if asset_id and asset_id in snap:
            snap = {asset_id: snap[asset_id]}
        baseline_id = f"am-bl-{uuid.uuid4().hex[:10]}"
        conn = db._get_connection()
        try:
            # 新基线设为激活，其它取消
            conn.execute("UPDATE am_baselines SET is_active=0")
            conn.execute("""
                INSERT INTO am_baselines
                    (id, asset_id, baseline_name, snapshot, created_at, created_by, is_active)
                VALUES (?, ?, ?, ?, ?, ?, 1)
            """, (baseline_id, asset_id, baseline_name,
                  json.dumps(snap, ensure_ascii=False), _now(), created_by))
            conn.commit()
            return {"success": True, "id": baseline_id, "assets_snapshotted": len(snap)}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def delete_baseline(self, baseline_id: str) -> Dict[str, Any]:
        """删除基线。"""
        conn = db._get_connection()
        try:
            conn.execute("DELETE FROM am_baselines WHERE id=?", (baseline_id,))
            conn.commit()
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def _active_baseline_snapshot(self) -> Dict[str, Dict[str, Any]]:
        """读取激活基线快照。"""
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT snapshot FROM am_baselines WHERE is_active=1 "
                "ORDER BY created_at DESC LIMIT 1").fetchone()
            if not row:
                return {}
            try:
                return json.loads(row["snapshot"])
            except Exception:
                return {}
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 变更检测
    # ------------------------------------------------------------------ #
    def detect_changes(self, created_by: str = "system") -> Dict[str, Any]:
        """对比当前资产与基线，检测 8 类变更并写入 am_changes。"""
        baseline = self._active_baseline_snapshot()
        current = self._current_snapshot()
        new_changes: List[Dict[str, Any]] = []

        if not baseline:
            # 无基线：把所有现有资产记为 new_asset
            for aid, snap in current.items():
                new_changes.append(self._make_change(
                    aid, "new_asset", None, snap,
                    f"首次发现资产 {snap.get('ip') or aid}（无基线，全部记为新增）"))
        else:
            # 新增 / 移除
            for aid, snap in current.items():
                if aid not in baseline:
                    new_changes.append(self._make_change(
                        aid, "new_asset", None, snap,
                        f"检测到新增资产 {snap.get('ip') or aid}"))
            for aid, old in baseline.items():
                if aid not in current:
                    new_changes.append(self._make_change(
                        aid, "removed_asset", old, None,
                        f"资产 {old.get('ip') or aid} 已从资产列表移除"))
            # 属性变化
            for aid, old in baseline.items():
                cur = current.get(aid)
                if not cur:
                    continue
                if old.get("ip") != cur.get("ip"):
                    new_changes.append(self._make_change(
                        aid, "ip_change", {"ip": old.get("ip")}, {"ip": cur.get("ip")},
                        f"资产 {aid} IP 变更: {old.get('ip')} -> {cur.get('ip')}"))
                if (old.get("open_ports_count") or 0) != (cur.get("open_ports_count") or 0):
                    new_changes.append(self._make_change(
                        aid, "port_change",
                        {"open_ports_count": old.get("open_ports_count")},
                        {"open_ports_count": cur.get("open_ports_count")},
                        f"资产 {aid} 开放端口数变化: {old.get('open_ports_count')} -> {cur.get('open_ports_count')}"))
                if old.get("asset_type") != cur.get("asset_type"):
                    new_changes.append(self._make_change(
                        aid, "service_change",
                        {"asset_type": old.get("asset_type")},
                        {"asset_type": cur.get("asset_type")},
                        f"资产 {aid} 类型/服务变化: {old.get('asset_type')} -> {cur.get('asset_type')}"))
                if old.get("importance") != cur.get("importance") or \
                   old.get("exposure_level") != cur.get("exposure_level"):
                    new_changes.append(self._make_change(
                        aid, "config_change",
                        {"importance": old.get("importance"),
                         "exposure_level": old.get("exposure_level")},
                        {"importance": cur.get("importance"),
                         "exposure_level": cur.get("exposure_level")},
                        f"资产 {aid} 配置（重要性/暴露程度）发生变化"))
                old_risk = old.get("risk_score") or 0
                new_risk = cur.get("risk_score") or 0
                if abs(new_risk - old_risk) >= 10:
                    new_changes.append(self._make_change(
                        aid, "risk_change",
                        {"risk_score": old_risk}, {"risk_score": new_risk},
                        f"资产 {aid} 风险评分显著变化: {old_risk} -> {new_risk}"))
                # os_change 占位：基线快照暂不含 os，保持类型可扩展
                if old.get("os") != cur.get("os") and old.get("os"):
                    new_changes.append(self._make_change(
                        aid, "os_change", {"os": old.get("os")}, {"os": cur.get("os")},
                        f"资产 {aid} 操作系统变化"))

        # 落库 + 自动告警
        inserted = 0
        for ch in new_changes:
            self._insert_change(ch)
            inserted += 1
            try:
                self.auto_alert_on_change(ch)
            except Exception as e:  # pragma: no cover
                log.warning(f"变更自动告警失败: {e}")
        return {"success": True, "detected": inserted,
                "items": [{"change_type": c["change_type"], "asset_id": c["asset_id"],
                           "description": c["description"]} for c in new_changes]}

    def _make_change(self, asset_id: Optional[str], ctype: str,
                     before: Optional[Dict[str, Any]], after: Optional[Dict[str, Any]],
                     desc: str) -> Dict[str, Any]:
        """构造一条变更记录。"""
        status = "pending" if ctype in _REQUIRE_APPROVAL else "approved"
        return {
            "asset_id": asset_id,
            "change_type": ctype,
            "before_value": before,
            "after_value": after,
            "description": desc,
            "status": status,
        }

    def _insert_change(self, ch: Dict[str, Any]) -> None:
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO am_changes
                    (id, asset_id, change_type, before_value, after_value,
                     detected_at, approved_by, approved_at, status, description)
                VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
            """, (f"am-chg-{uuid.uuid4().hex[:10]}", ch.get("asset_id"),
                  ch["change_type"],
                  json.dumps(ch.get("before_value"), ensure_ascii=False),
                  json.dumps(ch.get("after_value"), ensure_ascii=False),
                  _now(), ch["status"], ch.get("description", "")))
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"写入变更记录失败: {e}")
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 变更查询与审批
    # ------------------------------------------------------------------ #
    def list_changes(self, change_type: Optional[str] = None,
                     status: Optional[str] = None,
                     asset_id: Optional[str] = None,
                     page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """列出变更记录（筛选 + 分页）。"""
        conn = db._get_connection()
        try:
            where, params = " WHERE 1=1 ", []
            if change_type:
                where += " AND change_type=?"
                params.append(change_type)
            if status:
                where += " AND status=?"
                params.append(status)
            if asset_id:
                where += " AND asset_id=?"
                params.append(asset_id)
            total = conn.execute(
                f"SELECT COUNT(*) FROM am_changes {where}", params).fetchone()[0]
            start = (max(1, page) - 1) * max(1, page_size)
            rows = conn.execute(
                f"SELECT * FROM am_changes {where} ORDER BY detected_at DESC LIMIT ? OFFSET ?",
                params + [page_size, start]).fetchall()
            items = []
            for r in rows:
                d = dict(r)
                for k in ("before_value", "after_value"):
                    if d.get(k):
                        try:
                            d[k] = json.loads(d[k])
                        except Exception:
                            pass
                items.append(d)
            return {"total": total, "page": page, "page_size": page_size, "items": items}
        finally:
            conn.close()

    def get_change_detail(self, change_id: str) -> Optional[Dict[str, Any]]:
        """获取变更详情。"""
        conn = db._get_connection()
        try:
            row = conn.execute("SELECT * FROM am_changes WHERE id=?",
                               (change_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            for k in ("before_value", "after_value"):
                if d.get(k):
                    try:
                        d[k] = json.loads(d[k])
                    except Exception:
                        pass
            return d
        finally:
            conn.close()

    def approve_change(self, change_id: str, approved_by: str = "admin") -> Dict[str, Any]:
        """审批通过变更。"""
        conn = db._get_connection()
        try:
            cur = conn.execute("""
                UPDATE am_changes SET status='approved', approved_by=?, approved_at=?
                WHERE id=?
            """, (approved_by, _now(), change_id))
            conn.commit()
            if cur.rowcount == 0:
                return {"success": False, "error": "变更记录不存在"}
            return {"success": True, "id": change_id}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def reject_change(self, change_id: str, approved_by: str = "admin") -> Dict[str, Any]:
        """驳回变更。"""
        conn = db._get_connection()
        try:
            cur = conn.execute("""
                UPDATE am_changes SET status='rejected', approved_by=?, approved_at=?
                WHERE id=?
            """, (approved_by, _now(), change_id))
            conn.commit()
            if cur.rowcount == 0:
                return {"success": False, "error": "变更记录不存在"}
            return {"success": True, "id": change_id}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 对比与统计
    # ------------------------------------------------------------------ #
    def compare_with_baseline(self, baseline_id: Optional[str] = None) -> Dict[str, Any]:
        """资产当前状态与基线对比。"""
        conn = db._get_connection()
        try:
            if baseline_id:
                row = conn.execute("SELECT snapshot FROM am_baselines WHERE id=?",
                                   (baseline_id,)).fetchone()
            else:
                row = conn.execute(
                    "SELECT snapshot FROM am_baselines WHERE is_active=1 "
                    "ORDER BY created_at DESC LIMIT 1").fetchone()
            if not row:
                return {"success": False, "error": "未找到基线"}
            baseline = json.loads(row["snapshot"] or "{}")
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()
        current = self._current_snapshot()
        added = [a for a in current if a not in baseline]
        removed = [a for a in baseline if a not in current]
        changed = []
        for aid in baseline:
            if aid in current and baseline[aid] != current[aid]:
                changed.append(aid)
        return {"success": True, "added": added, "removed": removed,
                "changed": changed,
                "added_count": len(added), "removed_count": len(removed),
                "changed_count": len(changed)}

    def get_change_stats(self) -> Dict[str, Any]:
        """按类型/状态统计变更。"""
        conn = db._get_connection()
        try:
            by_type = {r["change_type"]: r["cnt"] for r in conn.execute(
                "SELECT change_type, COUNT(*) AS cnt FROM am_changes GROUP BY change_type")}
            by_status = {r["status"]: r["cnt"] for r in conn.execute(
                "SELECT status, COUNT(*) AS cnt FROM am_changes GROUP BY status")}
            total = conn.execute("SELECT COUNT(*) FROM am_changes").fetchone()[0]
            return {"total": total, "by_type": by_type, "by_status": by_status}
        finally:
            conn.close()

    def auto_alert_on_change(self, change: Dict[str, Any]) -> None:
        """检测到变更时自动写入 alerts 表。"""
        # 重要变更才告警
        if change["change_type"] not in _REQUIRE_APPROVAL:
            return
        severity = "high" if change["change_type"] in ("new_asset", "port_change") else "medium"
        conn = db._get_connection()
        try:
            # 确保 alerts 表存在
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY, title TEXT NOT NULL, message TEXT,
                    severity TEXT DEFAULT 'info', category TEXT DEFAULT 'general',
                    target TEXT, details TEXT, created_at TEXT,
                    status TEXT DEFAULT 'new', notified_channels TEXT
                )
            """)
            conn.execute("""
                INSERT INTO alerts
                    (alert_id, title, message, severity, category, target,
                     details, created_at, status)
                VALUES (?, ?, ?, ?, 'asset_change', ?, ?, ?, 'new')
            """, (
                f"am-alert-{uuid.uuid4().hex[:10]}",
                f"资产变更告警: {change['change_type']}",
                change.get("description", ""),
                severity,
                change.get("asset_id"),
                json.dumps({"change_type": change["change_type"],
                            "after": change.get("after_value")}, ensure_ascii=False),
                _now(),
            ))
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.warning(f"写入自动告警失败: {e}")
        finally:
            conn.close()


# 全局单例
change_detection_manager = ChangeDetectionManager()
