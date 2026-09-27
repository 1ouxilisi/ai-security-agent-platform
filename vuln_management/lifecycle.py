# -*- coding: utf-8 -*-
"""
lifecycle.py —— 漏洞生命周期管理器。

职责：
    - 在现有 vulnerabilities 表基础上扩展生命周期字段（兼容已有表）
    - 维护状态流转 new→confirmed→triaged→in_progress→fix_verified→resolved→closed
      以及特殊终态 false_positive / duplicate / risk_accepted
    - 记录生命周期历史、评论、标签
    - 自动分配负责人、综合优先级评分（0-100）

数据库表：
    - vulnerabilities（已有，扩展列）
    - vulnerability_history（已有，若不存在则创建）
    - vm_lifecycle_history（生命周期变更历史）
    - vm_vuln_comments（漏洞评论）
    - vm_vuln_tags（漏洞标签）
"""
import json
import time
import uuid
from typing import Optional, List, Dict, Any

from fastapi import Body  # noqa: F401  (保持与项目路由一致的导入习惯，业务层不强制使用)

from utils.database import db
from utils.logger import log


# 正常生命周期状态（按流转顺序）
NORMAL_FLOW = ["new", "confirmed", "triaged", "in_progress", "fix_verified", "resolved", "closed"]
# 特殊终态
SPECIAL_STATES = ["false_positive", "duplicate", "risk_accepted"]
ALL_STATES = NORMAL_FLOW + SPECIAL_STATES

# 严重程度权重（用于优先级评分）
SEVERITY_WEIGHT = {
    "critical": 60,
    "high": 40,
    "medium": 20,
    "low": 5,
    "info": 1,
}


def _now() -> float:
    """返回当前 Unix 时间戳（秒）。"""
    return time.time()


def _uid() -> str:
    """生成 UUID 主键。"""
    return str(uuid.uuid4())


class LifecycleManager:
    """漏洞生命周期管理器。"""

    def __init__(self):
        """初始化：建表 + 扩展列（幂等）。"""
        self._init_tables()

    # ==================== 建表 / 扩展列 ====================

    def _table_exists(self, conn, table: str) -> bool:
        """判断指定表是否存在。"""
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        return row is not None

    def _column_exists(self, conn, table: str, column: str) -> bool:
        """判断指定表是否已存在某列。"""
        cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        return column in cols

    def _add_column_if_missing(self, conn, table: str, column: str, ddl: str):
        """若列不存在则 ALTER TABLE 增加（SQLite 不支持 IF NOT EXISTS，故用 try/except）。"""
        if self._column_exists(conn, table, column):
            return
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
            log.info(f"[vuln-lifecycle] 已为 {table} 增加列 {column}")
        except Exception as e:  # noqa: BLE001
            log.warning(f"[vuln-lifecycle] 增加列 {table}.{column} 失败（可能已存在）: {e}")

    def _init_tables(self):
        """初始化漏洞主表、历史表、评论表、标签表，并扩展生命周期字段。"""
        conn = db._get_connection()
        try:
            # 1. 主表 vulnerabilities：若不存在则按约定字段创建
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id TEXT PRIMARY KEY,
                    assessment_id TEXT DEFAULT '',
                    name TEXT DEFAULT '',
                    severity TEXT DEFAULT 'medium',
                    cve TEXT DEFAULT '',
                    cwe TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    evidence TEXT DEFAULT '',
                    status TEXT DEFAULT 'new',
                    discovered_at REAL DEFAULT 0,
                    remediated_at REAL,
                    target TEXT DEFAULT '',
                    tenant_id TEXT DEFAULT 'default'
                )
            """)
            # 2. 变更历史表（若不存在则创建）
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerability_history (
                    id TEXT PRIMARY KEY,
                    vulnerability_id TEXT DEFAULT '',
                    from_status TEXT DEFAULT '',
                    to_status TEXT DEFAULT '',
                    changed_by TEXT DEFAULT '',
                    note TEXT DEFAULT '',
                    changed_at REAL DEFAULT 0
                )
            """)
            # 3. 生命周期历史表
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vm_lifecycle_history (
                    id TEXT PRIMARY KEY,
                    vulnerability_id TEXT DEFAULT '',
                    from_status TEXT DEFAULT '',
                    to_status TEXT DEFAULT '',
                    operator TEXT DEFAULT '',
                    note TEXT DEFAULT '',
                    changed_at REAL DEFAULT 0
                )
            """)
            # 4. 漏洞评论表
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vm_vuln_comments (
                    id TEXT PRIMARY KEY,
                    vulnerability_id TEXT DEFAULT '',
                    author TEXT DEFAULT '',
                    content TEXT DEFAULT '',
                    mentions TEXT DEFAULT '[]',
                    created_at REAL DEFAULT 0
                )
            """)
            # 5. 漏洞标签表
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vm_vuln_tags (
                    id TEXT PRIMARY KEY,
                    vulnerability_id TEXT DEFAULT '',
                    tag TEXT DEFAULT '',
                    created_at REAL DEFAULT 0
                )
            """)

            # 6. 扩展 vulnerabilities 列（兼容已有表）
            self._add_column_if_missing(conn, "vulnerabilities", "lifecycle_status", "TEXT DEFAULT 'new'")
            self._add_column_if_missing(conn, "vulnerabilities", "priority_score", "REAL DEFAULT 0")
            self._add_column_if_missing(conn, "vulnerabilities", "assigned_to", "TEXT DEFAULT ''")
            self._add_column_if_missing(conn, "vulnerabilities", "tags", "TEXT DEFAULT '[]'")
            self._add_column_if_missing(conn, "vulnerabilities", "comments_count", "INTEGER DEFAULT 0")
            self._add_column_if_missing(conn, "vulnerabilities", "sla_due_date", "REAL")
            self._add_column_if_missing(conn, "vulnerabilities", "risk_accepted", "INTEGER DEFAULT 0")
            self._add_column_if_missing(conn, "vulnerabilities", "risk_accepted_by", "TEXT DEFAULT ''")
            self._add_column_if_missing(conn, "vulnerabilities", "risk_accepted_at", "REAL")

            # 索引
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vm_lch_vuln ON vm_lifecycle_history(vulnerability_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vm_comment_vuln ON vm_vuln_comments(vulnerability_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vm_tag_vuln ON vm_vuln_tags(vulnerability_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vuln_lifecycle ON vulnerabilities(lifecycle_status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vuln_assigned ON vulnerabilities(assigned_to)")
            conn.commit()
            log.info("[vuln-lifecycle] 生命周期表结构初始化完成")
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-lifecycle] 初始化表结构失败: {e}")
        finally:
            conn.close()

    # ==================== 内部工具 ====================

    def _row_to_dict(self, row) -> Dict[str, Any]:
        """将 sqlite.Row 转为 dict，并解析 JSON 字段。"""
        d = dict(row)
        for jf in ("tags",):
            if d.get(jf):
                try:
                    d[jf] = json.loads(d[jf])
                except Exception:  # noqa: BLE001
                    d[jf] = []
        return d

    def _get_raw(self, conn, vuln_id: str) -> Optional[Dict[str, Any]]:
        """从主表读取原始漏洞记录（不关闭连接）。"""
        row = conn.execute("SELECT * FROM vulnerabilities WHERE id=?", (vuln_id,)).fetchone()
        if not row:
            return None
        return self._row_to_dict(row)

    # ==================== 查询 ====================

    def get_vulnerability(self, vuln_id: str, include_relations: bool = True) -> Optional[Dict[str, Any]]:
        """获取单个漏洞详情，可关联资产/事件/工单信息。

        Args:
            vuln_id: 漏洞ID
            include_relations: 是否附加评论数、标签、生命周期历史等关联数据

        Returns:
            漏洞字典，不存在返回 None
        """
        conn = db._get_connection()
        try:
            vuln = self._get_raw(conn, vuln_id)
            if not vuln:
                return None
            if include_relations:
                vuln["comments"] = self.get_comments(vuln_id)
                vuln["tags"] = self.get_tags(vuln_id)
                # 尝试关联资产信息（assets 表若存在）
                if self._table_exists(conn, "assets") and vuln.get("target"):
                    asset = conn.execute(
                        "SELECT ip, domain, owner, importance, risk_score FROM assets "
                        "WHERE ip=? OR domain=? LIMIT 1",
                        (vuln["target"], vuln["target"]),
                    ).fetchone()
                    vuln["asset"] = dict(asset) if asset else None
                else:
                    vuln["asset"] = None
                # 关联修复工单（remediation_tracker 表若已创建）
                if self._table_exists(conn, "vm_remediation_tasks"):
                    tasks = conn.execute(
                        "SELECT id, status, assignee FROM vm_remediation_tasks "
                        "WHERE vulnerability_id=? ORDER BY created_at DESC",
                        (vuln_id,),
                    ).fetchall()
                    vuln["remediation_tasks"] = [dict(t) for t in tasks]
                else:
                    vuln["remediation_tasks"] = []
            return vuln
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-lifecycle] 获取漏洞失败 {vuln_id}: {e}")
            return None
        finally:
            conn.close()

    def list_vulnerabilities(self,
                             status: Optional[str] = None,
                             severity: Optional[str] = None,
                             cve: Optional[str] = None,
                             target: Optional[str] = None,
                             keyword: Optional[str] = None,
                             lifecycle_status: Optional[str] = None,
                             assigned_to: Optional[str] = None,
                             page: int = 1,
                             page_size: int = 20,
                             sort: str = "discovered_at",
                             order: str = "desc") -> Dict[str, Any]:
        """分页查询漏洞列表，支持多条件筛选。

        Returns:
            {"items": [...], "total": n, "page": p, "page_size": s}
        """
        page = max(1, int(page))
        page_size = max(1, min(500, int(page_size)))
        offset = (page - 1) * page_size

        where = ["1=1"]
        params: List[Any] = []
        if status:
            where.append("status = ?")
            params.append(status)
        if severity:
            where.append("severity = ?")
            params.append(severity)
        if cve:
            where.append("cve LIKE ?")
            params.append(f"%{cve}%")
        if target:
            where.append("target LIKE ?")
            params.append(f"%{target}%")
        if keyword:
            where.append("(name LIKE ? OR description LIKE ? OR cve LIKE ?)")
            like = f"%{keyword}%"
            params.extend([like, like, like])
        if lifecycle_status:
            where.append("lifecycle_status = ?")
            params.append(lifecycle_status)
        if assigned_to:
            where.append("assigned_to = ?")
            params.append(assigned_to)
        where_sql = " AND ".join(where)

        # 排序字段白名单，防止注入
        allowed_sort = {"discovered_at", "priority_score", "severity", "created_at", "id"}
        sort_col = sort if sort in allowed_sort else "discovered_at"
        direction = "ASC" if str(order).lower() == "asc" else "DESC"

        conn = db._get_connection()
        try:
            total = conn.execute(
                f"SELECT COUNT(*) FROM vulnerabilities WHERE {where_sql}", params
            ).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM vulnerabilities WHERE {where_sql} "
                f"ORDER BY {sort_col} {direction} LIMIT ? OFFSET ?",
                params + [page_size, offset],
            ).fetchall()
            items = [self._row_to_dict(r) for r in rows]
            return {
                "items": items,
                "total": total,
                "page": page,
                "page_size": page_size,
            }
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-lifecycle] 列表查询失败: {e}")
            return {"items": [], "total": 0, "page": page, "page_size": page_size}
        finally:
            conn.close()

    # ==================== 状态流转 ====================

    def _record_history(self, conn, vuln_id: str, from_status: str, to_status: str,
                        operator: str, note: str):
        """同时写入 vm_lifecycle_history 与 vulnerability_history。"""
        now = _now()
        conn.execute(
            "INSERT INTO vm_lifecycle_history (id, vulnerability_id, from_status, to_status, "
            "operator, note, changed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (_uid(), vuln_id, from_status, to_status, operator, note, now),
        )
        # 同步写入已有变更历史表
        conn.execute(
            "INSERT INTO vulnerability_history (id, vulnerability_id, from_status, to_status, "
            "changed_by, note, changed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (_uid(), vuln_id, from_status, to_status, operator, note, now),
        )

    def update_lifecycle_status(self, vuln_id: str, new_status: str,
                                operator: str = "system", note: str = "",
                                auto: bool = False) -> Dict[str, Any]:
        """更新漏洞生命周期状态，并记录历史。

        自动流转规则：
            - new → confirmed（验证通过）
            - in_progress → fix_verified（修复验证通过）
        """
        if new_status not in ALL_STATES:
            return {"success": False, "error": f"非法状态: {new_status}"}

        conn = db._get_connection()
        try:
            vuln = self._get_raw(conn, vuln_id)
            if not vuln:
                return {"success": False, "error": "漏洞不存在"}

            from_status = vuln.get("lifecycle_status") or vuln.get("status") or "new"

            # 自动流转提示：若请求状态与自动规则不符，仅记录不阻断
            if new_status == "confirmed" and from_status == "new":
                log.info(f"[vuln-lifecycle] {vuln_id} 验证通过: new→confirmed")
            if new_status == "fix_verified" and from_status == "in_progress":
                log.info(f"[vuln-lifecycle] {vuln_id} 修复验证通过: in_progress→fix_verified")

            updates = ["lifecycle_status = ?", "status = ?"]
            params: List[Any] = [new_status, new_status]

            # 修复完成时回填 remediated_at
            if new_status in ("resolved", "closed", "fix_verified") and not vuln.get("remediated_at"):
                updates.append("remediated_at = ?")
                params.append(_now())
            # 风险接受终态
            if new_status == "risk_accepted":
                updates.append("risk_accepted = ?")
                updates.append("risk_accepted_by = ?")
                updates.append("risk_accepted_at = ?")
                params.extend([1, operator, _now()])

            params.append(vuln_id)
            conn.execute(f"UPDATE vulnerabilities SET {', '.join(updates)} WHERE id=?", params)
            self._record_history(conn, vuln_id, from_status, new_status, operator, note)
            conn.commit()
            log.info(f"[vuln-lifecycle] {vuln_id} 状态 {from_status}→{new_status} (by {operator}, auto={auto})")
            return {"success": True, "vulnerability_id": vuln_id,
                    "from_status": from_status, "to_status": new_status}
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-lifecycle] 更新状态失败 {vuln_id}: {e}")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    # ==================== 分配 ====================

    def assign_vulnerability(self, vuln_id: str, assignee: Optional[str] = None,
                             operator: str = "system") -> Dict[str, Any]:
        """分配漏洞负责人。

        未指定 assignee 时自动分配：优先按资产负责人，其次按当前负载最少的处理人轮询。
        """
        conn = db._get_connection()
        try:
            vuln = self._get_raw(conn, vuln_id)
            if not vuln:
                return {"success": False, "error": "漏洞不存在"}

            target_assignee = assignee
            # 自动分配：资产负责人
            if not target_assignee and self._table_exists(conn, "assets") and vuln.get("target"):
                asset = conn.execute(
                    "SELECT owner FROM assets WHERE ip=? OR domain=? LIMIT 1",
                    (vuln["target"], vuln["target"]),
                ).fetchone()
                if asset and asset["owner"]:
                    target_assignee = asset["owner"]

            # 自动分配：负载均衡（in_progress 数量最少者）
            if not target_assignee:
                row = conn.execute(
                    "SELECT assigned_to, COUNT(*) AS cnt FROM vulnerabilities "
                    "WHERE assigned_to IS NOT NULL AND assigned_to != '' "
                    "GROUP BY assigned_to ORDER BY cnt ASC LIMIT 1"
                ).fetchone()
                # 无历史处理人时，给默认安全处理人
                target_assignee = row["assigned_to"] if row and row["assigned_to"] else "secops-default"

            conn.execute(
                "UPDATE vulnerabilities SET assigned_to=? WHERE id=?",
                (target_assignee, vuln_id),
            )
            self._record_history(conn, vuln_id,
                                 vuln.get("lifecycle_status") or "new",
                                 vuln.get("lifecycle_status") or "new",
                                 operator, f"分配负责人: {target_assignee}")
            conn.commit()
            return {"success": True, "vulnerability_id": vuln_id, "assigned_to": target_assignee}
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-lifecycle] 分配失败 {vuln_id}: {e}")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    # ==================== 优先级评分 ====================

    def calculate_priority(self, vuln_id: str) -> Dict[str, Any]:
        """基于严重程度 / CVE / 资产重要性 / 暴露程度综合计算 0-100 优先级分。

        评分构成：
            - 严重程度权重（最高 60）
            - 存在 CVE（+15）
            - 资产重要性（高 +10 / 中 +5 / 低 +2）
            - 暴露程度：公网目标 +10，内网 +5
        """
        conn = db._get_connection()
        try:
            vuln = self._get_raw(conn, vuln_id)
            if not vuln:
                return {"success": False, "error": "漏洞不存在"}

            score = 0.0
            severity = (vuln.get("severity") or "medium").lower()
            score += SEVERITY_WEIGHT.get(severity, 10)

            if vuln.get("cve"):
                score += 15

            # 资产重要性
            importance = "medium"
            if self._table_exists(conn, "assets") and vuln.get("target"):
                asset = conn.execute(
                    "SELECT importance, risk_score FROM assets WHERE ip=? OR domain=? LIMIT 1",
                    (vuln["target"], vuln["target"]),
                ).fetchone()
                if asset:
                    importance = asset["importance"] or "medium"
            if importance == "high":
                score += 10
            elif importance == "medium":
                score += 5
            else:
                score += 2

            # 暴露程度：简单按目标是否像公网 IP/域名判定
            target = vuln.get("target") or ""
            is_external = not any(
                target.startswith(p) for p in ("10.", "192.168.", "172.16.", "172.17.",
                                               "172.18.", "172.19.", "172.2", "localhost", "127.")
            )
            score += 10 if is_external else 5

            score = max(0.0, min(100.0, round(score, 1)))
            conn.execute("UPDATE vulnerabilities SET priority_score=? WHERE id=?", (score, vuln_id))
            conn.commit()
            return {"success": True, "vulnerability_id": vuln_id, "priority_score": score,
                    "severity": severity, "importance": importance, "external": is_external}
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-lifecycle] 优先级计算失败 {vuln_id}: {e}")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    # ==================== 评论 ====================

    def add_comment(self, vuln_id: str, author: str, content: str,
                    mentions: Optional[List[str]] = None) -> Dict[str, Any]:
        """为漏洞添加评论，并维护 comments_count。"""
        conn = db._get_connection()
        try:
            if not self._get_raw(conn, vuln_id):
                return {"success": False, "error": "漏洞不存在"}
            cid = _uid()
            conn.execute(
                "INSERT INTO vm_vuln_comments (id, vulnerability_id, author, content, mentions, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (cid, vuln_id, author, content, json.dumps(mentions or [], ensure_ascii=False), _now()),
            )
            conn.execute(
                "UPDATE vulnerabilities SET comments_count = COALESCE(comments_count,0) + 1 WHERE id=?",
                (vuln_id,),
            )
            conn.commit()
            return {"success": True, "comment_id": cid, "vulnerability_id": vuln_id}
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-lifecycle] 添加评论失败 {vuln_id}: {e}")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def get_comments(self, vuln_id: str) -> List[Dict[str, Any]]:
        """获取漏洞评论列表。"""
        conn = db._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM vm_vuln_comments WHERE vulnerability_id=? ORDER BY created_at ASC",
                (vuln_id,),
            ).fetchall()
            result = []
            for r in rows:
                d = dict(r)
                if d.get("mentions"):
                    try:
                        d["mentions"] = json.loads(d["mentions"])
                    except Exception:  # noqa: BLE001
                        d["mentions"] = []
                result.append(d)
            return result
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-lifecycle] 获取评论失败 {vuln_id}: {e}")
            return []
        finally:
            conn.close()

    # ==================== 标签 ====================

    def add_tag(self, vuln_id: str, tag: str) -> Dict[str, Any]:
        """为漏洞添加标签（写入标签表并同步主表 tags JSON）。"""
        conn = db._get_connection()
        try:
            vuln = self._get_raw(conn, vuln_id)
            if not vuln:
                return {"success": False, "error": "漏洞不存在"}
            # 去重
            exists = conn.execute(
                "SELECT 1 FROM vm_vuln_tags WHERE vulnerability_id=? AND tag=?",
                (vuln_id, tag),
            ).fetchone()
            if exists:
                return {"success": True, "tag": tag, "duplicated": True}
            conn.execute(
                "INSERT INTO vm_vuln_tags (id, vulnerability_id, tag, created_at) VALUES (?, ?, ?, ?)",
                (_uid(), vuln_id, tag, _now()),
            )
            tags = set(self.get_tags(vuln_id))
            tags.add(tag)
            conn.execute("UPDATE vulnerabilities SET tags=? WHERE id=?",
                         (json.dumps(sorted(tags), ensure_ascii=False), vuln_id))
            conn.commit()
            return {"success": True, "tag": tag}
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-lifecycle] 添加标签失败 {vuln_id}: {e}")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def remove_tag(self, vuln_id: str, tag: str) -> Dict[str, Any]:
        """移除漏洞标签。"""
        conn = db._get_connection()
        try:
            conn.execute(
                "DELETE FROM vm_vuln_tags WHERE vulnerability_id=? AND tag=?",
                (vuln_id, tag),
            )
            tags = set(self.get_tags(vuln_id))
            tags.discard(tag)
            conn.execute("UPDATE vulnerabilities SET tags=? WHERE id=?",
                         (json.dumps(sorted(tags), ensure_ascii=False), vuln_id))
            conn.commit()
            return {"success": True, "removed": tag}
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-lifecycle] 移除标签失败 {vuln_id}: {e}")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def get_tags(self, vuln_id: str) -> List[str]:
        """获取漏洞标签列表。"""
        conn = db._get_connection()
        try:
            rows = conn.execute(
                "SELECT tag FROM vm_vuln_tags WHERE vulnerability_id=? ORDER BY created_at ASC",
                (vuln_id,),
            ).fetchall()
            return [r["tag"] for r in rows]
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-lifecycle] 获取标签失败 {vuln_id}: {e}")
            return []
        finally:
            conn.close()

    # ==================== 历史 / 特殊终态 ====================

    def get_history(self, vuln_id: str) -> List[Dict[str, Any]]:
        """获取漏洞生命周期变更历史。"""
        conn = db._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM vm_lifecycle_history WHERE vulnerability_id=? ORDER BY changed_at DESC",
                (vuln_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-lifecycle] 获取历史失败 {vuln_id}: {e}")
            return []
        finally:
            conn.close()

    def mark_false_positive(self, vuln_id: str, operator: str = "system",
                            note: str = "") -> Dict[str, Any]:
        """标记为误报。"""
        return self.update_lifecycle_status(vuln_id, "false_positive", operator, note or "标记为误报")

    def mark_duplicate(self, vuln_id: str, operator: str = "system",
                       note: str = "") -> Dict[str, Any]:
        """标记为重复漏洞。"""
        return self.update_lifecycle_status(vuln_id, "duplicate", operator, note or "标记为重复漏洞")

    def accept_risk(self, vuln_id: str, operator: str = "system",
                    note: str = "") -> Dict[str, Any]:
        """接受风险（风险已接受）。"""
        return self.update_lifecycle_status(vuln_id, "risk_accepted", operator, note or "接受风险")


# 全局单例
lifecycle_manager = LifecycleManager()
