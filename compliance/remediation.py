# -*- coding: utf-8 -*-
"""
remediation.py - 合规整改管理器

负责为不符合项创建整改任务、跟踪整改进度、验证整改结果并统计。

数据表：
    cp_remediation_tasks 整改任务

注意事项：
    - 本模块仅用于授权的合规整改管理
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.database import db
from utils.logger import log

from compliance.assessment import get_assessor


PRIORITIES = ("critical", "high", "medium", "low")
TASK_STATUSES = ("pending", "in_progress", "completed", "verified")


class RemediationManager:
    """合规整改管理器"""

    def __init__(self):
        """初始化并建表"""
        self._init_tables()

    @staticmethod
    def _now() -> str:
        return datetime.now().isoformat()

    # ==================== 数据库初始化 ====================

    def _init_tables(self):
        """初始化整改任务数据表（幂等）"""
        conn = db._get_connection()
        try:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cp_remediation_tasks (
                    id TEXT PRIMARY KEY,
                    assessment_id TEXT NOT NULL,
                    control_id INTEGER,
                    title TEXT NOT NULL,
                    description TEXT,
                    priority TEXT DEFAULT 'medium',
                    status TEXT DEFAULT 'pending',
                    assignee TEXT,
                    due_date TEXT,
                    remediation_steps TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    verified_at TEXT,
                    verification_result TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cp_rt_status ON cp_remediation_tasks(status)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cp_rt_pri ON cp_remediation_tasks(priority)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cp_rt_assess ON cp_remediation_tasks(assessment_id)")
            conn.commit()
            log.info("✅ 合规整改表初始化完成")
        except Exception as e:
            log.error(f"合规整改表初始化失败: {e}")
        finally:
            conn.close()

    @staticmethod
    def _row(row) -> Optional[dict]:
        if row is None:
            return None
        item = dict(row)
        raw = item.get("remediation_steps")
        if isinstance(raw, str):
            try:
                item["remediation_steps"] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                item["remediation_steps"] = []
        return item

    # ==================== 任务管理 ====================

    def list_tasks(self, status: str = None, priority: str = None,
                   assignee: str = None, assessment_id: str = None,
                   page: int = 1, page_size: int = 20) -> dict:
        """整改任务列表（多条件筛选 + 分页）"""
        where = "WHERE 1=1"
        params: list = []
        if status:
            where += " AND status = ?"
            params.append(status)
        if priority:
            where += " AND priority = ?"
            params.append(priority)
        if assignee:
            where += " AND assignee = ?"
            params.append(assignee)
        if assessment_id:
            where += " AND assessment_id = ?"
            params.append(assessment_id)
        conn = db._get_connection()
        try:
            total = conn.execute(
                f"SELECT COUNT(*) FROM cp_remediation_tasks {where}", params).fetchone()[0]
            page = max(1, page)
            page_size = max(1, min(200, page_size))
            offset = (page - 1) * page_size
            rows = conn.execute(
                f"SELECT * FROM cp_remediation_tasks {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                params + [page_size, offset]).fetchall()
            return {
                "total": total, "page": page, "page_size": page_size,
                "total_pages": (total + page_size - 1) // page_size if page_size else 0,
                "items": [self._row(r) for r in rows],
            }
        finally:
            conn.close()

    def create_remediation_task(self, assessment_id: str, control_id: int,
                                title: str, description: str = "",
                                priority: str = "medium",
                                assignee: str = "", due_date: str = "",
                                remediation_steps: List[str] = None) -> Optional[dict]:
        """为不符合项创建整改任务"""
        task_id = str(uuid.uuid4())
        now = self._now()
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO cp_remediation_tasks
                    (id, assessment_id, control_id, title, description, priority,
                     status, assignee, due_date, remediation_steps, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)
            """, (task_id, assessment_id, control_id, title, description, priority,
                  assignee, due_date,
                  json.dumps(remediation_steps or [], ensure_ascii=False), now, now))
            conn.commit()
            log.info(f"✅ 创建整改任务: {task_id} - {title}")
            return self.get_task(task_id)
        except Exception as e:
            log.error(f"创建整改任务失败: {e}")
            return None
        finally:
            conn.close()

    def get_task(self, task_id: str) -> Optional[dict]:
        """获取整改任务详情"""
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM cp_remediation_tasks WHERE id = ?", (task_id,)).fetchone()
            return self._row(row)
        finally:
            conn.close()

    def start_remediation(self, task_id: str) -> Optional[dict]:
        """开始整改，更新状态为 in_progress"""
        now = self._now()
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT started_at FROM cp_remediation_tasks WHERE id = ?", (task_id,)).fetchone()
            if not row:
                return None
            started = row["started_at"] or now
            conn.execute("""
                UPDATE cp_remediation_tasks
                SET status='in_progress', started_at=?, updated_at=?
                WHERE id=?
            """, (started, now, task_id))
            conn.commit()
            return self.get_task(task_id)
        except Exception as e:
            log.error(f"开始整改失败: {e}")
            return None
        finally:
            conn.close()

    def get_remediation_plan(self, assessment_id: str) -> Dict[str, Any]:
        """获取整改方案：整改步骤/配置修改/制度完善/人员培训建议"""
        assessor = get_assessor()
        gap = assessor.get_gap_analysis(assessment_id)
        plans = []
        for g in gap.get("gaps", []):
            plans.append({
                "control_id": g.get("control_id"),
                "title": g.get("title"),
                "priority": g.get("priority"),
                "config_changes": [f"针对「{g.get('title')}」调整相关系统配置基线"],
                "policy_updates": [f"完善{g.get('domain')}相关制度文件"],
                "training": ["对相关岗位进行专项安全培训"],
                "steps": [
                    f"1. 现状分析：{g.get('current')}",
                    f"2. 整改措施：{g.get('remediation')}",
                    f"3. 目标状态：{g.get('target')}",
                    f"4. 完成时限：{g.get('eta')}",
                ],
            })
        return {
            "assessment_id": assessment_id,
            "plan_count": len(plans),
            "plans": plans,
        }

    def verify_remediation(self, task_id: str, verification_result: str = "",
                           passed: bool = True) -> Optional[dict]:
        """整改完成后验证，更新验证结果，自动更新控制项评估结果"""
        task = self.get_task(task_id)
        if not task:
            return None
        now = self._now()
        new_status = "verified" if passed else "completed"
        conn = db._get_connection()
        try:
            conn.execute("""
                UPDATE cp_remediation_tasks
                SET status=?, completed_at=COALESCE(completed_at, ?),
                    verified_at=?, verification_result=?, updated_at=?
                WHERE id=?
            """, (new_status, now, now, verification_result, now, task_id))
            conn.commit()
        except Exception as e:
            log.error(f"验证整改失败: {e}")
            return None
        finally:
            conn.close()

        # 自动更新控制项评估结果
        if passed and task.get("control_id"):
            try:
                assessor = get_assessor()
                assessor.set_control_result(
                    task["assessment_id"], task["control_id"], "compliant",
                    finding="整改验证通过",
                    remediation_suggestion=verification_result,
                    assessed_by="remediation_verifier")
            except Exception as e:
                log.error(f"联动更新评估结果失败: {e}")
        log.info(f"✅ 整改验证完成: {task_id}，通过={passed}")
        return self.get_task(task_id)

    # ==================== 统计与进度 ====================

    def get_remediation_stats(self) -> Dict[str, Any]:
        """整改统计：完成率/平均整改时间/按控制域/按优先级"""
        conn = db._get_connection()
        try:
            total = conn.execute("SELECT COUNT(*) FROM cp_remediation_tasks").fetchone()[0]
            done = conn.execute(
                "SELECT COUNT(*) FROM cp_remediation_tasks WHERE status='verified'").fetchone()[0]
            # 按优先级
            by_priority = {}
            for p in PRIORITIES:
                by_priority[p] = conn.execute(
                    "SELECT COUNT(*) FROM cp_remediation_tasks WHERE priority=?",
                    (p,)).fetchone()[0]
            # 按状态
            by_status = {}
            for s in TASK_STATUSES:
                by_status[s] = conn.execute(
                    "SELECT COUNT(*) FROM cp_remediation_tasks WHERE status=?",
                    (s,)).fetchone()[0]
            # 平均整改时间（已验证任务 started_at -> verified_at）
            rows = conn.execute("""
                SELECT started_at, verified_at FROM cp_remediation_tasks
                WHERE status='verified' AND started_at IS NOT NULL AND verified_at IS NOT NULL
            """).fetchall()
            total_hours = 0.0
            cnt = 0
            for r in rows:
                try:
                    s = datetime.fromisoformat(r["started_at"])
                    v = datetime.fromisoformat(r["verified_at"])
                    total_hours += (v - s).total_seconds() / 3600.0
                    cnt += 1
                except Exception:
                    pass
            avg_hours = round(total_hours / cnt, 2) if cnt else 0.0
            return {
                "total": total,
                "verified": done,
                "completion_rate": round(done / total * 100, 2) if total else 0.0,
                "avg_remediation_hours": avg_hours,
                "by_priority": by_priority,
                "by_status": by_status,
            }
        finally:
            conn.close()

    def get_remediation_progress(self, assessment_id: str = None) -> Dict[str, Any]:
        """整改进度概览：总数/进行中/已完成/已验证/逾期"""
        where = "WHERE 1=1"
        params: list = []
        if assessment_id:
            where += " AND assessment_id = ?"
            params.append(assessment_id)
        conn = db._get_connection()
        try:
            total = conn.execute(
                f"SELECT COUNT(*) FROM cp_remediation_tasks {where}", params).fetchone()[0]
            in_progress = conn.execute(
                f"SELECT COUNT(*) FROM cp_remediation_tasks {where} AND status='in_progress'",
                params).fetchone()[0]
            completed = conn.execute(
                f"SELECT COUNT(*) FROM cp_remediation_tasks {where} AND status='completed'",
                params).fetchone()[0]
            verified = conn.execute(
                f"SELECT COUNT(*) FROM cp_remediation_tasks {where} AND status='verified'",
                params).fetchone()[0]
            now = self._now()
            overdue = conn.execute(
                f"SELECT COUNT(*) FROM cp_remediation_tasks {where} AND due_date IS NOT NULL AND due_date != '' AND due_date < ? AND status != 'verified'",
                params + [now]).fetchone()[0]
            return {
                "total": total,
                "in_progress": in_progress,
                "completed": completed,
                "verified": verified,
                "overdue": overdue,
            }
        finally:
            conn.close()


# 全局单例
_remediation: Optional[RemediationManager] = None


def get_remediation_manager() -> RemediationManager:
    """获取整改管理器全局单例"""
    global _remediation
    if _remediation is None:
        _remediation = RemediationManager()
    return _remediation
