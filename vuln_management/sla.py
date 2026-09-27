# -*- coding: utf-8 -*-
"""
sla.py —— 漏洞 SLA 管理器。

职责：
    - 维护按严重程度分级的 SLA 策略（响应 / 修复时限）
    - 根据发现时间与严重程度自动计算 SLA 截止时间
    - 评估 SLA 状态（on_track / at_risk / breached）
    - 管理 SLA 例外申请与审批
    - 输出 SLA 合规统计

数据库表：
    - vm_sla_policies   SLA 策略表
    - vm_sla_exceptions SLA 例外表
"""
import time
import uuid
from typing import Optional, List, Dict, Any

from utils.database import db
from utils.logger import log


# 默认 SLA 策略（单位：小时）
DEFAULT_POLICIES = [
    {"name": "严重(Critical)默认策略", "severity": "critical", "response_time_hours": 24, "remediation_time_hours": 24},
    {"name": "高危(High)默认策略", "severity": "high", "response_time_hours": 48, "remediation_time_hours": 168},
    {"name": "中危(Medium)默认策略", "severity": "medium", "response_time_hours": 72, "remediation_time_hours": 720},
    {"name": "低危(Low)默认策略", "severity": "low", "response_time_hours": 168, "remediation_time_hours": 2160},
]

HOURS = 3600.0
# at_risk 阈值：剩余时间占总时限比例
AT_RISK_RATIO = 0.20
# 未闭环的生命周期状态
OPEN_STATES = ("new", "confirmed", "triaged", "in_progress", "fix_verified")


def _now() -> float:
    return time.time()


def _uid() -> str:
    return str(uuid.uuid4())


class SLAManager:
    """漏洞 SLA 管理器。"""

    def __init__(self):
        """初始化策略表 / 例外表，并写入默认策略。"""
        self._init_tables()

    def _init_tables(self):
        """建表并写入默认策略（幂等）。"""
        conn = db._get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vm_sla_policies (
                    id TEXT PRIMARY KEY,
                    name TEXT DEFAULT '',
                    severity TEXT DEFAULT 'medium',
                    response_time_hours REAL DEFAULT 24,
                    remediation_time_hours REAL DEFAULT 720,
                    enabled INTEGER DEFAULT 1,
                    created_at REAL DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vm_sla_exceptions (
                    id TEXT PRIMARY KEY,
                    vulnerability_id TEXT DEFAULT '',
                    reason TEXT DEFAULT '',
                    requested_by TEXT DEFAULT '',
                    approved_by TEXT DEFAULT '',
                    approved_at REAL,
                    new_deadline REAL,
                    status TEXT DEFAULT 'pending',
                    created_at REAL DEFAULT 0
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sla_pol_sev ON vm_sla_policies(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sla_ex_vuln ON vm_sla_exceptions(vulnerability_id)")
            conn.commit()

            # 仅当无任何策略时写入默认策略
            count = conn.execute("SELECT COUNT(*) FROM vm_sla_policies").fetchone()[0]
            if count == 0:
                for p in DEFAULT_POLICIES:
                    conn.execute(
                        "INSERT INTO vm_sla_policies (id, name, severity, response_time_hours, "
                        "remediation_time_hours, enabled, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)",
                        (_uid(), p["name"], p["severity"], p["response_time_hours"],
                         p["remediation_time_hours"], _now()),
                    )
                conn.commit()
                log.info("[vuln-sla] 已写入默认 SLA 策略")
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-sla] 初始化失败: {e}")
        finally:
            conn.close()

    # ==================== 策略 CRUD ====================

    def list_policies(self) -> List[Dict[str, Any]]:
        """列出全部 SLA 策略。"""
        conn = db._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM vm_sla_policies ORDER BY severity DESC, created_at ASC"
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-sla] 列出策略失败: {e}")
            return []
        finally:
            conn.close()

    def create_policy(self, name: str, severity: str, response_time_hours: float,
                      remediation_time_hours: float, enabled: bool = True) -> Dict[str, Any]:
        """新建 SLA 策略。"""
        conn = db._get_connection()
        try:
            pid = _uid()
            conn.execute(
                "INSERT INTO vm_sla_policies (id, name, severity, response_time_hours, "
                "remediation_time_hours, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (pid, name, severity, response_time_hours, remediation_time_hours,
                 1 if enabled else 0, _now()),
            )
            conn.commit()
            return {"success": True, "id": pid}
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-sla] 新建策略失败: {e}")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def update_policy(self, policy_id: str, **fields) -> Dict[str, Any]:
        """更新 SLA 策略（name/severity/response_time_hours/remediation_time_hours/enabled）。"""
        allowed = {"name", "severity", "response_time_hours", "remediation_time_hours", "enabled"}
        sets, params = [], []
        for k, v in fields.items():
            if k in allowed and v is not None:
                if k == "enabled":
                    v = 1 if v else 0
                sets.append(f"{k} = ?")
                params.append(v)
        if not sets:
            return {"success": False, "error": "无可更新字段"}
        params.append(policy_id)
        conn = db._get_connection()
        try:
            conn.execute(f"UPDATE vm_sla_policies SET {', '.join(sets)} WHERE id=?", params)
            conn.commit()
            return {"success": True, "id": policy_id}
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-sla] 更新策略失败 {policy_id}: {e}")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def delete_policy(self, policy_id: str) -> Dict[str, Any]:
        """删除 SLA 策略。"""
        conn = db._get_connection()
        try:
            conn.execute("DELETE FROM vm_sla_policies WHERE id=?", (policy_id,))
            conn.commit()
            return {"success": True, "id": policy_id}
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-sla] 删除策略失败 {policy_id}: {e}")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    # ==================== SLA 计算 ====================

    def _get_policy(self, conn, severity: str) -> Optional[dict]:
        """根据严重程度取启用的策略。"""
        row = conn.execute(
            "SELECT * FROM vm_sla_policies WHERE severity=? AND enabled=1 ORDER BY created_at ASC LIMIT 1",
            (severity or "medium",),
        ).fetchone()
        return dict(row) if row else None

    def calculate_sla_deadline(self, discovered_at: float, severity: str,
                               vulnerability_id: Optional[str] = None) -> float:
        """根据发现时间和严重程度计算 SLA 修复截止时间戳。

        若存在已批准的 SLA 例外，则采用例外给出的新截止时间。
        """
        conn = db._get_connection()
        try:
            # 优先：已批准的例外
            if vulnerability_id:
                exc = conn.execute(
                    "SELECT new_deadline FROM vm_sla_exceptions "
                    "WHERE vulnerability_id=? AND status='approved' AND new_deadline IS NOT NULL "
                    "ORDER BY approved_at DESC LIMIT 1",
                    (vulnerability_id,),
                ).fetchone()
                if exc and exc["new_deadline"]:
                    return exc["new_deadline"]

            policy = self._get_policy(conn, severity)
            hours = policy["remediation_time_hours"] if policy else 720
            base = discovered_at if discovered_at else _now()
            return base + hours * HOURS
        finally:
            conn.close()

    def get_sla_status(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """计算单个漏洞的 SLA 状态。

        Returns:
            {"status": on_track|at_risk|breached|closed, "due_date": ts,
             "remaining_hours": h, "elapsed_hours": h}
        """
        now = _now()
        discovered = vuln.get("discovered_at") or now
        severity = vuln.get("severity") or "medium"
        lifecycle = vuln.get("lifecycle_status") or vuln.get("status") or "new"

        # 已闭环
        if lifecycle in ("resolved", "closed", "false_positive", "duplicate", "risk_accepted"):
            return {"status": "closed", "due_date": None, "remaining_hours": None, "elapsed_hours": (now - discovered) / HOURS}

        due = vuln.get("sla_due_date") or self.calculate_sla_deadline(discovered, severity, vuln.get("id"))
        total = due - discovered if due > discovered else 1.0
        remaining = due - now
        ratio = remaining / total if total > 0 else 0

        if remaining < 0:
            status = "breached"
        elif ratio < AT_RISK_RATIO:
            status = "at_risk"
        else:
            status = "on_track"

        return {
            "status": status,
            "due_date": due,
            "remaining_hours": round(remaining / HOURS, 2),
            "elapsed_hours": round((now - discovered) / HOURS, 2),
        }

    def get_sla_overview(self) -> Dict[str, int]:
        """统计各 SLA 状态漏洞数量。"""
        result = {"on_track": 0, "at_risk": 0, "breached": 0, "closed": 0}
        conn = db._get_connection()
        try:
            placeholders = ", ".join("?" for _ in OPEN_STATES)
            rows = conn.execute(
                f"SELECT * FROM vulnerabilities WHERE lifecycle_status IN ({placeholders}) "
                "OR lifecycle_status IS NULL OR lifecycle_status=''",
                list(OPEN_STATES),
            ).fetchall()
            for r in rows:
                v = dict(r)
                st = self.get_sla_status(v)["status"]
                result[st] = result.get(st, 0) + 1
            # 已闭环数量
            result["closed"] = conn.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE lifecycle_status IN ('resolved','closed')"
            ).fetchone()[0]
            return result
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-sla] 概览统计失败: {e}")
            return result
        finally:
            conn.close()

    # ==================== 例外审批 ====================

    def request_exception(self, vulnerability_id: str, reason: str,
                          requested_by: str, new_deadline: Optional[float] = None) -> Dict[str, Any]:
        """提交 SLA 例外申请（状态 pending）。"""
        conn = db._get_connection()
        try:
            eid = _uid()
            conn.execute(
                "INSERT INTO vm_sla_exceptions (id, vulnerability_id, reason, requested_by, "
                "approved_by, approved_at, new_deadline, status, created_at) "
                "VALUES (?, ?, ?, ?, '', NULL, ?, 'pending', ?)",
                (eid, vulnerability_id, reason, requested_by, new_deadline, _now()),
            )
            conn.commit()
            return {"success": True, "exception_id": eid, "status": "pending"}
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-sla] 申请例外失败 {vulnerability_id}: {e}")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def _set_exception_status(self, exception_id: str, status: str,
                              approver: str) -> Dict[str, Any]:
        """内部：更新例外审批状态。"""
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM vm_sla_exceptions WHERE id=?", (exception_id,)
            ).fetchone()
            if not row:
                return {"success": False, "error": "例外申请不存在"}
            if status == "approved":
                new_deadline = row["new_deadline"]
                conn.execute(
                    "UPDATE vm_sla_exceptions SET status='approved', approved_by=?, approved_at=? WHERE id=?",
                    (approver, _now(), exception_id),
                )
                if new_deadline:
                    conn.execute(
                        "UPDATE vulnerabilities SET sla_due_date=? WHERE id=?",
                        (new_deadline, row["vulnerability_id"]),
                    )
            else:
                conn.execute(
                    "UPDATE vm_sla_exceptions SET status='rejected', approved_by=?, approved_at=? WHERE id=?",
                    (approver, _now(), exception_id),
                )
            conn.commit()
            return {"success": True, "exception_id": exception_id, "status": status}
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-sla] 审批例外失败 {exception_id}: {e}")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def approve_exception(self, exception_id: str, approver: str = "admin") -> Dict[str, Any]:
        """批准 SLA 例外。"""
        return self._set_exception_status(exception_id, "approved", approver)

    def reject_exception(self, exception_id: str, approver: str = "admin") -> Dict[str, Any]:
        """拒绝 SLA 例外。"""
        return self._set_exception_status(exception_id, "rejected", approver)

    def list_exceptions(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """列出 SLA 例外申请。"""
        conn = db._get_connection()
        try:
            if status:
                rows = conn.execute(
                    "SELECT * FROM vm_sla_exceptions WHERE status=? ORDER BY created_at DESC",
                    (status,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM vm_sla_exceptions ORDER BY created_at DESC"
                ).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-sla] 列外出例外失败: {e}")
            return []
        finally:
            conn.close()

    # ==================== 统计 ====================

    def get_sla_stats(self) -> Dict[str, Any]:
        """SLA 统计：合规率 / 平均修复时间 / 超时数量 / 按严重程度分布。"""
        now = _now()
        conn = db._get_connection()
        try:
            placeholders = ", ".join("?" for _ in OPEN_STATES)
            open_rows = conn.execute(
                f"SELECT * FROM vulnerabilities WHERE lifecycle_status IN ({placeholders}) "
                "OR lifecycle_status IS NULL OR lifecycle_status=''",
                list(OPEN_STATES),
            ).fetchall()

            total = 0
            on_track = 0
            breached = 0
            at_risk = 0
            by_severity: Dict[str, Dict[str, int]] = {}

            for r in open_rows:
                v = dict(r)
                sev = v.get("severity") or "unknown"
                st = self.get_sla_status(v)["status"]
                total += 1
                by_severity.setdefault(sev, {"total": 0, "on_track": 0, "at_risk": 0, "breached": 0})
                by_severity[sev]["total"] += 1
                if st == "on_track":
                    on_track += 1
                    by_severity[sev]["on_track"] += 1
                elif st == "at_risk":
                    at_risk += 1
                    by_severity[sev]["at_risk"] += 1
                elif st == "breached":
                    breached += 1
                    by_severity[sev]["breached"] += 1

            compliance_rate = round(on_track / total * 100, 2) if total else 100.0

            # 平均修复时间（仅统计已闭环且有发现/修复时间的）
            fixed = conn.execute(
                "SELECT discovered_at, remediated_at FROM vulnerabilities "
                "WHERE remediated_at IS NOT NULL AND discovered_at IS NOT NULL "
                "AND remediated_at > discovered_at"
            ).fetchall()
            avg_seconds = 0.0
            if fixed:
                avg_seconds = sum((r["remediated_at"] - r["discovered_at"]) for r in fixed) / len(fixed)

            return {
                "total_open": total,
                "on_track": on_track,
                "at_risk": at_risk,
                "breached": breached,
                "compliance_rate_percent": compliance_rate,
                "avg_remediation_hours": round(avg_seconds / HOURS, 2),
                "by_severity": by_severity,
            }
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-sla] SLA 统计失败: {e}")
            return {"total_open": 0, "on_track": 0, "at_risk": 0, "breached": 0,
                    "compliance_rate_percent": 0.0, "avg_remediation_hours": 0.0, "by_severity": {}}
        finally:
            conn.close()

    def check_sla_breaches(self) -> Dict[str, Any]:
        """扫描全部未闭环漏洞，自动计算并回写 sla_due_date，返回超时预警列表。"""
        now = _now()
        conn = db._get_connection()
        try:
            placeholders = ", ".join("?" for _ in OPEN_STATES)
            rows = conn.execute(
                f"SELECT * FROM vulnerabilities WHERE lifecycle_status IN ({placeholders}) "
                "OR lifecycle_status IS NULL OR lifecycle_status=''",
                list(OPEN_STATES),
            ).fetchall()
            breached_list = []
            for r in rows:
                v = dict(r)
                due = v.get("sla_due_date") or self.calculate_sla_deadline(
                    v.get("discovered_at") or now, v.get("severity") or "medium", v.get("id"))
                # 回写 sla_due_date
                conn.execute("UPDATE vulnerabilities SET sla_due_date=? WHERE id=? AND sla_due_date IS NULL",
                             (due, v["id"]))
                if due < now:
                    breached_list.append({
                        "vulnerability_id": v["id"],
                        "name": v.get("name"),
                        "severity": v.get("severity"),
                        "target": v.get("target"),
                        "due_date": due,
                        "overdue_hours": round((now - due) / HOURS, 2),
                    })
            conn.commit()
            breached_list.sort(key=lambda x: x["overdue_hours"], reverse=True)
            log.warning(f"[vuln-sla] SLA 超时预警 {len(breached_list)} 个")
            return {"checked_at": now, "breached_count": len(breached_list),
                    "breached": breached_list}
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-sla] SLA 超时检查失败: {e}")
            return {"checked_at": now, "breached_count": 0, "breached": [], "error": str(e)}
        finally:
            conn.close()


# 全局单例
sla_manager = SLAManager()
