# -*- coding: utf-8 -*-
"""
remediation_tracker.py —— 漏洞修复跟踪器。

职责：
    - 为漏洞创建 / 跟踪修复任务（pending/in_progress/completed/failed）
    - 提供修复方案（优先查询 vuln_database 模块，否则按类型生成通用建议）
    - 修复完成后验证并自动驱动漏洞状态 in_progress → fix_verified
    - 修复失败时提供回滚方案
    - 输出修复统计

数据库表：
    - vm_remediation_tasks 修复任务表
"""
import time
import uuid
from typing import Optional, List, Dict, Any

from utils.database import db
from utils.logger import log


def _now() -> float:
    return time.time()


def _uid() -> str:
    return str(uuid.uuid4())


class RemediationTracker:
    """漏洞修复跟踪器。"""

    def __init__(self):
        """建表（幂等）。"""
        self._init_tables()

    def _init_tables(self):
        """初始化修复任务表。"""
        conn = db._get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vm_remediation_tasks (
                    id TEXT PRIMARY KEY,
                    vulnerability_id TEXT DEFAULT '',
                    title TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    assignee TEXT DEFAULT '',
                    status TEXT DEFAULT 'pending',
                    started_at REAL,
                    completed_at REAL,
                    verification_result TEXT DEFAULT '',
                    rollback_plan TEXT DEFAULT '',
                    created_at REAL DEFAULT 0,
                    updated_at REAL DEFAULT 0
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vm_rtask_vuln ON vm_remediation_tasks(vulnerability_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vm_rtask_status ON vm_remediation_tasks(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vm_rtask_assignee ON vm_remediation_tasks(assignee)")
            conn.commit()
            log.info("[vuln-remediation] 修复任务表初始化完成")
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-remediation] 初始化失败: {e}")
        finally:
            conn.close()

    # ==================== 修复任务 ====================

    def list_tasks(self, status: Optional[str] = None,
                   assignee: Optional[str] = None,
                   vulnerability_id: Optional[str] = None,
                   page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """分页查询修复任务。"""
        page = max(1, int(page))
        page_size = max(1, min(500, int(page_size)))
        offset = (page - 1) * page_size
        where = ["1=1"]
        params: List[Any] = []
        if status:
            where.append("status = ?")
            params.append(status)
        if assignee:
            where.append("assignee = ?")
            params.append(assignee)
        if vulnerability_id:
            where.append("vulnerability_id = ?")
            params.append(vulnerability_id)
        where_sql = " AND ".join(where)

        conn = db._get_connection()
        try:
            total = conn.execute(
                f"SELECT COUNT(*) FROM vm_remediation_tasks WHERE {where_sql}", params
            ).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM vm_remediation_tasks WHERE {where_sql} "
                f"ORDER BY created_at DESC LIMIT ? OFFSET ?",
                params + [page_size, offset],
            ).fetchall()
            return {"items": [dict(r) for r in rows], "total": total,
                    "page": page, "page_size": page_size}
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-remediation] 列表查询失败: {e}")
            return {"items": [], "total": 0, "page": page, "page_size": page_size}
        finally:
            conn.close()

    def get_remediation_plan(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """根据漏洞信息获取修复方案。

        优先尝试查询项目已有 vuln_database 模块；不可用时按漏洞类型生成通用建议。
        """
        name = (vuln.get("name") or "").lower()
        cwe = (vuln.get("cwe") or "").lower()
        cve = vuln.get("cve") or ""
        steps: List[str] = []
        code_example = ""
        config_change = ""

        # 尝试从 vuln_database 模块查询（可选依赖，失败则忽略）
        try:  # noqa: SIM105
            from vuln_database import query_remediation  # type: ignore
            plan = query_remediation(cve=cve, cwe=cwe, name=vuln.get("name"))
            if plan:
                return {"source": "vuln_database", "plan": plan}
        except Exception:
            pass

        # 通用规则匹配
        if any(k in name for k in ("xss", "跨站脚本")) or "cwe-79" in cwe:
            steps = [
                "对所有用户输入进行输出编码（HTML entity encode）",
                "使用成熟框架的自动转义模板，避免拼接 HTML",
                "部署 CSP（Content-Security-Policy）响应头",
                "对富文本输入使用白名单净化（如 DOMPurify）",
            ]
            code_example = "const safe = escapeHtml(userInput); element.innerHTML = safe;"
            config_change = "添加响应头: Content-Security-Policy: default-src 'self'"
        elif any(k in name for k in ("sql", "sql注入", "sql injection")) or "cwe-89" in cwe:
            steps = [
                "全部改用参数化查询 / 预编译语句",
                "禁止字符串拼接 SQL",
                "数据库账号最小权限，禁止应用使用 DBA 账号",
                "部署 WAF 规则作为临时缓解",
            ]
            code_example = "db.query('SELECT * FROM users WHERE id = ?', [uid])"
            config_change = "数据库账号移除 DROP/ALTER 等高权限"
        elif any(k in name for k in ("csrf", "跨站请求伪造")):
            steps = [
                "为所有状态变更请求绑定 CSRF Token",
                "校验 Origin / Referer 头",
                "关键操作要求二次确认",
            ]
            code_example = "<form method='post'><input type='hidden' name='csrf' value='...'>"
            config_change = "SameSite=Strict 的 Cookie 属性"
        elif any(k in name for k in ("认证", "authentication", "弱口令", "brute")):
            steps = [
                "强制强密码策略与多因素认证(MFA)",
                "登录失败限流与锁定",
                "移除默认/测试账号，定期轮换密钥",
            ]
            code_example = ""
            config_change = "启用 MFA；配置登录失败 5 次锁定 15 分钟"
        elif any(k in name for k in ("tls", "ssl", "https", "证书", "加密")):
            steps = ["升级到 TLS1.2+", "配置强加密套件", "移除过期证书，启用 HSTS"]
            code_example = ""
            config_change = "Strict-Transport-Security: max-age=63072000; includeSubDomains"
        else:
            steps = [
                f"确认漏洞 {vuln.get('name')} 的根因",
                "参照官方补丁/厂商公告进行升级或配置修改",
                "在预发环境验证修复效果",
                "回归扫描确认漏洞消失",
            ]
            code_example = ""
            config_change = "按厂商安全公告加固相关服务配置"

        return {
            "source": "generated",
            "vulnerability_id": vuln.get("id"),
            "vulnerability_name": vuln.get("name"),
            "steps": steps,
            "code_example": code_example,
            "config_change": config_change,
        }

    def start_remediation(self, vulnerability_id: str, assignee: str = "",
                         title: str = "", description: str = "") -> Dict[str, Any]:
        """为漏洞创建修复任务，并关联修复方案；同时将漏洞推进到 in_progress。"""
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM vulnerabilities WHERE id=?", (vulnerability_id,)
            ).fetchone()
            if not row:
                return {"success": False, "error": "漏洞不存在"}
            vuln = dict(row)

            plan = self.get_remediation_plan(vuln)
            task_id = _uid()
            now = _now()
            conn.execute(
                "INSERT INTO vm_remediation_tasks (id, vulnerability_id, title, description, "
                "assignee, status, started_at, completed_at, verification_result, rollback_plan, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'in_progress', ?, NULL, '', ?, ?, ?)",
                (task_id, vulnerability_id,
                 title or f"修复: {vuln.get('name')}",
                 description or "\n".join(plan.get("steps", [])),
                 assignee or vuln.get("assigned_to") or "",
                 now, self.get_rollback_plan(vuln).get("plan", ""), now, now),
            )
            # 漏洞生命周期推进到 in_progress
            cur_status = vuln.get("lifecycle_status") or vuln.get("status") or "new"
            conn.execute(
                "UPDATE vulnerabilities SET lifecycle_status='in_progress', status='in_progress' WHERE id=?",
                (vulnerability_id,),
            )
            conn.execute(
                "INSERT INTO vm_lifecycle_history (id, vulnerability_id, from_status, to_status, "
                "operator, note, changed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (_uid(), vulnerability_id, cur_status, "in_progress", assignee or "system",
                 "创建修复任务", now),
            )
            conn.commit()
            return {"success": True, "task_id": task_id, "vulnerability_id": vulnerability_id,
                    "remediation_plan": plan}
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-remediation] 启动修复失败 {vulnerability_id}: {e}")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def verify_remediation(self, task_id: str, verified: bool = True,
                           result: str = "", operator: str = "system") -> Dict[str, Any]:
        """修复完成后标记验证结果，成功则自动驱动漏洞 in_progress → fix_verified。"""
        conn = db._get_connection()
        try:
            task = conn.execute(
                "SELECT * FROM vm_remediation_tasks WHERE id=?", (task_id,)
            ).fetchone()
            if not task:
                return {"success": False, "error": "修复任务不存在"}
            now = _now()
            vuln_id = task["vulnerability_id"]

            if verified:
                conn.execute(
                    "UPDATE vm_remediation_tasks SET status='completed', completed_at=?, "
                    "verification_result=?, updated_at=? WHERE id=?",
                    (now, result or "修复验证通过", now, task_id),
                )
                # 自动驱动漏洞状态
                vrow = conn.execute(
                    "SELECT lifecycle_status FROM vulnerabilities WHERE id=?", (vuln_id,)
                ).fetchone()
                from_status = vrow["lifecycle_status"] if vrow else "in_progress"
                conn.execute(
                    "UPDATE vulnerabilities SET lifecycle_status='fix_verified', status='fix_verified', "
                    "remediated_at=? WHERE id=?",
                    (now, vuln_id),
                )
                conn.execute(
                    "INSERT INTO vm_lifecycle_history (id, vulnerability_id, from_status, to_status, "
                    "operator, note, changed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (_uid(), vuln_id, from_status, "fix_verified", operator,
                     result or "修复验证通过", now),
                )
                conn.commit()
                return {"success": True, "task_id": task_id, "vulnerability_id": vuln_id,
                        "vulnerability_status": "fix_verified"}
            else:
                conn.execute(
                    "UPDATE vm_remediation_tasks SET status='failed', verification_result=?, updated_at=? WHERE id=?",
                    (result or "修复验证未通过", now, task_id),
                )
                conn.commit()
                return {"success": True, "task_id": task_id, "vulnerability_id": vuln_id,
                        "vulnerability_status": task["status"], "note": "修复未通过验证，请参考回滚方案"}
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-remediation] 验证修复失败 {task_id}: {e}")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def get_rollback_plan(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """生成修复失败时的回滚方案。"""
        name = (vuln.get("name") or "漏洞").lower()
        plan = (
            f"1. 停止本次修复变更，回退到变更前版本/配置快照\n"
            f"2. 核对变更前备份（数据库/配置文件/二进制），确认可用性\n"
            f"3. 重新评估 {vuln.get('name') or name} 的风险与影响面\n"
            f"4. 临时缓解措施：WAF 规则 / 访问控制 / 下线受影响接口\n"
            f"5. 记录失败原因，转交更高优先级处理或申请 SLA 例外"
        )
        return {"vulnerability_id": vuln.get("id"), "plan": plan,
                "steps": [l.strip() for l in plan.split("\n") if l.strip()]}

    def get_remediation_stats(self) -> Dict[str, Any]:
        """修复成功率 / 平均修复时间 / 验证通过率 / 按严重程度统计。"""
        now = _now()
        conn = db._get_connection()
        try:
            total_tasks = conn.execute("SELECT COUNT(*) FROM vm_remediation_tasks").fetchone()[0]
            completed = conn.execute(
                "SELECT COUNT(*) FROM vm_remediation_tasks WHERE status='completed'"
            ).fetchone()[0]
            failed = conn.execute(
                "SELECT COUNT(*) FROM vm_remediation_tasks WHERE status='failed'"
            ).fetchone()[0]
            success_rate = round(completed / total_tasks * 100, 2) if total_tasks else 100.0

            # 平均修复时间
            rows = conn.execute(
                "SELECT started_at, completed_at FROM vm_remediation_tasks "
                "WHERE status='completed' AND started_at IS NOT NULL AND completed_at IS NOT NULL "
                "AND completed_at > started_at"
            ).fetchall()
            avg_hours = 0.0
            if rows:
                avg_hours = round(sum((r["completed_at"] - r["started_at"]) for r in rows)
                                  / len(rows) / 3600, 2)

            # 验证通过率（漏洞表）
            verified = conn.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE lifecycle_status='fix_verified'"
            ).fetchone()[0]
            in_progress = conn.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE lifecycle_status='in_progress'"
            ).fetchone()[0]
            verify_pass = round(verified / (verified + in_progress) * 100, 2) if (verified + in_progress) else 100.0

            # 按严重程度统计修复任务
            by_sev_rows = conn.execute(
                "SELECT v.severity, COUNT(t.id) AS cnt, "
                "SUM(CASE WHEN t.status='completed' THEN 1 ELSE 0 END) AS done "
                "FROM vm_remediation_tasks t "
                "LEFT JOIN vulnerabilities v ON v.id = t.vulnerability_id "
                "GROUP BY v.severity"
            ).fetchall()
            by_severity = {
                r["severity"] or "unknown": {"total": r["cnt"], "completed": r["done"] or 0}
                for r in by_sev_rows
            }

            return {
                "total_tasks": total_tasks,
                "completed": completed,
                "failed": failed,
                "success_rate_percent": success_rate,
                "avg_remediation_hours": avg_hours,
                "verification_pass_rate_percent": verify_pass,
                "by_severity": by_severity,
            }
        except Exception as e:  # noqa: BLE001
            log.error(f"[vuln-remediation] 修复统计失败: {e}")
            return {"total_tasks": 0, "completed": 0, "failed": 0,
                    "success_rate_percent": 0.0, "avg_remediation_hours": 0.0,
                    "verification_pass_rate_percent": 0.0, "by_severity": {}}
        finally:
            conn.close()


# 全局单例
remediation_tracker = RemediationTracker()
