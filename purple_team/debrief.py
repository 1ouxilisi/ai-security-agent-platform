# -*- coding: utf-8 -*-
"""
紫队复盘管理器（Purple Team Debrief）

模块功能：
    - 红蓝对抗演练编排与状态管理（pt_exercises）
    - 红队攻击路径 vs 蓝队检测结果对比分析（pt_comparisons）
    - ATT&CK 战术/技术检测覆盖率（pt_coverage）
    - 时间线分析与检测延迟计算
    - 复盘报告生成
    - 改进措施跟踪（pt_improvements）

安全声明：
    - 本模块只整合红队模拟与蓝队检测的推演结果，不执行真实攻击
"""
import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.database import db
from utils.logger import log


# ATT&CK 战术分类（用于覆盖率矩阵）
_ATTACK_TACTICS = {
    "Reconnaissance": "侦察",
    "Resource Development": "资源开发",
    "Initial Access": "初始访问",
    "Execution": "执行",
    "Persistence": "持久化",
    "Privilege Escalation": "权限提升",
    "Defense Evasion": "防御规避",
    "Credential Access": "凭证访问",
    "Discovery": "发现",
    "Lateral Movement": "横向移动",
    "Collection": "数据收集",
    "Command and Control": "命令控制",
    "Exfiltration": "数据渗出",
    "Impact": "影响",
}


class PurpleTeamDebrief:
    """紫队复盘管理器"""

    def __init__(self):
        """初始化：建表"""
        self._init_tables()

    def _get_conn(self):
        return db._get_connection()

    def _init_tables(self):
        """初始化紫队相关数据表"""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pt_exercises (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                red_simulation_id TEXT,
                blue_detection_id TEXT,
                status TEXT DEFAULT 'preparation',
                started_at TEXT,
                completed_at TEXT,
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pt_comparisons (
                id TEXT PRIMARY KEY,
                exercise_id TEXT,
                attack_step TEXT,
                technique TEXT,
                red_success INTEGER,
                blue_detected INTEGER,
                blue_blocked INTEGER,
                detection_latency_seconds REAL,
                notes TEXT,
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pt_coverage (
                id TEXT PRIMARY KEY,
                exercise_id TEXT,
                tactic TEXT,
                technique TEXT,
                detected INTEGER,
                blocked INTEGER,
                coverage_rate REAL,
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pt_improvements (
                id TEXT PRIMARY KEY,
                exercise_id TEXT,
                title TEXT NOT NULL,
                description TEXT,
                category TEXT DEFAULT 'detection_rule',
                priority TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'pending',
                assignee TEXT,
                due_date TEXT,
                completed_at TEXT,
                verification_result TEXT,
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_pt_ex_red ON pt_exercises(red_simulation_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_pt_cmp_ex ON pt_comparisons(exercise_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_pt_cov_ex ON pt_coverage(exercise_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_pt_imp_ex ON pt_improvements(exercise_id)")
        conn.commit()
        conn.close()
        log.info("✅ 紫队数据表初始化完成")

    # ---------- 演练管理 ----------

    def start_exercise(self, name: str, scenario_id: str,
                       target_scope: Optional[Dict[str, Any]] = None,
                       description: str = "") -> Dict[str, Any]:
        """启动演练：执行红队模拟与蓝队检测并关联"""
        from red_team.simulation import RedTeamSimulator
        from blue_team.detection import BlueTeamDetector

        rt = RedTeamSimulator()
        bt = BlueTeamDetector()

        # 1. 红队模拟
        sim = rt.start_simulation(scenario_id, name=f"{name}-红队模拟", target_scope=target_scope or {})
        # 2. 蓝队检测
        det = bt.start_detection(sim["id"], name=f"{name}-蓝队检测")

        now = datetime.now().isoformat()
        ex_id = str(uuid.uuid4())
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO pt_exercises
            (id, name, description, red_simulation_id, blue_detection_id,
             status, started_at, completed_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ex_id, name, description, sim["id"], det["id"],
              "debrief", now, now, now))
        conn.commit()
        conn.close()

        # 3. 生成对比、覆盖率数据
        self._build_comparison(ex_id, sim, det)
        log.info(f"✅ 紫队演练启动完成: {ex_id}")
        return self.get_exercise_status(ex_id)

    def _build_comparison(self, exercise_id: str, sim: Dict, det: Dict):
        """根据红队模拟与蓝队检测结果生成对比与覆盖率记录"""
        now = datetime.now().isoformat()
        steps = sim.get("attack_path_detail", []) or []
        alerts = det.get("alerts", []) or []
        detection_rate = det.get("detection_rate", 0.5) or 0.5
        block_rate = det.get("block_rate", 0.0) or 0.0

        conn = self._get_conn()
        # 对比表
        for i, s in enumerate(steps):
            red_success = 1
            # 第 i 步是否被检测：按检测概率分布
            detected = 1 if (i % 4 != 3) and (i / max(1, len(steps))) < detection_rate else 0
            blocked = 1 if detected and (i / max(1, len(steps))) < block_rate else 0
            latency = round((i + 1) * (30 + (i % 3) * 20), 1) if detected else None
            conn.execute("""
                INSERT INTO pt_comparisons
                (id, exercise_id, attack_step, technique, red_success, blue_detected,
                 blue_blocked, detection_latency_seconds, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4()), exercise_id, s.get("step_name", ""), s.get("technique", ""),
                red_success, detected, blocked, latency,
                "红队成功" if red_success else "红队受阻", now,
            ))
        # 覆盖率表（按 ttp）
        scenario = sim.get("scenario") or {}
        for t in scenario.get("ttps", []):
            covered = any(a.get("details", {}).get("ttp") == t for a in alerts)
            conn.execute("""
                INSERT INTO pt_coverage
                (id, exercise_id, tactic, technique, detected, blocked, coverage_rate, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4()), exercise_id, "通用", t,
                1 if covered else 0,
                1 if covered and block_rate > 0.5 else 0,
                round(1.0 if covered else 0.0, 2), now,
            ))
        conn.commit()
        conn.close()

    def list_exercises(self) -> List[Dict[str, Any]]:
        """演练列表"""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM pt_exercises ORDER BY created_at DESC").fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_exercise_status(self, exercise_id: str) -> Optional[Dict[str, Any]]:
        """演练状态详情"""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM pt_exercises WHERE id = ?", (exercise_id,)).fetchone()
        if not row:
            conn.close()
            return None
        ex = dict(row)
        stats = conn.execute("""
            SELECT
              SUM(blue_detected) AS detected,
              SUM(blue_blocked) AS blocked,
              COUNT(*) AS total
            FROM pt_comparisons WHERE exercise_id = ?
        """, (exercise_id,)).fetchone()
        conn.close()
        ex["stats"] = {
            "total_steps": stats["total"] or 0,
            "detected": stats["detected"] or 0,
            "blocked": stats["blocked"] or 0,
        }
        return ex

    def get_comparison(self, exercise_id: str) -> Dict[str, Any]:
        """对比分析：红队攻击路径 vs 蓝队检测结果"""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM pt_comparisons WHERE exercise_id = ? ORDER BY rowid",
            (exercise_id,)).fetchall()
        conn.close()
        items = [dict(r) for r in rows]
        detected = [i for i in items if i["blue_detected"]]
        not_detected = [i for i in items if not i["blue_detected"]]
        return {
            "exercise_id": exercise_id,
            "total_steps": len(items),
            "detected_count": len(detected),
            "not_detected_count": len(not_detected),
            "detected": detected,
            "not_detected": not_detected,
            "items": items,
        }

    def get_coverage(self, exercise_id: str) -> Dict[str, Any]:
        """检测覆盖率：按 ATT&CK 战术和技术统计，生成覆盖率矩阵数据"""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM pt_coverage WHERE exercise_id = ?", (exercise_id,)).fetchall()
        conn.close()
        items = [dict(r) for r in rows]
        covered = [i for i in items if i["detected"]]
        total = max(1, len(items))
        matrix = {}
        for i in items:
            tactic = i["tactic"] or "通用"
            matrix.setdefault(tactic, []).append({
                "technique": i["technique"],
                "detected": bool(i["detected"]),
                "blocked": bool(i["blocked"]),
                "coverage_rate": i["coverage_rate"],
            })
        return {
            "exercise_id": exercise_id,
            "total_techniques": len(items),
            "covered_techniques": len(covered),
            "coverage_rate": round(len(covered) / total, 4),
            "matrix": matrix,
            "tactics_catalog": _ATTACK_TACTICS,
        }

    def get_timeline(self, exercise_id: str) -> Dict[str, Any]:
        """时间线分析：攻击时间线 vs 检测时间线，计算检测延迟"""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT attack_step, technique, blue_detected, detection_latency_seconds
            FROM pt_comparisons WHERE exercise_id = ? ORDER BY rowid
        """, (exercise_id,)).fetchall()
        conn.close()
        attack_timeline = []
        detect_timeline = []
        latencies = []
        t = 0
        for r in rows:
            t += 60  # 攻击阶段间隔模拟 60 秒
            attack_timeline.append({"time": t, "event": f"攻击:{r['attack_step']}"})
            if r["blue_detected"]:
                lat = r["detection_latency_seconds"] or 0
                latencies.append(lat)
                detect_timeline.append({"time": t + lat, "event": f"检测:{r['attack_step']}",
                                        "latency": lat})
        avg_latency = round(sum(latencies) / len(latencies), 1) if latencies else 0.0
        return {
            "exercise_id": exercise_id,
            "attack_timeline": attack_timeline,
            "detect_timeline": detect_timeline,
            "avg_detection_latency_seconds": avg_latency,
        }

    # ---------- 改进措施 ----------

    def list_improvements(self, exercise_id: str,
                          status: Optional[str] = None) -> List[Dict[str, Any]]:
        """改进措施列表"""
        conn = self._get_conn()
        query = "SELECT * FROM pt_improvements WHERE exercise_id = ?"
        params: List[Any] = [exercise_id]
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def create_improvement(self, exercise_id: str, title: str, description: str = "",
                           category: str = "detection_rule", priority: str = "medium",
                           assignee: str = "", due_date: str = "") -> Dict[str, Any]:
        """创建改进措施"""
        imp_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO pt_improvements
            (id, exercise_id, title, description, category, priority, status,
             assignee, due_date, completed_at, verification_result, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (imp_id, exercise_id, title, description, category, priority, "pending",
              assignee, due_date, None, None, now))
        conn.commit()
        conn.close()
        return self._get_improvement(imp_id)

    def _get_improvement(self, imp_id: str) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM pt_improvements WHERE id = ?", (imp_id,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def complete_improvement(self, improvement_id: str,
                             verification_result: str = "") -> Optional[Dict[str, Any]]:
        """完成改进措施，记录验证结果"""
        now = datetime.now().isoformat()
        conn = self._get_conn()
        conn.execute("""
            UPDATE pt_improvements
            SET status = 'completed', completed_at = ?, verification_result = ?
            WHERE id = ?
        """, (now, verification_result or "已验证", improvement_id))
        conn.commit()
        conn.close()
        return self._get_improvement(improvement_id)

    def get_improvement_progress(self, exercise_id: str) -> Dict[str, Any]:
        """改进措施执行进度"""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT status, COUNT(*) AS c FROM pt_improvements WHERE exercise_id = ? GROUP BY status",
            (exercise_id,)).fetchall()
        conn.close()
        dist = {r["status"]: r["c"] for r in rows}
        total = sum(dist.values())
        done = dist.get("completed", 0)
        return {
            "exercise_id": exercise_id,
            "total": total,
            "completed": done,
            "pending": dist.get("pending", 0),
            "in_progress": dist.get("in_progress", 0),
            "progress_rate": round(done / total, 4) if total else 0.0,
            "distribution": dist,
        }

    # ---------- 复盘报告 ----------

    def generate_debrief_report(self, exercise_id: str) -> Dict[str, Any]:
        """生成紫队复盘报告"""
        ex = self.get_exercise_status(exercise_id)
        if not ex:
            raise ValueError(f"演练不存在: {exercise_id}")
        comparison = self.get_comparison(exercise_id)
        coverage = self.get_coverage(exercise_id)
        timeline = self.get_timeline(exercise_id)
        improvements = self.list_improvements(exercise_id)
        progress = self.get_improvement_progress(exercise_id)

        report = {
            "report_type": "purple_debrief",
            "title": f"紫队复盘报告 - {ex.get('name', '')}",
            "overview": {
                "name": ex.get("name"),
                "status": ex.get("status"),
                "stats": ex.get("stats"),
            },
            "comparison": {
                "detected_count": comparison["detected_count"],
                "not_detected_count": comparison["not_detected_count"],
                "items": comparison["items"],
            },
            "coverage": {
                "coverage_rate": coverage["coverage_rate"],
                "covered_techniques": coverage["covered_techniques"],
                "total_techniques": coverage["total_techniques"],
                "matrix": coverage["matrix"],
            },
            "timeline": {
                "avg_detection_latency_seconds": timeline["avg_detection_latency_seconds"],
            },
            "improvements": {
                "items": improvements,
                "progress": progress,
            },
            "improvement_plan": [
                {"title": i["title"], "priority": i["priority"], "status": i["status"]}
                for i in improvements
            ],
            "generated_at": datetime.now().isoformat(),
        }
        log.info(f"✅ 紫队复盘报告生成: {exercise_id}")
        return report
