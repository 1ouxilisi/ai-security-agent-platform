# -*- coding: utf-8 -*-
"""
restore_manager.py - 恢复管理器。

功能：
    - 恢复方式：完整恢复 / 指定表恢复 / 指定数据恢复
    - 恢复前验证：完整性 / 加密密码 / 可读性
    - 恢复预览：表列表 / 数据量 / 元数据
    - 恢复执行：自动备份当前数据 -> 恢复 -> 验证，支持恢复到新库文件
    - 恢复回滚：失败时用恢复前的临时备份自动回滚
    - 恢复报告：备份信息 / 内容 / 时间 / 结果 / 回滚信息

数据库表：restore_tasks
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from utils.logger import log  # type: ignore
except Exception:  # pragma: no cover
    import logging as log  # type: ignore

from backup.backup_manager import (  # noqa: E402
    BACKUP_ROOT, DATA_DIR, MAIN_DB_PATH, get_meta_connection, now_iso,
    unpack_blob, sha256_file, sha256_bytes,
)


class RestoreManager:
    """恢复管理器（单例）。"""

    def __init__(self) -> None:
        self._init_table()

    def _init_table(self) -> None:
        conn = get_meta_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS restore_tasks (
                    id TEXT PRIMARY KEY,
                    backup_id TEXT,
                    target_db TEXT,
                    tables TEXT,
                    status TEXT DEFAULT 'pending',
                    started_at TEXT,
                    completed_at TEXT,
                    result_summary TEXT,
                    rollback_backup_id TEXT,
                    error TEXT,
                    created_at TEXT
                )
            """)
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"restore_manager 建表失败: {e}")
        finally:
            conn.close()

    # ---------- 验证 / 预览 ----------

    def validate_backup(self, backup_id: str,
                        password: Optional[str] = None) -> Dict[str, Any]:
        """验证备份文件完整性与可读性。"""
        from backup.backup_manager import backup_manager
        info = backup_manager.get_backup(backup_id)
        if not info["success"]:
            return info
        rec = info["data"]
        fp = Path(rec["file_path"])
        if not fp.exists():
            return {"success": False, "data": None, "error": "备份文件丢失"}
        checks = {
            "file_exists": True,
            "size_ok": fp.stat().st_size == rec["file_size"],
            "checksum_ok": sha256_file(fp) == rec["checksum"],
        }
        # 尝试解包
        try:
            with open(fp, "rb") as f:
                blob = f.read()
            raw = unpack_blob(blob, compressed=bool(rec["compressed"]),
                              encrypted=bool(rec["encrypted"]), password=password)
            checks["decrypt_ok"] = True
            checks["preview_bytes"] = len(raw)
        except Exception as e:
            checks["decrypt_ok"] = False
            checks["error"] = str(e)
            return {"success": False, "data": checks, "error": f"解包失败: {e}"}
        return {"success": True, "data": checks, "error": None}

    def preview_restore(self, backup_id: str,
                        tables: Optional[List[str]] = None) -> Dict[str, Any]:
        """恢复前预览：表列表 / 每个表数据量 / 元数据。"""
        from backup.backup_manager import backup_manager
        info = backup_manager.get_backup(backup_id)
        if not info["success"]:
            return info
        rec = info["data"]
        try:
            with open(rec["file_path"], "rb") as f:
                blob = f.read()
            raw = unpack_blob(blob, compressed=bool(rec["compressed"]),
                              encrypted=bool(rec["encrypted"]), password="")
            marker = b"\n--SIDECAR--\n"
            sidecar: Dict[str, Any] = {}
            if marker in raw:
                main_part, side_part = raw.rsplit(marker, 1)
                try:
                    sidecar = json.loads(side_part.decode("utf-8", "ignore"))
                except Exception:
                    sidecar = {}
            else:
                main_part = raw

            table_stats: List[Dict[str, Any]] = []
            if rec["backup_type"] == "full":
                # SQL dump：统计 CREATE TABLE 与 INSERT 行数
                text = main_part.decode("utf-8", "ignore")
                tset = set()
                for line in text.splitlines():
                    if line.startswith("CREATE TABLE"):
                        parts = line.split('"')
                        if len(parts) >= 2:
                            tset.add(parts[1])
                for t in sorted(tset):
                    cnt = text.count(f'INSERT INTO "{t}"')
                    table_stats.append({"table": t, "est_rows": cnt})
            else:
                try:
                    j = json.loads(main_part.decode("utf-8", "ignore"))
                    for t, rows in (j.get("rows") or {}).items():
                        table_stats.append({"table": t, "est_rows": len(rows)})
                except Exception:
                    pass

            if tables:
                table_stats = [s for s in table_stats if s["table"] in tables]

            return {"success": True, "data": {
                "backup_id": backup_id,
                "backup_type": rec["backup_type"],
                "backup_time": rec["created_at"],
                "tables": table_stats,
                "total_tables": len(table_stats),
                "sidecar": sidecar,
                "encrypted": bool(rec["encrypted"]),
            }, "error": None}
        except Exception as e:
            return {"success": False, "data": None, "error": str(e)}

    # ---------- 执行恢复 ----------

    def execute_restore(self, backup_id: str,
                        tables: Optional[List[str]] = None,
                        target_db: Optional[str] = None,
                        password: Optional[str] = None) -> Dict[str, Any]:
        """执行恢复。流程：安全快照 -> 解包 -> 恢复 -> 验证 -> 失败回滚。"""
        from backup.backup_manager import backup_manager
        task_id = str(uuid.uuid4())
        started = now_iso()
        conn = get_meta_connection()
        try:
            conn.execute(
                "INSERT INTO restore_tasks "
                "(id,backup_id,target_db,tables,status,started_at,created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (task_id, backup_id, target_db or str(MAIN_DB_PATH),
                 json.dumps(tables or []), "running", started, started))
            conn.commit()
        finally:
            conn.close()

        rollback_bid = ""
        try:
            # 1) 验证
            v = self.validate_backup(backup_id, password=password)
            if not v["success"]:
                raise RuntimeError(f"备份验证失败: {v['error']}")

            # 2) 恢复前自动备份当前数据（安全快照）
            safety = backup_manager.create_backup(
                backup_type="full", description=f"恢复前自动快照 task={task_id}")
            if safety.get("success"):
                rollback_bid = safety["data"]["id"]

            # 3) 解包
            rec = backup_manager.get_backup(backup_id)["data"]
            with open(rec["file_path"], "rb") as f:
                blob = f.read()
            raw = unpack_blob(blob, compressed=bool(rec["compressed"]),
                              encrypted=bool(rec["encrypted"]), password=password)
            marker = b"\n--SIDECAR--\n"
            main_part = raw.rsplit(marker, 1)[0] if marker in raw else raw

            target = Path(target_db) if target_db else MAIN_DB_PATH
            applied_tables: List[str] = []
            applied_rows = 0

            # 4) 按类型恢复
            if rec["backup_type"] == "full":
                sql_text = main_part.decode("utf-8", "ignore")
                applied_tables, applied_rows = self._apply_sql_dump(
                    target, sql_text, tables)
            else:
                j = json.loads(main_part.decode("utf-8", "ignore"))
                applied_tables, applied_rows = self._apply_delta(
                    target, j.get("rows") or {}, tables)

            # 5) 验证恢复结果
            verify = self._verify_restored(target, applied_tables)

            summary = {
                "backup_id": backup_id,
                "target_db": str(target),
                "applied_tables": applied_tables,
                "applied_rows": applied_rows,
                "verified": verify,
                "rollback_backup_id": rollback_bid,
            }
            self._update_task(task_id, "success", summary, rollback_bid)
            return {"success": True, "data": {"task_id": task_id, "summary": summary},
                    "error": None}

        except Exception as e:
            log.exception(f"恢复执行失败: {e}")
            # 自动回滚
            rollback_info = {"rolled_back": False}
            if rollback_bid:
                try:
                    self._restore_safety_snapshot(rollback_bid, password)
                    rollback_info = {"rolled_back": True, "backup_id": rollback_bid}
                except Exception as re:  # pragma: no cover
                    rollback_info = {"rolled_back": False, "error": str(re)}
            self._update_task(task_id, "failed",
                              {"error": str(e), "rollback": rollback_info},
                              rollback_bid, error=str(e))
            return {"success": False, "data": {"task_id": task_id, "rollback": rollback_info},
                    "error": str(e)}

    def _apply_sql_dump(self, target: Path, sql_text: str,
                        tables: Optional[List[str]]) -> tuple:
        """把 SQL dump 应用到目标库（可选只应用指定表）。"""
        applied_tables: List[str] = []
        applied_rows = 0
        # 若指定表，则过滤 SQL：保留这些表的 CREATE / INSERT
        lines = sql_text.splitlines()
        if tables:
            keep = set(tables)
            filtered = []
            for ln in lines:
                if ln.startswith("CREATE TABLE"):
                    tname = ln.split('"')[1] if '"' in ln else ""
                    if tname in keep:
                        filtered.append(ln)
                elif ln.startswith("INSERT INTO"):
                    tname = ln.split('"')[1] if '"' in ln else ""
                    if tname in keep:
                        filtered.append(ln)
                        applied_rows += 1
                else:
                    filtered.append(ln)
            lines = filtered
            applied_tables = list(keep)
        else:
            for ln in lines:
                if ln.startswith("INSERT INTO"):
                    applied_rows += 1
                elif ln.startswith("CREATE TABLE"):
                    parts = ln.split('"')
                    if len(parts) >= 2:
                        applied_tables.append(parts[1])

        conn = sqlite3.connect(str(target))
        try:
            conn.executescript("\n".join(lines))
            conn.commit()
        finally:
            conn.close()
        return applied_tables, applied_rows

    def _apply_delta(self, target: Path, rows_map: Dict[str, List[Dict[str, Any]]],
                     tables: Optional[List[str]]) -> tuple:
        """把增量 JSON 行 upsert 到目标库。"""
        applied_tables: List[str] = []
        applied_rows = 0
        conn = sqlite3.connect(str(target))
        try:
            for t, rows in rows_map.items():
                if tables and t not in tables:
                    continue
                if not rows:
                    continue
                applied_tables.append(t)
                cols = list(rows[0].keys())
                placeholders = ",".join("?" * len(cols))
                col_sql = ",".join(f'"{c}"' for c in cols)
                # INSERT OR REPLACE 实现 upsert
                values = [[r.get(c) for c in cols] for r in rows]
                conn.executemany(
                    f'INSERT OR REPLACE INTO "{t}" ({col_sql}) VALUES ({placeholders})',
                    values)
                applied_rows += len(rows)
            conn.commit()
        finally:
            conn.close()
        return applied_tables, applied_rows

    def _verify_restored(self, target: Path, tables: List[str]) -> bool:
        """恢复后简单校验：目标库可打开且表存在。"""
        if not target.exists():
            return False
        try:
            conn = sqlite3.connect(str(target))
            try:
                existing = {r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
                for t in tables:
                    if t not in existing:
                        return False
                return True
            finally:
                conn.close()
        except Exception:
            return False

    def _restore_safety_snapshot(self, backup_id: str,
                                 password: Optional[str]) -> None:
        """用恢复前快照回滚（直接覆盖主库文件）。"""
        from backup.backup_manager import backup_manager
        rec = backup_manager.get_backup(backup_id)["data"]
        with open(rec["file_path"], "rb") as f:
            blob = f.read()
        raw = unpack_blob(blob, compressed=bool(rec["compressed"]),
                          encrypted=bool(rec["encrypted"]), password=password)
        marker = b"\n--SIDECAR--\n"
        main_part = raw.rsplit(marker, 1)[0] if marker in raw else raw
        # 快照是 SQL dump，重建主库
        if MAIN_DB_PATH.exists():
            shutil.copy2(str(MAIN_DB_PATH),
                         str(MAIN_DB_PATH.with_suffix(".db.before_rollback")))
        conn = sqlite3.connect(str(MAIN_DB_PATH))
        try:
            conn.executescript(main_part.decode("utf-8", "ignore"))
            conn.commit()
        finally:
            conn.close()

    def _update_task(self, task_id: str, status: str,
                     summary: Dict[str, Any], rollback_bid: str = "",
                     error: str = "") -> None:
        conn = get_meta_connection()
        try:
            conn.execute(
                "UPDATE restore_tasks SET status=?, result_summary=?, "
                "rollback_backup_id=?, completed_at=?, error=? WHERE id=?",
                (status, json.dumps(summary, ensure_ascii=False, default=str),
                 rollback_bid, now_iso(), error, task_id))
            conn.commit()
        finally:
            conn.close()

    # ---------- 查询 ----------

    def get_restore_status(self, task_id: str) -> Dict[str, Any]:
        """获取恢复任务状态。"""
        conn = get_meta_connection()
        try:
            row = conn.execute("SELECT * FROM restore_tasks WHERE id=?", (task_id,)).fetchone()
            if not row:
                return {"success": False, "data": None, "error": "任务不存在"}
            return {"success": True, "data": dict(row), "error": None}
        except Exception as e:
            return {"success": False, "data": None, "error": str(e)}
        finally:
            conn.close()

    def get_restore_report(self, task_id: str) -> Dict[str, Any]:
        """生成恢复报告。"""
        st = self.get_restore_status(task_id)
        if not st["success"]:
            return st
        d = st["data"]
        try:
            summary = json.loads(d.get("result_summary") or "{}")
        except Exception:
            summary = {}
        report = {
            "task_id": task_id,
            "backup_id": d.get("backup_id"),
            "target_db": d.get("target_db"),
            "status": d.get("status"),
            "started_at": d.get("started_at"),
            "completed_at": d.get("completed_at"),
            "result": summary,
            "rollback": summary.get("rollback", {}),
            "error": d.get("error"),
        }
        return {"success": True, "data": report, "error": None}

    def rollback_restore(self, task_id: str) -> Dict[str, Any]:
        """手动回滚一个恢复任务（使用其安全快照）。"""
        st = self.get_restore_status(task_id)
        if not st["success"]:
            return st
        rb = st["data"].get("rollback_backup_id")
        if not rb:
            return {"success": False, "data": None, "error": "无可用回滚快照"}
        try:
            self._restore_safety_snapshot(rb, "")
            return {"success": True, "data": {"rolled_back_to": rb}, "error": None}
        except Exception as e:
            return {"success": False, "data": None, "error": str(e)}

    def list_restores(self, page: int = 1,
                      page_size: int = 20) -> Dict[str, Any]:
        """分页列出恢复任务。"""
        conn = get_meta_connection()
        try:
            total = conn.execute("SELECT COUNT(*) FROM restore_tasks").fetchone()[0]
            rows = conn.execute(
                "SELECT * FROM restore_tasks ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (page_size, (page - 1) * page_size)).fetchall()
            return {"success": True, "data": {
                "total": total, "page": page, "page_size": page_size,
                "items": [dict(r) for r in rows]}, "error": None}
        except Exception as e:
            return {"success": False, "data": None, "error": str(e)}
        finally:
            conn.close()


# 模块级单例
restore_manager = RestoreManager()
