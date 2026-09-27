# -*- coding: utf-8 -*-
"""
export_manager.py - 数据导出管理器。

功能：
    - 导出格式：JSON / CSV / XML / SQL / HTML（Excel 用 CSV 代替）
    - 导出内容：指定表 / 指定 SQL 查询结果 / 指定字段 / 指定时间范围
    - 导出方式：立即导出
    - 导出压缩：gzip
    - 导出加密：XOR + base64
    - 导出统计：次数 / 大小 / 格式分布 / 时间

数据库表：export_records
"""

from __future__ import annotations

import base64
import csv
import gzip
import io
import json
import os
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
    sha256_bytes, xor_encrypt,
)

EXPORT_DIR = BACKUP_ROOT / "exports"
EXPORT_DIR.mkdir(parents=True, exist_ok=True)

VALID_FORMATS = {"json", "csv", "xml", "sql", "html"}


class ExportManager:
    """数据导出管理器（单例）。"""

    def __init__(self) -> None:
        self._init_table()

    def _init_table(self) -> None:
        conn = get_meta_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS export_records (
                    id TEXT PRIMARY KEY,
                    export_format TEXT NOT NULL,
                    file_path TEXT,
                    file_size INTEGER DEFAULT 0,
                    tables TEXT,
                    record_count INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'pending',
                    compressed INTEGER DEFAULT 0,
                    encrypted INTEGER DEFAULT 0,
                    description TEXT,
                    created_at TEXT,
                    error TEXT
                )
            """)
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"export_manager 建表失败: {e}")
        finally:
            conn.close()

    # ---------- 数据采集 ----------

    def _collect_rows(self, tables: Optional[List[str]],
                      query: Optional[str],
                      fields: Optional[List[str]],
                      time_range: Optional[Dict[str, str]]) -> List[Dict[str, Any]]:
        """从源库采集数据行。"""
        if not MAIN_DB_PATH.exists():
            return []
        conn = sqlite3.connect(str(MAIN_DB_PATH))
        conn.row_factory = sqlite3.Row
        try:
            rows: List[Dict[str, Any]] = []
            if query:
                # 直接执行 SQL 查询
                q = query
                if time_range and "where" not in q.lower():
                    start = time_range.get("start")
                    end = time_range.get("end")
                    if start:
                        q += f" WHERE created_at >= '{start}'"
                    if end:
                        q += f" {'AND' if start else 'WHERE'} created_at <= '{end}'"
                result = conn.execute(q).fetchall()
                rows = [dict(r) for r in result]
            else:
                targets = tables or [r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%'").fetchall()]
                for t in targets:
                    try:
                        cols = "*"
                        if fields:
                            cols = ",".join(f'"{f}"' for f in fields)
                        sql = f'SELECT {cols} FROM "{t}"'
                        if time_range:
                            start = time_range.get("start")
                            end = time_range.get("end")
                            if start:
                                sql += f" WHERE created_at >= '{start}'"
                            if end:
                                sql += f" {'AND' if start else 'WHERE'} created_at <= '{end}'"
                        for r in conn.execute(sql).fetchall():
                            d = dict(r)
                            d["_table"] = t
                            rows.append(d)
                    except Exception:
                        continue
            return rows
        finally:
            conn.close()

    # ---------- 格式渲染 ----------

    def _render(self, rows: List[Dict[str, Any]], fmt: str) -> bytes:
        if fmt == "json":
            return json.dumps(rows, ensure_ascii=False, indent=2,
                              default=str).encode("utf-8")
        if fmt == "csv":
            buf = io.StringIO()
            if not rows:
                return b""
            # 使用所有行的字段并集，避免不同表列不一致导致 DictWriter 报错
            cols: List[str] = []
            seen = set()
            for r in rows:
                for k in r.keys():
                    if k not in seen:
                        seen.add(k)
                        cols.append(k)
            w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow(r)
            return buf.getvalue().encode("utf-8")
        if fmt == "xml":
            parts = ['<?xml version="1.0" encoding="UTF-8"?>', "<root>"]
            for r in rows:
                parts.append("  <row>")
                for k, v in r.items():
                    k2 = str(k).replace(" ", "_")
                    parts.append(f"    <{k2}>{self._xml_escape(str(v))}</{k2}>")
                parts.append("  </row>")
            parts.append("</root>")
            return "\n".join(parts).encode("utf-8")
        if fmt == "sql":
            # 生成 INSERT 语句
            lines: List[str] = []
            for r in rows:
                t = r.get("_table", "unknown")
                cols = [k for k in r.keys() if k != "_table"]
                vals = []
                for c in cols:
                    v = r[c]
                    if v is None:
                        vals.append("NULL")
                    elif isinstance(v, (int, float)):
                        vals.append(str(v))
                    else:
                        s = str(v).replace("'", "''")
                        vals.append(f"'{s}'")
                lines.append(
                    f'INSERT INTO "{t}" ({",".join(chr(34)+c+chr(34) for c in cols)}) '
                    f'VALUES ({",".join(vals)});')
            return "\n".join(lines).encode("utf-8")
        if fmt == "html":
            parts = ["<html><head><meta charset='utf-8'><title>Export</title></head><body>",
                     "<table border='1'>"]
            if rows:
                cols = list(rows[0].keys())
                parts.append("<tr>" + "".join(f"<th>{self._xml_escape(c)}</th>" for c in cols) + "</tr>")
                for r in rows:
                    parts.append("<tr>" + "".join(
                        f"<td>{self._xml_escape(str(r.get(c,'')))}</td>" for c in cols) + "</tr>")
            parts.append("</table></body></html>")
            return "\n".join(parts).encode("utf-8")
        raise ValueError(f"不支持的导出格式: {fmt}")

    @staticmethod
    def _xml_escape(s: str) -> str:
        return (s.replace("&", "&amp;").replace("<", "&lt;")
                 .replace(">", "&gt;").replace('"', "&quot;"))

    # ---------- 主流程 ----------

    def create_export(self, tables: Optional[List[str]] = None,
                      query: Optional[str] = None,
                      format: str = "json",
                      fields: Optional[List[str]] = None,
                      time_range: Optional[Dict[str, str]] = None,
                      compress: bool = False,
                      encrypt: bool = False,
                      password: Optional[str] = None,
                      description: str = "") -> Dict[str, Any]:
        """创建导出任务（立即执行）。"""
        if format not in VALID_FORMATS:
            return {"success": False, "data": None,
                    "error": f"不支持的格式 {format}，可选 {sorted(VALID_FORMATS)}"}
        eid = str(uuid.uuid4())
        created = now_iso()
        rec = {
            "id": eid, "export_format": format, "file_path": "", "file_size": 0,
            "tables": json.dumps(tables or []), "record_count": 0,
            "status": "pending", "compressed": 1 if compress else 0,
            "encrypted": 1 if encrypt else 0, "description": description,
            "created_at": created, "error": "",
        }
        try:
            rows = self._collect_rows(tables, query, fields, time_range)
            payload = self._render(rows, format)
            if encrypt:
                payload = xor_encrypt(payload, password or "")
            if compress:
                payload = gzip.compress(payload)
            ext = {"json": "json", "csv": "csv", "xml": "xml",
                   "sql": "sql", "html": "html"}[format]
            fp = EXPORT_DIR / f"export_{eid[:8]}.{ext}"
            with open(fp, "wb") as f:
                f.write(payload)
            rec["file_path"] = str(fp)
            rec["file_size"] = fp.stat().st_size
            rec["record_count"] = len(rows)
            rec["status"] = "success"
        except Exception as e:
            rec["status"] = "failed"
            rec["error"] = str(e)

        self._insert(rec)
        if rec["status"] == "success":
            return {"success": True, "data": {
                "id": eid, "format": format, "file": rec["file_path"],
                "size": rec["file_size"], "records": rec["record_count"]},
                "error": None}
        return {"success": False, "data": None, "error": rec["error"]}

    def _insert(self, rec: Dict[str, Any]) -> None:
        conn = get_meta_connection()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO export_records "
                "(id,export_format,file_path,file_size,tables,record_count,"
                "status,compressed,encrypted,description,created_at,error) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (rec["id"], rec["export_format"], rec["file_path"], rec["file_size"],
                 rec["tables"], rec["record_count"], rec["status"],
                 rec["compressed"], rec["encrypted"], rec["description"],
                 rec["created_at"], rec["error"]))
            conn.commit()
        finally:
            conn.close()

    def get_export(self, export_id: str) -> Dict[str, Any]:
        conn = get_meta_connection()
        try:
            row = conn.execute(
                "SELECT * FROM export_records WHERE id=?", (export_id,)).fetchone()
            if not row:
                return {"success": False, "data": None, "error": "导出记录不存在"}
            return {"success": True, "data": dict(row), "error": None}
        except Exception as e:
            return {"success": False, "data": None, "error": str(e)}
        finally:
            conn.close()

    def list_exports(self, page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        conn = get_meta_connection()
        try:
            total = conn.execute("SELECT COUNT(*) FROM export_records").fetchone()[0]
            rows = conn.execute(
                "SELECT * FROM export_records ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (page_size, (page - 1) * page_size)).fetchall()
            return {"success": True, "data": {
                "total": total, "page": page, "page_size": page_size,
                "items": [dict(r) for r in rows]}, "error": None}
        except Exception as e:
            return {"success": False, "data": None, "error": str(e)}
        finally:
            conn.close()

    def download_export(self, export_id: str) -> Dict[str, Any]:
        info = self.get_export(export_id)
        if not info["success"]:
            return info
        fp = Path(info["data"]["file_path"])
        if not fp.exists():
            return {"success": False, "data": None, "error": "导出文件不存在"}
        return {"success": True, "data": {"path": str(fp), "name": fp.name,
                                          "size": fp.stat().st_size}, "error": None}

    def get_export_content(self, export_id: str,
                           password: Optional[str] = None) -> Dict[str, Any]:
        info = self.get_export(export_id)
        if not info["success"]:
            return info
        try:
            with open(info["data"]["file_path"], "rb") as f:
                blob = f.read()
            if info["data"]["compressed"]:
                blob = gzip.decompress(blob)
            if info["data"]["encrypted"]:
                from backup.backup_manager import xor_decrypt
                blob = xor_decrypt(blob, password or "")
            return {"success": True, "data": {
                "content": blob.decode("utf-8", "ignore"),
                "bytes": len(blob)}, "error": None}
        except Exception as e:
            return {"success": False, "data": None, "error": str(e)}

    def delete_export(self, export_id: str) -> Dict[str, Any]:
        info = self.get_export(export_id)
        if not info["success"]:
            return info
        try:
            fp = Path(info["data"]["file_path"])
            if fp.exists():
                fp.unlink()
            conn = get_meta_connection()
            try:
                conn.execute("DELETE FROM export_records WHERE id=?", (export_id,))
                conn.commit()
            finally:
                conn.close()
            return {"success": True, "data": {"id": export_id}, "error": None}
        except Exception as e:
            return {"success": False, "data": None, "error": str(e)}

    def get_stats(self) -> Dict[str, Any]:
        conn = get_meta_connection()
        try:
            total = conn.execute("SELECT COUNT(*) FROM export_records").fetchone()[0]
            by_fmt = {r[0]: r[1] for r in conn.execute(
                "SELECT export_format, COUNT(*) FROM export_records GROUP BY export_format")}
            size = conn.execute(
                "SELECT COALESCE(SUM(file_size),0) FROM export_records").fetchone()[0]
            return {"success": True, "data": {
                "total_exports": total, "by_format": by_fmt,
                "total_size_bytes": size}, "error": None}
        except Exception as e:
            return {"success": False, "data": None, "error": str(e)}
        finally:
            conn.close()


# 模块级单例
export_manager = ExportManager()
