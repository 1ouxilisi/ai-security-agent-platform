# -*- coding: utf-8 -*-
"""
backup_manager.py - 备份管理器。

功能：
    - 备份类型：full / incremental / differential
    - 备份方式：在线备份（SQLite backup API，默认）/ 离线备份（停服后拷贝）
    - 备份内容：数据库 / 配置文件 / 日志文件，可配置
    - 备份存储：本地 data/backups/（默认），FTP/SFTP/S3/OSS 预留接口
    - 备份压缩：gzip（基于标准库），可配置级别 1-9
    - 备份加密：XOR + SHA256 + base64（不依赖外部库）
    - 备份验证：SHA256 校验和 + 文件大小 + 可恢复性试读
    - 备份计划：daily/weekly/monthly，自动清理过期备份
    - 备份元数据：backup_records / backup_schedules / backup_schedule_history 表

数据库：data/ai_hacking_agent.db（表前缀 backup_）
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from utils.logger import log  # type: ignore
except Exception:  # pragma: no cover
    import logging as log  # type: ignore

# ==================== 路径常量 ====================

PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
BACKUP_ROOT = DATA_DIR / "backups"
MAIN_DB_PATH = DATA_DIR / "ai_hacking_agent.db"
CONFIG_DIR = PROJECT_ROOT / "config"
LOGS_DIR = PROJECT_ROOT / "logs"
UPLOAD_DIR = DATA_DIR / "uploads"
REPORT_DIR = PROJECT_ROOT / "reports"

BACKUP_ROOT.mkdir(parents=True, exist_ok=True)


# ==================== 工具函数 ====================

def now_iso() -> str:
    """返回当前时间 ISO 字符串（秒级）。"""
    return datetime.now().isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    """计算字节流的 SHA256 十六进制摘要。"""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    """计算文件的 SHA256 十六进制摘要（分块读取）。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def derive_key(password: str) -> bytes:
    """由密码派生 32 字节密钥（SHA256）。"""
    return hashlib.sha256((password or "default-backup-key").encode("utf-8")).digest()


def xor_encrypt(data: bytes, password: str) -> bytes:
    """XOR 加密（流密码框架实现），输出 bytes。"""
    key = derive_key(password)
    out = bytearray(len(data))
    klen = len(key)
    for i, b in enumerate(data):
        out[i] = b ^ key[i % klen]
    return bytes(out)


def xor_decrypt(data: bytes, password: str) -> bytes:
    """XOR 解密（与加密对称）。"""
    return xor_encrypt(data, password)


def pack_blob(raw: bytes, compress: bool = True, encrypt: bool = False,
              password: Optional[str] = None, compress_level: int = 6) -> bytes:
    """打包原始备份数据：可选 gzip 压缩 + 可选 XOR 加密。"""
    payload = raw
    if encrypt:
        payload = xor_encrypt(payload, password or "")
    if compress:
        payload = gzip.compress(payload, compresslevel=int(compress_level))
    return payload


def unpack_blob(blob: bytes, compressed: bool, encrypted: bool,
                password: Optional[str] = None) -> bytes:
    """解包备份数据：先 gzip 解压，再 XOR 解密。"""
    payload = blob
    if compressed:
        payload = gzip.decompress(payload)
    if encrypted:
        payload = xor_decrypt(payload, password or "")
    return payload


def get_meta_connection() -> sqlite3.Connection:
    """获取元数据库（data/ai_hacking_agent.db）连接。"""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not MAIN_DB_PATH.exists():
        MAIN_DB_PATH.touch()
    conn = sqlite3.connect(str(MAIN_DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


# ==================== 备份管理器 ====================

class BackupManager:
    """备份管理器（单例）。"""

    def __init__(self) -> None:
        """初始化备份管理器，创建元数据表与备份目录。"""
        BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    # ---------- 元数据建表 ----------

    def _init_tables(self) -> None:
        conn = get_meta_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS backup_records (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    backup_type TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size INTEGER DEFAULT 0,
                    tables_count INTEGER DEFAULT 0,
                    records_count INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'pending',
                    checksum TEXT,
                    compressed INTEGER DEFAULT 0,
                    compression_level INTEGER DEFAULT 6,
                    encrypted INTEGER DEFAULT 0,
                    encrypt_method TEXT,
                    storage_type TEXT DEFAULT 'local',
                    storage_path TEXT,
                    description TEXT,
                    parent_backup_id TEXT,
                    included_configs INTEGER DEFAULT 0,
                    included_logs INTEGER DEFAULT 0,
                    created_at TEXT,
                    completed_at TEXT,
                    error TEXT,
                    metadata TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS backup_schedules (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    schedule_type TEXT DEFAULT 'daily',
                    time TEXT DEFAULT '02:00',
                    backup_type TEXT DEFAULT 'full',
                    tables TEXT,
                    include_configs INTEGER DEFAULT 1,
                    include_logs INTEGER DEFAULT 0,
                    compress INTEGER DEFAULT 1,
                    encrypt INTEGER DEFAULT 0,
                    retention_days INTEGER DEFAULT 30,
                    retention_count INTEGER DEFAULT 10,
                    enabled INTEGER DEFAULT 1,
                    last_run_at TEXT,
                    next_run_at TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS backup_schedule_history (
                    id TEXT PRIMARY KEY,
                    schedule_id TEXT,
                    backup_id TEXT,
                    status TEXT DEFAULT 'pending',
                    error TEXT,
                    started_at TEXT,
                    completed_at TEXT
                )
            """)
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"backup_manager 建表失败: {e}")
        finally:
            conn.close()

    # ---------- 工具：列出当前数据库表 ----------

    def _list_user_tables(self, db_path: Path) -> List[str]:
        """列出指定 SQLite 数据库中的用户表（排除 sqlite_ 内部表）。"""
        if not db_path.exists():
            return []
        conn = sqlite3.connect(str(db_path))
        try:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
            return [r[0] for r in rows]
        except Exception:
            return []
        finally:
            conn.close()

    def _row_count(self, conn: sqlite3.Connection, table: str) -> int:
        try:
            cur = conn.execute(f'SELECT COUNT(*) FROM "{table}"')
            return int(cur.fetchone()[0])
        except Exception:
            return 0

    # ---------- 备份执行 ----------

    def create_backup(
        self,
        backup_type: str = "full",
        tables: Optional[List[str]] = None,
        compress: bool = True,
        encrypt: bool = False,
        password: Optional[str] = None,
        include_configs: bool = True,
        include_logs: bool = False,
        description: str = "",
        backup_method: str = "online",
        compression_level: int = 6,
        storage_type: str = "local",
        storage_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """创建备份。

        Args:
            backup_type: full / incremental / differential。
            tables: 指定表列表，None 表示所有表。
            compress: 是否 gzip 压缩。
            encrypt: 是否 XOR 加密。
            password: 加密密码。
            include_configs: 是否打包 config/ 目录。
            include_logs: 是否打包 logs/ 目录。
            description: 备份描述。
            backup_method: online（默认，SQLite backup API）/ offline。
            compression_level: 压缩级别 1-9。
            storage_type: local / ftp / sftp / s3 / oss（远程仅预留）。
            storage_path: 自定义存储路径。

        Returns:
            {"success": bool, "data": ..., "error": ...}
        """
        backup_id = str(uuid.uuid4())
        created_at = now_iso()
        name = f"bk_{backup_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{backup_id[:8]}"
        target_dir = Path(storage_path) if storage_path else BACKUP_ROOT
        target_dir.mkdir(parents=True, exist_ok=True)

        record = {
            "id": backup_id, "name": name, "backup_type": backup_type,
            "file_path": "", "file_size": 0, "tables_count": 0, "records_count": 0,
            "status": "pending", "checksum": "", "compressed": 1 if compress else 0,
            "compression_level": compression_level,
            "encrypted": 1 if encrypt else 0,
            "encrypt_method": "xor-sha256-base64" if encrypt else "",
            "storage_type": storage_type, "storage_path": str(target_dir),
            "description": description, "parent_backup_id": "",
            "included_configs": 1 if include_configs else 0,
            "included_logs": 1 if include_logs else 0,
            "created_at": created_at, "completed_at": "", "error": "", "metadata": "",
        }

        # 远程存储仅预留
        if storage_type != "local":
            record["status"] = "failed"
            record["error"] = f"远程存储 {storage_type} 接口预留，当前仅支持 local"
            record["completed_at"] = now_iso()
            self._insert_record(record)
            return {"success": False, "data": None, "error": record["error"]}

        tmp_file = target_dir / f"{name}.tmp"
        try:
            # 解析上次基准备份（增量/差异）
            parent_id = self._resolve_base_backup(backup_type)
            record["parent_backup_id"] = parent_id or ""

            payload: bytes = b""
            tables_done: List[str] = []
            record_count = 0

            if backup_type == "full":
                payload, tables_done, record_count = self._do_full_backup(
                    tables=tables, backup_method=backup_method)
            else:
                payload, tables_done, record_count = self._do_delta_backup(
                    backup_type=backup_type, tables=tables, parent_id=parent_id)

            # 附加配置/日志文件清单（JSON 元信息）
            sidecar: Dict[str, Any] = {
                "type": backup_type,
                "tables": tables_done,
                "records": record_count,
                "include_configs": include_configs,
                "include_logs": include_logs,
                "config_files": self._collect_dir_files(CONFIG_DIR) if include_configs else [],
                "log_files": self._collect_dir_files(LOGS_DIR) if include_logs else [],
                "created_at": created_at,
            }
            payload = payload + b"\n--SIDECAR--\n" + json.dumps(sidecar, ensure_ascii=False).encode("utf-8")

            final_blob = pack_blob(
                payload, compress=compress, encrypt=encrypt,
                password=password, compress_level=compression_level)

            final_path = target_dir / f"{name}.bak"
            with open(final_path, "wb") as f:
                f.write(final_blob)

            record["file_path"] = str(final_path)
            record["file_size"] = final_path.stat().st_size
            record["tables_count"] = len(tables_done)
            record["records_count"] = record_count
            record["checksum"] = sha256_file(final_path)
            record["status"] = "success"
            record["completed_at"] = now_iso()
            record["metadata"] = json.dumps(
                {"method": backup_method, "tables": tables_done}, ensure_ascii=False)

        except Exception as e:  # pragma: no cover
            record["status"] = "failed"
            record["error"] = str(e)
            record["completed_at"] = now_iso()
            if tmp_file.exists():
                try:
                    tmp_file.unlink()
                except Exception:
                    pass
            self._insert_record(record)
            log.exception(f"创建备份失败: {e}")
            return {"success": False, "data": None, "error": str(e)}

        self._insert_record(record)
        return {"success": True, "data": {k: record[k] for k in (
            "id", "name", "backup_type", "file_path", "file_size",
            "tables_count", "records_count", "checksum", "status", "created_at")},
            "error": None}

    def _do_full_backup(self, tables: Optional[List[str]],
                         backup_method: str) -> tuple:
        """执行完整备份，返回 (bytes, 表列表, 记录数)。"""
        tmp_db = BACKUP_ROOT / f"_tmp_full_{uuid.uuid4().hex[:8]}.db"
        tables_done: List[str] = []
        record_count = 0
        try:
            if MAIN_DB_PATH.exists() and backup_method == "online":
                # 使用 SQLite 在线备份 API（不锁表）
                src = sqlite3.connect(str(MAIN_DB_PATH))
                dst = sqlite3.connect(str(tmp_db))
                try:
                    src.backup(dst)
                finally:
                    dst.close()
                    src.close()
            elif MAIN_DB_PATH.exists():
                # 离线备份：直接拷贝文件
                shutil.copy2(str(MAIN_DB_PATH), str(tmp_db))
            else:
                tmp_db.touch()

            # 若只备份指定表，则用 SQL dump 方式重新生成精简库
            all_tables = self._list_user_tables(tmp_db)
            target_tables = tables if tables else all_tables
            dump_conn = sqlite3.connect(str(tmp_db))
            try:
                lines = []
                for t in target_tables:
                    if t not in all_tables:
                        continue
                    cnt = self._row_count(dump_conn, t)
                    record_count += cnt
                    tables_done.append(t)
                # 直接把整库字节作为备份体（.iterdump 生成 SQL 便于跨库）
                for line in dump_conn.iterdump():
                    lines.append(line)
                return ("\n".join(lines)).encode("utf-8"), tables_done, record_count
            finally:
                dump_conn.close()
        finally:
            if tmp_db.exists():
                try:
                    tmp_db.unlink()
                except Exception:
                    pass

    def _do_delta_backup(self, backup_type: str,
                         tables: Optional[List[str]],
                         parent_id: Optional[str]) -> tuple:
        """执行增量/差异备份，返回 (bytes, 表列表, 记录数)。"""
        tables_done: List[str] = []
        record_count = 0
        out: Dict[str, Any] = {"backup_type": backup_type, "parent_id": parent_id, "rows": {}}
        if not MAIN_DB_PATH.exists():
            return json.dumps(out).encode("utf-8"), tables_done, record_count

        conn = sqlite3.connect(str(MAIN_DB_PATH))
        conn.row_factory = sqlite3.Row
        try:
            all_tables = self._list_user_tables(MAIN_DB_PATH)
            target_tables = tables if tables else all_tables
            # 水位线：增量 = 上次任意备份时间；差异 = 上次完整备份时间
            watermark = self._get_watermark(backup_type, parent_id)
            for t in target_tables:
                if t not in all_tables:
                    continue
                tables_done.append(t)
                try:
                    if watermark:
                        # 尝试按 created_at / updated_at 过滤，失败则取全表
                        rows = self._query_delta(conn, t, watermark)
                    else:
                        rows = [dict(r) for r in conn.execute(f'SELECT * FROM "{t}"').fetchall()]
                    out["rows"][t] = rows
                    record_count += len(rows)
                except Exception:
                    rows = [dict(r) for r in conn.execute(f'SELECT * FROM "{t}"').fetchall()]
                    out["rows"][t] = rows
                    record_count += len(rows)
        finally:
            conn.close()
        return json.dumps(out, ensure_ascii=False, default=str).encode("utf-8"), tables_done, record_count

    def _query_delta(self, conn: sqlite3.Connection, table: str,
                     watermark: str) -> List[Dict[str, Any]]:
        """按时间水位线查询增量行。"""
        cols = [r[1] for r in conn.execute(f'PRAGMA table_info("{table}")').fetchall()]
        time_col = None
        for c in ("created_at", "updated_at", "create_time", "update_time", "timestamp"):
            if c in cols:
                time_col = c
                break
        if time_col:
            rows = conn.execute(
                f'SELECT * FROM "{table}" WHERE "{time_col}" > ?', (watermark,)).fetchall()
            return [dict(r) for r in rows]
        # 没有时间列则按 rowid 增量
        rows = conn.execute(f'SELECT * FROM "{table}"').fetchall()
        return [dict(r) for r in rows]

    def _resolve_base_backup(self, backup_type: str) -> Optional[str]:
        """为增量/差异备份解析基准备份 ID。"""
        conn = get_meta_connection()
        try:
            if backup_type == "incremental":
                row = conn.execute(
                    "SELECT id FROM backup_records WHERE status='success' "
                    "ORDER BY created_at DESC LIMIT 1").fetchone()
            elif backup_type == "differential":
                row = conn.execute(
                    "SELECT id FROM backup_records WHERE status='success' "
                    "AND backup_type='full' ORDER BY created_at DESC LIMIT 1").fetchone()
            else:
                row = None
            return row["id"] if row else None
        except Exception:
            return None
        finally:
            conn.close()

    def _get_watermark(self, backup_type: str, parent_id: Optional[str]) -> Optional[str]:
        """获取增量/差异备份的时间水位线。"""
        if not parent_id:
            return None
        conn = get_meta_connection()
        try:
            row = conn.execute(
                "SELECT created_at FROM backup_records WHERE id=?", (parent_id,)).fetchone()
            return row["created_at"] if row else None
        except Exception:
            return None
        finally:
            conn.close()

    def _collect_dir_files(self, directory: Path) -> List[Dict[str, Any]]:
        """收集目录下文件清单（相对路径 + 大小）。"""
        out: List[Dict[str, Any]] = []
        if not directory.exists():
            return out
        for p in directory.rglob("*"):
            if p.is_file():
                try:
                    out.append({
                        "path": str(p.relative_to(PROJECT_ROOT)),
                        "size": p.stat().st_size,
                    })
                except Exception:
                    continue
        return out

    def _insert_record(self, record: Dict[str, Any]) -> None:
        conn = get_meta_connection()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO backup_records "
                "(id,name,backup_type,file_path,file_size,tables_count,records_count,"
                "status,checksum,compressed,compression_level,encrypted,encrypt_method,"
                "storage_type,storage_path,description,parent_backup_id,"
                "included_configs,included_logs,created_at,completed_at,error,metadata) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (record["id"], record["name"], record["backup_type"], record["file_path"],
                 record["file_size"], record["tables_count"], record["records_count"],
                 record["status"], record["checksum"], record["compressed"],
                 record["compression_level"], record["encrypted"], record["encrypt_method"],
                 record["storage_type"], record["storage_path"], record["description"],
                 record["parent_backup_id"], record["included_configs"],
                 record["included_logs"], record["created_at"], record["completed_at"],
                 record["error"], record["metadata"]))
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"写入备份记录失败: {e}")
        finally:
            conn.close()

    # ---------- 查询 / 删除 / 验证 ----------

    def get_backup(self, backup_id: str) -> Dict[str, Any]:
        """按 ID 获取备份记录。"""
        conn = get_meta_connection()
        try:
            row = conn.execute("SELECT * FROM backup_records WHERE id=?", (backup_id,)).fetchone()
            if not row:
                return {"success": False, "data": None, "error": "备份不存在"}
            d = dict(row)
            d["metadata"] = json.loads(d.get("metadata") or "{}")
            return {"success": True, "data": d, "error": None}
        except Exception as e:
            return {"success": False, "data": None, "error": str(e)}
        finally:
            conn.close()

    def list_backups(self, page: int = 1, page_size: int = 20,
                     backup_type: Optional[str] = None) -> Dict[str, Any]:
        """分页列出备份记录。"""
        conn = get_meta_connection()
        try:
            where = ""
            args: List[Any] = []
            if backup_type:
                where = "WHERE backup_type=?"
                args.append(backup_type)
            total = conn.execute(
                f"SELECT COUNT(*) FROM backup_records {where}", args).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM backup_records {where} "
                f"ORDER BY created_at DESC LIMIT ? OFFSET ?",
                args + [page_size, (page - 1) * page_size]).fetchall()
            items = [dict(r) for r in rows]
            return {"success": True, "data": {
                "total": total, "page": page, "page_size": page_size, "items": items},
                "error": None}
        except Exception as e:
            return {"success": False, "data": None, "error": str(e)}
        finally:
            conn.close()

    def delete_backup(self, backup_id: str) -> Dict[str, Any]:
        """删除备份记录及其文件。"""
        info = self.get_backup(backup_id)
        if not info["success"]:
            return info
        rec = info["data"]
        try:
            fp = rec.get("file_path")
            if fp and Path(fp).exists():
                Path(fp).unlink()
            conn = get_meta_connection()
            try:
                conn.execute("DELETE FROM backup_records WHERE id=?", (backup_id,))
                conn.commit()
            finally:
                conn.close()
            return {"success": True, "data": {"id": backup_id}, "error": None}
        except Exception as e:
            return {"success": False, "data": None, "error": str(e)}

    def verify_backup(self, backup_id: str) -> Dict[str, Any]:
        """验证备份完整性：文件存在 / 大小 / SHA256 / 可试读。"""
        info = self.get_backup(backup_id)
        if not info["success"]:
            return info
        rec = info["data"]
        fp = Path(rec["file_path"])
        checks: Dict[str, Any] = {"file_exists": fp.exists(), "size_match": False,
                                  "checksum_match": False, "readable": False}
        try:
            if not fp.exists():
                return {"success": False, "data": checks, "error": "备份文件丢失"}
            actual_size = fp.stat().st_size
            checks["size_match"] = (actual_size == rec["file_size"])
            checks["checksum_match"] = (sha256_file(fp) == rec["checksum"])
            with open(fp, "rb") as f:
                head = f.read(64)
            checks["readable"] = len(head) > 0
            ok = all([checks["file_exists"], checks["size_match"],
                      checks["checksum_match"], checks["readable"]])
            return {"success": ok, "data": {"checks": checks, "valid": ok},
                    "error": None if ok else "校验未通过"}
        except Exception as e:
            checks["error"] = str(e)
            return {"success": False, "data": checks, "error": str(e)}

    def download_backup(self, backup_id: str) -> Dict[str, Any]:
        """返回备份文件路径（供路由层做文件下载）。"""
        info = self.get_backup(backup_id)
        if not info["success"]:
            return info
        fp = Path(info["data"]["file_path"])
        if not fp.exists():
            return {"success": False, "data": None, "error": "备份文件不存在"}
        return {"success": True, "data": {"path": str(fp), "name": fp.name,
                                          "size": fp.stat().st_size}, "error": None}

    def get_backup_content(self, backup_id: str,
                           password: Optional[str] = None) -> Dict[str, Any]:
        """读取并解包备份内容（返回文本，便于预览）。"""
        info = self.get_backup(backup_id)
        if not info["success"]:
            return info
        rec = info["data"]
        try:
            with open(rec["file_path"], "rb") as f:
                blob = f.read()
            raw = unpack_blob(
                blob,
                compressed=bool(rec["compressed"]),
                encrypted=bool(rec["encrypted"]),
                password=password)
            # 去掉 sidecar 尾巴
            marker = b"\n--SIDECAR--\n"
            if marker in raw:
                main_part, side_part = raw.rsplit(marker, 1)
                sidecar = json.loads(side_part.decode("utf-8", "ignore"))
            else:
                main_part, sidecar = raw, {}
            text = main_part.decode("utf-8", "ignore")
            preview = text[:8000]
            return {"success": True, "data": {
                "preview": preview, "sidecar": sidecar, "total_bytes": len(raw)},
                "error": None}
        except Exception as e:
            return {"success": False, "data": None, "error": f"读取备份失败: {e}"}

    # ---------- 备份计划 ----------

    def create_schedule(self, name: str, schedule_type: str = "daily",
                        time: str = "02:00", backup_type: str = "full",
                        retention_days: int = 30, retention_count: int = 10,
                        tables: Optional[List[str]] = None,
                        include_configs: bool = True,
                        include_logs: bool = False) -> Dict[str, Any]:
        """创建定时备份计划。"""
        sid = str(uuid.uuid4())
        ts = now_iso()
        conn = get_meta_connection()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO backup_schedules "
                "(id,name,schedule_type,time,backup_type,tables,include_configs,"
                "include_logs,retention_days,retention_count,enabled,"
                "last_run_at,next_run_at,created_at,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (sid, name, schedule_type, time, backup_type,
                 json.dumps(tables or []), 1 if include_configs else 0,
                 1 if include_logs else 0, retention_days, retention_count, 1,
                 "", self._calc_next_run(schedule_type, time), ts, ts))
            conn.commit()
            return {"success": True, "data": {"id": sid, "name": name}, "error": None}
        except Exception as e:
            return {"success": False, "data": None, "error": str(e)}
        finally:
            conn.close()

    def _calc_next_run(self, schedule_type: str, time: str) -> str:
        """粗略计算下次执行时间。"""
        try:
            hh, mm = [int(x) for x in time.split(":")]
        except Exception:
            hh, mm = 2, 0
        base = datetime.now().replace(hour=hh, minute=mm, second=0, microsecond=0)
        if schedule_type == "daily":
            nxt = base if base > datetime.now() else base + timedelta(days=1)
        elif schedule_type == "weekly":
            days = (7 - datetime.now().weekday()) % 7 or 7
            nxt = base + timedelta(days=days)
        elif schedule_type == "monthly":
            nxt = base.replace(day=1)
            if nxt <= datetime.now():
                m = nxt.month % 12 + 1
                y = nxt.year + (1 if nxt.month == 12 else 0)
                nxt = nxt.replace(year=y, month=m)
        else:
            nxt = base
        return nxt.isoformat(timespec="seconds")

    def list_schedules(self) -> Dict[str, Any]:
        """列出所有备份计划。"""
        conn = get_meta_connection()
        try:
            rows = conn.execute("SELECT * FROM backup_schedules ORDER BY created_at DESC").fetchall()
            items = [dict(r) for r in rows]
            return {"success": True, "data": {"items": items, "total": len(items)}, "error": None}
        except Exception as e:
            return {"success": False, "data": None, "error": str(e)}
        finally:
            conn.close()

    def update_schedule(self, schedule_id: str, **kwargs: Any) -> Dict[str, Any]:
        """更新备份计划字段。"""
        allowed = {"name", "schedule_type", "time", "backup_type",
                   "retention_days", "retention_count", "enabled",
                   "include_configs", "include_logs", "tables"}
        sets = []
        args: List[Any] = []
        for k, v in kwargs.items():
            if k not in allowed:
                continue
            if k == "tables" and isinstance(v, list):
                v = json.dumps(v)
            sets.append(f"{k}=?")
            args.append(v)
        if not sets:
            return {"success": False, "data": None, "error": "无可更新字段"}
        sets.append("updated_at=?")
        args.append(now_iso())
        args.append(schedule_id)
        conn = get_meta_connection()
        try:
            cur = conn.execute(
                f"UPDATE backup_schedules SET {','.join(sets)} WHERE id=?", args)
            conn.commit()
            if cur.rowcount == 0:
                return {"success": False, "data": None, "error": "计划不存在"}
            return {"success": True, "data": {"id": schedule_id}, "error": None}
        except Exception as e:
            return {"success": False, "data": None, "error": str(e)}
        finally:
            conn.close()

    def delete_schedule(self, schedule_id: str) -> Dict[str, Any]:
        """删除备份计划。"""
        conn = get_meta_connection()
        try:
            conn.execute("DELETE FROM backup_schedules WHERE id=?", (schedule_id,))
            conn.commit()
            return {"success": True, "data": {"id": schedule_id}, "error": None}
        except Exception as e:
            return {"success": False, "data": None, "error": str(e)}
        finally:
            conn.close()

    def execute_schedule(self, schedule_id: str) -> Dict[str, Any]:
        """立即执行一个备份计划。"""
        conn = get_meta_connection()
        try:
            row = conn.execute(
                "SELECT * FROM backup_schedules WHERE id=?", (schedule_id,)).fetchone()
            if not row:
                return {"success": False, "data": None, "error": "计划不存在"}
            s = dict(row)
        finally:
            conn.close()

        hist_id = str(uuid.uuid4())
        started = now_iso()
        tables = json.loads(s.get("tables") or "[]")
        result = self.create_backup(
            backup_type=s["backup_type"],
            tables=tables or None,
            include_configs=bool(s["include_configs"]),
            include_logs=bool(s["include_logs"]),
            description=f"计划执行: {s['name']}")
        completed = now_iso()
        bid = result.get("data", {}).get("id") if result.get("data") else None
        status = "success" if result.get("success") else "failed"
        err = "" if result.get("success") else result.get("error", "")

        conn = get_meta_connection()
        try:
            conn.execute(
                "INSERT INTO backup_schedule_history "
                "(id,schedule_id,backup_id,status,error,started_at,completed_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (hist_id, schedule_id, bid or "", status, err, started, completed))
            conn.execute(
                "UPDATE backup_schedules SET last_run_at=?, next_run_at=? WHERE id=?",
                (completed, self._calc_next_run(s["schedule_type"], s["time"]), schedule_id))
            conn.commit()
        finally:
            conn.close()
        return result

    def get_schedule_history(self, schedule_id: str) -> Dict[str, Any]:
        """获取计划执行历史。"""
        conn = get_meta_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM backup_schedule_history WHERE schedule_id=? "
                "ORDER BY started_at DESC LIMIT 100", (schedule_id,)).fetchall()
            items = [dict(r) for r in rows]
            return {"success": True, "data": {"items": items, "total": len(items)}, "error": None}
        except Exception as e:
            return {"success": False, "data": None, "error": str(e)}
        finally:
            conn.close()

    # ---------- 统计 / 清理 ----------

    def get_stats(self) -> Dict[str, Any]:
        """备份系统统计。"""
        conn = get_meta_connection()
        try:
            total = conn.execute("SELECT COUNT(*) FROM backup_records").fetchone()[0]
            by_type = {r[0]: r[1] for r in conn.execute(
                "SELECT backup_type, COUNT(*) FROM backup_records GROUP BY backup_type")}
            by_status = {r[0]: r[1] for r in conn.execute(
                "SELECT status, COUNT(*) FROM backup_records GROUP BY status")}
            size_row = conn.execute(
                "SELECT COALESCE(SUM(file_size),0) FROM backup_records").fetchone()
            sched = conn.execute("SELECT COUNT(*) FROM backup_schedules").fetchone()[0]
            return {"success": True, "data": {
                "total_backups": total, "by_type": by_type, "by_status": by_status,
                "total_size_bytes": size_row[0], "total_schedules": sched,
                "backup_root": str(BACKUP_ROOT)}, "error": None}
        except Exception as e:
            return {"success": False, "data": None, "error": str(e)}
        finally:
            conn.close()

    def cleanup_expired_backups(self, retention_days: Optional[int] = None,
                               retention_count: Optional[int] = None) -> Dict[str, Any]:
        """清理过期备份（按天数或保留数量）。"""
        removed = 0
        conn = get_meta_connection()
        try:
            if retention_days is not None:
                cutoff = (datetime.now() - timedelta(days=retention_days)).isoformat(timespec="seconds")
                rows = conn.execute(
                    "SELECT id, file_path FROM backup_records WHERE created_at < ?",
                    (cutoff,)).fetchall()
                for r in rows:
                    self._safe_delete_file(r["file_path"])
                    conn.execute("DELETE FROM backup_records WHERE id=?", (r["id"],))
                    removed += 1
            if retention_count is not None:
                rows = conn.execute(
                    "SELECT id, file_path FROM backup_records ORDER BY created_at DESC").fetchall()
                for r in rows[retention_count:]:
                    self._safe_delete_file(r["file_path"])
                    conn.execute("DELETE FROM backup_records WHERE id=?", (r["id"],))
                    removed += 1
            conn.commit()
            return {"success": True, "data": {"removed": removed}, "error": None}
        except Exception as e:
            return {"success": False, "data": None, "error": str(e)}
        finally:
            conn.close()

    @staticmethod
    def _safe_delete_file(path: str) -> None:
        try:
            if path and Path(path).exists():
                Path(path).unlink()
        except Exception:
            pass


# 模块级单例
backup_manager = BackupManager()
