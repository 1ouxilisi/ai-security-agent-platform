# -*- coding: utf-8 -*-
"""
importer.py - Data importer with task management.

Uses in-memory global dicts (no DB). Thread-safe via threading.Lock.
"""

import os
import time
import uuid
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional

from .parsers import parse_file, deduplicate

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

# Global stores.
_import_tasks: Dict[str, "ImportTask"] = {}
_import_records: Dict[str, Dict[str, Any]] = {}
_import_lock = threading.Lock()

# Simulated Vulnerability table (in-memory).
_vuln_store: List[Dict[str, Any]] = []
_vuln_id_seq = 0

# Stats.
_import_stats = {
    "total_imports": 0,
    "total_vulns": 0,
    "by_format": {},
}


def _next_vuln_id() -> int:
    global _vuln_id_seq
    _vuln_id_seq += 1
    return _vuln_id_seq


class ImportTask:
    """Manages a single import task lifecycle."""

    STATES = ("pending", "parsing", "preview", "importing", "completed", "failed")

    def __init__(self, task_id: str, file_path: str, file_name: str, size: int):
        self.task_id = task_id
        self.file_path = file_path
        self.file_name = file_name
        self.size = size
        self.state = "pending"
        self.created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.updated_at = self.created_at
        self.preview: Dict[str, Any] = {}
        self.report: Dict[str, Any] = {}
        self.error: Optional[str] = None

    def set_state(self, state: str):
        if state not in self.STATES:
            raise ValueError(f"Invalid state: {state}")
        self.state = state
        self.updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "file_name": self.file_name,
            "file_path": self.file_path,
            "size": self.size,
            "state": self.state,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "preview": self.preview,
            "report": self.report,
            "error": self.error,
        }


def create_import_task(file_path: str, file_name: str) -> str:
    """Create an import task. Returns task_id. Raises ValueError on size over limit."""
    size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
    if size > MAX_FILE_SIZE:
        raise ValueError(
            f"File too large: {size} bytes (max {MAX_FILE_SIZE})"
        )
    task_id = uuid.uuid4().hex[:16]
    task = ImportTask(task_id, file_path, file_name, size)
    with _import_lock:
        _import_tasks[task_id] = task
    return task_id


def parse_for_preview(task_id: str) -> Dict[str, Any]:
    """Parse file and return preview. Stores parsed vulns on the task."""
    with _import_lock:
        task = _import_tasks.get(task_id)
    if not task:
        return {"error": "Task not found", "total_count": 0}
    task.set_state("parsing")
    try:
        res = parse_file(task.file_path)
        vulns = res.get("vulns", [])
        vulns = deduplicate(vulns)
        task.parsed_vulns = vulns  # type: ignore[attr-defined]
        sev_dist: Dict[str, int] = {}
        for v in vulns:
            sev = v.get("severity", "info")
            sev_dist[sev] = sev_dist.get(sev, 0) + 1
        preview = {
            "total_count": len(vulns),
            "severity_distribution": sev_dist,
            "scanner_source": res.get("scanner", "unknown"),
            "parse_error": res.get("error"),
            "sample_vulns": vulns[:10],
        }
        task.preview = preview
        task.set_state("preview")
        return preview
    except Exception as e:  # noqa: BLE001
        task.set_state("failed")
        task.error = str(e)
        return {"error": str(e), "total_count": 0}


def confirm_import(task_id: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Confirm import and write vulns to in-memory store."""
    options = options or {}
    with _import_lock:
        task = _import_tasks.get(task_id)
    if not task:
        return {"error": "Task not found", "success_count": 0}
    task.set_state("importing")
    try:
        vulns = getattr(task, "parsed_vulns", None) or []
        # Optional severity filter.
        allowed = options.get("severities")
        if allowed:
            vulns = [v for v in vulns if v.get("severity") in allowed]
        skip_duplicates = options.get("skip_duplicates", True)

        success_count = 0
        failed_count = 0
        skipped_count = 0
        errors: List[str] = []
        imported_ids: List[int] = []

        existing_keys = set()
        if skip_duplicates:
            for v in _vuln_store:
                existing_keys.add(
                    (
                        (v.get("cve") or "").lower(),
                        (v.get("url") or "").lower(),
                        str(v.get("port") or ""),
                    )
                )

        for v in vulns:
            try:
                key = (
                    (v.get("cve") or "").lower(),
                    (v.get("url") or "").lower(),
                    str(v.get("port") or ""),
                )
                if skip_duplicates and key in existing_keys:
                    skipped_count += 1
                    continue
                vid = _next_vuln_id()
                record = {"id": vid, **v, "imported_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                _vuln_store.append(record)
                imported_ids.append(vid)
                success_count += 1
                existing_keys.add(key)
            except Exception as e:  # noqa: BLE001
                failed_count += 1
                errors.append(str(e))

        report = {
            "success_count": success_count,
            "failed_count": failed_count,
            "skipped_count": skipped_count,
            "errors": errors[:20],
            "imported_ids": imported_ids,
        }
        task.report = report
        task.set_state("completed")
        # Persist record.
        with _import_lock:
            _import_records[task_id] = task.to_dict()
            _import_stats["total_imports"] += 1
            _import_stats["total_vulns"] += success_count
            src = task.preview.get("scanner_source", "unknown")
            _import_stats["by_format"][src] = _import_stats["by_format"].get(src, 0) + success_count
        return report
    except Exception as e:  # noqa: BLE001
        task.set_state("failed")
        task.error = str(e)
        return {"error": str(e), "success_count": 0, "failed_count": 0, "skipped_count": 0, "errors": [str(e)], "imported_ids": []}


def list_import_history() -> List[Dict[str, Any]]:
    with _import_lock:
        return sorted(_import_records.values(), key=lambda r: r.get("created_at", ""), reverse=True)


def get_import_record(task_id: str) -> Optional[Dict[str, Any]]:
    with _import_lock:
        rec = _import_records.get(task_id)
        if rec:
            return rec
        task = _import_tasks.get(task_id)
        return task.to_dict() if task else None


def delete_import_record(task_id: str) -> bool:
    with _import_lock:
        existed = _import_records.pop(task_id, None) is not None
        _import_tasks.pop(task_id, None)
        return existed


def get_all_vulns() -> List[Dict[str, Any]]:
    """Expose in-memory vuln store for export."""
    return list(_vuln_store)


def get_import_stats() -> Dict[str, Any]:
    with _import_lock:
        return dict(_import_stats)
