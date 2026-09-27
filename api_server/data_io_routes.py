# -*- coding: utf-8 -*-
"""
data_io_routes.py - Data import/export API (11 endpoints).
"""

import os
import sys
import json
import time
import base64
import tempfile
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, UploadFile, File, Body
from fastapi.responses import JSONResponse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data_import import importer
from data_import.parsers import detect_format, _PARSERS  # type: ignore
from data_import.importer import (
    create_import_task,
    parse_for_preview,
    confirm_import,
    list_import_history,
    get_import_record,
    delete_import_record,
    get_all_vulns,
    get_import_stats,
)
from data_export import exporter

router = APIRouter(prefix="/api/v1/data-io", tags=["data-io"])

# Directory to buffer uploaded files.
_UPLOAD_DIR = os.path.join(tempfile.gettempdir(), "ai_hack_imports")
os.makedirs(_UPLOAD_DIR, exist_ok=True)


def _ok(data: Any) -> JSONResponse:
    return JSONResponse({"code": 0, "data": data})


def _err(msg: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"code": 1, "error": msg}, status_code=status)


# 1. POST /import - upload file, create task, auto preview
@router.post("/import")
async def import_upload(file: UploadFile = File(...)):
    try:
        suffix = os.path.splitext(file.filename or "")[1]
        tmp_path = os.path.join(_UPLOAD_DIR, f"{int(time.time()*1000)}{suffix}")
        # Stream write to keep memory bounded.
        with open(tmp_path, "wb") as f:
            while True:
                chunk = await file.read(1024 * 256)
                if not chunk:
                    break
                f.write(chunk)
        task_id = create_import_task(tmp_path, file.filename or "upload")
        preview = parse_for_preview(task_id)
        return _ok({"task_id": task_id, "preview": preview})
    except Exception as e:  # noqa: BLE001
        return _err(f"import upload failed: {e}")


# 2. GET /import/preview/{task_id}
@router.get("/import/preview/{task_id}")
def import_preview(task_id: str):
    try:
        rec = get_import_record(task_id)
        if not rec:
            return _err("task not found", 404)
        return _ok(rec.get("preview", {}))
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 3. POST /import/confirm/{task_id}
@router.post("/import/confirm/{task_id}")
def import_confirm(task_id: str, body: Dict[str, Any] = Body(default={})):
    try:
        report = confirm_import(task_id, body.get("options") or {})
        return _ok(report)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 4. GET /import/history
@router.get("/import/history")
def import_history():
    try:
        return _ok(list_import_history())
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 5. GET /import/history/{task_id}
@router.get("/import/history/{task_id}")
def import_history_detail(task_id: str):
    try:
        rec = get_import_record(task_id)
        if not rec:
            return _err("not found", 404)
        return _ok(rec)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 6. DELETE /import/history/{task_id}
@router.delete("/import/history/{task_id}")
def import_history_delete(task_id: str):
    try:
        ok = delete_import_record(task_id)
        return _ok({"deleted": ok})
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 7. POST /export - export data
@router.post("/export")
def export_data(body: Dict[str, Any] = Body(...)):
    try:
        fmt = body.get("format", "json")
        filters = body.get("filters") or {}
        fields = body.get("fields")
        template = body.get("template")
        vulns = get_all_vulns()
        result = exporter.export_data(
            vulns, fmt,
            options={"filters": filters, "fields": fields, "template": template,
                     "title": body.get("title", "Vulnerability Report")},
        )
        b64 = base64.b64encode(result["content"]).decode("ascii")
        return _ok({
            "format": fmt,
            "extension": result["extension"],
            "content_type": result["content_type"],
            "count": result["count"],
            "content_base64": b64,
        })
    except Exception as e:  # noqa: BLE001
        return _err(f"export failed: {e}")


# 8. GET /export/templates
@router.get("/export/templates")
def export_templates():
    try:
        return _ok(exporter.list_export_templates())
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 9. GET /formats
@router.get("/formats")
def io_formats():
    try:
        return _ok({
            "import_formats": [
                {"name": k, "description": f"{k} scanner XML"} for k in _PARSERS.keys()
            ],
            "export_formats": exporter.list_supported_formats(),
        })
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 10. GET /stats
@router.get("/stats")
def io_stats():
    try:
        s = get_import_stats()
        s["stored_vulns"] = len(get_all_vulns())
        s["export_templates"] = len(exporter.list_export_templates())
        return _ok(s)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 11. GET /parsers
@router.get("/parsers")
def list_parsers():
    try:
        out = []
        for key, cls in _PARSERS.items():
            out.append({"name": key, "class": cls.__name__, "label": cls.scanner_source})
        return _ok(out)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))
