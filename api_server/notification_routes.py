# -*- coding: utf-8 -*-
"""
notification_routes.py - Notification API (15 endpoints).
"""

import os
import sys
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Body, Query
from fastapi.responses import JSONResponse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from notifications import channels as ch
from notifications import templates as tpls
from notifications import router as dispatcher

router = APIRouter(prefix="/api/v1/notifications", tags=["notifications"])


def _ok(data: Any) -> JSONResponse:
    return JSONResponse({"code": 0, "data": data})


def _err(msg: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"code": 1, "error": msg}, status_code=status)


# 1. GET /channels
@router.get("/channels")
def get_channels():
    try:
        return _ok(ch.list_channels())
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 2. POST /channels/{name}/config
@router.post("/channels/{name}/config")
def set_channel_config(name: str, config: Dict[str, Any] = Body(...)):
    try:
        if not ch.get_channel(name):
            return _err(f"unknown channel: {name}", 404)
        ch.set_config(name, config)
        ch_obj = ch.get_channel(name)
        validation = ch_obj.validate_config(config)
        return _ok({"name": name, "saved": True, "validation": validation})
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 3. GET /channels/{name}/config
@router.get("/channels/{name}/config")
def get_channel_config(name: str):
    try:
        if not ch.get_channel(name):
            return _err(f"unknown channel: {name}", 404)
        return _ok({"name": name, "config": ch.get_config(name)})
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 4. POST /channels/{name}/test
@router.post("/channels/{name}/test")
def test_channel(name: str, config: Optional[Dict[str, Any]] = Body(default=None)):
    try:
        ch_obj = ch.get_channel(name)
        if not ch_obj:
            return _err(f"unknown channel: {name}", 404)
        cfg = config or ch.get_config(name)
        result = ch_obj.test(cfg)
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 5. GET /templates
@router.get("/templates")
def list_templates():
    try:
        return _ok(tpls.list_templates())
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 6. POST /templates
@router.post("/templates")
def create_template(body: Dict[str, Any] = Body(...)):
    try:
        tpl = tpls.create_template(body)
        return _ok(tpl)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 7. PUT /templates/{template_id}
@router.put("/templates/{template_id}")
def update_template(template_id: str, body: Dict[str, Any] = Body(...)):
    try:
        tpl = tpls.update_template(template_id, body)
        return _ok(tpl)
    except KeyError as e:
        return _err(str(e), 404)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 8. DELETE /templates/{template_id}
@router.delete("/templates/{template_id}")
def delete_template(template_id: str):
    try:
        return _ok({"deleted": tpls.delete_template(template_id)})
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 9. GET /subscriptions
@router.get("/subscriptions")
def list_subscriptions():
    try:
        return _ok(dispatcher.list_subscriptions())
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 10. POST /subscriptions
@router.post("/subscriptions")
def create_subscription(body: Dict[str, Any] = Body(...)):
    try:
        event_type = body.get("event_type")
        channels = body.get("channels") or []
        filters = body.get("filters") or {}
        if not event_type or not channels:
            return _err("event_type and channels are required")
        sub = dispatcher.create_subscription(event_type, channels, filters)
        return _ok(sub)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 11. DELETE /subscriptions/{sub_id}
@router.delete("/subscriptions/{sub_id}")
def delete_subscription(sub_id: str):
    try:
        return _ok({"deleted": dispatcher.delete_subscription(sub_id)})
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 12. POST /send
@router.post("/send")
def send_manual(body: Dict[str, Any] = Body(...)):
    try:
        channel = body.get("channel")
        message = body.get("message")
        template_id = body.get("template_id")
        variables = body.get("variables") or {}
        if template_id:
            message = tpls.render_template(template_id, variables)
        if not channel or not message:
            return _err("channel and message/template_id required")
        result = dispatcher.send_manual(channel, message)
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 13. GET /history
@router.get("/history")
def get_history(limit: int = Query(50, ge=1, le=500)):
    try:
        return _ok(dispatcher.get_history(limit))
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 14. GET /history/{record_id}
@router.get("/history/{record_id}")
def get_history_detail(record_id: int):
    try:
        rec = dispatcher.get_record(record_id)
        if not rec:
            return _err("not found", 404)
        return _ok(rec)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# 15. GET /stats
@router.get("/stats")
def notification_stats():
    try:
        return _ok(dispatcher.get_stats())
    except Exception as e:  # noqa: BLE001
        return _err(str(e))
