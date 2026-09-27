# -*- coding: utf-8 -*-
"""
router.py - Notification dispatcher.

Subscriptions, filtering, rate-limiting, async dispatch, history & stats.
"""

import time
import uuid
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional

from . import channels as ch
from . import templates as tpls

EVENT_TYPES = [
    "scan_completed",
    "high_risk_found",
    "workflow_completed",
    "task_failed",
    "system_alert",
    "periodic_report",
    "vuln_status_changed",
]

_subscriptions: Dict[str, Dict[str, Any]] = {}
_history: List[Dict[str, Any]] = []
_history_lock = threading.Lock()
# Rate-limit: key (event_type|channel) -> last timestamp.
_rate_bucket: Dict[str, float] = {}
RATE_WINDOW = 300  # 5 minutes
_history_seq = 0


def create_subscription(event_type: str, channels: List[str],
                        filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    sub_id = uuid.uuid4().hex[:12]
    sub = {
        "sub_id": sub_id,
        "event_type": event_type,
        "channels": channels,
        "filters": filters or {},
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    _subscriptions[sub_id] = sub
    return sub


def list_subscriptions() -> List[Dict[str, Any]]:
    return list(_subscriptions.values())


def delete_subscription(sub_id: str) -> bool:
    return _subscriptions.pop(sub_id, None) is not None


def _match_filters(filters: Dict[str, Any], data: Dict[str, Any]) -> bool:
    if not filters:
        return True
    for key, expected in filters.items():
        actual = data.get(key)
        if expected is None or expected == "":
            continue
        if str(actual).lower() != str(expected).lower():
            return False
    return True


def _rate_ok(event_type: str, channel: str) -> bool:
    key = f"{event_type}|{channel}"
    now = time.time()
    last = _rate_bucket.get(key, 0)
    if now - last < RATE_WINDOW:
        return False
    _rate_bucket[key] = now
    return True


def _record_log(entry: Dict[str, Any]):
    global _history_seq
    with _history_lock:
        _history_seq += 1
        entry = {"record_id": _history_seq, **entry,
                 "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        _history.append(entry)
        # Keep history bounded.
        if len(_history) > 1000:
            del _history[:200]


def send_manual(channel: str, message: str) -> Dict[str, Any]:
    """Manually send a raw message to a channel."""
    ch_obj = ch.get_channel(channel)
    if not ch_obj:
        return {"success": False, "error": f"unknown channel: {channel}"}
    result = ch_obj.send(message)
    _record_log({
        "event_type": "manual",
        "channel": channel,
        "message": message[:200],
        "success": result.get("success", False),
        "error": result.get("error", ""),
    })
    return result


def dispatch(event_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Find subscriptions -> filter -> render -> send asynchronously.
    Returns immediately with a summary; actual sending runs in a thread.
    """
    data = dict(data or {})
    data.setdefault("time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    matched = [s for s in _subscriptions.values() if s["event_type"] == event_type]
    if not matched:
        return {"dispatched": 0, "message": "no matching subscriptions"}

    # Build rendered message once per event.
    message = tpls.render_template(event_type, data)

    targets = []
    for sub in matched:
        if not _match_filters(sub["filters"], data):
            continue
        for channel in sub["channels"]:
            if not _rate_ok(event_type, channel):
                _record_log({
                    "event_type": event_type, "channel": channel,
                    "message": message[:200], "success": False,
                    "error": "rate-limited (5min window)",
                })
                continue
            targets.append((event_type, channel, message))

    def _worker():
        for etype, channel, msg in targets:
            ch_obj = ch.get_channel(channel)
            if not ch_obj:
                _record_log({"event_type": etype, "channel": channel,
                             "message": msg[:200], "success": False,
                             "error": "unknown channel"})
                continue
            try:
                result = ch_obj.send(msg)
            except Exception as e:  # noqa: BLE001
                result = {"success": False, "error": str(e)}
            _record_log({
                "event_type": etype, "channel": channel,
                "message": msg[:200], "success": bool(result.get("success")),
                "error": result.get("error", ""),
            })

    threading.Thread(target=_worker, daemon=True).start()
    return {"dispatched": len(targets), "event_type": event_type,
            "matched_subscriptions": len(matched)}


def get_history(limit: int = 50) -> List[Dict[str, Any]]:
    with _history_lock:
        return list(reversed(_history))[:limit]


def get_record(record_id: int) -> Optional[Dict[str, Any]]:
    with _history_lock:
        for h in _history:
            if h.get("record_id") == record_id:
                return h
    return None


def get_stats() -> Dict[str, Any]:
    by_channel: Dict[str, int] = {}
    by_event: Dict[str, int] = {}
    success = 0
    failed = 0
    with _history_lock:
        total = len(_history)
        for h in _history:
            c = h.get("channel", "unknown")
            e = h.get("event_type", "unknown")
            by_channel[c] = by_channel.get(c, 0) + 1
            by_event[e] = by_event.get(e, 0) + 1
            if h.get("success"):
                success += 1
            else:
                failed += 1
    return {
        "total": total,
        "success": success,
        "failed": failed,
        "success_rate": round(success / total * 100, 2) if total else 0.0,
        "by_channel": by_channel,
        "by_event": by_event,
    }
