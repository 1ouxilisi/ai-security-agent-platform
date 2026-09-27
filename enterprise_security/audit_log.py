# -*- coding: utf-8 -*-
"""audit_log.py — 操作审计日志。

记录: 用户ID / 操作时间 / 操作类型 / 操作对象 / IP地址 / 结果。
支持按时间/用户/操作类型筛选，导出审计报告（HTML/JSON/CSV）。
"""
from __future__ import annotations

import csv
import io
import threading
import time
import uuid
from typing import Any, Dict, List, Optional


class AuditLogger:
    """内存审计日志（追加写，不可篡改模拟）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._logs: List[Dict[str, Any]] = []
        self._next_seq = 1

    # ------------------------------------------------------------------ #
    def record(self, user_id: str, action: str, target: str,
               ip: str = "0.0.0.0", result: str = "success",
               detail: str = "", status_code: int = 200) -> Dict[str, Any]:
        """追加一条审计记录。不可修改。"""
        with self._lock:
            entry = {
                "seq": self._next_seq,
                "log_id": f"AUD-{uuid.uuid4().hex[:10]}",
                "user_id": user_id,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "ts": int(time.time()),
                "action": action,
                "target": target,
                "ip": ip,
                "result": result,
                "status_code": status_code,
                "detail": detail,
            }
            self._next_seq += 1
            self._logs.append(entry)
            return dict(entry)

    # ------------------------------------------------------------------ #
    def query(self,
              start_time: Optional[str] = None,
              end_time: Optional[str] = None,
              user_id: Optional[str] = None,
              action: Optional[str] = None,
              result: Optional[str] = None,
              target: Optional[str] = None,
              limit: int = 200,
              offset: int = 0) -> Dict[str, Any]:
        """多条件筛选，返回分页结果。时间格式 YYYY-MM-DD 或完整时间串。"""
        with self._lock:
            rows = self._logs
        out: List[Dict[str, Any]] = []
        for r in rows:
            if user_id and r["user_id"] != user_id:
                continue
            if action and r["action"] != action:
                continue
            if result and r["result"] != result:
                continue
            if target and target not in r["target"]:
                continue
            if start_time and r["timestamp"] < start_time:
                continue
            if end_time and r["timestamp"] > end_time + " 23:59:59":
                continue
            out.append(r)
        # 最新在前
        out.sort(key=lambda x: x["ts"], reverse=True)
        total = len(out)
        page = out[offset: offset + limit]
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": page,
        }

    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            rows = list(self._logs)
        by_action: Dict[str, int] = {}
        by_user: Dict[str, int] = {}
        failed = 0
        ips: Dict[str, int] = {}
        for r in rows:
            by_action[r["action"]] = by_action.get(r["action"], 0) + 1
            by_user[r["user_id"]] = by_user.get(r["user_id"], 0) + 1
            ips[r["ip"]] = ips.get(r["ip"], 0) + 1
            if r["result"] != "success":
                failed += 1
        top_users = sorted(by_user.items(), key=lambda x: x[1], reverse=True)[:5]
        top_ips = sorted(ips.items(), key=lambda x: x[1], reverse=True)[:5]
        return {
            "total_events": len(rows),
            "failed_events": failed,
            "success_rate": round((len(rows) - failed) / len(rows) * 100, 1) if rows else 100.0,
            "by_action": by_action,
            "top_users": [{"user_id": u, "count": c} for u, c in top_users],
            "top_ips": [{"ip": i, "count": c} for i, c in top_ips],
        }

    # ------------------------------------------------------------------ #
    def export(self, fmt: str = "html", **filters: Any) -> Dict[str, Any]:
        """导出审计报告。"""
        data = self.query(limit=100000, **filters)
        items = data["items"]
        report_id = f"AUD-REP-{uuid.uuid4().hex[:8]}"
        generated = time.strftime("%Y-%m-%d %H:%M:%S")
        if fmt == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["seq", "time", "user_id", "action", "target",
                         "ip", "result", "status_code", "detail"])
            for it in items:
                w.writerow([it["seq"], it["timestamp"], it["user_id"],
                            it["action"], it["target"], it["ip"],
                            it["result"], it["status_code"], it["detail"]])
            return {"report_id": report_id, "format": "csv",
                    "generated_at": generated, "count": len(items),
                    "content": buf.getvalue()}
        if fmt == "json":
            return {"report_id": report_id, "format": "json",
                    "generated_at": generated, "count": len(items),
                    "items": items}
        # 默认 HTML
        rows_html = "".join(
            f"<tr><td>{it['seq']}</td><td>{it['timestamp']}</td>"
            f"<td>{it['user_id']}</td><td>{it['action']}</td>"
            f"<td>{it['target']}</td><td>{it['ip']}</td>"
            f"<td>{it['result']}</td><td>{it['status_code']}</td>"
            f"<td>{it['detail']}</td></tr>" for it in items
        )
        html = f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>审计报告 {report_id}</title>
<style>body{{font-family:Segoe UI;margin:24px;background:#0d1117;color:#e6edf3}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #30363d;
padding:6px 10px;font-size:12px;text-align:left}}</style></head><body>
<h2>操作审计报告 {report_id}</h2>
<p>生成时间: {generated}　共 {len(items)} 条记录</p>
<table><thead><tr><th>#</th><th>时间</th><th>用户</th><th>操作</th>
<th>对象</th><th>IP</th><th>结果</th><th>HTTP</th><th>详情</th></tr></thead>
<tbody>{rows_html}</tbody></table></body></html>"""
        return {"report_id": report_id, "format": "html",
                "generated_at": generated, "count": len(items),
                "content": html}
