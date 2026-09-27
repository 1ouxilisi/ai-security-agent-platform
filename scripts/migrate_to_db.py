"""
migrate_to_db脚本 —— 从旧 JSON 数据文件迁移到 SQLite 数据库（data/platform.db）。

功能：
    - 扫描 data/ 目录下的 assessments / tasks / notifications / alerts /
      vulnerabilities / assets 等 JSON 文件
    - 按字段映射导入到新 SQLAlchemy 表
    - 文件不存在或解析失败则跳过，最后打印迁移摘要

用法（在项目根目录执行）：
    python scripts/migrate_to_db.py

注意：
    - 本脚本为授权安全评估 / 防御检测产品的数据迁移工具
    - 幂等：重复运行不会重复主键（按原始业务ID去重插入）
"""
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# 项目根目录加入 sys.path（本脚本位于 <root>/scripts/）
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from database.db_manager import db_manager  # noqa: E402
from database.models import (  # noqa: E402
    Asset,
    Assessment,
    Notification,
    Task,
    Vulnerability,
    Alert,
)

DATA_DIR = PROJECT_ROOT / "data"

# 迁移统计
summary: Dict[str, int] = {}


def to_epoch(value: Any) -> Optional[float]:
    """把 ISO 字符串 / 数字时间戳统一转成 Unix 时间戳（秒，float）。"""
    if value is None or value == "":
        return None
    # 已经是数字
    if isinstance(value, (int, float)):
        try:
            return float(value)
        except Exception:  # noqa: BLE001
            return None
    s = str(value).strip()
    if not s:
        return None
    # 纯数字字符串
    try:
        return float(s)
    except Exception:  # noqa: BLE001
        pass
    # ISO 字符串
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except Exception:  # noqa: BLE001
        return None


def load_json(path: Path) -> Any:
    """读取 JSON 文件，失败返回 None。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:  # noqa: BLE001
        print(f"  [跳过] 读取失败 {path}: {e}")
        return None


def records_from(data: Any, list_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """把 JSON 内容归一化为记录列表（支持 dict-of-records / list / {list_key:[...]}）。"""
    if data is None:
        return []
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        if list_key and isinstance(data.get(list_key), list):
            return [r for r in data[list_key] if isinstance(r, dict)]
        # dict-of-records：值本身是 dict 即视为记录
        out = []
        for v in data.values():
            if isinstance(v, dict):
                out.append(v)
        if out:
            return out
        # 否则整个 dict 视为一条记录
        return [data]
    return []


def ensure_id(record: Dict[str, Any], *keys: str) -> str:
    """从记录里取业务ID，没有则生成 UUID。"""
    import uuid

    for k in keys:
        if record.get(k):
            return str(record[k])
    return str(uuid.uuid4())


def migrate_assessments() -> int:
    """迁移评估数据。"""
    files: List[Path] = [
        DATA_DIR / "compliance" / "assessments.json",
    ]
    # 兼容 tenants 目录下的 assessments/*.json
    tdir = DATA_DIR / "tenants"
    if tdir.exists():
        files.extend(sorted(tdir.glob("*/assessments/*.json")))

    items: List[Dict[str, Any]] = []
    for fp in files:
        if not fp.exists():
            continue
        data = load_json(fp)
        for rec in records_from(data):
            started = to_epoch(rec.get("started_at"))
            completed = to_epoch(rec.get("completed_at"))
            items.append({
                "id": ensure_id(rec, "assessment_id", "id"),
                "target": rec.get("target_name") or rec.get("target") or rec.get("target_ip") or "",
                "assessment_type": rec.get("standard") or rec.get("assessment_type") or "compliance",
                "risk_score": float(rec.get("overall_score") or rec.get("risk_score") or 0.0),
                "status": rec.get("status") or "unknown",
                "started_at": started,
                "completed_at": completed,
                "tenant_id": rec.get("tenant_id") or "default",
                "user_id": rec.get("user_id") or "",
                "summary": json.dumps({k: rec.get(k) for k in ("pass_count", "fail_count", "level") if rec.get(k) is not None}, ensure_ascii=False) if isinstance(rec, dict) else "",
                "created_at": started or datetime.now().timestamp(),
            })
    n = db_manager.bulk_insert(Assessment, items)
    summary["assessments"] = n
    return n


def migrate_tasks() -> int:
    """迁移任务数据。"""
    files = [
        DATA_DIR / "collaboration" / "tasks.json",
        DATA_DIR / "distributed" / "tasks.json",
    ]
    items: List[Dict[str, Any]] = []
    for fp in files:
        if not fp.exists():
            continue
        data = load_json(fp)
        for rec in records_from(data):
            created = to_epoch(rec.get("created_at")) or datetime.now().timestamp()
            items.append({
                "id": ensure_id(rec, "task_id", "id"),
                "title": rec.get("title") or rec.get("name") or "",
                "description": rec.get("description") or rec.get("desc") or "",
                "assignee": rec.get("assignee") or rec.get("assigned_to") or "",
                "status": (rec.get("status") or "pending"),
                "priority": rec.get("priority") or rec.get("level") or "medium",
                "due_date": to_epoch(rec.get("due_date")),
                "tenant_id": rec.get("tenant_id") or "default",
                "created_at": created,
                "updated_at": to_epoch(rec.get("updated_at")) or created,
            })
    n = db_manager.bulk_insert(Task, items)
    summary["tasks"] = n
    return n


def migrate_notifications() -> int:
    """迁移通知数据。"""
    files = [DATA_DIR / "collaboration" / "notifications.json"]
    items: List[Dict[str, Any]] = []
    for fp in files:
        if not fp.exists():
            continue
        data = load_json(fp)
        for rec in records_from(data):
            created = to_epoch(rec.get("created_at")) or datetime.now().timestamp()
            status = str(rec.get("status") or "").lower()
            items.append({
                "id": ensure_id(rec, "notification_id", "id"),
                "user_id": rec.get("user") or rec.get("user_id") or "",
                "type": rec.get("type") or "general",
                "title": rec.get("title") or "",
                "content": rec.get("content") or rec.get("message") or "",
                "is_read": status == "read",
                "created_at": created,
            })
    n = db_manager.bulk_insert(Notification, items)
    summary["notifications"] = n
    return n


def migrate_alerts() -> int:
    """迁移告警数据。"""
    files = [
        DATA_DIR / "audit" / "alerts.json",
        DATA_DIR / "monitoring" / "alerts.json",
        DATA_DIR / "intelligence" / "alerts.json",
        DATA_DIR / "soc" / "alerts.json",
    ]
    items: List[Dict[str, Any]] = []
    for fp in files:
        if not fp.exists():
            continue
        data = load_json(fp)
        for rec in records_from(data):
            created = to_epoch(rec.get("created_at") or rec.get("timestamp")) or datetime.now().timestamp()
            items.append({
                "id": ensure_id(rec, "alert_id", "id"),
                "rule_id": rec.get("rule_id") or rec.get("source") or "",
                "level": rec.get("level") or rec.get("severity") or "medium",
                "title": rec.get("title") or rec.get("name") or "",
                "content": rec.get("content") or rec.get("message") or rec.get("description") or "",
                "status": rec.get("status") or "open",
                "acknowledged_by": rec.get("acknowledged_by") or "",
                "acknowledged_at": to_epoch(rec.get("acknowledged_at")),
                "tenant_id": rec.get("tenant_id") or "default",
                "created_at": created,
            })
    n = db_manager.bulk_insert(Alert, items)
    summary["alerts"] = n
    return n


def migrate_vulnerabilities() -> int:
    """迁移漏洞数据。"""
    files = [DATA_DIR / "vuln_management" / "vulnerabilities.json"]
    items: List[Dict[str, Any]] = []
    for fp in files:
        if not fp.exists():
            continue
        data = load_json(fp)
        for rec in records_from(data, list_key="vulnerabilities"):
            discovered = to_epoch(rec.get("discovered_at")) or datetime.now().timestamp()
            items.append({
                "id": ensure_id(rec, "vuln_id", "id"),
                "assessment_id": rec.get("assessment_id") or "",
                "name": rec.get("name") or rec.get("title") or "未命名漏洞",
                "severity": rec.get("severity") or "medium",
                "cve": rec.get("cve") or "",
                "cwe": rec.get("cwe") or "",
                "description": rec.get("description") or "",
                "evidence": rec.get("fix_evidence") or rec.get("evidence") or "",
                "status": str(rec.get("status") or "open").lower(),
                "discovered_at": discovered,
                "remediated_at": to_epoch(rec.get("fixed_at") or rec.get("remediated_at")),
                "target": rec.get("target") or rec.get("affected_asset") or "",
                "tenant_id": rec.get("tenant_id") or "default",
            })
    n = db_manager.bulk_insert(Vulnerability, items)
    summary["vulnerabilities"] = n
    return n


def migrate_assets() -> int:
    """迁移资产数据。"""
    files = [
        DATA_DIR / "soc" / "assets.json",
        DATA_DIR / "src_platform" / "assets.json",
    ]
    items: List[Dict[str, Any]] = []
    for fp in files:
        if not fp.exists():
            continue
        data = load_json(fp)
        for rec in records_from(data):
            last_scan = to_epoch(rec.get("last_scan") or rec.get("last_scanned"))
            items.append({
                "id": ensure_id(rec, "asset_id", "id"),
                "ip": rec.get("ip") or rec.get("ip_address") or "",
                "domain": rec.get("domain") or rec.get("hostname") or "",
                "asset_type": rec.get("asset_type") or rec.get("type") or "host",
                "fingerprint": rec.get("os") or rec.get("fingerprint") or "",
                "first_seen": to_epoch(rec.get("first_seen")) or datetime.now().timestamp(),
                "last_scanned": last_scan or 0.0,
                "tenant_id": rec.get("tenant_id") or "default",
                "risk_score": float(rec.get("risk_score") or 0.0),
                "owner": rec.get("owner") or "",
                "importance": rec.get("importance") or rec.get("criticality") or "medium",
            })
    n = db_manager.bulk_insert(Asset, items)
    summary["assets"] = n
    return n


def main() -> None:
    """执行迁移并打印摘要。"""
    print("=" * 60)
    print("开始 JSON -> SQLite 数据迁移")
    print(f"数据库: {db_manager.db_path}")
    print("=" * 60)

    migrate_assessments()
    migrate_tasks()
    migrate_notifications()
    migrate_alerts()
    migrate_vulnerabilities()
    migrate_assets()

    print("-" * 60)
    print("迁移摘要:")
    total = 0
    for k, v in summary.items():
        print(f"  {k:16s}: {v} 条")
        total += v
    print("-" * 60)
    print(f"合计导入: {total} 条")
    print("迁移完成。")


if __name__ == "__main__":
    main()
