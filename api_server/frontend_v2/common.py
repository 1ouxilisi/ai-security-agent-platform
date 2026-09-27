# -*- coding: utf-8 -*-
"""
common.py — frontend_v2 共享工具：响应清理、分页、ID生成、时间戳。
"""
from __future__ import annotations

import re
import time
import uuid
from typing import Any, Dict, List


# 控制字符（除 \t \n \r 外）
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(obj: Any) -> Any:
    """递归清理字符串中的控制字符，防止 JSON 序列化 / UTF-8 失败。"""
    if isinstance(obj, str):
        s = _CTRL_RE.sub(" ", obj)
        return s.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, tuple):
        return [_clean(v) for v in obj]
    return obj


def now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def ts() -> float:
    return time.time()


def new_id(prefix: str = "id") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def paginate(items: List[Dict[str, Any]], page: int, page_size: int,
             sort_by: str = "", sort_dir: str = "asc") -> Dict[str, Any]:
    """通用分页 + 排序。items 为字典列表。"""
    total = len(items)
    data = list(items)
    if sort_by and data and isinstance(data[0], dict):
        reverse = (sort_dir or "asc").lower() == "desc"

        def _key(it: Dict[str, Any]) -> Any:
            v = it.get(sort_by, "")
            if isinstance(v, (int, float)):
                return (0, v, "")
            return (1, 0, str(v))

        try:
            data.sort(key=_key, reverse=reverse)
        except Exception:
            pass
    page = max(1, int(page or 1))
    page_size = max(1, min(500, int(page_size or 20)))
    start = (page - 1) * page_size
    end = start + page_size
    return {
        "items": data[start:end],
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_more": end < total,
    }


def apply_filters(items: List[Dict[str, Any]], filters: Dict[str, Any]) -> List[Dict[str, Any]]:
    """简单等值/包含过滤：filters 的键对应字段。"""
    if not filters:
        return items
    out = []
    for it in items:
        ok = True
        for k, v in filters.items():
            if v in (None, "", "all"):
                continue
            iv = it.get(k)
            if isinstance(v, list):
                if iv not in v:
                    ok = False
                    break
            elif isinstance(iv, str) and isinstance(v, str):
                if v.lower() not in iv.lower():
                    ok = False
                    break
            else:
                if iv != v:
                    ok = False
                    break
        if ok:
            out.append(it)
    return out


def search_in(items: List[Dict[str, Any]], q: str, fields: List[str]) -> List[Dict[str, Any]]:
    """在指定字段中做不区分大小写的关键词搜索。"""
    if not q:
        return items
    ql = q.lower()
    out = []
    for it in items:
        blob = " ".join(str(it.get(f, "")) for f in fields).lower()
        if ql in blob:
            out.append(it)
    return out
