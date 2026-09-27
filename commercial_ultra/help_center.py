# -*- coding: utf-8 -*-
"""
commercial_ultra/help_center.py — 帮助中心（商业产品体验极致）。

- 完整使用文档
- FAQ
- 视频教程
- 常见问题检索
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List


class HelpCenter:
    """帮助中心（全内存模拟）。"""

    DOCS: List[Dict[str, Any]] = [
        {"id": "doc-001", "title": "快速开始：5 分钟首次扫描", "category": "入门",
         "body": "1) 注册账号 2) 新建项目并填写授权目标 3) 点击开始扫描 4) 查看在线报告。"},
        {"id": "doc-002", "title": "Web 扫描配置详解", "category": "扫描",
         "body": "支持爬取深度、并发、Cookie、自定义 Header，可排除敏感路径。"},
        {"id": "doc-003", "title": "API 扫描：导入 OpenAPI", "category": "扫描",
         "body": "上传 OpenAPI/Swagger JSON，平台自动构造用例并测鉴权与越权。"},
        {"id": "doc-004", "title": "导出 PDF 与报告定制", "category": "报告",
         "body": "报告页右上角导出，支持品牌 Logo 与脱敏选项。"},
        {"id": "doc-005", "title": "Webhook 回调接入", "category": "集成",
         "body": "在设置中配置 Webhook URL，扫描完成后自动推送结果 JSON。"},
    ]

    FAQS: List[Dict[str, Any]] = [
        {"id": "faq-001", "q": "扫描会对目标造成影响吗？",
         "a": "默认使用非破坏性 PoC，不会篡改数据；破坏性模块需手动开启并二次确认。"},
        {"id": "faq-002", "q": "免费版能扫多少？", "a": "每月 50 次扫描，单项目，基础 Web 扫描。"},
        {"id": "faq-003", "q": "支持私有化部署吗？", "a": "企业版支持私有化 / 离线部署。"},
        {"id": "faq-004", "q": "数据安全吗？", "a": "传输与存储全程加密，全操作审计留痕。"},
        {"id": "faq-005", "q": "如何退款？", "a": "订阅后 7 天内未使用可全额退款，联系 support@。"},
    ]

    VIDEOS: List[Dict[str, Any]] = [
        {"id": "vid-001", "title": "产品全景演示 3 分钟", "duration": "03:12",
         "cover": "demo", "url": "/demo/watch/vid-001"},
        {"id": "vid-002", "title": "首次扫描实操", "duration": "05:40",
         "cover": "tutorial", "url": "/demo/watch/vid-002"},
        {"id": "vid-003", "title": "报告解读与修复", "duration": "04:05",
         "cover": "report", "url": "/demo/watch/vid-003"},
    ]

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._search_log: List[str] = []

    def docs(self) -> List[Dict[str, Any]]:
        return [dict(d) for d in self.DOCS]

    def doc_detail(self, doc_id: str) -> Dict[str, Any]:
        for d in self.DOCS:
            if d["id"] == doc_id:
                return dict(d)
        raise ValueError("文档不存在")

    def faq(self) -> List[Dict[str, Any]]:
        return [dict(f) for f in self.FAQS]

    def videos(self) -> List[Dict[str, Any]]:
        return [dict(v) for v in self.VIDEOS]

    def search(self, keyword: str) -> Dict[str, Any]:
        """跨文档 / FAQ / 视频检索。"""
        kw = (keyword or "").strip().lower()
        if not kw:
            raise ValueError("请输入关键词")
        with self._lock:
            self._search_log.append(keyword)
        docs = [d for d in self.DOCS
                if kw in d["title"].lower() or kw in d["body"].lower()]
        faqs = [f for f in self.FAQS
                if kw in f["q"].lower() or kw in f["a"].lower()]
        vids = [v for v in self.VIDEOS if kw in v["title"].lower()]
        return {"keyword": keyword, "docs": docs, "faqs": faqs, "videos": vids,
                "total": len(docs) + len(faqs) + len(vids)}

    def hot_searches(self) -> List[str]:
        with self._lock:
            counts: Dict[str, int] = {}
            for k in self._search_log:
                counts[k] = counts.get(k, 0) + 1
            return sorted(counts, key=counts.get, reverse=True)[:10]


_help: HelpCenter | None = None


def get_help_center() -> HelpCenter:
    global _help
    if _help is None:
        _help = HelpCenter()
    return _help
