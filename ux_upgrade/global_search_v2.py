# -*- coding: utf-8 -*-
"""
ux_upgrade/global_search_v2.py — 全局搜索 V2

搜索任何功能 / 漏洞 / 报告，一键直达，Ctrl+K 快捷键。
内置索引 + 中文模糊匹配。
"""
from __future__ import annotations

from typing import Any, Dict, List

# 全局索引（内存，覆盖功能/漏洞/报告）
INDEX: List[Dict[str, Any]] = [
    {"id": "f_scan", "kind": "功能", "title": "一键扫描",
     "keywords": "scan 扫描 漏洞探测 开始", "path": "/ai-upgrade",
     "desc": "对目标发起全量扫描"},
    {"id": "f_report", "kind": "功能", "title": "生成报告",
     "keywords": "report 报告 导出 markdown", "path": "/ai-upgrade",
     "desc": "AI 生成渗透报告"},
    {"id": "f_qa", "kind": "功能", "title": "智能问答",
     "keywords": "qa 问答 chat 聊天 问", "path": "/ai-upgrade",
     "desc": "问 AI 安全问题"},
    {"id": "f_src", "kind": "功能", "title": "挖 SRC",
     "keywords": "src 补天 hackerone 众测", "path": "/ai-upgrade",
     "desc": "AI 辅助挖 SRC"},
    {"id": "f_theme", "kind": "功能", "title": "暗色主题",
     "keywords": "theme dark 主题 暗色 护眼", "path": "/ux-upgrade",
     "desc": "切换暗色/亮色"},
    {"id": "f_mobile", "kind": "功能", "title": "移动端",
     "keywords": "mobile 手机 响应式 适配", "path": "/ux-upgrade",
     "desc": "手机端仪表盘"},
    {"id": "v_sqli", "kind": "漏洞", "title": "SQL 注入",
     "keywords": "sql injection sqli 注入 数据库", "path": "/ai-upgrade",
     "desc": "CWE-89 严重"},
    {"id": "v_ssrf", "kind": "漏洞", "title": "SSRF 服务端请求伪造",
     "keywords": "ssrf 元数据 内网", "path": "/ai-upgrade", "desc": "CWE-918 高危"},
    {"id": "v_xss", "kind": "漏洞", "title": "XSS 跨站脚本",
     "keywords": "xss 跨站 脚本 cookie", "path": "/ai-upgrade", "desc": "CWE-79 中危"},
    {"id": "v_rce", "kind": "漏洞", "title": "RCE 远程代码执行",
     "keywords": "rce 代码执行 命令 shell", "path": "/ai-upgrade", "desc": "CWE-78 严重"},
    {"id": "r_demo", "kind": "报告", "title": "demo.target.com 渗透报告",
     "keywords": "report 报告 demo", "path": "/ai-upgrade", "desc": "最近生成"},
]


def _score(item: Dict[str, Any], q: str) -> int:
    ql = q.lower()
    text = (item["title"] + " " + item["keywords"]).lower()
    if item["title"].lower().startswith(ql):
        return 100
    if ql in text:
        return 80
    # 逐字符模糊
    hits = sum(1 for c in ql if c in text)
    return hits


class GlobalSearchV2:
    def search(self, query: str, limit: int = 15) -> Dict[str, Any]:
        q = (query or "").strip()
        if not q:
            return {"query": q, "total": 0, "results": [],
                    "hotkeys": ["Ctrl+K 打开搜索"]}
        scored = [(_score(it, q), it) for it in INDEX]
        scored = [(s, it) for s, it in scored if s > 0]
        scored.sort(key=lambda x: x[0], reverse=True)
        results = [{"id": it["id"], "kind": it["kind"], "title": it["title"],
                     "path": it["path"], "desc": it["desc"], "score": s}
                    for s, it in scored[:limit]]
        return {"query": q, "total": len(results), "results": results,
                "hotkeys": ["Ctrl+K", "↑↓ 选择", "Enter 直达"]}

    def index_size(self) -> int:
        return len(INDEX)

    def add(self, item: Dict[str, Any]) -> None:
        INDEX.append(item)


_gs_singleton: GlobalSearchV2 | None = None


def get_global_search_v2() -> GlobalSearchV2:
    global _gs_singleton
    if _gs_singleton is None:
        _gs_singleton = GlobalSearchV2()
    return _gs_singleton
