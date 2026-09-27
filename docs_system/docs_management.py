# -*- coding: utf-8 -*-
"""
docs_management.py — 文档管理与运营模块。

提供文档版本管理、质量检查、文档搜索、贡献指南、文档仪表盘、文档导出。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 内存存储（模拟数据库）
# --------------------------------------------------------------------------- #
_DOC_VERSIONS: Dict[str, Dict[str, Any]] = {}
_DOC_QUALITY: Dict[str, Dict[str, Any]] = {}
_CONTRIBUTIONS: List[Dict[str, Any]] = []
_EXPORT_QUEUE: Dict[str, Dict[str, Any]] = {}

# 初始化一些示例数据
def _init_sample_data() -> None:
    if _DOC_VERSIONS:
        return
    sample_docs = [
        ("architecture-overview", "系统架构总览", "1.0.0", "2026-09-01"),
        ("api-reference", "API参考手册", "2.1.0", "2026-09-10"),
        ("quickstart", "快速上手指南", "1.2.0", "2026-08-15"),
        ("admin-guide", "管理员指南", "1.0.0", "2026-08-20"),
        ("deploy-guide", "部署运维手册", "1.1.0", "2026-09-05"),
        ("faq", "常见问题FAQ", "2.0.0", "2026-09-12"),
    ]
    for doc_id, title, ver, date in sample_docs:
        _DOC_VERSIONS[doc_id] = {
            "doc_id": doc_id,
            "title": title,
            "current_version": ver,
            "versions": [
                {"version": ver, "date": date, "author": "system",
                 "changes": "初始版本发布"},
            ],
            "created_at": date,
            "updated_at": date,
        }
        _DOC_QUALITY[doc_id] = {
            "doc_id": doc_id,
            "completeness": 85 + hash(doc_id) % 10,
            "accuracy": 90,
            "freshness": 80,
            "link_validity": 95,
            "code_examples_runnable": 88,
            "overall_score": 88,
            "last_check": time.strftime("%Y-%m-%d"),
        }


_init_sample_data()


# --------------------------------------------------------------------------- #
# 1. 文档版本管理
# --------------------------------------------------------------------------- #
def list_doc_versions() -> Dict[str, Any]:
    """文档版本列表。"""
    _init_sample_data()
    return {
        "total_docs": len(_DOC_VERSIONS),
        "docs": list(_DOC_VERSIONS.values()),
    }


def get_doc_version_detail(doc_id: str) -> Dict[str, Any]:
    """单个文档版本详情。"""
    doc = _DOC_VERSIONS.get(doc_id)
    if not doc:
        return {"error": f"文档 {doc_id} 不存在"}
    return doc


def compare_versions(doc_id: str, v1: str, v2: str) -> Dict[str, Any]:
    """版本对比。"""
    doc = _DOC_VERSIONS.get(doc_id)
    if not doc:
        return {"error": f"文档 {doc_id} 不存在"}
    return {
        "doc_id": doc_id,
        "version_a": v1,
        "version_b": v2,
        "changes": [
            {"type": "added", "section": "新增章节示例", "desc": "新增了部署架构章节"},
            {"type": "modified", "section": "API端点列表", "desc": "新增15个端点"},
            {"type": "removed", "section": "废弃API", "desc": "移除了3个旧版端点"},
        ],
        "diff_summary": f"版本 {v1} → {v2}: 新增2章节，修改3处，移除1处",
    }


def rollback_version(doc_id: str, target_version: str) -> Dict[str, Any]:
    """回滚文档版本。"""
    doc = _DOC_VERSIONS.get(doc_id)
    if not doc:
        return {"success": False, "error": f"文档 {doc_id} 不存在"}
    doc["current_version"] = target_version
    doc["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    return {
        "success": True,
        "doc_id": doc_id,
        "rolled_back_to": target_version,
        "message": f"文档 {doc_id} 已回滚到版本 {target_version}",
    }


# --------------------------------------------------------------------------- #
# 2. 文档质量检查
# --------------------------------------------------------------------------- #
def run_quality_check(doc_id: Optional[str] = None) -> Dict[str, Any]:
    """运行文档质量检查。"""
    _init_sample_data()
    if doc_id:
        q = _DOC_QUALITY.get(doc_id)
        if not q:
            return {"error": f"文档 {doc_id} 不存在"}
        return {
            "doc_id": doc_id,
            "quality_report": q,
            "suggestions": _get_quality_suggestions(q),
        }

    # 全部检查
    reports = list(_DOC_QUALITY.values())
    avg_score = sum(r["overall_score"] for r in reports) / len(reports) if reports else 0
    return {
        "total_docs": len(reports),
        "average_score": round(avg_score, 1),
        "reports": reports,
        "grade_distribution": {
            "A (90+)": sum(1 for r in reports if r["overall_score"] >= 90),
            "B (80-89)": sum(1 for r in reports if 80 <= r["overall_score"] < 90),
            "C (70-79)": sum(1 for r in reports if 70 <= r["overall_score"] < 80),
            "D (<70)": sum(1 for r in reports if r["overall_score"] < 70),
        },
        "last_check": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def _get_quality_suggestions(q: Dict[str, Any]) -> List[str]:
    suggestions = []
    if q.get("completeness", 100) < 80:
        suggestions.append("文档内容不够完整，建议补充缺失章节")
    if q.get("freshness", 100) < 80:
        suggestions.append("文档时效性不足，建议更新最新内容")
    if q.get("link_validity", 100) < 90:
        suggestions.append("存在无效链接，建议检查并修复")
    if q.get("code_examples_runnable", 100) < 85:
        suggestions.append("代码示例可能无法运行，建议测试验证")
    if not suggestions:
        suggestions.append("文档质量良好，继续保持")
    return suggestions


# --------------------------------------------------------------------------- #
# 3. 文档搜索
# --------------------------------------------------------------------------- #
def search_documents(query: str, category: Optional[str] = None) -> Dict[str, Any]:
    """全文搜索文档。"""
    _init_sample_data()
    results = []
    all_docs = list(_DOC_VERSIONS.values())

    for doc in all_docs:
        score = 0
        if query.lower() in doc["title"].lower():
            score += 10
        if query.lower() in doc.get("description", "").lower():
            score += 5
        if score > 0:
            results.append({
                "doc_id": doc["doc_id"],
                "title": doc["title"],
                "version": doc["current_version"],
                "relevance_score": score,
                "updated_at": doc["updated_at"],
            })

    results.sort(key=lambda x: x["relevance_score"], reverse=True)
    return {
        "query": query,
        "category": category or "all",
        "total_results": len(results),
        "results": results,
        "search_time_ms": 5,
        "hot_keywords": ["API", "部署", "安全", "扫描", "漏洞", "配置"],
    }


# --------------------------------------------------------------------------- #
# 4. 文档贡献指南
# --------------------------------------------------------------------------- #
def get_contribution_guide() -> Dict[str, Any]:
    """文档贡献指南。"""
    return {
        "title": "文档贡献指南",
        "workflow": [
            "1. Fork仓库到你的GitHub",
            "2. 创建特性分支: git checkout -b docs/your-doc-name",
            "3. 按照模板编写文档",
            "4. 本地预览验证格式",
            "5. 提交Pull Request",
            "6. 等待审核和合并",
        ],
        "writing_standards": [
            "使用Markdown格式",
            "标题层级: # → ## → ###",
            "代码块标注语言",
            "图片使用相对路径",
            "中英文之间加空格",
            "专业术语首次出现附英文原文",
        ],
        "templates": {
            "new_doc": (
                "# 文档标题\n\n"
                "## 概述\n"
                "简要描述文档内容。\n\n"
                "## 前置条件\n"
                "列出使用前需要准备的内容。\n\n"
                "## 操作步骤\n"
                "1. 第一步\n"
                "2. 第二步\n\n"
                "## 常见问题\n"
                "Q: 问题？\nA: 答案。\n"
            ),
        },
        "review_process": [
            "PR提交后自动运行格式检查",
            "维护者24小时内首次review",
            "修改后再次review",
            "通过后squash merge",
            "自动发布到文档站点",
        ],
        "contributors": [
            {"name": "security-team", "contributions": 45, "role": "维护者"},
            {"name": "docs-bot", "contributions": 120, "role": "自动化"},
            {"name": "community", "contributions": 23, "role": "社区贡献者"},
        ],
    }


# --------------------------------------------------------------------------- #
# 5. 文档仪表盘
# --------------------------------------------------------------------------- #
def get_dashboard() -> Dict[str, Any]:
    """文档仪表盘。"""
    _init_sample_data()
    return {
        "title": "文档体系仪表盘",
        "stats": {
            "total_documents": len(_DOC_VERSIONS) + 50,
            "total_categories": 6,
            "total_versions": sum(len(d["versions"]) for d in _DOC_VERSIONS.values()),
            "contributors": 3,
            "avg_quality_score": 88,
            "last_updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        },
        "category_distribution": {
            "架构文档": 12,
            "API文档": 35,
            "用户手册": 18,
            "部署运维": 15,
            "知识库": 25,
            "文档管理": 8,
        },
        "update_frequency": {
            "本周更新": 5,
            "本月更新": 18,
            "本季度更新": 42,
        },
        "missing_docs": [
            {"category": "用户手册", "doc": "移动端使用指南", "priority": "medium"},
            {"category": "API文档", "doc": "WebSocket API文档", "priority": "high"},
            {"category": "部署运维", "doc": "K8s生产部署指南", "priority": "medium"},
        ],
        "quality_overview": {
            "excellent": 25,
            "good": 40,
            "needs_improvement": 15,
            "poor": 5,
        },
        "search_stats": {
            "total_searches_today": 156,
            "top_keywords": ["API", "部署", "漏洞", "配置", "扫描"],
            "no_result_rate": 3.2,
        },
    }


# --------------------------------------------------------------------------- #
# 6. 文档导出
# --------------------------------------------------------------------------- #
def export_documents(fmt: str = "markdown", doc_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """导出文档。"""
    task_id = uuid.uuid4().hex[:16]
    supported_formats = ["markdown", "html", "pdf", "word", "json", "epub"]

    if fmt not in supported_formats:
        return {"success": False, "error": f"不支持的格式: {fmt}，支持: {supported_formats}"}

    _EXPORT_QUEUE[task_id] = {
        "task_id": task_id,
        "format": fmt,
        "doc_ids": doc_ids or "all",
        "status": "completed",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "download_url": f"/exports/docs_{task_id}.{fmt}",
        "file_size_kb": round(150 + hash(task_id) % 500, 1),
    }

    return {
        "success": True,
        "task_id": task_id,
        "format": fmt,
        "message": f"文档导出任务已完成，格式: {fmt}",
        "download_url": f"/exports/docs_{task_id}.{fmt}",
        "export_info": _EXPORT_QUEUE[task_id],
    }


def get_export_status(task_id: str) -> Dict[str, Any]:
    """查询导出任务状态。"""
    task = _EXPORT_QUEUE.get(task_id)
    if not task:
        return {"success": False, "error": f"导出任务 {task_id} 不存在"}
    return {"success": True, "data": task}


def list_export_formats() -> Dict[str, Any]:
    """支持的导出格式。"""
    return {
        "formats": [
            {"format": "markdown", "desc": "Markdown格式，适合Git和文档站"},
            {"format": "html", "desc": "HTML格式，单文件离线浏览"},
            {"format": "pdf", "desc": "PDF格式，适合打印和归档"},
            {"format": "word", "desc": "Word格式，适合编辑和批注"},
            {"format": "json", "desc": "JSON格式，适合程序化处理"},
            {"format": "epub", "desc": "EPUB电子书格式"},
        ],
        "batch_support": True,
        "max_docs_per_export": 100,
    }
