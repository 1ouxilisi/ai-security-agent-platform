# -*- coding: utf-8 -*-
"""
report_generator.py - 合规报告生成器

负责基于评估任务生成结构化合规报告（HTML/多框架对比），
管理报告与报告模板。

数据表：
    cp_reports          报告
    cp_report_templates 报告模板

报告结构：
    封面 / 目录 / 执行摘要 / 评估范围 / 评估方法 / 控制项评估结果
    / 不符合项详情 / 差距分析 / 整改计划 / 合规评分 / 附录

注意事项：
    - 本模块仅用于授权的合规审计
"""

from __future__ import annotations

import html
import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.database import db
from utils.logger import log

from compliance.frameworks import get_framework_manager
from compliance.assessment import get_assessor


REPORT_DIR = Path(__file__).parent.parent / "data" / "compliance_reports"


class ReportGenerator:
    """合规报告生成器"""

    def __init__(self):
        """初始化并建表"""
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        self._init_tables()
        self._seed_default_template()

    @staticmethod
    def _now() -> str:
        return datetime.now().isoformat()

    # ==================== 数据库初始化 ====================

    def _init_tables(self):
        """初始化报告相关数据表（幂等）"""
        conn = db._get_connection()
        try:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cp_reports (
                    id TEXT PRIMARY KEY,
                    assessment_id TEXT,
                    title TEXT NOT NULL,
                    framework_id INTEGER,
                    format TEXT DEFAULT 'html',
                    file_path TEXT,
                    generated_at TEXT,
                    generated_by TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cp_report_templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    cover_title TEXT,
                    logo_path TEXT,
                    sections TEXT,
                    style TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cp_report_assess ON cp_reports(assessment_id)")
            conn.commit()
            log.info("✅ 合规报告表初始化完成")
        except Exception as e:
            log.error(f"合规报告表初始化失败: {e}")
        finally:
            conn.close()

    def _seed_default_template(self):
        """播种默认报告模板"""
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT id FROM cp_report_templates WHERE name = 'default'").fetchone()
            if row:
                return
            sections = ["封面", "目录", "执行摘要", "评估范围", "评估方法",
                        "控制项评估结果", "不符合项详情", "差距分析",
                        "整改计划", "合规评分", "附录"]
            style = {"theme": "dark", "primary": "#58a6ff", "font": "Microsoft YaHei"}
            conn.execute("""
                INSERT INTO cp_report_templates
                    (name, cover_title, logo_path, sections, style, created_at)
                VALUES ('default', '合规审计报告', '', ?, ?, ?)
            """, (json.dumps(sections, ensure_ascii=False),
                  json.dumps(style, ensure_ascii=False), self._now()))
            conn.commit()
        except Exception as e:
            log.error(f"播种默认模板失败: {e}")
        finally:
            conn.close()

    # ==================== HTML 渲染 ====================

    def get_report_html(self, assessment_id: str) -> str:
        """直接生成 HTML 格式报告内容，用于在线预览"""
        assessor = get_assessor()
        fm = get_framework_manager()
        assessment = assessor.get_assessment_status(assessment_id)
        if not assessment:
            return "<html><body><h1>评估任务不存在</h1></body></html>"
        results = assessor.get_assessment_results(assessment_id)
        gap = assessor.get_gap_analysis(assessment_id)
        fw = fm.get_framework(assessment.get("framework_id", 0)) or {}

        score = assessment.get("overall_score", 0)
        items = results.get("items", [])

        def _badge(status: str) -> str:
            colors = {"compliant": "#3fb950", "partially_compliant": "#d29922",
                      "non_compliant": "#f85149", "not_applicable": "#8b949e",
                      "not_assessed": "#8b949e"}
            labels = {"compliant": "符合", "partially_compliant": "部分符合",
                      "non_compliant": "不符合", "not_applicable": "不适用",
                      "not_assessed": "待评估"}
            c = colors.get(status, "#8b949e")
            return f'<span style="color:{c}">{labels.get(status, status)}</span>'

        rows_html = ""
        for it in items:
            rows_html += (
                f"<tr><td>{html.escape(str(it.get('domain','')))}</td>"
                f"<td>{html.escape(str(it.get('control_id','')))}</td>"
                f"<td>{html.escape(str(it.get('title','')))}</td>"
                f"<td>{_badge(it.get('status',''))}</td>"
                f"<td>{html.escape(str(it.get('severity','')))}</td></tr>"
            )

        gap_html = ""
        for g in gap.get("gaps", [])[:50]:
            gap_html += (
                f"<tr><td>{html.escape(str(g.get('title','')))}</td>"
                f"<td>{html.escape(str(g.get('gap','')))}</td>"
                f"<td>{html.escape(str(g.get('remediation','')))}</td>"
                f"<td>{html.escape(str(g.get('priority','')))}</td>"
                f"<td>{html.escape(str(g.get('eta','')))}</td></tr>"
            )

        return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>合规审计报告 - {html.escape(str(assessment.get('name','')))}</title>
<style>
body{{font-family:'Microsoft YaHei',Arial,sans-serif;margin:0;padding:40px;background:#0d1117;color:#c9d1d9;}}
h1{{color:#58a6ff;border-bottom:2px solid #30363d;padding-bottom:10px;}}
h2{{color:#58a6ff;margin-top:32px;}}
table{{width:100%%;border-collapse:collapse;margin:16px 0;}}
th,td{{border:1px solid #30363d;padding:8px;text-align:left;font-size:13px;}}
th{{background:#161b22;color:#58a6ff;}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:16px 0;}}
.score{{font-size:48px;color:#3fb950;font-weight:bold;}}
</style></head><body>
<h1>合规审计报告</h1>
<p>框架：{html.escape(str(fw.get('name','')))}（{html.escape(str(fw.get('version','')))}）</p>
<p>评估任务：{html.escape(str(assessment.get('name','')))}　评估人：{html.escape(str(assessment.get('assessor','')))}</p>
<div class="card"><div class="score">{score}</div><p>合规评分（0-100）</p></div>
<h2>执行摘要</h2>
<div class="card">总控制项 {assessment.get('total_controls',0)}，
符合 {assessment.get('compliant_count',0)}，
部分符合 {assessment.get('partial_count',0)}，
不符合 {assessment.get('non_compliant_count',0)}，
不适用 {assessment.get('not_applicable_count',0)}，
差距项 {gap.get('gap_count',0)}。</div>
<h2>控制项评估结果</h2>
<table><tr><th>控制域</th><th>控制编号</th><th>控制项</th><th>状态</th><th>严重程度</th></tr>{rows_html}</table>
<h2>差距分析</h2>
<table><tr><th>控制项</th><th>差距</th><th>整改措施</th><th>优先级</th><th>预计时间</th></tr>{gap_html}</table>
<h2>附录</h2><p>证据清单与参考标准见附件。生成时间：{self._now()}</p>
</body></html>"""

    # ==================== 报告生成 ====================

    def generate_report(self, assessment_id: str, title: str = None,
                        fmt: str = "html", generated_by: str = "") -> Optional[dict]:
        """生成合规报告"""
        assessor = get_assessor()
        assessment = assessor.get_assessment_status(assessment_id)
        if not assessment:
            log.error(f"生成报告失败：评估 {assessment_id} 不存在")
            return None
        # 未完成则先计算评分
        if assessment.get("status") != "completed":
            assessor.complete_assessment(assessment_id)
        report_id = str(uuid.uuid4())
        html_content = self.get_report_html(assessment_id)
        file_path = str(REPORT_DIR / f"report_{report_id}.html")
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
        except Exception as e:
            log.error(f"写入报告文件失败: {e}")
            file_path = ""
        now = self._now()
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO cp_reports
                    (id, assessment_id, title, framework_id, format, file_path,
                     generated_at, generated_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (report_id, assessment_id,
                  title or f"合规报告-{assessment.get('name','')}",
                  assessment.get("framework_id"), fmt, file_path,
                  now, generated_by, now))
            conn.commit()
            log.info(f"✅ 合规报告已生成: {report_id}")
            return self.get_report(report_id)
        except Exception as e:
            log.error(f"记录报告失败: {e}")
            return None
        finally:
            conn.close()

    def get_report(self, report_id: str) -> Optional[dict]:
        """获取报告信息"""
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM cp_reports WHERE id = ?", (report_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def download_report(self, report_id: str) -> Dict[str, Any]:
        """返回报告文件路径与HTML内容"""
        rep = self.get_report(report_id)
        if not rep:
            return {"exists": False}
        content = ""
        if rep.get("file_path") and os.path.exists(rep["file_path"]):
            try:
                with open(rep["file_path"], "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception as e:
                log.error(f"读取报告文件失败: {e}")
        return {"exists": True, "report": rep, "content": content}

    def list_reports(self, assessment_id: str = None,
                     page: int = 1, page_size: int = 20) -> dict:
        """报告列表"""
        conn = db._get_connection()
        try:
            where = "WHERE 1=1"
            params: list = []
            if assessment_id:
                where += " AND assessment_id = ?"
                params.append(assessment_id)
            total = conn.execute(
                f"SELECT COUNT(*) FROM cp_reports {where}", params).fetchone()[0]
            page = max(1, page)
            page_size = max(1, min(200, page_size))
            offset = (page - 1) * page_size
            rows = conn.execute(
                f"SELECT * FROM cp_reports {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                params + [page_size, offset]).fetchall()
            return {
                "total": total, "page": page, "page_size": page_size,
                "total_pages": (total + page_size - 1) // page_size if page_size else 0,
                "items": [dict(r) for r in rows],
            }
        finally:
            conn.close()

    # ==================== 模板管理 ====================

    def list_templates(self) -> List[dict]:
        """报告模板列表"""
        conn = db._get_connection()
        try:
            rows = conn.execute("SELECT * FROM cp_report_templates").fetchall()
            result = []
            for r in rows:
                item = dict(r)
                for jf in ("sections", "style"):
                    raw = item.get(jf)
                    if isinstance(raw, str):
                        try:
                            item[jf] = json.loads(raw)
                        except (json.JSONDecodeError, TypeError):
                            item[jf] = []
                result.append(item)
            return result
        finally:
            conn.close()

    def create_template(self, name: str, cover_title: str = "",
                        logo_path: str = "",
                        sections: List[str] = None,
                        style: Dict[str, Any] = None) -> Optional[int]:
        """创建报告模板"""
        conn = db._get_connection()
        try:
            cur = conn.execute("""
                INSERT INTO cp_report_templates
                    (name, cover_title, logo_path, sections, style, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (name, cover_title, logo_path,
                  json.dumps(sections or [], ensure_ascii=False),
                  json.dumps(style or {}, ensure_ascii=False), self._now()))
            conn.commit()
            return cur.lastrowid
        except Exception as e:
            log.error(f"创建报告模板失败: {e}")
            return None
        finally:
            conn.close()

    def update_template(self, template_id: int, **kwargs) -> bool:
        """更新报告模板"""
        sets, params = [], []
        for k in ("name", "cover_title", "logo_path"):
            if k in kwargs:
                sets.append(f"{k} = ?")
                params.append(kwargs[k])
        for jf in ("sections", "style"):
            if jf in kwargs:
                sets.append(f"{jf} = ?")
                params.append(json.dumps(kwargs[jf], ensure_ascii=False))
        if not sets:
            return False
        params.append(template_id)
        conn = db._get_connection()
        try:
            conn.execute(
                f"UPDATE cp_report_templates SET {', '.join(sets)} WHERE id = ?", params)
            conn.commit()
            return True
        except Exception as e:
            log.error(f"更新报告模板失败: {e}")
            return False
        finally:
            conn.close()

    def delete_template(self, template_id: int) -> bool:
        """删除报告模板"""
        conn = db._get_connection()
        try:
            conn.execute("DELETE FROM cp_report_templates WHERE id = ?", (template_id,))
            conn.commit()
            return True
        except Exception as e:
            log.error(f"删除报告模板失败: {e}")
            return False
        finally:
            conn.close()

    # ==================== 多框架对比 ====================

    def generate_multi_framework_comparison(self, assessment_ids: List[str],
                                            title: str = "多框架合规对比") -> Dict[str, Any]:
        """一次评估生成多框架对比报告，对比不同框架的符合率"""
        assessor = get_assessor()
        fm = get_framework_manager()
        comparison = []
        for aid in assessment_ids:
            a = assessor.get_assessment_status(aid)
            if not a:
                continue
            if a.get("status") != "completed":
                assessor.complete_assessment(aid)
                a = assessor.get_assessment_status(aid)
            fw = fm.get_framework(a.get("framework_id", 0)) or {}
            total = a.get("total_controls", 0) or 1
            comparison.append({
                "assessment_id": aid,
                "framework": fw.get("name"),
                "score": a.get("overall_score", 0),
                "compliance_rate": round(a.get("compliant_count", 0) / total * 100, 2),
                "compliant": a.get("compliant_count", 0),
                "non_compliant": a.get("non_compliant_count", 0),
                "total_controls": a.get("total_controls", 0),
            })
        html_content = f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>body{{font-family:'Microsoft YaHei';background:#0d1117;color:#c9d1d9;padding:40px;}}
table{{width:100%%;border-collapse:collapse;}}th,td{{border:1px solid #30363d;padding:10px;text-align:center;}}
th{{background:#161b22;color:#58a6ff;}}</style></head><body>
<h1 style="color:#58a6ff">{html.escape(title)}</h1>
<table><tr><th>框架</th><th>合规评分</th><th>符合率(%%)</th><th>符合项</th><th>不符合项</th><th>总控制项</th></tr>
"""
        for c in comparison:
            html_content += (
                f"<tr><td>{html.escape(str(c['framework']))}</td>"
                f"<td>{c['score']}</td><td>{c['compliance_rate']}</td>"
                f"<td>{c['compliant']}</td><td>{c['non_compliant']}</td>"
                f"<td>{c['total_controls']}</td></tr>")
        html_content += "</table></body></html>"
        return {"title": title, "comparison": comparison, "html": html_content}


# 全局单例
_report_generator: Optional[ReportGenerator] = None


def get_report_generator() -> ReportGenerator:
    """获取报告生成器全局单例"""
    global _report_generator
    if _report_generator is None:
        _report_generator = ReportGenerator()
    return _report_generator
