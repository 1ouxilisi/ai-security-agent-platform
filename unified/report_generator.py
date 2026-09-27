#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一报告生成器 - 为全域安全评估结果生成 HTML / Markdown / JSON 报告

所有报告均为中文，HTML 报告为独立可打开的单文件（内联 CSS/SVG，不依赖外部资源）。
"""
import html
import json
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from unified.models import (
    DomainAssessment,
    ReportConfig,
    Severity,
    UnifiedAssessmentResult,
)

# 多格式导出器（PDF / Word / Excel），可选依赖
try:
    from reporting.template_manager import TemplateManager
    from reporting.pdf_exporter import PDFExporter
    from reporting.word_exporter import WordExporter
    from reporting.excel_exporter import ExcelExporter
    _REPORTING_EXPORTERS_AVAILABLE = True
except Exception:  # pragma: no cover - 依赖缺失时降级
    TemplateManager = None
    PDFExporter = None
    WordExporter = None
    ExcelExporter = None
    _REPORTING_EXPORTERS_AVAILABLE = False


# 严重程度颜色（与前端保持一致）
SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#6b7280",
}

SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}

RISK_LEVEL_COLORS = {
    "严重": "#dc2626",
    "高危": "#ea580c",
    "中危": "#ca8a04",
    "低危": "#2563eb",
    "轻微": "#0891b2",
    "安全": "#16a34a",
    "未评估": "#6b7280",
}


def _esc(text: Any) -> str:
    """HTML 转义"""
    if text is None:
        return ""
    return html.escape(str(text), quote=True)


def _fmt_time(ts: float) -> str:
    """时间戳格式化"""
    if not ts:
        return "-"
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


class UnifiedReportGenerator:
    """全域安全评估统一报告生成器"""

    def __init__(self, output_root: str = "reports"):
        self.output_root = output_root

    # ---------------- 公共入口 ----------------

    def generate(self, result: UnifiedAssessmentResult,
                 config: Optional[ReportConfig] = None) -> str:
        """根据格式生成报告，返回报告文件绝对/相对路径"""
        if config is None:
            config = ReportConfig()
        fmt = (config.format or "html").lower()
        os.makedirs(config.output_dir or self.output_root, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"unified_report_{result.assessment_id}_{ts}"

        if fmt == "html":
            content = self._render_html(result, config)
            path = os.path.join(config.output_dir or self.output_root, base_name + ".html")
        elif fmt in ("md", "markdown"):
            content = self._render_markdown(result, config)
            path = os.path.join(config.output_dir or self.output_root, base_name + ".md")
        elif fmt == "json":
            content = self._render_json(result)
            path = os.path.join(config.output_dir or self.output_root, base_name + ".json")
        else:
            raise ValueError(f"不支持的报告格式: {fmt}")

        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

        result.report_path = os.path.abspath(path)
        return result.report_path

    # ---------------- 统一多格式入口 ----------------

    def generate_report(self, assessment_data: Any,
                        format: str = "html",
                        template_id: Optional[str] = None,
                        output_dir: Optional[str] = None) -> str:
        """统一报告生成入口，根据 format 生成 html/pdf/docx/xlsx 报告。

        Args:
            assessment_data: 评估数据（dict 或 UnifiedAssessmentResult）
            format: 目标格式 html/pdf/docx/xlsx/markdown/json
            template_id: 模板 ID，None 则使用默认模板
            output_dir: 输出目录，None 则用 self.output_root

        Returns:
            生成的报告文件绝对路径
        """
        fmt = (format or "html").lower()
        out_dir = output_dir or self.output_root
        os.makedirs(out_dir, exist_ok=True)

        # 统一为 dict，便于多格式导出器处理
        if hasattr(assessment_data, "to_dict"):
            data_dict = assessment_data.to_dict()
        else:
            data_dict = assessment_data if isinstance(assessment_data, dict) else {}

        target = str(data_dict.get("target") or "target").replace("/", "_").replace("\\", "_")
        atype = str(data_dict.get("assessment_type") or "assessment")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{target}_{atype}_{ts}"

        # 获取模板配置
        template_config: Dict[str, Any] = {}
        if _REPORTING_EXPORTERS_AVAILABLE and TemplateManager is not None:
            try:
                tm = TemplateManager()
                tpl = tm.get_template(template_id) if template_id else tm.get_default()
                if tpl:
                    template_config = tpl
            except Exception:
                template_config = {}

        if fmt == "html":
            # 复用原有 HTML 渲染
            if isinstance(assessment_data, UnifiedAssessmentResult):
                config = ReportConfig()
                path = os.path.join(out_dir, base_name + ".html")
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self._render_html(assessment_data, config))
                return os.path.abspath(path)
            return self._render_html_from_dict(data_dict, out_dir, base_name, template_config)

        if fmt in ("md", "markdown"):
            if isinstance(assessment_data, UnifiedAssessmentResult):
                config = ReportConfig()
                path = os.path.join(out_dir, base_name + ".md")
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self._render_markdown(assessment_data, config))
                return os.path.abspath(path)
            raise ValueError("Markdown 导出需要 UnifiedAssessmentResult 对象")

        if fmt == "json":
            path = os.path.join(out_dir, base_name + ".json")
            with open(path, "w", encoding="utf-8") as f:
                f.write(json.dumps(data_dict, ensure_ascii=False, indent=2))
            return os.path.abspath(path)

        if not _REPORTING_EXPORTERS_AVAILABLE:
            raise ImportError("reporting 导出依赖（reportlab/python-docx/openpyxl）不可用")

        if fmt == "pdf":
            exporter = PDFExporter()
            return exporter.export(data_dict, os.path.join(out_dir, base_name + ".pdf"),
                                  template_config=template_config)
        if fmt in ("docx", "word", "doc"):
            exporter = WordExporter()
            return exporter.export(data_dict, os.path.join(out_dir, base_name + ".docx"),
                                  template_config=template_config)
        if fmt in ("xlsx", "excel"):
            exporter = ExcelExporter()
            return exporter.export(data_dict, os.path.join(out_dir, base_name + ".xlsx"),
                                   template_config=template_config)

        raise ValueError(f"不支持的报告格式: {fmt}")

    @staticmethod
    def supported_formats() -> List[Dict[str, Any]]:
        """返回支持的格式列表"""
        avail = _REPORTING_EXPORTERS_AVAILABLE
        return [
            {"format": "html", "name": "HTML", "available": True,
             "description": "独立可打开的单文件 HTML 报告"},
            {"format": "pdf", "name": "PDF", "available": avail and PDFExporter is not None,
             "description": "专业排版 PDF 报告（含封面/目录/中文字体）"},
            {"format": "docx", "name": "Word", "available": avail and WordExporter is not None,
             "description": "可编辑 Word 文档（标题层级+表格）"},
            {"format": "xlsx", "name": "Excel", "available": avail and ExcelExporter is not None,
             "description": "多 Sheet Excel 工作簿（含统计图表）"},
            {"format": "markdown", "name": "Markdown", "available": True,
             "description": "Markdown 格式报告"},
            {"format": "json", "name": "JSON", "available": True,
             "description": "原始数据 JSON"},
        ]

    def _render_html_from_dict(self, data: Dict[str, Any], out_dir: str,
                               base_name: str,
                               template_config: Dict[str, Any]) -> str:
        """从 dict 生成一个简单 HTML 报告（非 UnifiedAssessmentResult 时使用）"""
        tpl_title = template_config.get("report_title") or "安全评估报告"
        findings = data.get("findings") or []
        rows = "".join(
            f"<tr><td>{f.get('cve','')}</td><td>{_esc(f.get('title',''))}</td>"
            f"<td>{_esc(f.get('severity',''))}</td><td>{_esc(f.get('description',''))}</td></tr>"
            for f in findings
        )
        html_doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>{_esc(tpl_title)}</title></head>
<body style="font-family:'Microsoft YaHei',sans-serif;padding:32px;">
<h1>{_esc(tpl_title)}</h1>
<h2>执行摘要</h2><p>{_esc(data.get('executive_summary',''))}</p>
<h2>漏洞详情</h2>
<table border="1" cellpadding="6"><tr><th>CVE</th><th>名称</th><th>严重</th><th>描述</th></tr>{rows}</table>
</body></html>"""
        path = os.path.join(out_dir, base_name + ".html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_doc)
        return os.path.abspath(path)

    # ---------------- JSON ----------------

    def _render_json(self, result: UnifiedAssessmentResult) -> str:
        return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)

    # ---------------- Markdown ----------------

    def _render_markdown(self, result: UnifiedAssessmentResult, config: ReportConfig) -> str:
        lines: List[str] = []
        sev = result._severity_counts()

        lines.append(f"# {_esc(config.title)}")
        lines.append("")
        lines.append(f"- **评估目标**：{_esc(result.target)}")
        lines.append(f"- **评估类型**：{_esc(result.assessment_type)}")
        lines.append(f"- **评估编号**：`{_esc(result.assessment_id)}`")
        lines.append(f"- **开始时间**：{_fmt_time(result.started_at)}")
        lines.append(f"- **完成时间**：{_fmt_time(result.completed_at)}")
        lines.append(f"- **耗时**：{result.duration:.2f} 秒")
        lines.append(f"- **综合风险等级**：**{_esc(result.overall_risk_level)}**（{result.overall_risk_score} 分）")
        lines.append("")

        # 执行摘要
        lines.append("## 一、执行摘要")
        lines.append("")
        lines.append(result.executive_summary or "（无执行摘要）")
        lines.append("")

        # 关键发现
        if result.key_findings:
            lines.append("### 关键发现")
            for kf in result.key_findings:
                lines.append(f"- {kf}")
            lines.append("")

        # 漏洞统计
        lines.append("## 二、漏洞统计")
        lines.append("")
        lines.append("| 严重程度 | 数量 |")
        lines.append("| --- | --- |")
        for k in ("critical", "high", "medium", "low", "info"):
            lines.append(f"| {SEVERITY_LABELS[k]} | {sev.get(k, 0)} |")
        lines.append(f"| **合计** | **{len(result.all_findings)}** |")
        lines.append("")

        # 各领域风险分
        lines.append("### 各领域风险分")
        lines.append("")
        lines.append("| 领域 | 状态 | 风险分 | 风险等级 | 发现数 |")
        lines.append("| --- | --- | --- | --- | --- |")
        for dkey, da in result.domain_results.items():
            lines.append(
                f"| {_esc(da.domain.label())} | {_esc(da.status)} | "
                f"{da.risk_score} | {_esc(da.risk_level)} | {len(da.findings)} |"
            )
        lines.append("")

        # 详细发现
        lines.append("## 三、详细漏洞发现")
        lines.append("")
        for dkey, da in result.domain_results.items():
            lines.append(f"### {_esc(da.domain.label())}（{len(da.findings)} 项）")
            lines.append("")
            if not da.findings:
                lines.append("_未发现问题_")
                lines.append("")
                continue
            for idx, f in enumerate(da.findings, 1):
                lines.append(
                    f"#### {idx}. [{SEVERITY_LABELS.get(f.severity.value, f.severity.value)}] {_esc(f.title)}"
                )
                lines.append("")
                lines.append(f"- **分类**：{_esc(f.category)}")
                lines.append(f"- **位置**：{_esc(f.location or f.target)}")
                if f.cwe:
                    lines.append(f"- **CWE**：{_esc(f.cwe)}")
                if f.owasp:
                    lines.append(f"- **OWASP**：{_esc(f.owasp)}")
                if f.cvss:
                    lines.append(f"- **CVSS**：{f.cvss}")
                lines.append(f"- **描述**：{_esc(f.description)}")
                if f.evidence:
                    lines.append(f"- **证据**：`{_esc(f.evidence)}`")
                if f.recommendation:
                    lines.append(f"- **修复建议**：{_esc(f.recommendation)}")
                lines.append("")

        # 修复建议汇总
        lines.append("## 四、修复建议汇总")
        lines.append("")
        if result.recommendations:
            for i, rec in enumerate(result.recommendations, 1):
                lines.append(f"{i}. {rec}")
        else:
            lines.append("暂无修复建议。")
        lines.append("")

        # 附录
        lines.append("## 五、附录")
        lines.append("")
        all_tools: List[str] = []
        all_checks: List[str] = []
        for da in result.domain_results.values():
            all_tools.extend(da.tools_used)
            all_checks.extend(da.checks_run)
        lines.append("### 工具列表")
        lines.append("")
        if all_tools:
            for t in sorted(set(all_tools)):
                lines.append(f"- {t}")
        else:
            lines.append("_无_")
        lines.append("")
        lines.append("### 检测项列表")
        lines.append("")
        if all_checks:
            for c in sorted(set(all_checks)):
                lines.append(f"- {c}")
        else:
            lines.append("_无_")
        lines.append("")
        lines.append("---")
        lines.append(f"_报告生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_")
        lines.append("")
        return "\n".join(lines)

    # ---------------- HTML ----------------

    def _render_html(self, result: UnifiedAssessmentResult, config: ReportConfig) -> str:
        sev = result._severity_counts()
        total_findings = len(result.all_findings) or 1

        # 各领域风险分柱状图数据
        domain_bars = []
        for dkey, da in result.domain_results.items():
            color = RISK_LEVEL_COLORS.get(da.risk_level, "#6b7280")
            domain_bars.append({
                "label": da.domain.label(),
                "score": da.risk_score,
                "level": da.risk_level,
                "count": len(da.findings),
                "color": color,
            })

        # 严重程度饼图（用 SVG conic-gradient 实现，纯 CSS）
        total_sev = sum(sev.values()) or 1
        # 构建 conic-gradient 分段
        acc = 0.0
        stops = []
        for k in ("critical", "high", "medium", "low", "info"):
            cnt = sev.get(k, 0)
            if cnt == 0:
                continue
            start = (acc / total_sev) * 360
            acc += cnt
            end = (acc / total_sev) * 360
            stops.append(f"{SEVERITY_COLORS[k]} {start:.1f}deg {end:.1f}deg")
        pie_gradient = ", ".join(stops) if stops else "#374151 0deg 360deg"

        risk_color = RISK_LEVEL_COLORS.get(result.overall_risk_level, "#6b7280")

        # 构建领域详细发现 HTML
        domain_sections = []
        for dkey, da in result.domain_results.items():
            findings_html = self._render_findings_html(da)
            domain_sections.append(f"""
            <div class="domain-section">
                <div class="domain-header">
                    <h3>{_esc(da.domain.label())}</h3>
                    <span class="badge" style="background:{RISK_LEVEL_COLORS.get(da.risk_level, '#6b7280')}">
                        {_esc(da.risk_level)} · {da.risk_score}分
                    </span>
                    <span class="muted">状态: {_esc(da.status)} · 发现 {len(da.findings)} 项</span>
                </div>
                <p class="summary">{_esc(da.summary)}</p>
                {findings_html}
            </div>
            """)

        # 修复建议
        rec_items = "".join(f"<li>{_esc(r)}</li>" for r in result.recommendations) or "<li>暂无</li>"

        # 工具与检测项
        all_tools: List[str] = []
        all_checks: List[str] = []
        for da in result.domain_results.values():
            all_tools.extend(da.tools_used)
            all_checks.extend(da.checks_run)
        tools_html = "".join(f"<span class='chip'>{_esc(t)}</span>" for t in sorted(set(all_tools))) or "<span class='muted'>无</span>"
        checks_html = "".join(f"<span class='chip'>{_esc(c)}</span>" for c in sorted(set(all_checks))) or "<span class='muted'>无</span>"

        # 关键发现
        kf_items = "".join(f"<li>{_esc(k)}</li>" for k in result.key_findings) or "<li>无</li>"

        html_doc = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc(config.title)} - {_esc(result.target)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, "Microsoft YaHei", "PingFang SC", sans-serif;
         background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
  .cover {{ background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 100%);
           border: 1px solid #334155; border-radius: 12px; padding: 48px; margin-bottom: 24px; }}
  .cover h1 {{ font-size: 32px; color: #fff; margin-bottom: 16px; }}
  .cover-meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-top: 24px; }}
  .meta-item {{ background: rgba(255,255,255,0.05); padding: 12px 16px; border-radius: 8px; }}
  .meta-item .label {{ font-size: 12px; color: #94a3b8; }}
  .meta-item .value {{ font-size: 16px; color: #fff; font-weight: 600; margin-top: 4px; }}
  .risk-hero {{ display: inline-block; padding: 8px 20px; border-radius: 999px;
               color: #fff; font-weight: 700; font-size: 18px; }}
  .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px;
           padding: 24px; margin-bottom: 20px; }}
  .card h2 {{ font-size: 20px; color: #fff; margin-bottom: 16px;
             border-left: 4px solid #3b82f6; padding-left: 12px; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }}
  .stat-box {{ background: #0f172a; border-radius: 8px; padding: 16px; text-align: center; }}
  .stat-box .num {{ font-size: 28px; font-weight: 700; }}
  .stat-box .lbl {{ font-size: 12px; color: #94a3b8; margin-top: 4px; }}
  .bar-row {{ display: flex; align-items: center; margin-bottom: 10px; gap: 12px; }}
  .bar-row .bar-label {{ width: 100px; font-size: 14px; color: #cbd5e1; }}
  .bar-track {{ flex: 1; height: 22px; background: #0f172a; border-radius: 4px; overflow: hidden; }}
  .bar-fill {{ height: 100%; border-radius: 4px; transition: width .3s; }}
  .bar-row .bar-val {{ width: 80px; text-align: right; font-size: 13px; color: #94a3b8; }}
  .pie-wrap {{ display: flex; align-items: center; gap: 32px; flex-wrap: wrap; }}
  .pie {{ width: 180px; height: 180px; border-radius: 50%;
         background: conic-gradient({pie_gradient}); position: relative; }}
  .pie::after {{ content: "{total_findings}"; position: absolute; inset: 50px;
                background: #1e293b; border-radius: 50%;
                display: flex; align-items: center; justify-content: center;
                font-size: 28px; font-weight: 700; color: #fff; }}
  .legend {{ display: flex; flex-direction: column; gap: 8px; }}
  .legend-item {{ display: flex; align-items: center; gap: 8px; font-size: 14px; }}
  .legend-dot {{ width: 12px; height: 12px; border-radius: 50%; }}
  .finding {{ border: 1px solid #334155; border-radius: 8px; margin-bottom: 12px; overflow: hidden; }}
  .finding-head {{ display: flex; align-items: center; gap: 12px; padding: 12px 16px;
                   background: #0f172a; cursor: pointer; }}
  .sev-badge {{ padding: 3px 10px; border-radius: 4px; color: #fff; font-size: 12px; font-weight: 700; }}
  .finding-title {{ flex: 1; font-weight: 600; color: #e2e8f0; }}
  .finding-body {{ padding: 16px; border-top: 1px solid #334155; }}
  .finding-body p {{ margin-bottom: 8px; }}
  .finding-body .label {{ color: #94a3b8; font-size: 13px; }}
  pre, code {{ font-family: "Consolas", "Courier New", monospace;
              background: #0f172a; padding: 10px; border-radius: 6px;
              overflow-x: auto; font-size: 13px; color: #e2e8f0; display: block; }}
  .domain-header {{ display: flex; align-items: center; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }}
  .domain-header h3 {{ color: #fff; }}
  .badge {{ padding: 4px 12px; border-radius: 999px; font-size: 12px; font-weight: 600; color: #fff; }}
  .muted {{ color: #94a3b8; font-size: 13px; }}
  .summary {{ color: #cbd5e1; margin-bottom: 12px; }}
  .chip {{ display: inline-block; background: #0f172a; border: 1px solid #334155;
          padding: 4px 10px; border-radius: 4px; font-size: 12px; margin: 2px; }}
  ul {{ padding-left: 20px; }}
  li {{ margin-bottom: 6px; }}
  .footer {{ text-align: center; color: #64748b; font-size: 12px; padding: 24px; }}
</style>
</head>
<body>
<div class="container">

  <div class="cover">
    <h1>{_esc(config.title)}</h1>
    <p style="color:#94a3b8;">AI Hacking Agent · 全域安全评估统一框架</p>
    <div class="cover-meta">
      <div class="meta-item"><div class="label">评估目标</div><div class="value">{_esc(result.target)}</div></div>
      <div class="meta-item"><div class="label">评估类型</div><div class="value">{_esc(result.assessment_type)}</div></div>
      <div class="meta-item"><div class="label">评估编号</div><div class="value" style="font-size:13px;">{_esc(result.assessment_id)}</div></div>
      <div class="meta-item"><div class="label">完成时间</div><div class="value">{_fmt_time(result.completed_at)}</div></div>
      <div class="meta-item"><div class="label">综合风险等级</div>
        <div class="value"><span class="risk-hero" style="background:{risk_color}">{_esc(result.overall_risk_level)} · {result.overall_risk_score}分</span></div>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>执行摘要</h2>
    <p>{_esc(result.executive_summary)}</p>
    <h3 style="margin-top:16px;color:#fff;">关键发现</h3>
    <ul>{kf_items}</ul>
  </div>

  <div class="card">
    <h2>风险概览</h2>
    <div class="stats-grid" style="margin-bottom:20px;">
      <div class="stat-box"><div class="num" style="color:{risk_color}">{result.overall_risk_score}</div><div class="lbl">综合风险分</div></div>
      <div class="stat-box"><div class="num" style="color:#dc2626">{sev.get('critical',0)}</div><div class="lbl">严重</div></div>
      <div class="stat-box"><div class="num" style="color:#ea580c">{sev.get('high',0)}</div><div class="lbl">高危</div></div>
      <div class="stat-box"><div class="num" style="color:#ca8a04">{sev.get('medium',0)}</div><div class="lbl">中危</div></div>
      <div class="stat-box"><div class="num" style="color:#2563eb">{sev.get('low',0)}</div><div class="lbl">低危</div></div>
      <div class="stat-box"><div class="num" style="color:#6b7280">{sev.get('info',0)}</div><div class="lbl">信息</div></div>
    </div>
    <h3 style="color:#fff;margin-bottom:12px;">各领域风险分</h3>
    {"".join(f'''
    <div class="bar-row">
      <div class="bar-label">{_esc(b["label"])}</div>
      <div class="bar-track"><div class="bar-fill" style="width:{b["score"]}%;background:{b["color"]}"></div></div>
      <div class="bar-val">{b["score"]}分 · {b["level"]}</div>
    </div>''' for b in domain_bars)}
  </div>

  <div class="card">
    <h2>漏洞严重程度分布</h2>
    <div class="pie-wrap">
      <div class="pie"></div>
      <div class="legend">
        {"".join(f'''
        <div class="legend-item">
          <span class="legend-dot" style="background:{SEVERITY_COLORS[k]}"></span>
          {SEVERITY_LABELS[k]}: {sev.get(k,0)} 项
        </div>''' for k in ("critical","high","medium","low","info") if sev.get(k,0) > 0)}
      </div>
    </div>
  </div>

  {''.join(domain_sections)}

  <div class="card">
    <h2>修复建议汇总</h2>
    <ol>{rec_items}</ol>
  </div>

  <div class="card">
    <h2>附录</h2>
    <h3 style="color:#fff;margin-bottom:8px;">使用工具</h3>
    <div style="margin-bottom:16px;">{tools_html}</div>
    <h3 style="color:#fff;margin-bottom:8px;">检测项</h3>
    <div>{checks_html}</div>
  </div>

  <div class="footer">
    报告由 AI Hacking Agent 全域安全评估框架自动生成 · {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
    本报告仅用于授权安全测试与防御评估。
  </div>

</div>
<script>
document.querySelectorAll('.finding-head').forEach(function(h){{
  h.addEventListener('click', function(){{
    var body = h.nextElementSibling;
    body.style.display = (body.style.display === 'none') ? 'block' : 'none';
  }});
}});
</script>
</body>
</html>
"""
        return html_doc

    def _render_findings_html(self, da: DomainAssessment) -> str:
        if not da.findings:
            return '<p class="muted">该领域未发现问题。</p>'
        items = []
        for f in da.findings:
            color = SEVERITY_COLORS.get(f.severity.value, "#6b7280")
            label = SEVERITY_LABELS.get(f.severity.value, f.severity.value)
            evidence_html = ""
            if f.evidence:
                evidence_html = f'<p><span class="label">证据:</span><pre>{_esc(f.evidence)}</pre></p>'
            rec_html = ""
            if f.recommendation:
                rec_html = f'<p><span class="label">修复建议:</span> {_esc(f.recommendation)}</p>'
            meta_parts = []
            if f.cwe:
                meta_parts.append(f"CWE: {_esc(f.cwe)}")
            if f.owasp:
                meta_parts.append(f"OWASP: {_esc(f.owasp)}")
            if f.cvss:
                meta_parts.append(f"CVSS: {f.cvss}")
            if f.location:
                meta_parts.append(f"位置: {_esc(f.location)}")
            meta_html = " · ".join(meta_parts)
            items.append(f"""
            <div class="finding">
              <div class="finding-head">
                <span class="sev-badge" style="background:{color}">{label}</span>
                <span class="finding-title">{_esc(f.title)}</span>
                <span class="muted">{_esc(f.category)}</span>
              </div>
              <div class="finding-body">
                <p><span class="label">描述:</span> {_esc(f.description) or '无'}</p>
                {evidence_html}
                {rec_html}
                <p class="muted">{meta_html}</p>
              </div>
            </div>
            """)
        return "".join(items)
