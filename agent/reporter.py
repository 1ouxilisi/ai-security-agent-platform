"""
reporter智能体模块，提供相关AI驱动的安全分析和决策功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import json
import time
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
from utils.logger import log
from utils.helpers import ensure_dir, sanitize_filename
from agent.memory import AgentMemory, Finding
from config.settings import settings


class ReportGenerator:
    """报告生成器"""

    # 严重程度排序
    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    SEVERITY_COLOR = {
        "critical": "#dc2626", "high": "#ea580c",
        "medium": "#ca8a04", "low": "#2563eb", "info": "#6b7280"
    }

    def __init__(self):
        """初始化ReportGenerator实例。

        Args:
            self: 类实例。
        """
        self.output_dir = ensure_dir(settings.report.output_dir)

    def generate(self, memory: AgentMemory, format: Optional[str] = None) -> str:
        """
        生成报告
        返回报告文件路径
        """
        fmt = format or settings.report.format
        log.info(f"生成报告，格式: {fmt}")

        if fmt == "json":
            return self._generate_json(memory)
        elif fmt == "html":
            return self._generate_html(memory)
        else:
            return self._generate_markdown(memory)

    def _generate_markdown(self, memory: AgentMemory) -> str:
        """生成Markdown格式报告"""
        stats = memory.get_statistics()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        lines = []

        # 标题
        lines.append(f"# 安全测试报告")
        lines.append("")
        lines.append(f"**任务ID**: {memory.task_id}")
        lines.append(f"**生成时间**: {timestamp}")
        lines.append(f"**测试目标**: {memory.target or '未指定'}")
        lines.append(f"**任务描述**: {memory.task_description}")
        lines.append(f"**执行状态**: {memory.status}")
        lines.append(f"**执行时长**: {stats['duration_seconds']}秒")
        lines.append("")

        # 执行摘要
        lines.append("## 执行摘要")
        lines.append("")
        lines.append(f"- 总步骤数: {stats['total_steps']}")
        lines.append(f"- 已完成: {stats['completed_steps']}")
        lines.append(f"- 失败: {stats['failed_steps']}")
        lines.append(f"- 待执行: {stats['pending_steps']}")
        lines.append(f"- 发现安全问题: {stats['findings_count']}个")
        lines.append("")

        # 安全发现统计
        lines.append("### 安全问题分布")
        lines.append("")
        lines.append("| 严重程度 | 数量 |")
        lines.append("|---------|------|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = stats["findings_by_severity"].get(sev, 0)
            if count > 0:
                lines.append(f"| {self.SEVERITY_EMOJI.get(sev, '')} {sev.upper()} | {count} |")
        lines.append("")

        # 详细发现
        if memory.findings:
            lines.append("## 安全问题详情")
            lines.append("")

            # 按严重程度排序
            sorted_findings = sorted(memory.findings, key=lambda f: self.SEVERITY_ORDER.get(f.severity, 99))

            for i, finding in enumerate(sorted_findings, 1):
                emoji = self.SEVERITY_EMOJI.get(finding.severity, "")
                lines.append(f"### {i}. {emoji} [{finding.severity.upper()}] {finding.title}")
                lines.append("")
                lines.append(f"**类型**: {finding.type}")
                lines.append(f"**目标**: {finding.target or 'N/A'}")
                lines.append(f"**发现工具**: {finding.tool or 'N/A'}")
                lines.append(f"**发现时间**: {datetime.fromtimestamp(finding.timestamp).strftime('%Y-%m-%d %H:%M:%S')}")
                lines.append("")
                lines.append(f"**描述**:")
                lines.append(f"> {finding.description}")
                lines.append("")
                if finding.evidence:
                    lines.append(f"**证据**:")
                    lines.append(f"```")
                    lines.append(finding.evidence)
                    lines.append(f"```")
                    lines.append("")
                if finding.recommendations:
                    lines.append(f"**修复建议**:")
                    lines.append(f"> {finding.recommendations}")
                    lines.append("")
                lines.append("---")
                lines.append("")
        else:
            lines.append("## 安全问题详情")
            lines.append("")
            lines.append("本次测试未发现安全问题。")
            lines.append("")

        # 执行步骤详情
        lines.append("## 执行步骤详情")
        lines.append("")
        lines.append("| # | 步骤 | 工具 | 状态 |")
        lines.append("|---|------|------|------|")
        for step in memory.plan:
            status_icon = {"completed": "✅", "failed": "❌", "pending": "⏳", "running": "🔄", "skipped": "⏭️"}.get(step.status, "❓")
            lines.append(f"| {step.step_number} | {step.description[:50]} | {step.tool_name or '-'} | {status_icon} {step.status} |")
        lines.append("")

        # 收集的数据
        if memory.collected_data:
            lines.append("## 收集的数据")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(memory.collected_data, ensure_ascii=False, indent=2, default=str)[:2000])
            lines.append("```")
            lines.append("")

        # 免责声明
        lines.append("## 免责声明")
        lines.append("")
        lines.append("本报告由AI自动化安全测试工具生成，仅供参考。所有测试均应在授权范围内进行。报告中的发现需要人工复核确认，AI工具可能存在误报。")
        lines.append("")
        lines.append("---")
        lines.append(f"*报告由 AI Hacking Agent 自动生成于 {timestamp}*")

        # 保存文件
        filename = f"report_{memory.task_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        filepath = self.output_dir / sanitize_filename(filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        log.info(f"Markdown报告已生成: {filepath}")
        return str(filepath)

    def _generate_json(self, memory: AgentMemory) -> str:
        """生成JSON格式报告"""
        report_data = {
            "report_version": "1.0",
            "generated_at": datetime.now().isoformat(),
            "task": memory.to_dict(),
        }

        filename = f"report_{memory.task_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.output_dir / sanitize_filename(filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2, default=str)

        log.info(f"JSON报告已生成: {filepath}")
        return str(filepath)

    def _generate_html(self, memory: AgentMemory) -> str:
        """生成HTML格式报告"""
        # 先生成Markdown，再简单转HTML（简化版）
        md_path = self._generate_markdown(memory)

        # 简单的HTML包装
        html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全测试报告 - {memory.task_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1000px; margin: 0 auto; padding: 20px; line-height: 1.6; }}
        h1 {{ color: #1a1a1a; border-bottom: 3px solid #dc2626; padding-bottom: 10px; }}
        h2 {{ color: #2d2d2d; margin-top: 30px; border-left: 4px solid #3b82f6; padding-left: 10px; }}
        h3 {{ color: #404040; }}
        table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
        th {{ background-color: #f5f5f5; font-weight: 600; }}
        tr:nth-child(even) {{ background-color: #fafafa; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }}
        pre {{ background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        blockquote {{ border-left: 4px solid #3b82f6; margin: 10px 0; padding: 10px 20px; background: #f0f7ff; }}
        .severity-critical {{ color: #dc2626; font-weight: bold; }}
        .severity-high {{ color: #ea580c; font-weight: bold; }}
        .severity-medium {{ color: #ca8a04; font-weight: bold; }}
        .severity-low {{ color: #2563eb; font-weight: bold; }}
        .severity-info {{ color: #6b7280; }}
    </style>
</head>
<body>
    <div style="background: #fef2f2; border: 1px solid #fecaca; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
        <strong>⚠️ 免责声明：</strong>本报告由AI自动化工具生成，仅供参考，所有发现需人工复核。测试应在授权范围内进行。
    </div>
    <pre style="white-space: pre-wrap; word-wrap: break-word; background: #fff; color: #333; border: 1px solid #ddd;">
{Path(md_path).read_text(encoding='utf-8')}
    </pre>
</body>
</html>"""

        filename = f"report_{memory.task_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = self.output_dir / sanitize_filename(filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        log.info(f"HTML报告已生成: {filepath}")
        return str(filepath)

    def generate_summary(self, memory: AgentMemory) -> str:
        """生成简短摘要，用于控制台输出"""
        stats = memory.get_statistics()
        lines = [
            "=" * 60,
            "任务执行摘要",
            "=" * 60,
            f"任务ID: {memory.task_id}",
            f"目标: {memory.target or '未指定'}",
            f"状态: {memory.status}",
            f"进度: {stats['progress']}",
            f"时长: {stats['duration_seconds']}秒",
            f"发现问题: {stats['findings_count']}个",
        ]

        if stats["findings_count"] > 0:
            lines.append("-" * 60)
            lines.append("问题分布:")
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = stats["findings_by_severity"].get(sev, 0)
                if count > 0:
                    emoji = self.SEVERITY_EMOJI.get(sev, "")
                    lines.append(f"  {emoji} {sev.upper()}: {count}")

        lines.append("=" * 60)
        return "\n".join(lines)
