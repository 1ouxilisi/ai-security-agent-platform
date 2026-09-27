"""
report_exporter模块，提供相关安全测试功能。

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
from typing import Any, Dict, List, Optional
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from utils.logger import log


@dataclass
class ReportConfig:
    """报告配置"""
    title: str = "安全测试报告"
    author: str = "AI Hacking Agent"
    company: str = ""
    target: str = ""
    task_type: str = ""
    include_technical_details: bool = True
    include_remediation: bool = True
    include_appendix: bool = True
    logo_path: str = ""


class ReportExporter:
    """专业报告导出器"""

    # 风险评级矩阵
    SEVERITY_MATRIX = {
        "critical": {"color": "#8B0000", "label": "严重", "score": 9.0, "description": "可直接获取系统控制权或敏感数据，需立即修复"},
        "high": {"color": "#FF4500", "label": "高危", "score": 7.0, "description": "可获取重要数据或执行关键操作，需尽快修复"},
        "medium": {"color": "#FFA500", "label": "中危", "score": 5.0, "description": "存在一定安全风险，建议计划修复"},
        "low": {"color": "#FFD700", "label": "低危", "score": 3.0, "description": "安全隐患较小，可择机修复"},
        "info": {"color": "#87CEEB", "label": "信息", "score": 1.0, "description": "安全相关信息，无需修复"},
    }

    def __init__(self, output_dir: str = "reports"):
        """初始化ReportExporter实例。

        Args:
            self: 类实例。
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        log.info(f"报告导出器初始化，输出目录: {self.output_dir}")

    def generate_report(self, data: Dict, config: Optional[ReportConfig] = None) -> Dict[str, str]:
        """
        生成多格式报告
        返回: {格式: 文件路径}
        """
        config = config or ReportConfig()
        report_id = f"report_{int(time.time())}"
        results = {}

        # 生成各格式
        results["markdown"] = self._generate_markdown(data, config, report_id)
        results["html"] = self._generate_html(data, config, report_id)
        results["json"] = self._generate_json(data, config, report_id)

        log.info(f"报告已生成: {report_id}, 格式: {list(results.keys())}")
        return results

    def _generate_markdown(self, data: Dict, config: ReportConfig, report_id: str) -> str:
        """生成Markdown报告"""
        findings = data.get("findings", [])
        if isinstance(findings, dict):
            findings = [findings]

        md = []
        md.append(f"# {config.title}")
        md.append("")
        md.append(f"**报告编号**: {report_id}")
        md.append(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md.append(f"**测试目标**: {config.target or data.get('target', 'N/A')}")
        md.append(f"**测试类型**: {config.task_type or data.get('task_type', 'N/A')}")
        md.append(f"**报告作者**: {config.author}")
        md.append("")
        md.append("---")
        md.append("")

        # 执行摘要
        md.append("## 1. 执行摘要")
        md.append("")
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        md.append(f"本次安全测试共发现 **{len(findings)}** 个安全问题：")
        md.append("")
        md.append("| 严重程度 | 数量 |")
        md.append("|----------|------|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            md.append(f"| {self.SEVERITY_MATRIX[sev]['label']} | {severity_counts[sev]} |")
        md.append("")

        # 漏洞详情
        if findings and config.include_technical_details:
            md.append("## 2. 漏洞详情")
            md.append("")
            for i, finding in enumerate(findings, 1):
                sev = finding.get("severity", "info").lower()
                sev_info = self.SEVERITY_MATRIX.get(sev, self.SEVERITY_MATRIX["info"])
                md.append(f"### {i}. {finding.get('title', '未命名漏洞')}")
                md.append("")
                md.append(f"- **严重程度**: {sev_info['label']} ({sev_info['score']}/10)")
                md.append(f"- **漏洞类型**: {finding.get('type', 'N/A')}")
                md.append(f"- **目标地址**: {finding.get('target', 'N/A')}")
                md.append(f"- **发现工具**: {finding.get('tool', 'N/A')}")
                md.append(f"- **置信度**: {finding.get('confidence', 0):.2f}")
                md.append("")
                if finding.get("description"):
                    md.append(f"**描述**: {finding['description']}")
                    md.append("")
                if finding.get("evidence"):
                    md.append(f"**证据**:")
                    md.append("```")
                    md.append(str(finding["evidence"])[:500])
                    md.append("```")
                    md.append("")
                if config.include_remediation and finding.get("recommendations"):
                    md.append("**修复建议**:")
                    for rec in finding["recommendations"]:
                        md.append(f"- {rec}")
                    md.append("")
                md.append("---")
                md.append("")

        # 修复建议汇总
        if config.include_remediation:
            md.append("## 3. 修复建议汇总")
            md.append("")
            md.append("| 优先级 | 漏洞 | 建议修复时间 |")
            md.append("|--------|------|-------------|")
            for i, finding in enumerate(findings, 1):
                sev = finding.get("severity", "info").lower()
                timeline = {"critical": "立即", "high": "24小时内", "medium": "1周内", "low": "1个月内", "info": "无需"}
                md.append(f"| {self.SEVERITY_MATRIX.get(sev, {}).get('label', '信息')} | {finding.get('title', '')} | {timeline.get(sev, '择机')} |")
            md.append("")

        # 附录
        if config.include_appendix:
            md.append("## 4. 附录")
            md.append("")
            md.append("### 4.1 测试工具")
            md.append("- AI Hacking Agent v4.0")
            md.append("- 34个MCP安全工具")
            md.append("- ReAct推理引擎")
            md.append("- RAG知识库增强")
            md.append("")
            md.append("### 4.2 免责声明")
            md.append("本报告仅供授权安全测试使用，未经授权的测试属于违法行为。")
            md.append("")

        # 保存文件
        filepath = self.output_dir / f"{report_id}.md"
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(md))
        return str(filepath)

    def _generate_html(self, data: Dict, config: ReportConfig, report_id: str) -> str:
        """生成HTML报告"""
        # 简单HTML包装Markdown内容
        md_path = self.output_dir / f"{report_id}.md"
        if md_path.exists():
            with open(md_path, "r", encoding="utf-8") as f:
                md_content = f.read()
        else:
            md_content = "报告内容生成中..."

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{config.title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 40px 20px; line-height: 1.6; color: #333; }}
        h1 {{ color: #1a1a1a; border-bottom: 3px solid #0066cc; padding-bottom: 10px; }}
        h2 {{ color: #0066cc; margin-top: 30px; }}
        h3 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th {{ background-color: #f5f5f5; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }}
        pre {{ background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .critical {{ color: #8B0000; font-weight: bold; }}
        .high {{ color: #FF4500; font-weight: bold; }}
        .medium {{ color: #FFA500; font-weight: bold; }}
        .low {{ color: #FFD700; }}
        .footer {{ margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div id="content">
        <pre style="white-space: pre-wrap; word-wrap: break-word; background: none; border: none;">{md_content}</pre>
    </div>
    <div class="footer">
        <p>由 AI Hacking Agent v4.0 自动生成 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
</body>
</html>"""

        filepath = self.output_dir / f"{report_id}.html"
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        return str(filepath)

    def _generate_json(self, data: Dict, config: ReportConfig, report_id: str) -> str:
        """生成JSON报告"""
        report_data = {
            "report_id": report_id,
            "title": config.title,
            "generated_at": datetime.now().isoformat(),
            "target": config.target or data.get("target", ""),
            "task_type": config.task_type or data.get("task_type", ""),
            "author": config.author,
            "summary": {
                "total_findings": len(data.get("findings", [])),
            },
            "findings": data.get("findings", []),
            "raw_data": data,
        }

        filepath = self.output_dir / f"{report_id}.json"
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2, default=str)
        return str(filepath)

    def list_reports(self) -> List[Dict]:
        """列出所有报告"""
        reports = []
        for f in self.output_dir.glob("report_*"):
            reports.append({
                "filename": f.name,
                "size": f.stat().st_size,
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
            })
        return sorted(reports, key=lambda x: x["modified"], reverse=True)


# 全局报告导出器实例
report_exporter = ReportExporter()
