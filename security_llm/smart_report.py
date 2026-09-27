#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
smart_report.py — 安全报告智能生成（第26轮升级方向1）。

六大能力：
    1. 报告规划：大纲生成/章节编排/受众定制
    2. 内容生成：风险发现/修复建议/ executive summary
    3. 报告优化：语言润色/结构调整/图表建议
    4. 报告审核：合规检查/数据校验/一致性校验
    5. 报告版本：版本管理/对比/回滚
    6. 报告模板：模板库/自定义模板/导出

全部内存字典模拟，仅用于授权安全场景。
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _gen_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


# 内置报告模板
_REPORT_TEMPLATES: List[Dict[str, Any]] = [
    {"id": "tpl-exec", "name": "高管摘要版", "audience": "管理层",
     "sections": ["执行摘要", "关键风险", "投入建议", "路线图"],
     "style": "简洁、量化、决策导向"},
    {"id": "tpl-tech", "name": "技术详细版", "audience": "技术团队",
     "sections": ["测试范围", "漏洞详情", "复现步骤", "修复方案", "复测计划"],
     "style": "专业、详细、可操作"},
    {"id": "tpl-compliance", "name": "合规审计版", "audience": "审计/监管",
     "sections": ["合规依据", "控制项矩阵", "差距分析", "整改计划", "证据清单"],
     "style": "严谨、规范、证据充分"},
]


class SmartReport:
    """安全报告智能生成。"""

    def __init__(self) -> None:
        self.reports: Dict[str, Dict[str, Any]] = {}
        self.versions: Dict[str, List[Dict[str, Any]]] = {}
        self.templates: List[Dict[str, Any]] = list(_REPORT_TEMPLATES)

    # ==================== 1. 报告规划 ====================
    def plan(self, title: str, target: str, audience: str = "tech",
             findings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        findings = findings or [
            {"name": "SQL注入", "severity": "critical", "location": "/api/login"},
            {"name": "XSS", "severity": "high", "location": "/comment"},
            {"name": "弱TLS", "severity": "medium", "location": "443"},
        ]
        # 选择模板
        tpl = next((t for t in self.templates if audience in t["audience"] or audience in t["id"]),
                   self.templates[1])
        outline = [
            {"section": s, "key_points": [
                f"针对{target}的{len(findings)}项发现",
                "风险量化与影响评估",
            ]}
            for s in tpl["sections"]
        ]
        plan_id = _gen_id("plan")
        return {
            "id": plan_id, "title": title, "target": target,
            "audience": audience, "template": tpl["name"],
            "outline": outline, "finding_count": len(findings),
            "estimated_pages": max(4, len(findings) * 2),
            "ts": _now(),
        }

    # ==================== 2. 内容生成 ====================
    def generate(self, title: str, target: str,
                 findings: Optional[List[Dict[str, Any]]] = None,
                 template_id: str = "tpl-tech") -> Dict[str, Any]:
        findings = findings or [
            {"name": "SQL注入", "severity": "critical", "location": "/api/login",
             "desc": "登录接口未使用参数化查询，存在SQL注入", "fix": "改用预编译语句"},
            {"name": "XSS", "severity": "high", "location": "/comment",
             "desc": "评论区未过滤用户输入，可注入脚本", "fix": "输出编码+CSP"},
            {"name": "弱TLS", "severity": "medium", "location": "443",
             "desc": "支持TLS1.0及弱加密套件", "fix": "禁用TLS1.0/1.1，启用TLS1.2+"},
        ]
        tpl = next((t for t in self.templates if t["id"] == template_id), self.templates[1])
        # 统计风险分布
        sev_count: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev_count[f.get("severity", "low")] = sev_count.get(f.get("severity", "low"), 0) + 1

        report_id = _gen_id("rpt")
        content = self._build_content(title, target, findings, sev_count, tpl)
        report = {
            "id": report_id, "title": title, "target": target,
            "template_id": template_id, "template_name": tpl["name"],
            "content": content, "findings": findings,
            "severity_dist": sev_count, "pages": max(4, len(findings) * 2 + 2),
            "status": "draft", "version": "v1.0", "created_at": _now(),
        }
        self.reports[report_id] = report
        self.versions[report_id] = [{
            "version": "v1.0", "content_hash": hash(content),
            "ts": _now(), "note": "初稿",
        }]
        return report

    def _build_content(self, title: str, target: str,
                        findings: List[Dict[str, Any]],
                        sev: Dict[str, int], tpl: Dict[str, Any]) -> str:
        lines = [f"# {title}", f"\n目标：{target}\n",
                 f"模板：{tpl['name']}（受众：{tpl['audience']}）\n"]
        lines.append("## 一、执行摘要")
        lines.append(
            f"本次安全评估共发现 {len(findings)} 项问题，其中严重 {sev.get('critical', 0)} 项、"
            f"高危 {sev.get('high', 0)} 项、中危 {sev.get('medium', 0)} 项。"
            f"建议立即修复严重及高危问题，并在 30 天内完成中危整改。\n"
        )
        lines.append("## 二、风险发现详情")
        for i, f in enumerate(findings, 1):
            lines.append(f"### {i}. [{f.get('severity', 'medium').upper()}] {f.get('name', '未知')}")
            lines.append(f"- 位置：{f.get('location', 'N/A')}")
            lines.append(f"- 描述：{f.get('desc', '详见技术附件')}")
            lines.append(f"- 修复建议：{f.get('fix', '参考最佳实践')}\n")
        lines.append("## 三、修复优先级路线图")
        lines.append("- 0-7天：修复严重级问题（SQL注入、远程代码执行）")
        lines.append("- 8-30天：修复高危问题（XSS、越权访问）")
        lines.append("- 31-90天：修复中低危问题并完成复测\n")
        lines.append("## 四、附录")
        lines.append("- 测试时间窗口：见工单")
        lines.append("- 测试工具：Nmap、Nuclei、Burp Suite")
        lines.append(f"- 报告生成时间：{_now()}")
        return "\n".join(lines)

    def list_reports(self) -> List[Dict[str, Any]]:
        return list(self.reports.values())

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        return self.reports.get(report_id)

    # ==================== 3. 报告优化 ====================
    def optimize(self, report_id: str) -> Dict[str, Any]:
        rpt = self.reports.get(report_id)
        if not rpt:
            raise ValueError(f"报告不存在: {report_id}")
        content = rpt["content"]
        suggestions = [
            "增加风险趋势对比图（环比上月）",
            "补充财务影响估算（按业务中断时长）",
            "增加控制项成熟度评分",
            "附录补充日志证据哈希",
        ]
        optimized = content + "\n\n## 优化建议补充\n" + "\n".join(f"- {s}" for s in suggestions)
        new_ver = f"v{float(rpt['version'][1:]) + 0.1:.1f}"
        rpt["content"] = optimized
        rpt["version"] = new_ver
        rpt["status"] = "optimized"
        self.versions.setdefault(report_id, []).append({
            "version": new_ver, "content_hash": hash(optimized),
            "ts": _now(), "note": "AI优化",
        })
        return {"id": report_id, "version": new_ver, "suggestions": suggestions, "ts": _now()}

    # ==================== 4. 报告审核 ====================
    def audit(self, report_id: str) -> Dict[str, Any]:
        rpt = self.reports.get(report_id)
        if not rpt:
            raise ValueError(f"报告不存在: {report_id}")
        issues: List[str] = []
        # 合规检查
        if "执行摘要" not in rpt["content"]:
            issues.append("缺少执行摘要")
        if not rpt.get("findings"):
            issues.append("无具体发现项")
        if rpt["severity_dist"].get("critical", 0) > 0 and "立即" not in rpt["content"]:
            issues.append("存在严重漏洞但未强调立即修复")
        score = 100 - len(issues) * 10
        return {
            "id": _gen_id("audit"), "report_id": report_id,
            "passed": len(issues) == 0, "issues": issues,
            "score": max(0, score), "ts": _now(),
        }

    # ==================== 5. 报告版本 ====================
    def list_versions(self, report_id: str) -> List[Dict[str, Any]]:
        return self.versions.get(report_id, [])

    def rollback(self, report_id: str, version: str) -> Dict[str, Any]:
        versions = self.versions.get(report_id, [])
        target = next((v for v in versions if v["version"] == version), None)
        if not target:
            raise ValueError(f"版本不存在: {version}")
        rpt = self.reports.get(report_id)
        rpt["version"] = version
        rpt["status"] = f"rolled-back-to-{version}"
        return {"id": report_id, "rolled_back_to": version, "ts": _now()}

    # ==================== 6. 报告模板 ====================
    def list_templates(self) -> List[Dict[str, Any]]:
        return self.templates

    def add_template(self, name: str, audience: str,
                     sections: List[str], style: str) -> Dict[str, Any]:
        tpl = {
            "id": _gen_id("tpl"), "name": name, "audience": audience,
            "sections": sections, "style": style, "created_at": _now(),
        }
        self.templates.append(tpl)
        return tpl


# 单例
smart_report = SmartReport()
