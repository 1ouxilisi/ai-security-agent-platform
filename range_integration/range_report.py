# -*- coding: utf-8 -*-
"""
range_report.py - 靶场报告生成模块

生成 6 类报告：
- 靶场评估报告
- 漏洞利用报告
- 学习路径报告
- 对比分析报告
- 合规映射报告
- 教练反馈报告

全部内存字典模拟，无文件 I/O。
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

NOTICE = "报告仅用于授权安全测试与教学评估。"


def _clean(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, str):
        return "".join(ch for ch in obj if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    return obj


# ----------------------------------------------------------------------
# 合规映射数据
# ----------------------------------------------------------------------
COMPLIANCE_FRAMEWORKS = {
    "owasp_top10_2021": {
        "name": "OWASP Top 10 (2021)",
        "clauses": [
            {"id": "A01", "name": "失效的访问控制", "related_vulns": ["IDOR", "越权"]},
            {"id": "A02", "name": "加密机制失效", "related_vulns": ["敏感信息泄露"]},
            {"id": "A03", "name": "注入", "related_vulns": ["SQL注入", "XSS", "命令注入"]},
            {"id": "A04", "name": "不安全设计", "related_vulns": ["业务逻辑缺陷"]},
            {"id": "A05", "name": "安全配置错误", "related_vulns": ["配置错误", "目录列表"]},
            {"id": "A06", "name": "脆弱和过时的组件", "related_vulns": ["过时依赖"]},
            {"id": "A07", "name": "身份识别和认证失败", "related_vulns": ["弱口令", "会话缺陷"]},
            {"id": "A08", "name": "软件和数据完整性故障", "related_vulns": ["反序列化"]},
            {"id": "A09", "name": "安全日志和监控失败", "related_vulns": ["日志缺失"]},
            {"id": "A10", "name": "服务器端请求伪造", "related_vulns": ["SSRF"]},
        ],
    },
    "iso27001": {
        "name": "ISO 27001:2022",
        "clauses": [
            {"id": "A.8.1", "name": "用户终端设备", "related_vulns": ["终端安全"]},
            {"id": "A.8.2", "name": "特权访问权限", "related_vulns": ["权限提升"]},
            {"id": "A.8.8", "name": "技术脆弱性管理", "related_vulns": ["已知漏洞"]},
            {"id": "A.8.9", "name": "配置管理", "related_vulns": ["配置错误"]},
            {"id": "A.8.15", "name": "开发和测试设施", "related_vulns": ["测试环境"]},
        ],
    },
    "等保2.0": {
        "name": "网络安全等级保护 2.0",
        "clauses": [
            {"id": "安全计算环境", "name": "身份鉴别", "related_vulns": ["弱口令"]},
            {"id": "安全计算环境", "name": "访问控制", "related_vulns": ["越权", "IDOR"]},
            {"id": "安全计算环境", "name": "安全审计", "related_vulns": ["日志缺失"]},
            {"id": "安全区域边界", "name": "边界防护", "related_vulns": ["网络暴露"]},
        ],
    },
}


# ======================================================================
# RangeReportGenerator
# ======================================================================
class RangeReportGenerator:
    """报告生成器。"""

    def __init__(self) -> None:
        self._reports: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # 1. 靶场评估报告
    # ------------------------------------------------------------------
    def evaluation_report(self, range_id: str, instance_id: str,
                          scan_summary: Optional[Dict] = None) -> Dict[str, Any]:
        rid = f"rpt_{uuid.uuid4().hex[:8]}"
        report = {
            "report_id": rid,
            "report_type": "靶场评估报告",
            "range_id": range_id,
            "instance_id": instance_id,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "range_info": {
                "id": range_id,
                "name": range_id,
                "assessment": "完整评估",
            },
            "scan_summary": scan_summary or {
                "total_vulns": 8, "critical": 2, "high": 3, "medium": 2, "low": 1,
            },
            "vuln_list": [
                {"name": "SQL 注入", "severity": "高危", "verified": True,
                 "fix": "使用参数化查询"},
                {"name": "XSS 跨站脚本", "severity": "中危", "verified": True,
                 "fix": "输入验证+输出编码"},
                {"name": "任意文件上传", "severity": "严重", "verified": False,
                 "fix": "白名单校验+文件重命名"},
            ],
            "risk_rating": "中高风险",
            "fix_suggestions": [
                "1. 立即修复严重级别的文件上传漏洞",
                "2. 对所有用户输入进行参数化处理",
                "3. 实施 CSP 策略缓解 XSS",
            ],
            "notice": NOTICE,
        }
        self._reports[rid] = report
        return {"success": True, "report": report}

    # ------------------------------------------------------------------
    # 2. 漏洞利用报告
    # ------------------------------------------------------------------
    def exploitation_report(self, range_id: str, vuln_name: str,
                            steps: List[str]) -> Dict[str, Any]:
        rid = f"rpt_{uuid.uuid4().hex[:8]}"
        report = {
            "report_id": rid,
            "report_type": "漏洞利用报告",
            "range_id": range_id,
            "vuln_name": vuln_name,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "exploit_steps": steps,
            "result": "成功验证（检测性）",
            "data_obtained": "敏感数据已确认存在（不展示具体内容）",
            "privilege_level": "已确认可获取普通用户权限",
            "lateral_movement": "未测试横向移动",
            "impact_scope": "Web 应用层面",
            "notice": NOTICE,
        }
        self._reports[rid] = report
        return {"success": True, "report": report}

    # ------------------------------------------------------------------
    # 3. 学习路径报告
    # ------------------------------------------------------------------
    def learning_path_report(self, user_id: str = "default") -> Dict[str, Any]:
        rid = f"rpt_{uuid.uuid4().hex[:8]}"
        report = {
            "report_id": rid,
            "report_type": "学习路径报告",
            "user_id": user_id,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "learning_objectives": [
                "掌握 OWASP Top 10 漏洞原理",
                "熟练使用常用安全工具",
                "能够独立完成漏洞复现",
                "理解漏洞修复方案",
            ],
            "progress": {
                "web_basics": {"completed": 60, "status": "进行中"},
                "web_advanced": {"completed": 20, "status": "未开始"},
                "system_pentest": {"completed": 0, "status": "未开始"},
            },
            "mastered_skills": ["SQL注入基础", "XSS基础", "端口扫描"],
            "need_improvement": ["命令注入", "反序列化", "权限提升"],
            "recommended_next": ["完成 DVWA High 难度 SQL 注入",
                                 "练习 Juice Shop 前 10 个挑战"],
            "practice_suggestions": [
                "每日完成 2 个靶场练习",
                "每周进行 1 次综合测试",
            ],
        }
        self._reports[rid] = report
        return {"success": True, "report": report}

    # ------------------------------------------------------------------
    # 4. 对比分析报告
    # ------------------------------------------------------------------
    def comparison_report(self, type_: str = "scan",
                          items: Optional[List[str]] = None) -> Dict[str, Any]:
        rid = f"rpt_{uuid.uuid4().hex[:8]}"
        report = {
            "report_id": rid,
            "report_type": "对比分析报告",
            "comparison_type": type_,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "items": items or [],
            "analysis": {
                "trend": "整体漏洞数量呈下降趋势",
                "new_findings": 2,
                "fixed_findings": 5,
                "improvement_rate": 62.5,
            },
            "progress_chart": [
                {"month": "1月", "vulns": 15},
                {"month": "2月", "vulns": 12},
                {"month": "3月", "vulns": 8},
                {"month": "4月", "vulns": 6},
            ],
        }
        self._reports[rid] = report
        return {"success": True, "report": report}

    # ------------------------------------------------------------------
    # 5. 合规映射报告
    # ------------------------------------------------------------------
    def compliance_report(self, framework: str = "owasp_top10_2021") -> Dict[str, Any]:
        fw = COMPLIANCE_FRAMEWORKS.get(framework, COMPLIANCE_FRAMEWORKS["owasp_top10_2021"])
        rid = f"rpt_{uuid.uuid4().hex[:8]}"

        mappings = []
        for clause in fw["clauses"]:
            mappings.append({
                "clause_id": clause["id"],
                "clause_name": clause["name"],
                "related_vulns": clause["related_vulns"],
                "coverage": "已覆盖" if len(clause["related_vulns"]) > 1 else "部分覆盖",
                "violations": max(0, len(clause["related_vulns"]) - 1),
            })

        report = {
            "report_id": rid,
            "report_type": "合规映射报告",
            "framework": fw["name"],
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_clauses": len(fw["clauses"]),
            "covered": sum(1 for m in mappings if m["coverage"] == "已覆盖"),
            "partially_covered": sum(1 for m in mappings if m["coverage"] == "部分覆盖"),
            "mappings": mappings,
            "score": 72,
            "trend": "较上月提升 5%",
        }
        self._reports[rid] = report
        return {"success": True, "report": report}

    # ------------------------------------------------------------------
    # 6. 教练反馈报告
    # ------------------------------------------------------------------
    def coach_feedback_report(self, user_id: str = "default",
                              session_data: Optional[Dict] = None) -> Dict[str, Any]:
        rid = f"rpt_{uuid.uuid4().hex[:8]}"
        report = {
            "report_id": rid,
            "report_type": "教练反馈报告",
            "user_id": user_id,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "operation_records": [
                {"step": 1, "action": "打开 DVWA", "result": "成功"},
                {"step": 2, "action": "尝试 SQL 注入", "result": "成功（Low难度）"},
                {"step": 3, "action": "尝试 XSS", "result": "未成功，建议练习输出编码"},
            ],
            "step_analysis": "信息收集步骤完整，但漏洞验证时缺少 Payload 变体测试",
            "error_analysis": [
                "XSS 测试时未尝试事件型 XSS（onerror 等）",
                "SQL 注入未测试时间盲注",
            ],
            "best_practice_comparison": "与标准操作流程相比，缺少自动化工具辅助环节",
            "improvement_suggestions": [
                "1. 学习 Burp Suite 的 Repeater 功能",
                "2. 练习盲注技巧",
                "3. 了解 WAF 绕过基本方法",
            ],
            "skill_assessment": {
                "reconnaissance": 70,
                "web_exploitation": 55,
                "post_exploitation": 30,
            },
            "growth_trajectory": "本月评分从 45 提升至 52，进步明显",
        }
        self._reports[rid] = report
        return {"success": True, "report": report}

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def list_reports(self) -> List[Dict[str, Any]]:
        return list(self._reports.values())

    def get_report(self, report_id: str) -> Dict[str, Any]:
        r = self._reports.get(report_id)
        if not r:
            return {"success": False, "error": "报告不存在"}
        return {"success": True, "report": r}


_generator: Optional[RangeReportGenerator] = None


def get_report_generator() -> RangeReportGenerator:
    global _generator
    if _generator is None:
        _generator = RangeReportGenerator()
    return _generator
