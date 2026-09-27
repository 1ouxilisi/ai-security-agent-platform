# -*- coding: utf-8 -*-
"""compliance_report.py — 一键生成等保2.0 / ISO27001 合规报告。

报告结构:
  合规项 / 符合情况 / 不符合项 / 整改建议
导出 HTML / PDF(基于 HTML，浏览器打印) / JSON。
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# 等保2.0 三级 主要控制项（节选映射）
MLPS20_ITEMS = [
    {"id": "MLPS-8.1.1", "domain": "安全物理环境", "control": "机房选址与物理访问控制",
     "status": "partial", "evidence": "云端部署，物理安全由云厂商承担",
     "advice": "补充云厂商等保备案证明与物理安全责任共担说明"},
    {"id": "MLPS-8.1.4", "domain": "安全通信网络", "control": "通信传输加密 / 完整性",
     "status": "pass", "evidence": "全链路 HTTPS + TLS1.2+", "advice": ""},
    {"id": "MLPS-8.1.5", "domain": "安全区域边界", "control": "边界访问控制 / 入侵防范",
     "status": "pass", "evidence": "API 网关限流 + WAF 规则", "advice": ""},
    {"id": "MLPS-8.1.4.1", "domain": "安全计算环境", "control": "身份鉴别（多因子）",
     "status": "fail", "evidence": "当前仅静态口令", "advice": "接入 MFA / 证书登录"},
    {"id": "MLPS-8.1.4.2", "domain": "安全计算环境", "control": "访问控制（最小权限）",
     "status": "pass", "evidence": "RBAC 四角色，功能+数据权限", "advice": ""},
    {"id": "MLPS-8.1.4.3", "domain": "安全计算环境", "control": "安全审计（不可篡改）",
     "status": "pass", "evidence": "审计日志追加写，支持筛选导出", "advice": ""},
    {"id": "MLPS-8.1.4.4", "domain": "安全计算环境", "control": "数据保密性 / 备份恢复",
     "status": "pass", "evidence": "敏感字段 AES-256-GCM 加密；定时备份", "advice": ""},
    {"id": "MLPS-8.1.4.5", "domain": "安全计算环境", "control": "剩余信息保护 / 个人信息保护",
     "status": "partial", "evidence": "凭据库不落明文，但日志含操作详情",
     "advice": "审计日志中脱敏高敏字段"},
    {"id": "MLPS-8.1.3", "domain": "安全管理中心", "control": "系统管理 / 审计管理 / 安全管理三权分立",
     "status": "pass", "evidence": "管理员/审计员角色分离", "advice": ""},
    {"id": "MLPS-8.1.10", "domain": "安全运维管理", "control": "漏洞和风险管理 / 应急预案",
     "status": "partial", "evidence": "具备漏洞扫描与基线检查",
     "advice": "补充定期演练记录与应急预案文档"},
]

# ISO27001:2022 Annex A 主要控制项
ISO27001_ITEMS = [
    {"id": "A.5.1", "domain": "组织控制", "control": "信息安全策略",
     "status": "pass", "evidence": "安全策略已文档化并审批", "advice": ""},
    {"id": "A.5.15", "domain": "组织控制", "control": "访问控制",
     "status": "pass", "evidence": "RBAC + 最小权限", "advice": ""},
    {"id": "A.5.16", "domain": "组织控制", "control": "身份管理",
     "status": "partial", "evidence": "账号生命周期管理",
     "advice": "定期审阅账号并回收离职权限"},
    {"id": "A.5.17", "domain": "组织控制", "control": "鉴别信息",
     "status": "fail", "evidence": "口令策略已定义但未强制 MFA",
     "advice": "为管理员账号强制 MFA"},
    {"id": "A.8.2", "domain": "技术控制", "control": "特权访问权限",
     "status": "pass", "evidence": "管理员与分析师权限分离", "advice": ""},
    {"id": "A.8.5", "domain": "技术控制", "control": "安全认证",
     "status": "pass", "evidence": "TLS 传输 + AES-256 存储", "advice": ""},
    {"id": "A.8.11", "domain": "技术控制", "control": "脱敏数据",
     "status": "partial", "evidence": "凭据脱敏展示", "advice": "扩展至日志/报表脱敏"},
    {"id": "A.8.15", "domain": "技术控制", "control": "日志",
     "status": "pass", "evidence": "操作审计全量记录", "advice": ""},
    {"id": "A.8.20", "domain": "技术控制", "control": "网络安全",
     "status": "pass", "evidence": "WAF / 网关限流 / 安全响应头", "advice": ""},
    {"id": "A.8.28", "domain": "技术控制", "control": "安全编码",
     "status": "pass", "evidence": "防 SQLi/XSS 输入校验", "advice": ""},
]


class ComplianceReportGenerator:
    """合规报告生成器（内存存储）。"""

    def __init__(self) -> None:
        self._reports: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ #
    def _assess(self, framework: str) -> Dict[str, Any]:
        items = list(MLPS20_ITEMS if framework == "mlps2" else ISO27001_ITEMS)
        passed = sum(1 for i in items if i["status"] == "pass")
        partial = sum(1 for i in items if i["status"] == "partial")
        failed = sum(1 for i in items if i["status"] == "fail")
        total = len(items)
        # 符合率: pass 计 1，partial 计 0.5
        score = round((passed + 0.5 * partial) / total * 100, 1) if total else 0.0
        gaps = [i for i in items if i["status"] != "pass"]
        level = "基本符合" if score >= 90 else ("部分符合" if score >= 70 else "不符合")
        return {
            "framework": framework,
            "framework_name": "网络安全等级保护2.0（三级）" if framework == "mlps2"
                              else "ISO/IEC 27001:2022",
            "total": total, "passed": passed,
            "partial": partial, "failed": failed,
            "score": score, "level": level,
            "items": items, "gaps": gaps,
        }

    def generate(self, framework: str = "mlps2") -> Dict[str, Any]:
        if framework not in ("mlps2", "iso27001"):
            raise ValueError("framework 仅支持 mlps2 / iso27001")
        assessment = self._assess(framework)
        report_id = f"COMP-{uuid.uuid4().hex[:10]}"
        report = {
            "report_id": report_id,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            **assessment,
        }
        self._reports[report_id] = report
        return report

    def list_reports(self) -> List[Dict[str, Any]]:
        return [
            {"report_id": r["report_id"], "framework": r["framework"],
             "framework_name": r["framework_name"],
             "score": r["score"], "level": r["level"],
             "generated_at": r["generated_at"],
             "failed": r["failed"], "partial": r["partial"]}
            for r in sorted(self._reports.values(),
                            key=lambda x: x["generated_at"], reverse=True)
        ]

    def get(self, report_id: str) -> Optional[Dict[str, Any]]:
        return self._reports.get(report_id)

    # ------------------------------------------------------------------ #
    def render_html(self, report_id: str) -> str:
        r = self._reports.get(report_id)
        if not r:
            return "<h2>报告不存在</h2>"

        def badge(s: str) -> str:
            return {"pass": '<span style="color:#3fb950">符合</span>',
                    "partial": '<span style="color:#d29922">部分符合</span>',
                    "fail": '<span style="color:#f85149">不符合</span>'}.get(s, s)

        rows = "".join(
            f"<tr><td>{i['id']}</td><td>{i['domain']}</td>"
            f"<td>{i['control']}</td><td>{badge(i['status'])}</td>"
            f"<td>{i['evidence']}</td><td>{i['advice'] or '—'}</td></tr>"
            for i in r["items"]
        )
        return f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>合规报告 {r['report_id']}</title>
<style>body{{font-family:Segoe UI;margin:24px;background:#0d1117;color:#e6edf3}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #30363d;
padding:6px 10px;font-size:12px;text-align:left}}</style></head><body>
<h2>{r['framework_name']} 合规报告</h2>
<p>报告编号: {r['report_id']}　生成时间: {r['generated_at']}</p>
<p>符合率: <b>{r['score']}%</b>　结论: {r['level']}　
   符合 {r['passed']} / 部分 {r['partial']} / 不符合 {r['failed']}</p>
<table><thead><tr><th>编号</th><th>域</th><th>控制项</th><th>符合情况</th>
<th>证据</th><th>整改建议</th></tr></thead><tbody>{rows}</tbody></table>
<p class="muted">导出 PDF: 浏览器 Ctrl+P → 另存为 PDF。</p>
</body></html>"""

    def export(self, report_id: str, fmt: str = "html") -> Dict[str, Any]:
        r = self._reports.get(report_id)
        if not r:
            raise KeyError(f"报告不存在: {report_id}")
        if fmt == "html":
            return {"report_id": report_id, "format": "html",
                    "content": self.render_html(report_id)}
        return {"report_id": report_id, "format": "json", "content": r}
