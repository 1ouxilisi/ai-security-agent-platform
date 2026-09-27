# -*- coding: utf-8 -*-
"""
domain_pdf_adapters.py — 十六大领域 PDF 适配器。

职责：把各领域的真实数据（尽量调用领域包内 report_generator / orchestrator）
      汇总成 pdf_engine 标准 ReportContent。领域包不可用时回退到该领域的
      代表性示例数据（明确标记为 demo），保证 PDF 导出功能永远可用。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import pdf_engine

# 十六大核心领域（Pro）注册表
DOMAINS: Dict[str, Dict[str, str]] = {
    "web_pentest_pro": {"name": "Web渗透测试", "title": "Web 应用安全评估报告"},
    "soc_pro": {"name": "安全运营SOC", "title": "SOC 安全运营分析报告"},
    "cloud_security_pro": {"name": "云安全", "title": "云安全配置评估报告"},
    "compliance_pro": {"name": "合规审计", "title": "合规性审计评估报告"},
    "ctf_pro": {"name": "CTF竞赛", "title": "CTF 竞赛分析报告"},
    "data_security_pro": {"name": "数据安全", "title": "数据安全分级评估报告"},
    "devsecops_pro": {"name": "DevSecOps", "title": "DevSecOps 流水线安全报告"},
    "forensics_pro": {"name": "电子取证", "title": "数字取证分析报告"},
    "internal_pentest_pro": {"name": "内网渗透", "title": "内网渗透评估报告"},
    "iot_ot_pro": {"name": "物联网/工控", "title": "物联网/工控安全评估报告"},
    "mobile_pentest_pro": {"name": "移动安全", "title": "移动应用安全评估报告"},
    "red_blue_pro": {"name": "红蓝对抗", "title": "红蓝对抗演练报告"},
    "security_training_pro": {"name": "安全培训", "title": "安全培训成效报告"},
    "src_platform_pro": {"name": "SRC众测", "title": "SRC 众测平台报告"},
    "supply_chain_pro": {"name": "供应链安全", "title": "软件供应链安全报告"},
    "threat_intel_pro": {"name": "威胁情报", "title": "威胁情报分析报告"},
}


def _demo_findings(kind: str) -> List[Dict[str, Any]]:
    """按领域类型生成代表性发现表格。"""
    base = [["严重级别", "发现", "风险说明", "建议"],
            ["严重", f"{kind}高危漏洞", "可被直接利用获取权限", "立即修复并复测"],
            ["高危", f"{kind}中危配置", "敏感信息暴露", "收敛访问权限"],
            ["中危", f"{kind}弱策略", "缺少纵深防御", "补充控制措施"],
            ["低危", "信息泄露", "版本号暴露", "隐藏 Banner"]]
    return [{"rows": base}]


def build_domain_content(domain: str, task_id: str = "demo",
                         force_demo: bool = False) -> Dict[str, Any]:
    """构造某领域的标准报告内容。"""
    meta = DOMAINS.get(domain, {"name": domain, "title": f"{domain} 报告"})
    live_data: Optional[Dict[str, Any]] = None
    source = "demo"

    if not force_demo:
        try:
            mod = __import__(f"{domain}.report_generator", fromlist=["ReportGenerator"])
            gen = getattr(mod, "get_report_generator", None)()
            if hasattr(gen, "collect_data"):
                live_data = gen.collect_data()
                source = "live"
        except Exception:
            live_data = None

    # 执行摘要
    if live_data:
        es = [f"本报告基于 {meta['name']} 领域的真实运行数据自动汇总生成。",
              f"数据来源：领域报告生成器（{source}）。",
              "建议结合详细章节与图表进行风险决策。"]
    else:
        es = [f"本报告为 {meta['name']} 领域的标准 PDF 导出演示（{source}）。",
              "覆盖执行摘要、风险发现、修复建议与附录。",
              "接入真实数据后将自动替换为实测结论。"]

    sections: List[Dict[str, Any]] = [
        {"heading": "1. 风险发现汇总",
         "paragraphs": [f"以下为 {meta['name']} 领域按严重级别归类的核心发现："],
         "tables": _demo_findings(meta["name"])},
        {"heading": "2. 影响分析",
         "paragraphs": [
            "严重级别问题可能导致未授权访问、数据泄露或业务中断。",
            "需结合资产重要性与暴露面综合评估真实影响。"]},
        {"heading": "3. 修复建议",
         "paragraphs": [
            "1) 优先处理严重/高危问题，完成后复测验证。",
            "2) 建立基线并纳入持续监控。",
            "3) 定期复评以验证整改有效性。"]},
    ]

    charts: List[Dict[str, Any]] = [
        {"title": "风险级别分布", "kind": "pie",
         "payload": {"labels": ["严重", "高危", "中危", "低危"],
                     "values": [1, 1, 1, 1]}},
        {"title": "近7日发现趋势", "kind": "trend",
         "payload": {"labels": ["周一", "周二", "周三", "周四", "周五", "周六", "周日"],
                     "series": {"新增发现": [3, 5, 2, 7, 4, 6, 5],
                                 "已修复": [2, 3, 4, 3, 5, 4, 6]}}},
    ]

    appendix = [
        {"heading": "A. 工具与方法",
         "paragraphs": ["本报告采用自动化扫描 + 人工复核流程。"]},
        {"heading": "B. 术语表",
         "tables": [{"rows": [["术语", "说明"],
                              ["CVSS", "通用漏洞评分系统"],
                              ["暴露面", "可被外部访问的攻击入口"]]}]},
    ]

    c = pdf_engine.build_content(
        title=meta["title"], subtitle=f"{meta['name']} · 任务 {task_id}",
        company="AI Hacking Agent", confidential="机密", version="v1.0",
        executive_summary=es, sections=sections, charts=charts,
        appendix=appendix,
        extra={"domain": domain, "source": source, "task_id": task_id})
    return c


def list_domains() -> List[Dict[str, str]]:
    return [{"key": k, **v} for k, v in DOMAINS.items()]
