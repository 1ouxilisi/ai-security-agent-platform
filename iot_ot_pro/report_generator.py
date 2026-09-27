# -*- coding: utf-8 -*-
"""
report_generator.py — 工控IoT 安全报告生成（MD/HTML）。

章节: 执行摘要 / 设备清单 / 协议分析 / 固件分析 / 漏洞详情 /
      配置审计 / 流量监控 / 风险评级 / 合规审计 / 整改建议。
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, Optional

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports", "iot_ot_pro")


class ReportGenerator:
    """工控IoT 安全报告生成器。"""

    def __init__(self) -> None:
        os.makedirs(REPORTS_DIR, exist_ok=True)

    # ------------------------------------------------------------------ #
    def collect_data(self) -> Dict[str, Any]:
        from .device_discovery_phase import get_device_discovery_phase
        from .protocol_analysis_phase import get_protocol_analysis_phase
        from .firmware_analysis_phase import get_firmware_analysis_phase
        from .vuln_detection_phase import get_vuln_detection_phase
        from .config_audit_phase import get_config_audit_phase
        from .traffic_monitor_phase import get_traffic_monitor_phase
        from .risk_rating_phase import get_risk_rating_phase
        from .compliance_audit_phase import get_compliance_audit_phase
        from .iot_ot_dashboard import get_dashboard
        from .ai_analysis import get_ai_analysis

        return {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "devices": get_device_discovery_phase().list_devices(),
            "protocol": get_protocol_analysis_phase().stats(),
            "firmware": get_firmware_analysis_phase().stats(),
            "vulns": get_vuln_detection_phase().stats(),
            "config": get_config_audit_phase().stats(),
            "traffic": get_traffic_monitor_phase().stats(),
            "risk": get_risk_rating_phase().stats(),
            "compliance": get_compliance_audit_phase().summary(),
            "dashboard": get_dashboard().overview(),
            "ai": get_ai_analysis().history(5),
        }

    # ------------------------------------------------------------------ #
    def to_markdown(self, d: Optional[Dict[str, Any]] = None) -> str:
        d = d or self.collect_data()
        lines: List[str] = []
        lines.append("# 工控/IoT 安全评估报告")
        lines.append("")
        lines.append(f"- 生成时间：{d['generated_at']}")
        lines.append("")
        kpi = d["dashboard"]["kpi"]
        lines.append("## 1. 执行摘要")
        lines.append("")
        lines.append(f"- 发现设备总数：**{kpi['devices_total']}**")
        lines.append(f"- 漏洞总数：**{kpi['vulns_total']}**"
                     f"（高危及以上 {kpi['vulns_high']}）")
        lines.append(f"- 流量告警：{kpi['alerts_total']}")
        lines.append(f"- 合规评分：{kpi['compliance_rate']}/100")
        lines.append(f"- 综合风险均分：{d['risk'].get('avg_score', 0)}")
        lines.append("")
        lines.append("## 2. 设备清单")
        lines.append("")
        lines.append("| IP | 厂商 | 型号 | 类型 | 位置 |")
        lines.append("|---|---|---|---|---|")
        for dev in d["devices"][:15]:
            lines.append(f"| {dev.get('ip','')} | {dev.get('vendor','')} "
                         f"| {dev.get('model','')} "
                         f"| {dev.get('device_type','')} "
                         f"| {dev.get('location','')} |")
        lines.append("")
        lines.append("## 3. 协议分析")
        lines.append("")
        for p, n in d["protocol"].get("by_protocol", {}).items():
            lines.append(f"- {p}: {n} 条发现")
        lines.append("")
        lines.append("## 4. 固件分析")
        lines.append("")
        lines.append(f"- 固件发现总数：{d['firmware'].get('total', 0)}")
        for k, v in d["firmware"].get("by_category", {}).items():
            lines.append(f"- {k}: {v}")
        lines.append("")
        lines.append("## 5. 漏洞详情")
        lines.append("")
        for k, v in d["vulns"].get("by_severity", {}).items():
            lines.append(f"- {k}: {v}")
        lines.append("")
        lines.append("## 6. 配置审计")
        lines.append("")
        lines.append(f"- 审计项总数：{d['config'].get('total', 0)}，"
                     f"失败率 {d['config'].get('fail_rate', 0)}")
        lines.append("")
        lines.append("## 7. 流量监控")
        lines.append("")
        lines.append(f"- 告警总数：{d['traffic'].get('total', 0)}")
        lines.append("")
        lines.append("## 8. 风险评级")
        lines.append("")
        for k, v in d["risk"].get("by_level", {}).items():
            lines.append(f"- {k}: {v}")
        lines.append("")
        lines.append("## 9. 合规审计")
        lines.append("")
        lines.append(f"- 合规总分：{d['compliance'].get('overall_score', 0)}")
        for std, s in d["compliance"].get("by_standard", {}).items():
            lines.append(f"- {std}: 通过 {s.get('pass',0)} / "
                         f"失败 {s.get('fail',0)}")
        lines.append("")
        lines.append("## 10. 整改建议")
        lines.append("")
        lines.append("1. P0：对暴露的 PLC/SCADA 立即启用访问控制，"
                     "网络分段")
        lines.append("2. P1：MQTT/OPC UA 启用认证加密，收敛默认口令")
        lines.append("3. P1：升级固件至最新版本，关闭 Telnet/多余端口")
        lines.append("4. P2：建立工业流量基线，部署异常检测与告警")
        lines.append("5. P2：对照 IEC 62443-3-3/NIST 8259 补齐合规缺口")
        lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    def to_html(self, md: str) -> str:
        import html as _h
        body = _h.escape(md)
        return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>工控IoT 安全报告</title>
<style>
body{{font-family:-apple-system,Segoe UI,Microsoft YaHei,sans-serif;
background:#0f1419;color:#e6e6e6;padding:32px;line-height:1.7;}}
pre{{white-space:pre-wrap;background:#1a2029;padding:20px;border-radius:8px;
border:1px solid #2a3441;}}
h1,h2{{color:#26c6da;}}
</style></head><body>
<pre>{body}</pre>
</body></html>"""

    # ------------------------------------------------------------------ #
    def generate(self, fmt: str = "both") -> Dict[str, Any]:
        data = self.collect_data()
        md = self.to_markdown(data)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        md_path = os.path.join(REPORTS_DIR, f"iot_ot_report_{ts}.md")
        html_path = os.path.join(REPORTS_DIR, f"iot_ot_report_{ts}.html")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)
        html = self.to_html(md)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        return {"md_path": md_path, "html_path": html_path,
                "markdown": md, "html": html,
                "stats": data["dashboard"]["kpi"]}


_default: Optional[ReportGenerator] = None


def get_report_generator() -> ReportGenerator:
    global _default
    if _default is None:
        _default = ReportGenerator()
    return _default
