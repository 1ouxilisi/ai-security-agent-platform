# -*- coding: utf-8 -*-
"""
report_templates.py — 专业安全公司级报告模板。

风格参考 Nessus / AWVS：
    - 执行摘要（给老板看的一页纸）
    - 目标信息
    - 风险概览（高/中/低）
    - 漏洞详情列表（CVSS/CWE/影响/利用条件/复现步骤/修复/参考）
    - 资产风险热力图
    - 风险分布饼图
    - 漏洞严重程度柱状图
    - 整改建议优先级
"""

from __future__ import annotations

import html
from typing import Any, Dict, List


# CVSS 评分辅助
CVSS_SEVERITY = {
    "critical": (9.0, 10.0, "#ff4d4f"),
    "high":     (7.0, 8.9,  "#ff7a45"),
    "medium":   (4.0, 6.9,  "#fadb14"),
    "low":      (0.1, 3.9,  "#52c41a"),
    "info":     (0.0, 0.0,  "#1677ff"),
}


def cvss_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


# 内置漏洞知识库（常见 CVE/CWE 元数据）
VULN_DB: Dict[str, Dict[str, Any]] = {
    "SQL注入": {
        "cwe": "CWE-89", "cvss": 9.8,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "impact": "攻击者可读取/篡改/删除数据库全部内容，"
                  "可能进一步获取服务器权限",
        "prereq": "目标存在可控制的 SQL 参数，且服务端未做参数化",
        "repro": "1. 定位参数 2. 加单引号触发错误 "
                 "3. 用 sqlmap 自动验证 4. 导出数据库",
        "fix": "使用参数化查询/预编译；最小权限 DB 账号；"
               "输入白名单校验",
        "refs": ["https://cwe.mitre.org/data/definitions/89.html",
                 "https://owasp.org/www-community/attacks/SQL_Injection"],
    },
    "XSS": {
        "cwe": "CWE-79", "cvss": 6.1,
        "vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "impact": "窃取会话 Cookie、伪造用户操作、钓鱼",
        "prereq": "用户输入未经过滤直接输出到 HTML",
        "repro": "1. 在输入点提交 <script>alert(1)</script> "
                 "2. 观察是否原样回显",
        "fix": "输出 HTML 实体编码；设置 CSP；HttpOnly Cookie",
        "refs": ["https://cwe.mitre.org/data/definitions/79.html"],
    },
    "目录遍历": {
        "cwe": "CWE-22", "cvss": 7.5,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "impact": "读取服务器任意文件，获取配置/密钥",
        "prereq": "文件/路径参数未过滤 ../",
        "repro": "提交 ../../../../etc/passwd 观察返回内容",
        "fix": "白名单允许的文件；禁止路径拼接；chroot",
        "refs": ["https://cwe.mitre.org/data/definitions/22.html"],
    },
    "本地文件包含": {
        "cwe": "CWE-98", "cvss": 9.8,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "impact": "包含远程/本地文件，可直接 Getshell",
        "prereq": "allow_url_include=On 且 include 变量可控",
        "repro": "php://filter/convert.base64-encode/resource=index.php",
        "fix": "关闭 allow_url_include；白名单；禁用危险协议",
        "refs": ["https://cwe.mitre.org/data/definitions/98.html"],
    },
    "信息泄露": {
        "cwe": "CWE-200", "cvss": 5.3,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "impact": "泄露敏感路径、版本、配置，辅助进一步攻击",
        "prereq": "敏感文件/端点未做访问控制",
        "repro": "访问 /.git/HEAD /.env /phpinfo.php /actuator/env",
        "fix": "删除/移走敏感文件；Web 服务器 deny 规则",
        "refs": ["https://cwe.mitre.org/data/definitions/200.html"],
    },
    "弱口令": {
        "cwe": "CWE-521", "cvss": 9.8,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "impact": "直接登录后台/系统",
        "prereq": "存在登录接口且未启用锁定/验证码",
        "repro": "暴力破解 admin/admin、admin/123456",
        "fix": "强密码策略；失败锁定；多因素认证",
        "refs": ["https://cwe.mitre.org/data/definitions/521.html"],
    },
    "未授权访问": {
        "cwe": "CWE-862", "cvss": 8.6,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "impact": "未登录即可访问敏感功能/数据",
        "prereq": "缺少鉴权中间件或角色校验",
        "repro": "直接访问 /admin /api/v1/users 等",
        "fix": "统一鉴权中间件；最小权限原则",
        "refs": ["https://cwe.mitre.org/data/definitions/862.html"],
    },
}


class ReportTemplates:
    """专业报告模板渲染。"""

    # ------------------------------------------------------------------ #
    # 整体 HTML 骨架
    # ------------------------------------------------------------------ #
    @staticmethod
    def render_skeleton(title: str, body: str,
                        extra_css: str = "") -> str:
        return f"""<!DOCTYPE html>
<html lang=\"zh-CN\"><head><meta charset=\"UTF-8\">
<title>{html.escape(title)}</title>
<script src=\"https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js\"></script>
<style>
:root{{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#e6edf3;
--muted:#8b949e;--accent:#58a6ff;}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);
font-family:'Microsoft YaHei','Segoe UI',Arial,sans-serif;font-size:13px;line-height:1.6}}
.wrap{{max-width:1100px;margin:0 auto;padding:32px}}
h1{{font-size:24px;margin:0 0 6px}}
h2{{font-size:18px;color:var(--accent);border-bottom:1px solid var(--border);
padding-bottom:6px;margin-top:32px}}
h3{{font-size:15px;margin-top:18px}}
.meta{{color:var(--muted);font-size:12px}}
.card{{background:var(--panel);border:1px solid var(--border);
border-radius:6px;padding:16px;margin:12px 0}}
table{{width:100%;border-collapse:collapse;font-size:12px;margin:8px 0}}
th,td{{border:1px solid var(--border);padding:6px 10px;text-align:left;vertical-align:top}}
th{{background:#21262d}}
.badge{{display:inline-block;padding:2px 10px;border-radius:10px;
font-size:11px;font-weight:bold}}
.b-critical{{background:#ff4d4f22;color:#ff4d4f}}
.b-high{{background:#ff7a4522;color:#ff7a45}}
.b-medium{{background:#fadb1422;color:#fadb14}}
.b-low{{background:#52c41a22;color:#52c41a}}
.b-info{{background:#1677ff22;color:#1677ff}}
.kv{{display:grid;grid-template-columns:160px 1fr;gap:4px 12px}}
.kv .k{{color:var(--muted)}}
pre{{background:#0d1117;border:1px solid var(--border);padding:10px;
border-radius:4px;overflow:auto;max-height:300px;
font-family:Consolas,monospace;font-size:12px;white-space:pre-wrap}}
.risk-big{{font-size:42px;font-weight:bold;text-align:center;padding:20px}}
.chart-box{{height:280px}}
.heat-cell{{display:inline-block;width:36px;height:36px;margin:2px;
border-radius:4px;text-align:center;line-height:36px;font-size:10px;
color:#fff;font-weight:bold}}
{extra_css}
</style></head><body><div class=\"wrap\">
{body}
</div></body></html>"""

    # ------------------------------------------------------------------ #
    # 执行摘要（老板一页纸）
    # ------------------------------------------------------------------ #
    @staticmethod
    def render_exec_summary(target: str, overall: str,
                            sev: Dict[str, int],
                            top_vulns: List[Dict[str, Any]],
                            report_id: str,
                            date_str: str) -> str:
        meta_color = CVSS_SEVERITY.get(overall,
                                       CVSS_SEVERITY["info"])[2]
        label = {"critical": "严重风险", "high": "高风险",
                 "medium": "中风险", "low": "低风险",
                 "info": "信息"}.get(overall, "未知")
        rows = "".join(
            f"<tr><td><span class='badge b-{v.get('severity','info')}'>"
            f"{v.get('severity','info').upper()}</span></td>"
            f"<td>{html.escape(v.get('name',''))}</td>"
            f"<td>{v.get('cvss_score','-')}</td>"
            f"<td>{html.escape(v.get('cwe','') or '-')}</td>"
            f"<td>{html.escape(v.get('url','') or '-')}</td></tr>"
            for v in top_vulns[:5])
        return f"""
<h1>安全评估报告 — 执行摘要</h1>
<div class="meta">报告编号: {report_id} &nbsp;|&nbsp; 日期: {date_str}</div>
<div class="card" style="margin-top:14px">
  <div class="meta">目标系统</div>
  <h3>{html.escape(target)}</h3>
  <div class="meta">综合风险评级</div>
  <div class="risk-big" style="color:{meta_color}">{label}</div>
</div>

<div class="card">
  <h3>风险概览</h3>
  <table>
    <tr><th>严重程度</th><th>数量</th></tr>
    <tr><td><span class="badge b-critical">严重</span></td><td>{sev.get('critical',0)}</td></tr>
    <tr><td><span class="badge b-high">高危</span></td><td>{sev.get('high',0)}</td></tr>
    <tr><td><span class="badge b-medium">中危</span></td><td>{sev.get('medium',0)}</td></tr>
    <tr><td><span class="badge b-low">低危</span></td><td>{sev.get('low',0)}</td></tr>
    <tr><td><span class="badge b-info">信息</span></td><td>{sev.get('info',0)}</td></tr>
  </table>
</div>

<div class="card">
  <h3>需立即处置的 Top 风险</h3>
  <table><tr><th>等级</th><th>名称</th><th>CVSS</th>
  <th>CWE</th><th>位置</th></tr>{rows}</table>
</div>

<div class="card">
  <h3>总体建议</h3>
  <p>建议在 <b>7 个工作日</b>内完成严重/高危漏洞修复，
     并在 <b>30 个工作日</b>内完成中危漏洞整改。
     修复完成后建议安排复测。</p>
</div>
"""

    # ------------------------------------------------------------------ #
    # 漏洞详情卡片
    # ------------------------------------------------------------------ #
    @staticmethod
    def render_vuln_detail(idx: int, v: Dict[str, Any]) -> str:
        sev = (v.get("severity") or "info").lower()
        cve = v.get("cve") or "-"
        cwe = v.get("cwe") or "-"
        cvss = v.get("cvss_score", "-")
        vector = v.get("cvss_vector", "")
        db = VULN_DB.get(v.get("name", ""), {})
        impact = v.get("impact") or db.get("impact", "-")
        prereq = v.get("prereq") or db.get("prereq", "-")
        repro = v.get("repro") or db.get("repro", "-")
        fix = v.get("fix") or v.get("solution") or db.get("fix", "-")
        refs = v.get("refs") or db.get("refs", [])
        refs_html = "<br>".join(
            f'<a href="{html.escape(r)}" style="color:var(--accent)">'
            f'{html.escape(r)}</a>' for r in refs) or "-"
        return f"""
<div class="card">
  <h3>{idx}. {html.escape(v.get('name',''))}
      <span class="badge b-{sev}">{sev.upper()}</span></h3>
  <div class="kv">
    <div class="k">CVSS</div><div><b>{cvss}</b> {html.escape(vector)}</div>
    <div class="k">CVE</div><div>{html.escape(str(cve))}</div>
    <div class="k">CWE</div><div>{html.escape(str(cwe))}</div>
    <div class="k">影响位置</div><div>{html.escape(v.get('url','-'))}</div>
    <div class="k">影响范围</div><div>{html.escape(str(impact))}</div>
    <div class="k">利用条件</div><div>{html.escape(str(prereq))}</div>
  </div>
  <p><b>复现步骤:</b></p>
  <pre>{html.escape(str(repro))}</pre>
  <p><b>修复方案:</b> {html.escape(str(fix))}</p>
  <p><b>参考链接:</b><br>{refs_html}</p>
</div>
"""

    # ------------------------------------------------------------------ #
    # 资产风险热力图
    # ------------------------------------------------------------------ #
    @staticmethod
    def render_heatmap(assets: List[Dict[str, Any]]) -> str:
        """assets: [{name, critical, high, medium, low}]"""
        cells = []
        for a in assets:
            tot = (a.get("critical", 0) + a.get("high", 0)
                   + a.get("medium", 0) + a.get("low", 0))
            if a.get("critical", 0) > 0:
                color = "#ff4d4f"
            elif a.get("high", 0) > 0:
                color = "#ff7a45"
            elif a.get("medium", 0) > 0:
                color = "#fadb14"
            elif a.get("low", 0) > 0:
                color = "#52c41a"
            else:
                color = "#30363d"
            cells.append(
                f'<div style="display:inline-block;margin:6px;'
                f'text-align:center">'
                f'<div class="heat-cell" style="background:{color}">'
                f'{tot}</div>'
                f'<div class="meta" style="max-width:120px;word-break:break-all">'
                f'{html.escape(a.get("name",""))}</div></div>')
        return f'<div style="padding:8px">{"".join(cells)}</div>'
