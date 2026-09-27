# -*- coding: utf-8 -*-
"""
interactive_report.py — 交互式报告查看器后端。

提供：
  - 报告数据获取
  - 漏洞列表（筛选/排序/搜索）
  - 漏洞详情 / 状态管理 / 评论
  - 批量操作
  - 报告导出（pdf/html/md/json/csv）
内存字典模拟。
"""
from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict, List, Optional

from .common import now_str, new_id, paginate, apply_filters, search_in


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
VALID_STATUSES = {"open", "in_progress", "fixed", "false_positive", "accepted"}


REPORTS: Dict[str, Dict[str, Any]] = {}
VULNS: Dict[str, Dict[str, Any]] = {}
COMMENTS: Dict[str, List[Dict[str, Any]]] = {}


def _seed() -> None:
    if REPORTS:
        return
    report_specs = [
        ("rep_1000", "Web 主站漏洞报告", "web_vuln_scan", "https://shop.example.com", 82,
         "high", 202),
        ("rep_1001", "开放 API 接口安全评估", "api_security", "https://api.example.com", 68,
         "medium", 97),
        ("rep_1002", "生产资产配置基线审计", "config_audit", "prod-web-01..08", 75,
         "high", 138),
    ]
    vuln_templates = [
        ("CVE-2024-3000", "SQL 注入", "critical", "sql_injection", 9.8,
         "登录接口 username 参数存在字符型注入，可通过 UNION 注入拖库。",
         "POST /login username=' OR SLEEP(5)-- - 响应延迟 5.1s",
         "升级框架版本；使用参数化查询；对登录接口增加 WAF 规则。",
         "https://owasp.org/www-community/attacks/SQL_Injection"),
        ("CVE-2024-1122", "反射型 XSS", "high", "xss", 7.4,
         "搜索页 q 参数未做输出编码，可注入任意脚本。",
         "/search?q=<script>alert(1)</script> 弹窗触发",
         "对输出做 HTML 实体编码；设置 CSP。",
         "https://owasp.org/www-community/attacks/xss/"),
        ("CVE-2023-9988", "越权访问(IDOR)", "high", "idor", 7.5,
         "/api/order/{id} 未校验归属，可遍历他人订单。",
         "替换 id=1001 为 id=1002 返回他人数据",
         "服务端做对象级授权校验。",
         "https://portswigger.net/web-security/idor"),
        ("CVE-2024-0555", "敏感信息泄露", "medium", "info_disclosure", 5.3,
         "响应头 X-Powered-By 泄露后端版本。",
         "响应头包含 X-Powered-By: Express/4.18",
         "移除该响应头。",
         "https://owasp.org/www-community/Information_exposure_through_query_strings_in_url"),
        ("CVE-2024-2210", "弱口令策略", "medium", "weak_password", 5.0,
         "管理员密码策略允许长度 <8。",
         "策略配置 min_length=6",
         "强制最小长度 12 并启用多因素。",
         "https://owasp.org/www-community/vulnerabilities/Weak_password"),
        ("CVE-2023-7788", "缺失安全响应头", "low", "misconfig", 3.7,
         "未设置 HSTS / X-Frame-Options。",
         "curl -I 检查头部缺失",
         "在网关层补全安全头。",
         "https://owasp.org/www-project-secure-headers/"),
        ("CVE-2024-4430", "反序列化漏洞", "critical", "deserialization", 9.1,
         "缓存服务使用不安全反序列化，可 RCE。",
         "构造恶意 payload 触发命令执行",
         "关闭原生反序列化，改用 JSON。",
         "https://portswigger.net/web-security/deserialization"),
        ("CVE-2024-9001", "CSRF 防护缺失", "medium", "csrf", 6.5,
         "敏感操作接口无 CSRF Token。",
         "跨域表单可直接提交",
         "引入 CSRF Token 校验。",
         "https://owasp.org/www-community/attacks/csrf"),
    ]
    statuses = ["open", "in_progress", "fixed", "open", "accepted", "false_positive",
                "open", "in_progress"]
    for rid, name, sc, tgt, score, lvl, found in report_specs:
        REPORTS[rid] = {
            "report_id": rid, "title": name, "scenario": sc, "target": tgt,
            "risk_score": score, "risk_level": lvl, "findings_count": found,
            "created_at": now_str(), "author": "sec-agent",
            "severity_breakdown": {"critical": 2, "high": 3, "medium": 2, "low": 1},
        }
        for i, vt in enumerate(vuln_templates):
            vid = f"{rid}_v{i+1:02d}"
            cve, title, sev, vtype, cvss, desc, evidence, fix, ref = vt
            VULNS[vid] = {
                "vuln_id": vid, "report_id": rid, "cve": cve, "title": title,
                "severity": sev, "vuln_type": vtype, "cvss": cvss,
                "description": desc, "evidence": evidence, "fix": fix,
                "reference": ref, "asset": tgt,
                "status": statuses[i % len(statuses)],
                "discovered_at": now_str(), "updated_at": now_str(),
                "poc": f'curl -X POST "https://{tgt}/login" -d "username=admin\\\'-- -"',
            }
            COMMENTS[vid] = []


_seed()


# --------------------------------------------------------------------------- #
# 报告
# --------------------------------------------------------------------------- #
def list_reports(page: int = 1, page_size: int = 20, q: str = "",
                 sort_by: str = "created_at", sort_dir: str = "desc") -> Dict[str, Any]:
    items = list(REPORTS.values())
    items = search_in(items, q, ["report_id", "title", "target", "scenario"])
    return paginate(items, page, page_size, sort_by, sort_dir)


def get_report(report_id: str) -> Optional[Dict[str, Any]]:
    return REPORTS.get(report_id)


# --------------------------------------------------------------------------- #
# 漏洞
# --------------------------------------------------------------------------- #
def list_vulns(report_id: str, severity: str = "", status: str = "",
               vtype: str = "", q: str = "",
               page: int = 1, page_size: int = 20,
               sort_by: str = "cvss", sort_dir: str = "desc") -> Dict[str, Any]:
    items = [v for v in VULNS.values() if v["report_id"] == report_id]
    items = apply_filters(items, {"severity": severity, "status": status,
                                  "vuln_type": vtype})
    items = search_in(items, q, ["cve", "title", "description", "vuln_type"])
    # 严重程度优先排序兜底
    if sort_by == "severity":
        items.sort(key=lambda v: (SEVERITY_ORDER.get(v["severity"], 9),
                                  -float(v.get("cvss", 0)) if sort_dir == "asc"
                                  else float(v.get("cvss", 0))),
                   reverse=(sort_dir == "desc"))
        total = len(items)
        p = max(1, page); ps = max(1, min(500, page_size))
        s = (p - 1) * ps
        return {"items": items[s:s + ps], "total": total, "page": p,
                "page_size": ps, "has_more": s + ps < total}
    return paginate(items, page, page_size, sort_by, sort_dir)


def get_vuln(report_id: str, vuln_id: str) -> Optional[Dict[str, Any]]:
    v = VULNS.get(vuln_id)
    if not v or v["report_id"] != report_id:
        return None
    return v


def update_vuln_status(report_id: str, vuln_id: str,
                       status: str) -> Optional[Dict[str, Any]]:
    v = get_vuln(report_id, vuln_id)
    if not v:
        return None
    if status not in VALID_STATUSES:
        raise ValueError(f"非法状态: {status}，可选 {sorted(VALID_STATUSES)}")
    v["status"] = status
    v["updated_at"] = now_str()
    return v


def list_comments(report_id: str, vuln_id: str) -> List[Dict[str, Any]]:
    get_vuln(report_id, vuln_id)  # 校验存在
    return list(COMMENTS.get(vuln_id, []))


def add_comment(report_id: str, vuln_id: str, author: str,
                content: str) -> Dict[str, Any]:
    get_vuln(report_id, vuln_id)
    cid = new_id("cmt")
    c = {"comment_id": cid, "author": author or "analyst",
         "content": content, "created_at": now_str()}
    COMMENTS.setdefault(vuln_id, []).append(c)
    return c


def delete_comment(report_id: str, vuln_id: str, comment_id: str) -> bool:
    get_vuln(report_id, vuln_id)
    arr = COMMENTS.get(vuln_id, [])
    before = len(arr)
    COMMENTS[vuln_id] = [c for c in arr if c["comment_id"] != comment_id]
    return len(COMMENTS[vuln_id]) < before


def batch_update_status(report_id: str, vuln_ids: List[str],
                        status: str) -> Dict[str, int]:
    if status not in VALID_STATUSES:
        raise ValueError(f"非法状态: {status}")
    updated = 0
    for vid in vuln_ids:
        v = VULNS.get(vid)
        if v and v["report_id"] == report_id:
            v["status"] = status
            v["updated_at"] = now_str()
            updated += 1
    return {"updated": updated, "requested": len(vuln_ids)}


def batch_export(report_id: str, vuln_ids: List[str],
                 fmt: str = "csv") -> Dict[str, Any]:
    rows = [v for v in VULNS.values()
            if v["report_id"] == report_id and (not vuln_ids or v["vuln_id"] in vuln_ids)]
    if fmt == "json":
        content = json.dumps(rows, ensure_ascii=False, indent=2)
    else:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["vuln_id", "cve", "title", "severity", "cvss", "status", "asset"])
        for v in rows:
            w.writerow([v["vuln_id"], v["cve"], v["title"], v["severity"],
                        v["cvss"], v["status"], v["asset"]])
        content = buf.getvalue()
    return {"report_id": report_id, "format": fmt, "count": len(rows),
            "filename": f"{report_id}_vulns.{fmt}", "content": content}


def export_report(report_id: str, fmt: str = "html") -> Optional[Dict[str, Any]]:
    r = get_report(report_id)
    if not r:
        return None
    vulns = [v for v in VULNS.values() if v["report_id"] == report_id]
    if fmt == "json":
        content = json.dumps({"report": r, "vulns": vulns}, ensure_ascii=False, indent=2)
    elif fmt == "markdown" or fmt == "md":
        lines = [f"# {r['title']}", "", f"- 目标: {r['target']}",
                 f"- 风险分: {r['risk_score']} ({r['risk_level']})",
                 f"- 发现: {len(vulns)}", "", "## 漏洞清单", ""]
        for v in vulns:
            lines.append(f"### [{v['severity'].upper()}] {v['title']} ({v['cve']})")
            lines.append(f"- CVSS: {v['cvss']}  状态: {v['status']}")
            lines.append(f"- 描述: {v['description']}")
            lines.append(f"- 修复: {v['fix']}\n")
        content = "\n".join(lines)
    elif fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["cve", "title", "severity", "cvss", "status", "description"])
        for v in vulns:
            w.writerow([v["cve"], v["title"], v["severity"], v["cvss"],
                        v["status"], v["description"]])
        content = buf.getvalue()
    elif fmt == "pdf":
        content = f"%PDF stub — 标题:{r['title']} 发现:{len(vulns)}\n"
    else:
        rows = "".join(f"<tr><td>{v['cve']}</td><td>{v['title']}</td>"
                       f"<td>{v['severity']}</td><td>{v['cvss']}</td>"
                       f"<td>{v['status']}</td></tr>" for v in vulns)
        content = (f"<html><head><meta charset='utf-8'><title>{r['title']}</title>"
                   f"</head><body><h1>{r['title']}</h1>"
                   f"<p>目标:{r['target']} 风险:{r['risk_score']}</p>"
                   f"<table border=1><tr><th>CVE</th><th>标题</th><th>级别</th>"
                   f"<th>CVSS</th><th>状态</th></tr>{rows}</table></body></html>")
    return {"report_id": report_id, "format": fmt,
            "filename": f"{report_id}.{fmt}", "content": content,
            "vuln_count": len(vulns)}
