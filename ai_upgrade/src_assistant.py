# -*- coding: utf-8 -*-
"""
ai_upgrade/src_assistant.py — AI 辅助挖 SRC

1) 自动分析 SRC 目标，发现最有价值的攻击面（子域/接口/历史漏洞/资产价值）
2) 自动写 SRC 提交报告，支持补天(butian) 与 HackerOne 两种模板
真实 LLM 可用时润色叙述；否则用模板引擎生成。
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from .llm_integration import get_enhanced_llm

# 内存存储
TARGETS: Dict[str, Dict[str, Any]] = {}
SUBMISSIONS: Dict[str, Dict[str, Any]] = {}

# 模拟资产库
_SEED_ASSETS = {
    "example.com": {
        "subdomains": ["www.example.com", "api.example.com",
                       "admin.example.com", "dev.example.com",
                       "static.example.com", "m.example.com"],
        "tech": ["Nginx", "React", "MySQL", "Redis", "K8s"],
        "historical_vulns": ["git 源码泄露", "未授权 API", "旧版 Struts"],
        "business_value": "电商交易平台",
    }
}


def _attack_surface_score(asset: Dict[str, Any]) -> List[Dict[str, Any]]:
    """启发式：给每个子域/接口打分，找最有价值攻击面。"""
    surfaces = []
    hot = {"admin": 9.5, "dev": 9.0, "test": 8.5, "api": 8.0,
           "upload": 9.0, "pay": 9.5, "login": 8.0, "old": 8.5,
           "backup": 9.0, "jenkins": 9.5, "git": 9.5}
    for sub in asset.get("subdomains", []):
        score = 5.0
        reasons = []
        for kw, sc in hot.items():
            if kw in sub.lower():
                score = max(score, sc)
                reasons.append(f"命中关键词「{kw}」")
        if "admin" in sub.lower():
            reasons.append("后台类，权限价值高")
        if "dev" in sub.lower():
            reasons.append("测试环境，防护通常较弱")
        surfaces.append({
            "host": sub,
            "score": round(score, 1),
            "reasons": reasons or ["常规资产，需进一步指纹识别"],
            "suggestion": "优先探测未授权访问 / 弱口令 / 历史漏洞复现",
        })
    surfaces.sort(key=lambda x: x["score"], reverse=True)
    return surfaces


class SRCAssistant:
    """SRC 辅助分析与报告撰写。"""

    def analyze_target(self, domain: str) -> Dict[str, Any]:
        asset = _SEED_ASSETS.get(domain, {
            "subdomains": [f"www.{domain}", f"api.{domain}",
                           f"admin.{domain}", f"dev.{domain}"],
            "tech": ["Nginx", "Linux"],
            "historical_vulns": [],
            "business_value": "待识别",
        })
        surfaces = _attack_surface_score(asset)
        tid = uuid.uuid4().hex[:10]
        result = {
            "target_id": tid,
            "domain": domain,
            "business_value": asset["business_value"],
            "tech_stack": asset["tech"],
            "historical_vulns": asset["historical_vulns"],
            "attack_surfaces": surfaces,
            "top_priority": surfaces[0]["host"] if surfaces else None,
            "strategy": self._rule_strategy(surfaces, asset),
        }
        TARGETS[tid] = result
        return result

    def _rule_strategy(self, surfaces: List[Dict[str, Any]],
                       asset: Dict[str, Any]) -> str:
        top = surfaces[0]["host"] if surfaces else "目标"
        return (f"建议攻击顺序：1) 从价值最高的 {top} 入手，先做指纹与目录扫描；"
                f"2) 复核历史漏洞 {asset.get('historical_vulns') or '（暂无记录）'} 是否仍存在；"
                "3) 对 api 子域做未授权接口与越权测试；"
                "4) 收集可证明危害的 PoC 截图后再提交，避免无效报告。")

    def write_submission(self, domain: str, vuln: Dict[str, Any],
                         platform: str = "butian") -> Dict[str, Any]:
        """生成 SRC 提交报告。platform: butian | hackerone。"""
        el = get_enhanced_llm()
        vname = vuln.get("name", "未命名漏洞")
        detail = vuln.get("detail", "")
        sys_p = ("你是 SRC 漏洞提交专家。用清晰、客观、可复现的中文写漏洞报告，"
                 "包含标题、漏洞类型、危害等级、复现步骤、证明证据、修复建议。")
        user_p = (f"厂商：{domain}\n漏洞：{vname}\n详情：{detail}\n"
                  f"提交平台：{platform}\n请撰写提交报告。")
        r = el.chat(sys_p, user_p, rule_fallback="", task="src_report",
                    max_tokens=600)

        if platform == "hackerone":
            body = self._hackerone_template(domain, vuln, r["content"])
        else:
            body = self._butian_template(domain, vuln, r["content"])

        sid = uuid.uuid4().hex[:10]
        sub = {
            "submission_id": sid,
            "platform": platform,
            "domain": domain,
            "vuln_name": vname,
            "engine": r["engine"],
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "title": body["title"],
            "content": body["content"],
            "fields": body["fields"],
        }
        SUBMISSIONS[sid] = sub
        return sub

    def _butian_template(self, domain: str, vuln: Dict[str, Any],
                         ai_text: str) -> Dict[str, Any]:
        title = f"【{domain}】{vuln.get('name','安全漏洞')} 可被利用"
        fields = {
            "漏洞标题": title,
            "漏洞类型": vuln.get("type", "其他"),
            "危害等级": vuln.get("severity", "high"),
            "漏洞URL": vuln.get("url", f"https://{domain}/"),
            "是否需登录": "是" if vuln.get("requires_auth") else "否",
            "提交人": "AI SRC 助手",
        }
        content = (ai_text or
                   "【漏洞描述】\n" + (vuln.get("detail") or "") + "\n\n"
                   "【复现步骤】\n1. 访问相关接口\n2. 构造 PoC 请求\n3. 观察响应确认漏洞\n\n"
                   "【危害】可导致未授权访问/数据泄露。\n\n"
                   "【修复建议】输入校验 + 鉴权 + 最小权限。")
        return {"title": title, "content": content, "fields": fields}

    def _hackerone_template(self, domain: str, vuln: Dict[str, Any],
                            ai_text: str) -> Dict[str, Any]:
        title = f"{domain}: {vuln.get('name','Vulnerability')} leads to risk"
        fields = {
            "Asset": domain,
            "Weakness": vuln.get("type", "Other"),
            "Severity": vuln.get("severity", "high"),
            "Weakness Category": vuln.get("cwe", "CWE-"),
        }
        content = (ai_text or
                   "## Summary\n" + (vuln.get("detail") or "") + "\n\n"
                   "## Steps To Reproduce\n1. Visit endpoint\n"
                   "2. Send crafted request\n3. Observe impact\n\n"
                   "## Impact\nUnauthorized access / data exposure.\n\n"
                   "## Recommendation\nInput validation + authz checks.")
        return {"title": title, "content": content, "fields": fields}

    def list_targets(self) -> List[Dict[str, Any]]:
        return list(TARGETS.values())

    def list_submissions(self) -> List[Dict[str, Any]]:
        return list(SUBMISSIONS.values())


_singleton: Optional[SRCAssistant] = None


def get_src_assistant() -> SRCAssistant:
    global _singleton
    if _singleton is None:
        _singleton = SRCAssistant()
    return _singleton
