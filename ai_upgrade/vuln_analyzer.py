# -*- coding: utf-8 -*-
"""
ai_upgrade/vuln_analyzer.py — 漏洞智能分析

AI 自动判断漏洞严重程度、生成利用建议与修复建议。
真实 LLM 可用时进行自然语言推理；否则走内置规则引擎（CVSS 打分 +
CWE/OWASP 知识库模板）。两种模式都返回统一结构，engine 字段区分来源。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .llm_integration import get_enhanced_llm


# --------------------------------------------------------------------------- #
# 规则知识库：漏洞类型 -> 基线严重度与利用/修复模板
# --------------------------------------------------------------------------- #
_RULE_KB: Dict[str, Dict[str, Any]] = {
    "sql_injection": {
        "cwe": "CWE-89", "owasp": "A03", "base_score": 9.8,
        "level": "critical",
        "vector": "Network/Low/None/None/None/High/High/High",
        "exploit": "使用 sqlmap 自动探测：sqlmap -u 'http://target/page?id=1' --dbs --batch。"
                   "手工验证用单引号触发报错：' AND 1=1-- 。",
        "fix": "使用参数化查询/预编译语句；ORM 绑定变量；禁止字符串拼接 SQL；"
               "最小权限数据库账号；开启 WAF 规则。",
        "impact": "可拖库、绕过登录、写入 Webshell，远程系统控制。",
    },
    "xss": {
        "cwe": "CWE-79", "owasp": "A03", "base_score": 6.1,
        "level": "medium",
        "vector": "Network/None/Required/None/None/Low/Low/High",
        "exploit": "插入 <script>alert(document.cookie)</script> 验证反射型；"
                   "存储型提交到评论/个人资料看是否持久化触发。",
        "fix": "输出编码（HTML entity）；CSP 头；HttpOnly Cookie；富文本白名单过滤。",
        "impact": "窃取会话、钓鱼、键盘记录、打管理员。",
    },
    "ssrf": {
        "cwe": "CWE-918", "owasp": "A10", "base_score": 8.6,
        "level": "high",
        "vector": "Network/Low/None/None/None/High/Low/High",
        "exploit": "让服务端请求 http://169.254.169.254/latest/meta-data/ 读云元数据；"
                   "试 file:///etc/passwd 与内网端口扫描。",
        "fix": "URL 白名单；禁止内网/链路本地地址；协议限制仅 http/https；"
               "DNS 重绑定防护。",
        "impact": "访问云元数据拿 AK/SK、扫内网、打未授权服务。",
    },
    "rce": {
        "cwe": "CWE-78", "owasp": "A03", "base_score": 10.0,
        "level": "critical",
        "vector": "Network/Low/None/None/None/High/High/High",
        "exploit": "验证命令拼接点：; id 、| whoami 、`id` 、$(id)；"
                   "确认回显后反弹 shell。",
        "fix": "禁止 shell=True；用 subprocess 参数数组；输入白名单；"
               "不调用 eval/exec/system。",
        "impact": "直接获得服务器执行权限，完全控制。",
    },
    "deserialization": {
        "cwe": "CWE-502", "owasp": "A08", "base_score": 9.8,
        "level": "critical",
        "vector": "Network/Low/None/None/None/High/High/High",
        "exploit": "Python pickle / Java 反序列化用 ysoserial / 自制 gadget 链；"
                   "观察 Content-Type 与回显。",
        "fix": "禁止反序列化不可信数据；改用 JSON；沙箱；签名校验。",
        "impact": "RCE、权限提升、敏感文件读取。",
    },
    "path_traversal": {
        "cwe": "CWE-22", "owasp": "A01", "base_score": 7.5,
        "level": "high",
        "vector": "Network/Low/None/None/None/High/None/High",
        "exploit": "../etc/passwd 、....//....//etc/passwd 绕过；"
                   "URL 编码 %2e%2e%2f。",
        "fix": "规范化后校验目录前缀；白名单文件；禁止 ../。",
        "impact": "读任意文件、配置泄露、源码泄露。",
    },
    "weak_auth": {
        "cwe": "CWE-521", "owasp": "A07", "base_score": 7.5,
        "level": "high",
        "vector": "Network/Low/None/None/None/High/None/High",
        "exploit": "hydra / burp 爆破常见弱口令 admin/admin、root/123456；"
                   "观察登录频率限制。",
        "fix": "强密码策略；MFA；登录限速；锁定策略；单点登录。",
        "impact": "身份冒用、横向移动。",
    },
    "info_disclosure": {
        "cwe": "CWE-200", "owasp": "A01", "base_score": 5.3,
        "level": "medium",
        "vector": "Network/Low/None/None/None/Low/None/Low",
        "exploit": "查看 /.git 、/.env、/robots.txt、debug 报错堆栈；"
                   "观察版本指纹。",
        "fix": "关闭调试模式；隐藏版本号；移除敏感备份文件；错误页脱敏。",
        "impact": "信息收集、辅助进一步攻击。",
    },
}

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _classify_type(name: str) -> str:
    n = (name or "").lower()
    table = [
        (("sql", "注入", "sqli"), "sql_injection"),
        (("xss", "跨站脚本"), "xss"),
        (("ssrf",), "ssrf"),
        (("rce", "代码执行", "命令执行", "远程代码"), "rce"),
        (("反序列化", "deserialization"), "deserialization"),
        (("路径", "目录穿越", "traversal", "lfi"), "path_traversal"),
        (("弱口令", "爆破", "弱认证", "weak"), "weak_auth"),
        (("信息泄露", "指纹", "disclosure", "exposure"), "info_disclosure"),
    ]
    for keys, key in table:
        if any(k in n for k in keys):
            return key
    return "info_disclosure"


def _rule_analyze(vuln: Dict[str, Any]) -> Dict[str, Any]:
    vtype = _classify_type(vuln.get("type") or vuln.get("name", ""))
    kb = _RULE_KB.get(vtype, _RULE_KB["info_disclosure"])
    # 上下文微调：是否认证后、是否公网 -> 上调
    score = kb["base_score"]
    level = kb["level"]
    ctx_notes: List[str] = []
    if vuln.get("requires_auth") is False:
        score = min(10.0, score + 0.5)
        ctx_notes.append("无需认证即可触发，风险上调")
    if vuln.get("has_poc"):
        score = min(10.0, score + 0.3)
        ctx_notes.append("已存在可用 PoC，利用难度低")
    if vuln.get("is_internal"):
        score = max(0.0, score - 1.0)
        ctx_notes.append("仅内网可达，外部暴露面有限")
    level = _score_to_level(score)
    return {
        "vuln_id": vuln.get("id"),
        "name": vuln.get("name") or vtype,
        "type": vtype,
        "cwe": kb["cwe"], "owasp": kb["owasp"],
        "cvss_score": round(score, 1),
        "cvss_vector": kb["vector"],
        "severity": level,
        "exploit_advice": kb["exploit"],
        "fix_advice": kb["fix"],
        "impact": kb["impact"],
        "context_adjustments": ctx_notes,
    }


def _score_to_level(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


class VulnAnalyzer:
    """漏洞智能分析器。"""

    def analyze_one(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        rule = _rule_analyze(vuln)
        el = get_enhanced_llm()
        sys_p = ("你是资深渗透测试专家。基于给出的漏洞信息，用专业、简练的中文"
                 "输出：1)严重度判断依据 2)一句话利用建议 3)一句话修复建议。"
                 "不要编造不存在的细节。")
        user_p = (f"漏洞名称：{rule['name']}\n类型：{rule['type']}\n"
                  f"规则CVSS：{rule['cvss_score']}（{rule['severity']}）\n"
                  f"CWE：{rule['cwe']}  OWASP：{rule['owasp']}\n"
                  f"详情：{vuln.get('detail', '')}\n"
                  f"请给出你的专业判断。")
        r = el.chat(sys_p, user_p, rule_fallback="", task="vuln_analysis",
                    max_tokens=512)
        rule["engine"] = r["engine"]
        rule["latency_ms"] = r["latency_ms"]
        if r["engine"] == "llm" and r["content"]:
            rule["ai_judgement"] = r["content"]
        else:
            rule["ai_judgement"] = (
                f"规则模式判断：{rule['name']} 属 {rule['severity']} 级。"
                f"{rule['impact']} 建议优先按修复方案处理。")
        return rule

    def analyze_batch(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = [self.analyze_one(v) for v in vulns]
        sev_count: Dict[str, int] = {"critical": 0, "high": 0,
                                      "medium": 0, "low": 0, "info": 0}
        for r in results:
            sev_count[r["severity"]] = sev_count.get(r["severity"], 0) + 1
        sorted_v = sorted(results,
                          key=lambda x: _SEVERITY_ORDER.get(x["severity"], 0),
                          reverse=True)
        return {
            "total": len(results),
            "severity_count": sev_count,
            "priority_order": [r["name"] for r in sorted_v],
            "top_risk": sorted_v[0]["name"] if sorted_v else None,
            "items": results,
        }


_singleton: Optional[VulnAnalyzer] = None


def get_vuln_analyzer() -> VulnAnalyzer:
    global _singleton
    if _singleton is None:
        _singleton = VulnAnalyzer()
    return _singleton
