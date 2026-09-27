# -*- coding: utf-8 -*-
"""rule_optimizer_pro.py — 规则优化器Pro。

功能：
1. 优化nuclei扫描规则，排除常见误报（测试页面/默认页面/静态资源）
2. 基于历史FP统计自动收紧规则
3. 规则版本管理与回滚
4. 白名单路径/参数自动跳过
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional


# 已知误报特征库：这些pattern命中的finding直接标记为FP候选
FP_SIGNATURES: List[Dict[str, Any]] = [
    {
        "id": "fp-default-page",
        "name": "默认/测试页面",
        "pattern": r"(?i)(index of /|apache2 default|nginx welcome|iisstart\.htm|welcome to)",
        "severity_block": "all",
        "description": "Web服务器默认欢迎页/测试页，非真实漏洞",
    },
    {
        "id": "fp-static-asset",
        "name": "静态资源目录",
        "pattern": r"(?i)\.(css|js|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot)(\?|$)",
        "severity_block": "all",
        "description": "静态资源文件，不含可执行逻辑",
    },
    {
        "id": "fp-docs-w3c",
        "name": "W3C/规范文档",
        "pattern": r"(?i)(w3\.org|validator\.w3\.org|whatwg\.org)",
        "severity_block": "all",
        "description": "标准文档引用，非漏洞",
    },
    {
        "id": "fp-demo-framework",
        "name": "Demo/示例框架页",
        "pattern": r"(?i)(laravel.*welcome|symfony.*welcome|django.*debug.*toolbar|rails.*welcome)",
        "severity_block": "all",
        "description": "框架自带Demo页，非业务漏洞",
    },
    {
        "id": "fp-security-header-missing",
        "name": "安全头缺失(低危噪声)",
        "pattern": r"(?i)(x-frame-options.*missing|content-security-policy.*not.*found|x-content-type-options.*missing)",
        "severity_block": "low",
        "description": "安全头缺失默认低危，噪声大，需严格过滤",
    },
    {
        "id": "fp-tech-fingerprint",
        "name": "技术栈指纹(非漏洞)",
        "pattern": r"(?i)(powered by x-generator|x-powered-by:.*php|server:.*apache.*2\.2)",
        "severity_block": "all",
        "description": "版本指纹披露，通常低危且噪声大",
    },
    {
        "id": "fp-cookie-no-httponly",
        "name": "Cookie未设HttpOnly",
        "pattern": r"(?i)(cookie.*without.*httponly|session.*cookie.*not.*httponly)",
        "severity_block": "low",
        "description": "Cookie属性建议，非可利用漏洞",
    },
    {
        "id": "fp-outdated-lib",
        "name": "过期库版本(无CVE)",
        "pattern": r"(?i)(jquery.*1\.[0-9]|bootstrap.*3\.[0-9])",
        "severity_block": "low",
        "description": "仅版本号旧但无明确CVE利用链",
    },
]

# 白名单：已知安全的路径/参数自动跳过
WHITELIST_PATHS: List[Dict[str, str]] = [
    {"pattern": r"(?i)/favicon\.ico$", "reason": "网站图标，无安全风险"},
    {"pattern": r"(?i)/robots\.txt$", "reason": "爬虫协议文件"},
    {"pattern": r"(?i)/sitemap\.xml$", "reason": "站点地图"},
    {"pattern": r"(?i)/static/.*\.(css|js|png|jpg|svg)", "reason": "静态资源目录"},
    {"pattern": r"(?i)/assets/.*\.(css|js|png|jpg|svg)", "reason": "前端打包资源"},
    {"pattern": r"(?i)/vendor/.*\.(php|css|js)", "reason": "第三方依赖目录"},
    {"pattern": r"(?i)/\.well-known/.*", "reason": "Let's Encrypt验证路径"},
    {"pattern": r"(?i)/healthz?$", "reason": "健康检查端点"},
    {"pattern": r"(?i)/metrics$", "reason": "监控指标端点"},
]


class RuleOptimizerPro:
    """规则优化器Pro：基于误报统计自动调优nuclei/扫描规则。"""

    def __init__(self) -> None:
        self._version = "1.0.0-pro"
        self._rules: Dict[str, Dict[str, Any]] = self._init_rules()
        self._fp_signatures: List[Dict[str, Any]] = list(FP_SIGNATURES)
        self._whitelist: List[Dict[str, str]] = list(WHITELIST_PATHS)
        self._history: List[Dict[str, Any]] = []
        self._custom_rules: Dict[str, Dict[str, Any]] = {}
        self._stats: Dict[str, int] = {
            "total_findings_seen": 0,
            "fp_filtered": 0,
            "tp_kept": 0,
            "whitelist_skipped": 0,
        }

    def _init_rules(self) -> Dict[str, Dict[str, Any]]:
        """初始化优化后的规则集（Pro版）。"""
        return {
            "sql_injection": {
                "severity": "high",
                "min_evidence": 2,
                "evidence_keywords": [
                    "' OR 1=1--", "UNION SELECT", "sleep(", "BENCHMARK(",
                    "information_schema", "pg_sleep(", "WAITFOR DELAY",
                ],
                "exclude_patterns": [
                    r"(?i)(search=.*')",  # 搜索框单引号反射不算
                ],
                "requires_verification": True,
                "description": "SQL注入 — 需真实payload验证数据泄露",
            },
            "xss_reflected": {
                "severity": "medium",
                "min_evidence": 1,
                "evidence_keywords": [
                    "<script>", "onerror=", "onload=", "javascript:",
                    "<img src=x", "<svg onload",
                ],
                "exclude_patterns": [
                    r"(?i)(&lt;script&gt;)",  # HTML编码的不算反射
                    r"(?i)(//w3\.org)",
                ],
                "requires_verification": True,
                "description": "反射型XSS — 需检查响应中未编码反射",
            },
            "xss_stored": {
                "severity": "high",
                "min_evidence": 1,
                "evidence_keywords": ["<script>", "onload=", "onerror="],
                "exclude_patterns": [],
                "requires_verification": True,
                "description": "存储型XSS — 需二次请求验证持久化",
            },
            "path_traversal": {
                "severity": "high",
                "min_evidence": 2,
                "evidence_keywords": [
                    "../../../etc/passwd", "..\\..\\..\\windows\\",
                    "..%2f..%2f..%2f", "....//....//....//",
                ],
                "exclude_patterns": [
                    r"(?i)(static|assets|vendor)",  # 静态目录不算遍历
                ],
                "requires_verification": True,
                "description": "目录遍历 — 需验证能读取敏感文件内容",
            },
            "command_injection": {
                "severity": "critical",
                "min_evidence": 2,
                "evidence_keywords": [
                    ";id", "&&id", "|whoami", "`id`",
                    ";cat /etc/passwd", "|uname -a",
                ],
                "exclude_patterns": [],
                "requires_verification": True,
                "description": "命令注入 — 需验证命令执行回显",
            },
            "sensitive_info_disclosure": {
                "severity": "medium",
                "min_evidence": 1,
                "evidence_keywords": [
                    ".git/config", ".env", ".svn/entries",
                    "backup.sql", "dump.sql", "web.config.bak",
                    ".DS_Store", "id_rsa",
                ],
                "exclude_patterns": [
                    r"(?i)(.env\.example)",  # 示例文件不算
                ],
                "requires_verification": True,
                "description": "敏感信息泄露 — 需验证文件可下载且含敏感数据",
            },
            "directory_listing": {
                "severity": "low",
                "min_evidence": 2,
                "evidence_keywords": [
                    "Index of /", "Parent Directory", "[To Parent Directory]",
                ],
                "exclude_patterns": [
                    r"(?i)(/icons/|/manual/)",  # Apache默认图标目录不算
                ],
                "requires_verification": False,
                "description": "目录列表 — 特征明确，可直接判定",
            },
            "weak_password": {
                "severity": "medium",
                "min_evidence": 1,
                "evidence_keywords": [
                    "admin:admin", "root:root", "test:test",
                    "admin:123456", "guest:guest",
                ],
                "exclude_patterns": [],
                "requires_verification": True,
                "description": "弱口令 — 需验证登录成功",
            },
            "ssrf": {
                "severity": "high",
                "min_evidence": 2,
                "evidence_keywords": [
                    "169.254.169.254", "metadata.google.internal",
                    "internal:8080", "localhost:6379",
                ],
                "exclude_patterns": [],
                "requires_verification": True,
                "description": "SSRF — 需验证内网资源可达",
            },
            "deserialization": {
                "severity": "critical",
                "min_evidence": 1,
                "evidence_keywords": [
                    "rO0AB", "aced0005", "base64.*object",
                    "java.lang.Runtime", "popchain",
                ],
                "exclude_patterns": [],
                "requires_verification": True,
                "description": "反序列化 — 需验证RCE或回显",
            },
        }

    def get_rules(self) -> Dict[str, Any]:
        """返回当前规则集概览。"""
        return {
            "version": self._version,
            "total_rules": len(self._rules),
            "rules": self._rules,
            "fp_signatures_count": len(self._fp_signatures),
            "whitelist_count": len(self._whitelist),
            "stats": dict(self._stats),
            "history_count": len(self._history),
        }

    def get_fp_signatures(self) -> List[Dict[str, Any]]:
        return list(self._fp_signatures)

    def get_whitelist(self) -> List[Dict[str, str]]:
        return list(self._whitelist)

    def add_fp_signature(self, sig_id: str, name: str, pattern: str,
                         description: str = "") -> Dict[str, Any]:
        """添加自定义误报特征。"""
        sig = {
            "id": sig_id, "name": name, "pattern": pattern,
            "severity_block": "all", "description": description,
        }
        self._fp_signatures.append(sig)
        self._history.append({
            "ts": datetime.utcnow().isoformat() + "Z",
            "action": "add_fp_signature", "sig_id": sig_id,
        })
        return sig

    def add_whitelist(self, pattern: str, reason: str = "") -> Dict[str, str]:
        """添加白名单路径。"""
        entry = {"pattern": pattern, "reason": reason}
        self._whitelist.append(entry)
        self._history.append({
            "ts": datetime.utcnow().isoformat() + "Z",
            "action": "add_whitelist", "pattern": pattern,
        })
        return entry

    def is_whitelisted(self, url: str) -> Optional[Dict[str, str]]:
        """检查URL是否命中白名单。"""
        for w in self._whitelist:
            if re.search(w["pattern"], url):
                self._stats["whitelist_skipped"] += 1
                return w
        return None

    def match_fp_signature(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """检查finding是否命中已知误报特征。"""
        text = " ".join(str(x) for x in (
            finding.get("name", ""), finding.get("detail", ""),
            finding.get("url", ""), finding.get("title", ""),
            finding.get("severity", ""),
        ))
        for sig in self._fp_signatures:
            if re.search(sig["pattern"], text):
                # severity_block过滤
                block = sig.get("severity_block", "all")
                if block != "all":
                    sev = (finding.get("severity") or "").lower()
                    if block == "low" and sev not in ("low", "info"):
                        continue
                return sig
        return None

    def optimize_rules(self, fp_per_rule: Dict[str, int],
                       tp_per_rule: Dict[str, int]) -> Dict[str, Any]:
        """根据FP/TP统计自动优化规则。

        策略：
        - FP率 > 30% 的规则自动收紧（提高min_evidence、加exclude_patterns）
        - FP率 > 50% 的规则直接降级或标记为默认隐藏
        """
        changes: List[Dict[str, Any]] = []
        for rule_name, rule in self._rules.items():
            fp = fp_per_rule.get(rule_name, 0)
            tp = tp_per_rule.get(rule_name, 0)
            total = fp + tp
            if total == 0:
                continue
            fp_rate = fp / total
            if fp_rate > 0.5:
                # FP率>50%：严重收紧
                rule["min_evidence"] = max(rule.get("min_evidence", 1), 3)
                rule["auto_hide"] = True
                changes.append({
                    "rule": rule_name, "action": "strict_hide",
                    "fp_rate": f"{fp_rate:.2%}",
                    "reason": f"FP率{fp_rate:.0%}>50%，自动隐藏需手动确认",
                })
            elif fp_rate > 0.3:
                # FP率>30%：收紧
                rule["min_evidence"] = rule.get("min_evidence", 1) + 1
                changes.append({
                    "rule": rule_name, "action": "tighten",
                    "fp_rate": f"{fp_rate:.2%}",
                    "reason": f"FP率{fp_rate:.0%}>30%，提高证据要求",
                })
        snapshot = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "fp_per_rule": fp_per_rule,
            "tp_per_rule": tp_per_rule,
            "changes": changes,
        }
        self._history.append(snapshot)
        return snapshot

    def apply_rules_to_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """对一批finding应用规则过滤，返回过滤结果。"""
        kept: List[Dict[str, Any]] = []
        filtered_fp: List[Dict[str, Any]] = []
        whitelisted: List[Dict[str, Any]] = []
        self._stats["total_findings_seen"] += len(findings)

        for f in findings:
            url = f.get("url", "")
            # 1. 白名单跳过
            wl = self.is_whitelisted(url)
            if wl:
                f["_whitelisted"] = wl["reason"]
                whitelisted.append(f)
                continue
            # 2. 已知误报特征匹配
            sig = self.match_fp_signature(f)
            if sig:
                f["_fp_signature"] = sig["name"]
                filtered_fp.append(f)
                continue
            # 3. 规则证据检查
            rule_type = (f.get("type") or "").lower()
            rule = self._rules.get(rule_type)
            if rule:
                evidence = " ".join(str(x) for x in (
                    f.get("detail", ""), f.get("evidence", ""), f.get("name", "")
                ))
                kws = [k.lower() for k in rule.get("evidence_keywords", [])]
                matched = sum(1 for k in kws if k in evidence.lower())
                min_ev = rule.get("min_evidence", 1)
                if matched < min_ev:
                    f["_filtered_reason"] = (
                        f"证据不足: {matched}/{min_ev} keywords"
                    )
                    filtered_fp.append(f)
                    continue
                # 排除模式检查
                excl = rule.get("exclude_patterns", [])
                if excl and any(re.search(e, evidence) for e in excl):
                    f["_filtered_reason"] = "命中排除模式"
                    filtered_fp.append(f)
                    continue
            f["_rule_passed"] = True
            kept.append(f)
            self._stats["tp_kept"] += 1

        self._stats["fp_filtered"] += len(filtered_fp)
        return {
            "total": len(findings),
            "kept": kept,
            "filtered_fp": filtered_fp,
            "whitelisted": whitelisted,
            "filter_stats": {
                "kept_count": len(kept),
                "fp_filtered_count": len(filtered_fp),
                "whitelisted_count": len(whitelisted),
                "fp_rate_after_filter": (
                    len(filtered_fp) / len(findings) if findings else 0
                ),
            },
        }

    def get_stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    def reset_stats(self) -> None:
        self._stats = {k: 0 for k in self._stats}


_singleton: Optional[RuleOptimizerPro] = None


def get_rule_optimizer_pro() -> RuleOptimizerPro:
    global _singleton
    if _singleton is None:
        _singleton = RuleOptimizerPro()
    return _singleton
