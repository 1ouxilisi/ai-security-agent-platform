# -*- coding: utf-8 -*-
"""fp_filter_engine.py — 误报过滤引擎。

功能：
1. 已知误报特征库自动排除
2. 白名单机制（已知安全的路径/参数自动跳过）
3. 多轮过滤流水线
4. 过滤效果统计与分析
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional


# 综合误报规则库：分类组织
FP_RULES_LIBRARY: List[Dict[str, Any]] = [
    # === 测试页面/框架默认页 ===
    {
        "category": "default_page",
        "id": "apache_default",
        "pattern": r"(?i)(Apache2 Ubuntu Default Page|It works!)",
        "description": "Apache默认欢迎页",
        "action": "filter",
    },
    {
        "category": "default_page",
        "id": "nginx_welcome",
        "pattern": r"(?i)(Welcome to nginx!|nginx is installed)",
        "description": "Nginx默认欢迎页",
        "action": "filter",
    },
    {
        "category": "default_page",
        "id": "iis_start",
        "pattern": r"(?i)(IIS Windows Server|Under Construction)",
        "description": "IIS默认页",
        "action": "filter",
    },
    {
        "category": "default_page",
        "id": "tomcat_default",
        "pattern": r"(?i)(Apache Tomcat.*Web Application Manager|Tomcat documentation)",
        "description": "Tomcat默认管理页",
        "action": "filter",
    },
    {
        "category": "default_page",
        "id": "laravel_welcome",
        "pattern": r"(?i)(Laravel.*PHP Framework|Laravel Documentation)",
        "description": "Laravel欢迎页",
        "action": "filter",
    },
    # === 静态资源/框架引用 ===
    {
        "category": "static_resource",
        "id": "css_file",
        "pattern": r"(?i)\.css(\?|$)",
        "description": "CSS样式文件",
        "action": "filter",
    },
    {
        "category": "static_resource",
        "id": "js_file",
        "pattern": r"(?i)\.js(\?|$)",
        "description": "JavaScript文件",
        "action": "filter",
    },
    {
        "category": "static_resource",
        "id": "image_file",
        "pattern": r"(?i)\.(png|jpg|jpeg|gif|bmp|webp|ico|svg)(\?|$)",
        "description": "图片文件",
        "action": "filter",
    },
    {
        "category": "static_resource",
        "id": "font_file",
        "pattern": r"(?i)\.(woff2?|ttf|eot|otf)(\?|$)",
        "description": "字体文件",
        "action": "filter",
    },
    # === 低价值安全建议 ===
    {
        "category": "security_header_noise",
        "id": "missing_frame_options",
        "pattern": r"(?i)(X-Frame-Options.*(not set|missing|absent))",
        "description": "缺失X-Frame-Options头",
        "action": "downgrade",
    },
    {
        "category": "security_header_noise",
        "id": "missing_csp",
        "pattern": r"(?i)(Content-Security-Policy.*(not set|missing|absent))",
        "description": "缺失CSP头",
        "action": "downgrade",
    },
    {
        "category": "security_header_noise",
        "id": "cookie_no_httponly",
        "pattern": r"(?i)(cookie.*(not set with|missing).*HttpOnly)",
        "description": "Cookie未设HttpOnly",
        "action": "downgrade",
    },
    {
        "category": "security_header_noise",
        "id": "cookie_no_secure",
        "pattern": r"(?i)(cookie.*(not set with|missing).*Secure)",
        "description": "Cookie未设Secure",
        "action": "downgrade",
    },
    # === 版本指纹噪声 ===
    {
        "category": "tech_fingerprint",
        "id": "server_version_disclosure",
        "pattern": r"(?i)(Server:.*(Apache|Nginx|IIS).*\d+\.\d+)",
        "description": "服务器版本披露",
        "action": "downgrade",
    },
    {
        "category": "tech_fingerprint",
        "id": "x_powered_by",
        "pattern": r"(?i)(X-Powered-By:.*(PHP|Express|ASP\.NET))",
        "description": "技术栈披露头",
        "action": "downgrade",
    },
    # === 编码/输出防护误报 ===
    {
        "category": "encoding_false_positive",
        "id": "html_encoded_xss",
        "pattern": r"(?i)(&lt;script&gt;|&lt;img)",
        "description": "HTML编码输出，非XSS漏洞",
        "action": "filter",
    },
    {
        "category": "encoding_false_positive",
        "id": "url_encoded_traversal",
        "pattern": r"(?i)(%252e%252e|%252f).*not.*decoded",
        "description": "双重编码未解码，非真实遍历",
        "action": "filter",
    },
]

# 白名单路径规则
WHITELIST_RULES: List[Dict[str, str]] = [
    {"path": "/favicon.ico", "reason": "网站图标"},
    {"path": "/robots.txt", "reason": "爬虫协议"},
    {"path": "/sitemap.xml", "reason": "站点地图"},
    {"path": "/static/", "reason": "静态资源目录", "prefix": True},
    {"path": "/assets/", "reason": "前端资源目录", "prefix": True},
    {"path": "/vendor/", "reason": "第三方依赖", "prefix": True},
    {"path": "/node_modules/", "reason": "Node.js依赖", "prefix": True},
    {"path": "/.well-known/", "reason": "证书验证路径", "prefix": True},
    {"path": "/health", "reason": "健康检查"},
    {"path": "/healthz", "reason": "K8s健康检查"},
    {"path": "/ready", "reason": "就绪检查"},
    {"path": "/metrics", "reason": "Prometheus指标"},
    {"path": "/api-docs", "reason": "Swagger文档", "prefix": True},
    {"path": "/swagger", "reason": "Swagger UI", "prefix": True},
    {"path": "/openapi", "reason": "OpenAPI文档", "prefix": True},
]


class FPFilterEngine:
    """误报过滤引擎：多阶段流水线过滤。"""

    def __init__(self) -> None:
        self._rules: List[Dict[str, Any]] = list(FP_RULES_LIBRARY)
        self._whitelist: List[Dict[str, str]] = list(WHITELIST_RULES)
        self._custom_rules: List[Dict[str, Any]] = []
        self._custom_whitelist: List[Dict[str, str]] = []
        self._filter_log: List[Dict[str, Any]] = []
        self._stats: Dict[str, int] = {
            "total_input": 0,
            "whitelist_filtered": 0,
            "rule_filtered": 0,
            "rule_downgraded": 0,
            "passed": 0,
        }

    def get_rules(self) -> Dict[str, Any]:
        return {
            "total_rules": len(self._rules) + len(self._custom_rules),
            "categories": self._categorize_rules(),
            "builtin_rules": self._rules,
            "custom_rules": self._custom_rules,
            "whitelist_count": len(self._whitelist) + len(self._custom_whitelist),
            "whitelist": self._whitelist + self._custom_whitelist,
        }

    def _categorize_rules(self) -> Dict[str, int]:
        cats: Dict[str, int] = {}
        for r in self._rules:
            c = r.get("category", "uncategorized")
            cats[c] = cats.get(c, 0) + 1
        return cats

    def add_rule(self, category: str, rule_id: str, pattern: str,
                 description: str, action: str = "filter") -> Dict[str, Any]:
        """添加自定义误报过滤规则。"""
        rule = {
            "category": category, "id": f"custom_{rule_id}",
            "pattern": pattern, "description": description,
            "action": action,
        }
        self._custom_rules.append(rule)
        return rule

    def remove_rule(self, rule_id: str) -> bool:
        """删除自定义规则。"""
        before = len(self._custom_rules)
        self._custom_rules = [r for r in self._custom_rules
                              if r["id"] != rule_id]
        return len(self._custom_rules) < before

    def add_whitelist(self, path: str, reason: str = "",
                      prefix: bool = False) -> Dict[str, str]:
        """添加白名单路径。"""
        entry = {"path": path, "reason": reason}
        if prefix:
            entry["prefix"] = "true"
        self._custom_whitelist.append(entry)
        return entry

    def is_whitelisted(self, url_path: str) -> Optional[Dict[str, str]]:
        """检查URL路径是否在白名单中。"""
        all_wl = self._whitelist + self._custom_whitelist
        for w in all_wl:
            wp = w["path"]
            if w.get("prefix"):
                if url_path.startswith(wp):
                    return w
            else:
                if url_path == wp or url_path.startswith(wp + "?"):
                    return w
        return None

    def filter_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """对一批finding执行多阶段过滤。

        流水线：
        1. 白名单阶段 — 安全路径直接跳过
        2. 规则过滤阶段 — 匹配FP规则直接过滤
        3. 规则降级阶段 — 匹配降级规则降低严重级别
        4. 通过阶段 — 保留给后续二次验证
        """
        self._stats["total_input"] += len(findings)
        passed: List[Dict[str, Any]] = []
        filtered: List[Dict[str, Any]] = []
        downgraded: List[Dict[str, Any]] = []
        wl_filtered: List[Dict[str, Any]] = []

        all_rules = self._rules + self._custom_rules

        for f in findings:
            url_path = f.get("url", "")
            text = " ".join(str(x) for x in (
                f.get("name", ""), f.get("detail", ""),
                f.get("title", ""), url_path,
            ))

            # 阶段1: 白名单
            wl = self.is_whitelisted(url_path)
            if wl:
                f["_filter_stage"] = "whitelist"
                f["_filter_reason"] = wl.get("reason", "whitelisted")
                wl_filtered.append(f)
                self._stats["whitelist_filtered"] += 1
                continue

            # 阶段2&3: 规则匹配
            matched_rule = None
            for rule in all_rules:
                if re.search(rule["pattern"], text):
                    matched_rule = rule
                    break

            if matched_rule:
                f["_matched_rule"] = matched_rule["id"]
                f["_filter_category"] = matched_rule["category"]
                f["_filter_description"] = matched_rule["description"]
                if matched_rule["action"] == "filter":
                    f["_filter_stage"] = "rule_filter"
                    filtered.append(f)
                    self._stats["rule_filtered"] += 1
                else:
                    # downgrade
                    f["_filter_stage"] = "rule_downgrade"
                    f["original_severity"] = f.get("severity", "medium")
                    f["severity"] = "low"
                    f["_downgrade_reason"] = matched_rule["description"]
                    downgraded.append(f)
                    self._stats["rule_downgraded"] += 1
                continue

            # 通过所有过滤
            f["_filter_stage"] = "passed"
            passed.append(f)
            self._stats["passed"] += 1

        self._filter_log.append({
            "ts": datetime.utcnow().isoformat() + "Z",
            "input_count": len(findings),
            "passed_count": len(passed),
            "whitelist_count": len(wl_filtered),
            "filtered_count": len(filtered),
            "downgraded_count": len(downgraded),
        })

        total = len(findings) or 1
        return {
            "input": len(findings),
            "passed": passed,
            "whitelist_filtered": wl_filtered,
            "rule_filtered": filtered,
            "rule_downgraded": downgraded,
            "pipeline_stats": {
                "passed_count": len(passed),
                "whitelist_count": len(wl_filtered),
                "rule_filtered_count": len(filtered),
                "rule_downgraded_count": len(downgraded),
                "pass_rate": len(passed) / total,
                "filter_rate": (len(filtered) + len(wl_filtered)) / total,
            },
        }

    def get_stats(self) -> Dict[str, Any]:
        total = self._stats["total_input"] or 1
        return {
            **self._stats,
            "pass_rate": self._stats["passed"] / total,
            "filter_rate": (self._stats["whitelist_filtered"] +
                           self._stats["rule_filtered"]) / total,
            "log_entries": len(self._filter_log),
        }

    def get_filter_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(reversed(self._filter_log[-limit:]))

    def reset_stats(self) -> None:
        self._stats = {k: 0 for k in self._stats}


_singleton: Optional[FPFilterEngine] = None


def get_fp_filter_engine() -> FPFilterEngine:
    global _singleton
    if _singleton is None:
        _singleton = FPFilterEngine()
    return _singleton
