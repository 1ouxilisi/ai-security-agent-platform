# -*- coding: utf-8 -*-
"""
dynamic_adjuster.py — 动态调整器。

当某个渗透步骤失败时，记录失败原因，并从“替代策略池”中自动挑选下一个
尝试方向。例如：
    SQL 注入失败 → 换 XSS → 换目录遍历 → 换越权访问
    端口扫描无结果 → 换 CDN 绕过 → 换子域名枚举 → 换历史 DNS

设计为纯内存、可序列化，供 autonomous_agent 在运行时调用。
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 失败 → 替代策略映射
# --------------------------------------------------------------------------- #
# key: 失败的技术方向；value: 按优先级排列的替代方向
_FALLBACK_CHAIN: Dict[str, List[str]] = {
    "sql_injection": ["xss", "directory_traversal", "auth_bypass", "ssrf"],
    "xss": ["directory_traversal", "sql_injection", "csrf", "open_redirect"],
    "directory_traversal": ["lfi_rfi", "file_upload", "auth_bypass"],
    "lfi_rfi": ["directory_traversal", "file_upload", "ssrf"],
    "auth_bypass": ["weak_password", "session_fixation", "jwt_none"],
    "weak_password": ["default_credential", "auth_bypass", "two_factor_bypass"],
    "port_scan_empty": ["cdn_bypass", "subdomain_enum", "historical_dns", "whois_osint"],
    "subdomain_enum_empty": ["permutation_brute", "cert_transparency", "search_engine_osint"],
    "file_upload": ["content_type_bypass", "webshell_upload", "race_condition"],
    "ssrf": ["internal_port_scan", "cloud_metadata", "redis_unauth"],
    "cve_no_match": ["version_fuzz", "misconfig_check", "exposed_panel"],
    "default": ["recon_refresh", "other_attack_surface", "report_partial"],
}

# 策略元信息（每个替代方向的描述与预期收益）
_STRATEGY_META: Dict[str, Dict[str, str]] = {
    "sql_injection": {"label": "SQL 注入检测", "benefit": "可能直接拖库"},
    "xss": {"label": "XSS 跨站脚本", "benefit": "会话劫持 / 钓鱼"},
    "directory_traversal": {"label": "目录遍历", "benefit": "读取敏感文件"},
    "lfi_rfi": {"label": "文件包含", "benefit": "本地文件读取 / 代码执行"},
    "auth_bypass": {"label": "认证绕过", "benefit": "未授权访问后台"},
    "weak_password": {"label": "弱口令爆破", "benefit": "直接登录"},
    "default_credential": {"label": "默认凭据", "benefit": "设备/组件后台登录"},
    "session_fixation": {"label": "会话固定", "benefit": "劫持会话"},
    "jwt_none": {"label": "JWT 算法混淆", "benefit": "伪造令牌"},
    "csrf": {"label": "CSRF 跨站请求", "benefit": "篡改用户操作"},
    "open_redirect": {"label": "开放重定向", "benefit": "钓鱼 / 令牌泄露"},
    "file_upload": {"label": "文件上传", "benefit": "Webshell 落地"},
    "content_type_bypass": {"label": "Content-Type 绕过", "benefit": "绕过上传校验"},
    "webshell_upload": {"label": "Webshell 上传", "benefit": "远程命令执行"},
    "race_condition": {"label": "竞态条件", "benefit": "业务逻辑绕过"},
    "ssrf": {"label": "SSRF 服务端请求伪造", "benefit": "访问内网"},
    "internal_port_scan": {"label": "内网端口扫描", "benefit": "内网测绘"},
    "cloud_metadata": {"label": "云元数据获取", "benefit": "云凭证泄露"},
    "redis_unauth": {"label": "Redis 未授权", "benefit": "写计划任务/公钥"},
    "cdn_bypass": {"label": "CDN 源站绕过", "benefit": "拿到真实 IP"},
    "subdomain_enum": {"label": "子域名枚举", "benefit": "扩大攻击面"},
    "historical_dns": {"label": "历史 DNS 记录", "benefit": "发现旧资产"},
    "whois_osint": {"label": "WHOIS/OSINT", "benefit": "收集关联信息"},
    "permutation_brute": {"label": "排列爆破子域", "benefit": "发现隐藏子域"},
    "cert_transparency": {"label": "证书透明度", "benefit": "枚举子域"},
    "search_engine_osint": {"label": "搜索引擎 OSINT", "benefit": "被动信息收集"},
    "version_fuzz": {"label": "版本模糊测试", "benefit": "精确指纹"},
    "misconfig_check": {"label": "错误配置检查", "benefit": "后台/默认页"},
    "exposed_panel": {"label": "暴露管理面板", "benefit": "未授权控制台"},
    "recon_refresh": {"label": "刷新侦察", "benefit": "重新测绘"},
    "other_attack_surface": {"label": "其他攻击面", "benefit": "扩大范围"},
    "report_partial": {"label": "部分结果出报告", "benefit": "收尾"},
}


@dataclass
class AdjustmentEvent:
    """一次失败 → 换策略事件。"""

    event_id: str
    session_id: str
    failed_direction: str
    failure_reason: str
    fallback_chain: List[str]
    chosen: str
    round_no: int
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DynamicAdjuster:
    """失败时记录原因并推荐替代策略。"""

    def __init__(self) -> None:
        self._events: Dict[str, List[AdjustmentEvent]] = {}
        # 每个 session 当前已尝试过的方向，避免重复
        self._tried: Dict[str, List[str]] = {}

    # ------------------------------------------------------------------ #
    def record_failure(self, session_id: str, failed_direction: str,
                       failure_reason: str,
                       extra_tried: Optional[List[str]] = None) -> Dict[str, Any]:
        """记录一次失败并挑选下一个策略。"""
        chain = _FALLBACK_CHAIN.get(failed_direction,
                                    _FALLBACK_CHAIN["default"])
        tried = self._tried.setdefault(session_id, [])
        if failed_direction not in tried:
            tried.append(failed_direction)
        if extra_tried:
            for t in extra_tried:
                if t not in tried:
                    tried.append(t)

        chosen = ""
        for cand in chain:
            if cand not in tried:
                chosen = cand
                break

        ev = AdjustmentEvent(
            event_id=f"adj_{uuid.uuid4().hex[:8]}",
            session_id=session_id,
            failed_direction=failed_direction,
            failure_reason=failure_reason,
            fallback_chain=chain,
            chosen=chosen or "report_partial",
            round_no=len(self._events.get(session_id, [])) + 1,
        )
        self._events.setdefault(session_id, []).append(ev)
        if chosen:
            tried.append(chosen)
        return ev.to_dict()

    def mark_tried(self, session_id: str, direction: str) -> None:
        self._tried.setdefault(session_id, []).append(direction)

    # ------------------------------------------------------------------ #
    def get_events(self, session_id: str) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._events.get(session_id, [])]

    def get_fallback_chain(self, direction: str) -> List[Dict[str, Any]]:
        chain = _FALLBACK_CHAIN.get(direction, _FALLBACK_CHAIN["default"])
        out = []
        for d in chain:
            meta = _STRATEGY_META.get(d, {"label": d, "benefit": ""})
            out.append({"direction": d, **meta})
        return out

    def list_strategies(self) -> List[Dict[str, Any]]:
        return [
            {"direction": k, **v} for k, v in _STRATEGY_META.items()
        ]

    def stats(self) -> Dict[str, Any]:
        total = sum(len(v) for v in self._events.values())
        return {
            "sessions_with_adjustment": len(self._events),
            "total_adjustments": total,
            "strategy_pool_size": len(_STRATEGY_META),
        }


adjuster = DynamicAdjuster()
