# -*- coding: utf-8 -*-
"""
ai_upgrade/ai_upgrade_dashboard.py — AI 能力聚合 & 智能攻击链规划

聚合：漏洞分析 / 报告生成 / 智能问答 / SRC 助手 / LLM 状态 / 决策日志。
并实现「AI 渗透决策真正智能」：
    - 攻击链规划：从信息收集 -> 初始访问 -> 权限提升 -> 横向移动 -> 权限维持
    - 动态调整：某一步失败，AI 自动换策略（备选路径）
    - 决策依据可视化：每一步带 reasoning / evidence / confidence
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from .llm_integration import get_enhanced_llm, get_decision_log
from .vuln_analyzer import get_vuln_analyzer
from .report_writer import get_report_writer
from .smart_qa import get_smart_qa
from .src_assistant import get_src_assistant

# 攻击链存储
CHAINS: Dict[str, Dict[str, Any]] = {}


# 标准攻击链阶段
CHAIN_STAGES = ["信息收集", "初始访问", "权限提升", "横向移动", "权限维持"]


def _rule_plan_chain(target: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """基于发现的漏洞，推理一条完整攻击链。"""
    fmap = {f.get("type"): f for f in findings}
    steps: List[Dict[str, Any]] = [
        {
            "stage": "信息收集",
            "action": "子域枚举 + 端口/指纹识别 + 目录扫描",
            "tool_suggested": "amass / subfinder / httpx / ffuf",
            "goal": "梳理资产与技术栈，确定突破口",
            "reasoning": "攻击面决定后续成本，先做被动+主动信息收集。",
            "confidence": 0.95,
            "status": "planned",
        }
    ]
    # 初始访问：根据发现的漏洞类型选择
    if "sql_injection" in fmap:
        steps.append({
            "stage": "初始访问",
            "action": "利用 SQL 注入拖库 / 写 Webshell",
            "tool_suggested": "sqlmap",
            "goal": "获取数据库权限与服务器控制权",
            "reasoning": "存在 SQL 注入，优先用 sqlmap 验证并尝试 --os-shell。",
            "confidence": 0.9, "status": "planned",
        })
    elif "ssrf" in fmap:
        steps.append({
            "stage": "初始访问",
            "action": "SSRF 读云元数据获取临时凭证",
            "tool_suggested": "Burp Collaborator / curl",
            "goal": "拿到云 AK/SK",
            "reasoning": "SSRF 可访问 169.254.169.254，潜在高价值。",
            "confidence": 0.8, "status": "planned",
        })
    elif "weak_auth" in fmap:
        steps.append({
            "stage": "初始访问",
            "action": "爆破后台弱口令",
            "tool_suggested": "hydra / burp Intruder",
            "goal": "获得后台账号",
            "reasoning": "存在弱口令，先做字典爆破。",
            "confidence": 0.75, "status": "planned",
        })
    else:
        steps.append({
            "stage": "初始访问",
            "action": "常规 Web 漏洞利用（XSS/文件上传）",
            "tool_suggested": "Burp",
            "goal": "寻找可利用的入口点",
            "reasoning": "无明显高危入口，需手动深挖上传点。",
            "confidence": 0.5, "status": "planned",
        })

    steps.extend([
        {"stage": "权限提升",
         "action": "本地提权（内核/SUID/配置错误）",
         "tool_suggested": "linpeas / winpeas",
         "goal": "拿到 root/System",
         "reasoning": "初始 webshell 多为低权限，需提权。",
         "confidence": 0.6, "status": "planned"},
        {"stage": "横向移动",
         "action": "内网资产探测 + 凭据复用",
         "tool_suggested": "fscan / crackmapexec",
         "goal": "访问数据库/缓存等核心服务",
         "reasoning": "redis/mysql 常被错误暴露，可横向。",
         "confidence": 0.55, "status": "planned"},
        {"stage": "权限维持",
         "action": "建立隐蔽后门 / 计划任务",
         "tool_suggested": "crontab / 持久化脚本",
         "goal": "长期访问能力",
         "reasoning": "清理后仍需保留入口，注意日志规避。",
         "confidence": 0.5, "status": "planned"},
    ])
    return {"steps": steps}


class AIUpgradeDashboard:
    """聚合所有 AI 能力。"""

    def overview(self) -> Dict[str, Any]:
        llm = get_enhanced_llm().status()
        return {
            "module": "AI 能力大升级",
            "version": "2.0",
            "target_score": 9.0,
            "llm": llm,
            "capabilities": {
                "vuln_analysis": True,
                "report_writing": True,
                "smart_qa": True,
                "src_assistant": True,
                "attack_chain_planning": True,
                "dynamic_adjustment": True,
            },
            "stats": {
                "reports": len(get_report_writer().list_reports()),
                "qa_history": len(get_smart_qa().history(limit=9999)),
                "src_targets": len(get_src_assistant().list_targets()),
                "src_submissions": len(get_src_assistant().list_submissions()),
                "chains": len(CHAINS),
                "decisions": len(get_decision_log(limit=9999)),
            },
        }

    # ------------------------------------------------------------------ #
    # 攻击链规划
    # ------------------------------------------------------------------ #
    def plan_chain(self, target: str,
                   findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        rule = _rule_plan_chain(target, findings)
        el = get_enhanced_llm()
        r = el.chat(
            "你是红队战术规划专家，输出简练中文攻击链思路。",
            f"目标：{target}\n发现：{[f.get('name') for f in findings]}\n"
            "给出下一步最优策略。",
            rule_fallback="", task="attack_chain", max_tokens=300)
        cid = uuid.uuid4().hex[:10]
        chain = {
            "chain_id": cid,
            "target": target,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "engine": r["engine"],
            "ai_insight": r["content"] or "（规则模式）已基于发现规划完整攻击链。",
            "steps": rule["steps"],
        }
        CHAINS[cid] = chain
        return chain

    def adjust_step(self, chain_id: str, step_index: int,
                    failure_reason: str) -> Dict[str, Any]:
        """某一步失败，动态换策略。"""
        chain = CHAINS.get(chain_id)
        if not chain:
            return {"success": False, "error": "chain not found"}
        steps = chain["steps"]
        if step_index < 0 or step_index >= len(steps):
            return {"success": False, "error": "step index out of range"}
        old = steps[step_index]
        # 备选策略库
        alternates = {
            "sql_injection": "改用报错注入/时间盲注；或换 WAF 绕过 payload。",
            "ssrf": "改用 DNS 重绑定 / gopher 协议打内网 redis。",
            "default": "换用相邻攻击面：先做信息收集补全，再尝试其它入口。",
        }
        new_action = alternates.get(old["action"][:12], alternates["default"])
        new_step = {
            "stage": old["stage"],
            "action": new_action,
            "tool_suggested": "Burp / 手工",
            "goal": old["goal"],
            "reasoning": f"原策略失败（{failure_reason}），AI 切换备选路径。",
            "confidence": max(0.3, old["confidence"] - 0.15),
            "status": "replanned",
        }
        old["status"] = "failed"
        old["failure_reason"] = failure_reason
        steps.insert(step_index + 1, new_step)
        el = get_enhanced_llm()
        r = el.chat("你是红队决策专家，给一句下一步建议。",
                    f"步骤失败：{old['action']}\n原因：{failure_reason}",
                    rule_fallback="", task="chain_adjust", max_tokens=120)
        return {"success": True, "chain_id": chain_id,
                "replaced_step": old, "new_step": new_step,
                "ai_suggestion": r["content"] or new_step["reasoning"],
                "engine": r["engine"]}

    def list_chains(self) -> List[Dict[str, Any]]:
        return [{"chain_id": c["chain_id"], "target": c["target"],
                 "created_at": c["created_at"], "steps": len(c["steps"]),
                 "engine": c["engine"]} for c in CHAINS.values()]


_singleton: Optional[AIUpgradeDashboard] = None


def get_ai_dashboard() -> AIUpgradeDashboard:
    global _singleton
    if _singleton is None:
        _singleton = AIUpgradeDashboard()
    return _singleton
