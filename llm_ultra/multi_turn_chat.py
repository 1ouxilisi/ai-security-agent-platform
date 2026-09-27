# -*- coding: utf-8 -*-
"""multi_turn_chat.py — 多轮对话。

用户可以和AI持续对话，深入讨论漏洞细节，追问机制。
结合上下文记忆，支持基于历史数据的持续分析。
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from .context_memory import get_context_memory
from .prompt_master import get_prompt_master


# 追问建议模板
FOLLOWUP_SUGGESTIONS: Dict[str, List[str]] = {
    "sql_injection": [
        "这个SQL注入是基于错误还是时间盲注？",
        "能否通过UNION注入获取数据库版本？",
        "如何修复这个SQL注入？给出具体代码示例",
        "这个漏洞能拖库吗？评估数据泄露风险",
    ],
    "xss": [
        "这个XSS是反射型还是存储型？",
        "能否窃取管理员Cookie？",
        "CSP能否防御这种XSS？",
        "给出XSS修复的最佳实践",
    ],
    "path_traversal": [
        "能读取/etc/shadow吗？",
        "这个遍历能写文件吗？",
        "如何防止目录遍历攻击？",
        "有哪些WAF规则可以检测？",
    ],
    "default": [
        "这个漏洞的CVSS评分是多少？",
        "修复这个漏洞需要多久？",
        "有没有相关的CVE或Exploit？",
        "这个漏洞能被自动化利用吗？",
    ],
}


class MultiTurnChat:
    """多轮对话引擎：支持基于上下文的持续安全讨论。"""

    def __init__(self) -> None:
        self._memory = get_context_memory()
        self._prompts = get_prompt_master()
        self._chat_history: List[Dict[str, Any]] = []
        self._followup_count: int = 0

    def chat(self, session_id: str, user_message: str,
             context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """进行一轮多轮对话。

        流程：
        1. 从上下文记忆中加载历史对话
        2. 构建带上下文的prompt
        3. 生成AI回复（或降级回复）
        4. 保存对话到记忆
        5. 生成追问建议
        """
        # 加载上下文
        history = self._memory.get_history(session_id, limit=10)
        ctx_summary = self._memory.get_context_summary(session_id)

        # 检测当前讨论的漏洞类型
        vuln_type = self._detect_vuln_type(user_message, context)

        # 构建prompt
        base_prompt = self._prompts.build_prompt(
            "smart_qa",
            context=user_message,
            extra_context=f"历史对话:\n{ctx_summary}",
        )

        # 生成回复（降级模式：模板化回复）
        reply = self._generate_reply(user_message, vuln_type, history, context)

        # 保存对话
        self._memory.add_message(session_id, "user", user_message, context)
        self._memory.add_message(session_id, "assistant", reply,
                                 {"vuln_type": vuln_type})

        # 生成追问建议
        suggestions = self._get_followup_suggestions(vuln_type)

        result = {
            "session_id": session_id,
            "user_message": user_message,
            "assistant_reply": reply,
            "vuln_type_detected": vuln_type,
            "followup_suggestions": suggestions,
            "history_used": len(history),
            "degraded": True,  # 实际配置LLM后会变为False
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._chat_history.append(result)
        return result

    def _generate_reply(self, message: str, vuln_type: str,
                        history: List[Dict[str, Any]],
                        context: Optional[Dict[str, Any]]) -> str:
        """生成AI回复（降级模式：基于规则的模板回复）。"""
        degraded_note = self._prompts.get_prompt("smart_qa", ) or {}
        note = degraded_note.get("degraded_note", "[降级模式]")

        reply_parts = [note, ""]

        if vuln_type == "sql_injection":
            reply_parts.append("## 关于SQL注入的分析")
            reply_parts.append("")
            reply_parts.append("**直接回答**: 检测到SQL注入相关讨论。SQL注入是OWASP Top 10第一名的Web安全漏洞。")
            reply_parts.append("")
            reply_parts.append("## 关键技术要点")
            reply_parts.append("1. **注入点识别**: 通过单引号、UNION SELECT、SLEEP()等payload测试")
            reply_parts.append("2. **注入类型**: 报错型/布尔盲注/时间盲注/UNION查询")
            reply_parts.append("3. **影响**: 数据泄露、数据篡改、甚至服务器接管")
            reply_parts.append("")
            reply_parts.append("## 修复建议")
            reply_parts.append("1. 使用参数化查询（Prepared Statements）")
            reply_parts.append("2. 输入验证和白名单过滤")
            reply_parts.append("3. 最小权限原则：数据库账户只给必要权限")
            reply_parts.append("4. 部署WAF作为深度防御")

        elif vuln_type == "xss":
            reply_parts.append("## 关于XSS跨站脚本的分析")
            reply_parts.append("")
            reply_parts.append("**直接回答**: 检测到XSS相关讨论。XSS分为反射型、存储型和DOM型三种。")
            reply_parts.append("")
            reply_parts.append("## 关键技术要点")
            reply_parts.append("1. **反射型**: 恶意脚本通过URL参数反射到页面")
            reply_parts.append("2. **存储型**: 恶意脚本存储在服务器（如评论区），影响所有访问者")
            reply_parts.append("3. **DOM型**: 纯前端JS操作DOM导致的XSS")
            reply_parts.append("")
            reply_parts.append("## 修复建议")
            reply_parts.append("1. 输出编码：对所有用户输入做HTML实体编码")
            reply_parts.append("2. CSP策略：Content-Security-Policy限制脚本源")
            reply_parts.append("3. HttpOnly Cookie：防止XSS窃取Session")

        elif vuln_type == "path_traversal":
            reply_parts.append("## 关于目录遍历的分析")
            reply_parts.append("")
            reply_parts.append("**直接回答**: 检测到路径遍历相关讨论。目录遍历允许攻击者访问Web根目录外的文件。")
            reply_parts.append("")
            reply_parts.append("## 常见payload")
            reply_parts.append("- `../../../../etc/passwd` (Linux)")
            reply_parts.append("- `..\\..\\..\\windows\\win.ini` (Windows)")
            reply_parts.append("- `..%2f..%2f..%2fetc%2fpasswd` (URL编码)")
            reply_parts.append("")
            reply_parts.append("## 修复建议")
            reply_parts.append("1. 白名单：只允许访问指定目录下的文件")
            reply_parts.append("2. 路径规范化：realpath()后检查是否在允许目录内")
            reply_parts.append("3. 禁止使用用户输入直接拼接文件路径")

        else:
            reply_parts.append("## 安全咨询回复")
            reply_parts.append("")
            reply_parts.append(f"您的问题: {message[:100]}...")
            reply_parts.append("")
            reply_parts.append("**分析**: 基于当前对话上下文进行安全分析。")
            if history:
                reply_parts.append(f"\n（已参考 {len(history)} 条历史对话记录）")
            reply_parts.append("")
            reply_parts.append("## 建议")
            reply_parts.append("1. 配置LLM Key后可获得更深入的AI分析")
            reply_parts.append("2. 使用漏洞知识库查询CVE详情")
            reply_parts.append("3. 可进行二次验证确认漏洞可利用性")

        return "\n".join(reply_parts)

    def _detect_vuln_type(self, message: str,
                          context: Optional[Dict[str, Any]]) -> str:
        """从消息内容中检测讨论的漏洞类型。"""
        if context and context.get("vuln_type"):
            return context["vuln_type"]
        msg_lower = message.lower()
        if any(k in msg_lower for k in ("sql", "注入", "sqli", "union", "select")):
            return "sql_injection"
        if any(k in msg_lower for k in ("xss", "跨站", "script", "cookie")):
            return "xss"
        if any(k in msg_lower for k in ("遍历", "traversal", "../", "passwd")):
            return "path_traversal"
        return "general"

    def _get_followup_suggestions(self, vuln_type: str) -> List[str]:
        """根据当前讨论的漏洞类型生成追问建议。"""
        return FOLLOWUP_SUGGESTIONS.get(vuln_type, FOLLOWUP_SUGGESTIONS["default"])

    def chat_history(self, session_id: Optional[str] = None,
                      limit: int = 50) -> List[Dict[str, Any]]:
        """获取对话历史。"""
        items = self._chat_history
        if session_id:
            items = [h for h in items if h["session_id"] == session_id]
        return list(reversed(items[-limit:]))

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_chats": len(self._chat_history),
            "followup_suggestions_generated": self._followup_count,
            "memory_stats": self._memory.get_stats(),
        }

    def start_new_session(self, session_id: str,
                          topic: str = "") -> Dict[str, Any]:
        """开启新的对话会话。"""
        s = self._memory.create_session(session_id, {"topic": topic})
        self._memory.add_message(
            session_id, "assistant",
            f"您好！我是AI安全分析助手。我们可以讨论 '{topic}' 相关的安全问题。"
            "您可以随时追问，我会记住我们之前的讨论。",
        )
        return {"session_id": session_id, "topic": topic, "status": "started"}


_singleton: Optional[MultiTurnChat] = None


def get_multi_turn_chat() -> MultiTurnChat:
    global _singleton
    if _singleton is None:
        _singleton = MultiTurnChat()
    return _singleton
