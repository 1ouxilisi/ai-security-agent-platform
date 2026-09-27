# -*- coding: utf-8 -*-
"""
ai/security_assistant.py — AI 安全分析师助手

对话式安全专家：结合项目知识库（PoC/攻击链/指纹/CVE/功能模块说明）
与 LLM，回答"漏洞原理、工具用法、安全建议、报告解读"等问题。LLM 不可
用时回退到内置知识库 + 模板回答。支持多轮对话上下文。

合法定位：仅做防御性知识解答与建设建议，不提供真实攻击利用指导。
"""
import os
import re
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # pragma: no cover
    pass

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

try:
    from utils.logger import log
except Exception:  # pragma: no cover
    import logging

    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("ai.security_assistant")


# 内置项目功能知识库（>=20 个模块说明）
BUILTIN_FUNCTION_KB: List[Dict[str, str]] = [
    {"name": "端口扫描", "module": "scanner", "desc": "对目标做 TCP/端口连通性与服务识别，建立攻击面基线。"},
    {"name": "Web 指纹识别", "module": "scanner", "desc": "识别目标 Web 框架/CMS/中间件版本，用于匹配已知漏洞。"},
    {"name": "目录与敏感文件探测", "module": "scanner", "desc": "探测 /admin、/.git、备份文件等敏感路径暴露。"},
    {"name": "漏洞库查询", "module": "database", "desc": "按 CVE/组件名检索已知漏洞、严重程度与补丁建议。"},
    {"name": "漏洞自动验证", "module": "ai.vuln_verifier", "desc": "对告警做非破坏性复测，给出确认/疑似/未验证结论与证据。"},
    {"name": "修复方案生成", "module": "ai.remediation_generator", "desc": "按漏洞类型生成多语言代码修复、配置加固与验证方法。"},
    {"name": "扫描策略规划", "module": "ai.planner", "desc": "基于已知信息自动规划循序渐进的扫描与复测策略。"},
    {"name": "自然语言交互", "module": "ai.natural_language", "desc": "用自然语言指挥扫描、查漏洞、生成报告与任务。"},
    {"name": "评估报告生成", "module": "report", "desc": "汇总扫描/验证结果输出结构化评估报告。"},
    {"name": "趋势统计", "module": "monitoring", "desc": "统计漏洞/告警随时间变化，辅助安全运营决策。"},
    {"name": "定时任务调度", "module": "scheduler", "desc": "定期自动执行扫描与复测，支持计划与结果留存。"},
    {"name": "代码审计", "module": "code_audit", "desc": "静态分析源码，发现硬编码密钥、危险函数等缺陷。"},
    {"name": "内网安全评估", "module": "internal", "desc": "SMB/LDAP/Kerberos/AD 域安全评估（授权场景）。"},
    {"name": "移动应用检测", "module": "mobile_security", "desc": "APK 反编译分析：硬编码、组件导出、明文流量等。"},
    {"name": "智能合约安全", "module": "blockchain_security", "desc": "Solidity 合约重入/权限等风险静态分析。"},
    {"name": "云安全配置基线", "module": "cloud_security", "desc": "检查云存储/访问控制/审计日志等安全配置。"},
    {"name": "IoT 设备安全", "module": "iot_security", "desc": "IoT 设备默认口令、固件与暴露服务检测。"},
    {"name": "威胁情报", "module": "threat_intel", "desc": "IOC/IP/域名信誉与攻击组织情报 enrichment。"},
    {"name": "日志取证", "module": "forensics", "desc": "事件后日志分析与攻击痕迹提取。"},
    {"name": "SIEM 关联", "module": "siem", "desc": "多源告警聚合与规则关联，降低误报。"},
    {"name": "SOAR 编排", "module": "soar", "desc": "把检测 -> 验证 -> 修复串成自动化剧本。"},
    {"name": "防御加固基线", "module": "defense", "desc": "输出操作系统/中间件安全加固 checklist。"},
    {"name": "合规对照", "module": "compliance", "desc": "对照等保/ISO27001 等框架给出差距项。"},
    {"name": "AI 应用安全", "module": "ai_security", "desc": "提示注入/越权调用/敏感数据泄露等 AI 风险评估。"},
]

# 内置漏洞原理速查 KB（关键词 -> 解释）
VULN_PRINCIPLE_KB: Dict[str, str] = {
    "sql注入": ("SQL 注入指用户输入被拼接到 SQL 语句中并被数据库当作代码执行。"
               "影响：可越权读取/篡改数据，严重时拖库。利用方式：在参数中注入单引号/布尔条件触发报错或盲注。"
               "修复：使用参数化查询/预编译，关闭详细报错，最小化数据库账号权限。"),
    "xss": ("跨站脚本（XSS）指攻击者注入的脚本被受害者浏览器执行。分反射型、存储型、DOM 型。"
            "影响：窃取 Cookie、会话劫持、钓鱼。修复：输出编码 + CSP + HttpOnly Cookie + 富文本白名单。"),
    "弱口令": ("弱口令指可被轻易猜到/字典命中的账号密码。影响：直接未授权登录。"
               "修复：强制强密码策略、多因子认证、登录限速与锁定、禁用默认账号。"),
    "路径穿越": ("路径穿越指通过 ../ 等序列跳出受限目录读写任意文件。影响：读取配置/源码，进而泄露密钥。"
               "修复：规范化路径并限制在白名单目录内，禁止用户输入直接拼接文件路径。"),
    "文件上传": ("任意文件上传指攻击者可上传 WebShell 等可执行文件。影响：服务器失陷。"
               "修复：白名单扩展名/类型、重命名、上传目录禁用脚本执行、校验文件内容头。"),
    "csrf": ("跨站请求伪造指诱导已登录用户在不知情下发起请求。影响：以用户身份执行敏感操作。"
            "修复：CSRF Token、SameSite Cookie、关键操作二次确认。"),
}


class SecurityAssistant:
    """AI 安全分析师助手（对话式、知识库增强）。"""

    MAX_CONTEXT = 12

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None,
                 model: Optional[str] = None):
        """初始化 LLM 配置与会话上下文（复用统一 LLM 客户端）。"""
        from llm_integration import get_llm_client  # 延迟导入，避免循环依赖
        self._llm = get_llm_client()
        self.api_key = api_key or self._llm.api_key
        self.base_url = (base_url or self._llm.base_url).rstrip("/")
        self.model = model or self._llm.model
        self.timeout = self._llm.timeout
        self.llm_available = bool(self.api_key and self.base_url and requests)
        self.sessions: Dict[str, List[Dict[str, str]]] = {}
        self.kb = self._load_knowledge_base()
        if not self.llm_available:
            log.warning("LLM 不可用，安全助手使用内置知识库回答")

    # ------------------------------------------------------------------
    # 内部：LLM 调用
    # ------------------------------------------------------------------
    def _call_llm(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """调用统一 LLM 客户端，失败返回 None。"""
        return self._llm.simple_chat(system_prompt, user_prompt,
                                     temperature=0.3, max_tokens=1024)

    # ------------------------------------------------------------------
    # 知识库加载
    # ------------------------------------------------------------------
    def _load_knowledge_base(self) -> List[str]:
        """从 knowledge/、database/ 读取知识片段；不可用时回退内置库。"""
        chunks: List[str] = []
        for dirname in ("knowledge", "database"):
            try:
                base_dir = os.path.join(os.getcwd(), dirname)
                if not os.path.isdir(base_dir):
                    continue
                for root, _dirs, files in os.walk(base_dir):
                    for fn in files:
                        if not fn.lower().endswith((".md", ".txt", ".json")):
                            continue
                        fp = os.path.join(root, fn)
                        try:
                            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                                content = f.read(2000)  # 只读前 2KB，控制体积
                            if content.strip():
                                chunks.append(f"[{dirname}/{fn}] {content[:800]}")
                        except Exception:
                            continue
            except Exception as e:
                log.debug(f"加载知识库 {dirname} 失败: {e}")
        # 内置知识库兜底
        for item in BUILTIN_FUNCTION_KB:
            chunks.append(f"[功能:{item['name']}] {item['desc']}")
        return chunks

    def _knowledge_search(self, query: str) -> List[str]:
        """从知识库检索与 query 相关的片段（简单关键词打分）。"""
        q = (query or "").lower()
        if not q:
            return []
        scored: List[tuple] = []
        for chunk in self.kb:
            score = sum(1 for kw in re.findall(r"[\w\u4e00-\u9fa5]{2,}", q) if kw in chunk.lower())
            if score > 0:
                scored.append((score, chunk))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [c for _s, c in scored[:5]]

    # ------------------------------------------------------------------
    # 专项能力
    # ------------------------------------------------------------------
    def _explain_vulnerability(self, vuln_name: str) -> str:
        """解释漏洞原理/影响/利用方式/修复方法。"""
        name = (vuln_name or "").lower()
        # 内置 KB 命中
        for key, text in VULN_PRINCIPLE_KB.items():
            if key in name:
                return text
        # LLM 解释
        system_prompt = (
            "你是安全专家。用通俗中文解释这个漏洞：原理、影响、常见利用方式、修复方法。"
            "只讲防御/检测视角，不要给出可直接复制的攻击 payload。300 字以内。"
        )
        content = self._call_llm(system_prompt, f"漏洞名称: {vuln_name}")
        if content:
            return content.strip()
        return (f"关于「{vuln_name}」：当前未在内置库命中，且 LLM 暂不可用。"
                "建议在漏洞库按 CVE 检索官方描述，并参考修复方案生成模块获取加固建议。")

    def _tool_usage_guide(self, tool_name: str) -> str:
        """指导用户如何使用项目各功能。"""
        name = (tool_name or "").lower()
        matched = [it for it in BUILTIN_FUNCTION_KB if name in it["name"].lower()
                   or name in it["module"].lower() or name in it["desc"].lower()]
        if matched:
            lines = [f"「{m['name']}」（模块 {m['module']}）：{m['desc']}" for m in matched]
            return "项目功能指引：\n" + "\n".join(lines)
        # 未指定具体工具，列出全部
        lines = [f"- {m['name']}：{m['desc']}" for m in BUILTIN_FUNCTION_KB]
        return "项目内置功能清单（共 %d 项）：\n%s\n你可以告诉我具体想了解哪个功能。" % (
            len(BUILTIN_FUNCTION_KB), "\n".join(lines))

    def _security_advice(self, context: str) -> str:
        """根据用户环境与需求给出安全建设建议。"""
        system_prompt = (
            "你是安全架构顾问。根据用户的环境描述，给出 3~5 条可落地的安全建设建议"
            "（覆盖资产梳理、访问控制、监控告警、应急响应），中文，务实，不要空话。"
        )
        content = self._call_llm(system_prompt, f"用户环境: {context}")
        if content:
            return content.strip()
        return ("安全建设通用建议：\n"
                "1) 资产梳理：盘点对外暴露的端口、服务与域名，形成资产台账。\n"
                "2) 访问控制：默认拒绝入站，按最小权限分配账号与密钥。\n"
                "3) 监控告警：开启日志采集与关键告警，定期复盘。\n"
                "4) 补丁管理：建立补丁灰度上线与复测流程。\n"
                "5) 应急响应：预置联系人、备份与回滚方案，定期演练。")

    def _interpret_report(self, report_summary: str) -> str:
        """用通俗语言解读评估报告。"""
        system_prompt = (
            "你是安全分析师。把这份评估报告摘要用通俗中文讲给非技术管理者听："
            "主要风险、为什么危险、先做什么、预期效果。不要堆砌术语。"
        )
        content = self._call_llm(system_prompt, f"报告摘要: {report_summary}")
        if content:
            return content.strip()
        return ("报告解读（降级模板）：这份评估列出了若干风险项。建议你按优先级从高到低处理："
                "先修会直接被利用的高危项，再处理中低危与加固项；每项修复后复测确认闭环。"
                "如需逐条解读，可把报告内容贴给我。")

    # ------------------------------------------------------------------
    # 意图路由（轻量）
    # ------------------------------------------------------------------
    def _route(self, message: str) -> str:
        """把用户消息路由到对应专项能力。"""
        low = (message or "").lower()
        if any(k in low for k in ["报告", "评估结果", "解读", "这份报告"]):
            return "interpret_report"
        if any(k in low for k in ["建议", "怎么建设", "如何防护", "加固", "安全体系"]):
            return "security_advice"
        if any(k in low for k in ["怎么用", "如何使用", "功能", "模块", "工具", "有哪些"]):
            return "tool_usage_guide"
        if any(k in low for k in ["什么是", "原理", "漏洞", "cve", "为什么", "影响"]):
            return "explain_vuln"
        return "general"

    # ------------------------------------------------------------------
    # 主对话方法
    # ------------------------------------------------------------------
    def chat(self, user_message: str, session_id: str = "default") -> Dict[str, Any]:
        """对话式交互主方法：返回 reply / related_knowledge / intent。"""
        msg = (user_message or "").strip()
        if session_id not in self.sessions:
            self.sessions[session_id] = []
        self.sessions[session_id].append({"role": "user", "content": msg})
        # 裁剪上下文
        if len(self.sessions[session_id]) > self.MAX_CONTEXT:
            self.sessions[session_id] = self.sessions[session_id][-self.MAX_CONTEXT:]

        intent = self._route(msg)
        related = self._knowledge_search(msg)

        if intent == "explain_vuln":
            reply = self._explain_vulnerability(msg)
        elif intent == "tool_usage_guide":
            reply = self._tool_usage_guide(msg)
        elif intent == "security_advice":
            reply = self._security_advice(msg)
        elif intent == "interpret_report":
            reply = self._interpret_report(msg)
        else:
            reply = self._general_chat(msg, related)

        self.sessions[session_id].append({"role": "assistant", "content": reply})
        return {"reply": reply, "related_knowledge": related, "intent": intent}

    def _general_chat(self, message: str, related: List[str]) -> str:
        """通用对话：结合知识库与 LLM 回答。"""
        system_prompt = (
            "你是本安全平台的 AI 安全分析师助手。基于提供的项目知识库回答用户问题，"
            "保持防御/检测/修复视角，不提供真实攻击利用步骤。简洁中文。"
        )
        kb_text = "\n".join(related) if related else "（无相关知识库片段）"
        user_prompt = f"项目知识库：\n{kb_text}\n\n用户问题: {message}"
        content = self._call_llm(system_prompt, user_prompt)
        if content:
            return content.strip()
        # 降级：把相关知识库拼起来
        if related:
            return "根据内置知识库，我找到以下相关信息：\n" + "\n".join(
                f"- {r[:120]}" for r in related)
        return ("你好，我是 AI 安全助手。你可以问我：某个漏洞的原理与修复、"
                "平台各功能怎么用、安全建设建议，或让我解读评估报告。")

    # ------------------------------------------------------------------
    # 上下文管理
    # ------------------------------------------------------------------
    def get_history(self, session_id: str, limit: int = 20) -> List[Dict[str, str]]:
        """获取会话历史。"""
        hist = self.sessions.get(session_id, [])
        return hist[-limit:] if limit else hist

    def clear_history(self, session_id: str) -> bool:
        """清空会话历史。"""
        if session_id in self.sessions:
            self.sessions[session_id] = []
            return True
        return False


# 模块级单例
_assistant: Optional[SecurityAssistant] = None


def get_security_assistant() -> SecurityAssistant:
    """获取全局 SecurityAssistant 单例。"""
    global _assistant
    if _assistant is None:
        _assistant = SecurityAssistant()
    return _assistant
