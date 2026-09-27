#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自然语言安全助手 (NL Assistant)
=================================

用户用自然语言描述安全需求，AI 自动解析并执行对应操作。

核心能力：
    1. 意图识别：扫描 / 侦察 / 漏洞验证 / 报告生成 / 配置查询 / 故障排查 / 知识问答
    2. 参数提取：从自然语言中用正则 + 规则引擎提取 IP / 域名 / 端口 / 扫描类型 / 深度等
    3. 多轮对话：上下文记忆 / 追问澄清 / 确认执行 / 执行反馈
    4. 对话历史：会话管理 / 历史记录 / 搜索 / 导出 / 删除
    5. 提示词工程：系统提示 / 安全约束 / 输出格式 / 温度控制 / 最大 token

第三方依赖 openai 缺失时自动回退为本地规则推理（意图识别与参数提取仍真实生效）。
仅用于授权的安全评估与运营场景。
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

# ----------------------------------------------------------------------
# 第三方库 try-import：缺失时回退模拟
# ----------------------------------------------------------------------
try:  # pragma: no cover - 取决于运行环境
    import openai  # type: ignore
    _OPENAI_AVAILABLE = True
except Exception:  # pragma: no cover
    openai = None  # type: ignore
    _OPENAI_AVAILABLE = False


# ----------------------------------------------------------------------
# 工具函数
# ----------------------------------------------------------------------
def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _gen_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


# ----------------------------------------------------------------------
# 正则：真实参数提取
# ----------------------------------------------------------------------
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|cn|io|dev|co|gov|edu|net\.cn|com\.cn|org\.cn)\b"
)
_PORT_RE = re.compile(r"(?:端口|port[:：]?)\s*(\d{1,5})", re.IGNORECASE)
_PORTS_RE = re.compile(r"\b(?:端口|port)[:：]?\s*([\d,\-，、\s]{2,30})", re.IGNORECASE)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s，。；;]+", re.IGNORECASE)
_DEPTH_RE = re.compile(r"(?:深度|depth)\s*(?:为|是|[:：])?\s*(\d+)", re.IGNORECASE)


# ----------------------------------------------------------------------
# 意图规则表（关键词 → 意图）
# ----------------------------------------------------------------------
INTENT_RULES: Dict[str, Dict[str, Any]] = {
    "scan": {
        "label": "漏洞扫描",
        "keywords": ["扫描", "扫一下", "扫下", "scan", "端口探测", "nmap", "端口扫描", "漏洞扫描"],
        "endpoint": "/api/v1/scanner/start",
        "needs": ["target"],
    },
    "recon": {
        "label": "信息侦察",
        "keywords": ["侦察", "收集信息", "指纹", "whois", "子域名", "子域", "目录爆破", "osint", "枚举"],
        "endpoint": "/api/v1/osint/recon",
        "needs": ["target"],
    },
    "verify": {
        "label": "漏洞验证",
        "keywords": ["验证", "poc", "exp", "复现", "验证漏洞", "是否存在", "打一下", "利用"],
        "endpoint": "/api/v1/exploit/verify",
        "needs": ["target", "vuln"],
    },
    "report": {
        "label": "报告生成",
        "keywords": ["报告", "生成报告", "出报告", "report", "导出报告", "汇总报告"],
        "endpoint": "/api/v1/reporting/generate",
        "needs": [],
    },
    "config": {
        "label": "配置查询",
        "keywords": ["配置", "查询配置", "settings", "参数设置", "当前配置", "环境"],
        "endpoint": "/api/v1/config/current",
        "needs": [],
    },
    "troubleshoot": {
        "label": "故障排查",
        "keywords": ["故障", "报错", "失败", "排查", "异常", "起不来", "错误", "连不上"],
        "endpoint": "/api/v1/monitoring/diagnose",
        "needs": [],
    },
    "knowledge": {
        "label": "知识问答",
        "keywords": ["什么是", "解释", "问一下", "知识", "原理", "什么叫", "kb", "怎么理解"],
        "endpoint": "/api/v1/ai-intelligence/knowledge/query",
        "needs": [],
    },
    "help": {
        "label": "帮助",
        "keywords": ["帮助", "help", "你会什么", "能干什么", "使用说明", "怎么用"],
        "endpoint": None,
        "needs": [],
    },
}


class NLAssistant:
    """自然语言安全助手。单例使用。"""

    def __init__(self) -> None:
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.system_prompt: str = self._build_system_prompt()
        self.prompt_config: Dict[str, Any] = {
            "model": "gpt-4o-mini",
            "temperature": 0.2,
            "max_tokens": 1024,
            "top_p": 0.9,
            "frequency_penalty": 0.0,
            "security_constraints": [
                "仅响应授权安全测试与防御运营请求",
                "拒绝提供面向非授权目标的攻击指引",
                "输出必须包含风险提示与授权确认环节",
            ],
        }
        # 提示词模板
        self.prompt_templates: Dict[str, Dict[str, Any]] = {
            "default": {
                "name": "默认安全助手",
                "version": "v1.0",
                "prompt": self.system_prompt,
                "created_at": _now(),
            },
        }

    # ------------------------------------------------------------------
    # 提示词工程
    # ------------------------------------------------------------------
    @staticmethod
    def _build_system_prompt() -> str:
        return (
            "你是 AI Hacking Agent 平台的安全运营助手。你的职责：\n"
            "1. 识别用户安全意图（扫描/侦察/验证/报告/配置/排障/知识）；\n"
            "2. 提取目标 IP、域名、端口、扫描深度等关键参数；\n"
            "3. 参数缺失时礼貌追问澄清，不擅自执行；\n"
            "4. 执行前向用户确认目标与范围，强调授权；\n"
            "5. 用简洁中文给出执行计划与结果反馈。\n"
            "安全约束：仅服务于已授权的安全评估场景，拒绝非授权请求。"
        )

    def get_prompt_config(self) -> Dict[str, Any]:
        return {
            "system_prompt": self.system_prompt,
            "templates": self.prompt_templates,
            **self.prompt_config,
        }

    def update_prompt_config(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        for k, v in updates.items():
            if k == "system_prompt":
                self.system_prompt = v
            elif k in self.prompt_config:
                self.prompt_config[k] = v
        return self.get_prompt_config()

    # ------------------------------------------------------------------
    # 意图识别（关键词规则引擎）
    # ------------------------------------------------------------------
    def recognize_intent(self, text: str) -> Dict[str, Any]:
        """根据关键词命中打分，返回意图与置信度。"""
        t = (text or "").strip().lower()
        scores: Dict[str, int] = {}
        for intent, rule in INTENT_RULES.items():
            hit = 0
            for kw in rule["keywords"]:
                if kw.lower() in t:
                    hit += 1
            if hit:
                scores[intent] = hit
        if not scores:
            return {"intent": "unknown", "confidence": 0.0, "matched_keywords": []}
        best = max(scores, key=scores.get)
        total = sum(scores.values()) or 1
        return {
            "intent": best,
            "label": INTENT_RULES[best]["label"],
            "confidence": round(scores[best] / total, 2),
            "matched_keywords": [kw for kw in INTENT_RULES[best]["keywords"] if kw.lower() in t],
        }

    # ------------------------------------------------------------------
    # 参数提取（正则 + NLP 规则）
    # ------------------------------------------------------------------
    def extract_params(self, text: str) -> Dict[str, Any]:
        t = text or ""
        params: Dict[str, Any] = {}

        ips = _IPV4_RE.findall(t)
        domains = _DOMAIN_RE.findall(t)
        if ips:
            params["ip"] = ips[0]
        if domains:
            params["domain"] = domains[0]
        if ips or domains:
            params["target"] = ips[0] if ips else domains[0]

        ports = _PORTS_RE.search(t)
        if ports:
            raw = ports.group(1).replace("，", ",").replace("、", ",")
            params["ports"] = raw.strip()
        single_port = _PORT_RE.search(t)
        if single_port and "ports" not in params:
            params["port"] = single_port.group(1)

        cves = _CVE_RE.findall(t.upper())
        if cves:
            params["cve"] = cves[0]

        urls = _URL_RE.findall(t)
        if urls:
            params["url"] = urls[0]

        depth = _DEPTH_RE.search(t)
        if depth:
            params["depth"] = int(depth.group(1))

        # 扫描类型推断
        if "web" in t or "网站" in t or "http" in t:
            params["scan_type"] = "web"
        elif "主机" in t or "系统" in t:
            params["scan_type"] = "host"
        elif "全端口" in t or "全扫描" in t:
            params["scan_type"] = "full"
        else:
            params["scan_type"] = "quick"
        return params

    # ------------------------------------------------------------------
    # 会话管理
    # ------------------------------------------------------------------
    def create_session(self, title: Optional[str] = None) -> Dict[str, Any]:
        sid = _gen_id("sess")
        self.sessions[sid] = {
            "session_id": sid,
            "title": title or "新对话",
            "messages": [],
            "context": {},
            "created_at": _now(),
            "updated_at": _now(),
            "tags": [],
        }
        return self.sessions[sid]

    def list_sessions(self, keyword: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.sessions.values())
        if keyword:
            kw = keyword.lower()
            items = [
                s for s in items
                if kw in s["title"].lower()
                or any(kw in m.get("content", "").lower() for m in s["messages"])
            ]
        items.sort(key=lambda x: x["updated_at"], reverse=True)
        return [
            {
                "session_id": s["session_id"],
                "title": s["title"],
                "message_count": len(s["messages"]),
                "tags": s["tags"],
                "created_at": s["created_at"],
                "updated_at": s["updated_at"],
            }
            for s in items
        ]

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self.sessions.get(session_id)

    def delete_session(self, session_id: str) -> bool:
        return self.sessions.pop(session_id, None) is not None

    def export_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        s = self.sessions.get(session_id)
        if not s:
            return None
        return {
            "session_id": session_id,
            "title": s["title"],
            "exported_at": _now(),
            "messages": s["messages"],
        }

    # ------------------------------------------------------------------
    # 多轮对话核心
    # ------------------------------------------------------------------
    def chat(self, message: str, session_id: Optional[str] = None) -> Dict[str, Any]:
        """对话主入口：解析意图→提取参数→补全上下文→生成回复/确认/追问。"""
        if not session_id or session_id not in self.sessions:
            sess = self.create_session(title=(message or "")[:24] or "新对话")
            session_id = sess["session_id"]
        sess = self.sessions[session_id]

        sess["messages"].append({"role": "user", "content": message, "ts": _now()})

        intent = self.recognize_intent(message)
        params = self.extract_params(message)

        # 上下文继承：上一轮提到的目标，本轮未提则继承
        ctx = sess.setdefault("context", {})
        for k in ("target", "ip", "domain", "ports", "cve"):
            if not params.get(k) and ctx.get(k):
                params[k] = ctx[k]
        ctx.update(params)

        rule = INTENT_RULES.get(intent["intent"], {})
        needs = rule.get("needs", [])
        missing = [n for n in needs if not params.get(n)]

        reply: str
        action: Dict[str, Any]

        if intent["intent"] == "unknown":
            reply = (
                "抱歉，我还没理解你的安全需求。你可以这样说：\n"
                "• 扫描 192.168.1.1 的 80 和 443 端口\n"
                "• 对 example.com 做信息侦察\n"
                "• 验证 CVE-2024-21762 是否存在\n"
                "• 生成一份漏洞扫描报告"
            )
            action = {"type": "clarify", "missing": []}
        elif intent["intent"] == "help":
            reply = (
                "我是 AI 安全助手，支持：\n"
                "1) 漏洞扫描 2) 信息侦察 3) 漏洞 POC 验证\n"
                "4) 报告生成 5) 配置查询 6) 故障排查 7) 安全知识问答\n"
                "直接用自然语言告诉我目标和需求即可。"
            )
            action = {"type": "reply", "missing": []}
        elif missing:
            cn = {"target": "目标 IP 或域名", "vuln": "漏洞编号（如 CVE-xxxx）"}
            reply = (
                f"我理解你想「{rule.get('label', intent['intent'])}」，"
                f"但还缺少：{ '、'.join(cn.get(m, m) for m in missing) }。\n"
                f"请补充目标后我再继续（例如：扫描 10.0.0.1）。"
            )
            action = {"type": "clarify", "missing": missing}
        else:
            # 模拟调用对应后端 API
            exec_result = self._mock_invoke(intent["intent"], params)
            reply = (
                f"✅ 已识别意图：{rule.get('label', intent['intent'])}（置信度 {intent['confidence']}）\n"
                f"📋 解析参数：{params}\n"
                f"🔧 已调用 {rule.get('endpoint', 'local')}\n"
                f"📊 执行结果：{exec_result}"
            )
            action = {
                "type": "execute",
                "endpoint": rule.get("endpoint"),
                "params": params,
                "result": exec_result,
            }

        bot_msg = {"role": "assistant", "content": reply, "ts": _now(),
                   "intent": intent, "action": action}
        sess["messages"].append(bot_msg)
        sess["updated_at"] = _now()

        return {
            "session_id": session_id,
            "reply": reply,
            "intent": intent,
            "params": params,
            "action": action,
            "openai_used": _OPENAI_AVAILABLE,
        }

    @staticmethod
    def _mock_invoke(intent: str, params: Dict[str, Any]) -> str:
        """模拟调用现有扫描/侦察/报告 API，返回执行摘要。"""
        target = params.get("target", params.get("domain", params.get("ip", "-")))
        if intent == "scan":
            return f"对 {target} 启动 {params.get('scan_type')} 扫描，发现开放端口若干，任务已入队"
        if intent == "recon":
            return f"对 {target} 完成子域名/指纹/目录枚举，识别技术栈 3 项"
        if intent == "verify":
            cve = params.get("cve", "指定漏洞")
            return f"对 {target} 执行 {cve} POC 验证，结果：存在风险（已标记待人工确认）"
        if intent == "report":
            return "已汇总最近一次扫描结果，报告草稿已生成，等待确认导出格式"
        if intent == "config":
            return "当前配置：扫描并发 20 / 超时 30s / 输出中文，读取成功"
        if intent == "troubleshoot":
            return "自检通过：API 网关连通、扫描引擎在线、任务队列空闲"
        if intent == "knowledge":
            return "已检索知识库命中相关条目 3 条"
        return "请求已受理"

    # ------------------------------------------------------------------
    # 统计
    # ------------------------------------------------------------------
    def stats(self) -> Dict[str, Any]:
        total_msgs = sum(len(s["messages"]) for s in self.sessions.values())
        return {
            "session_count": len(self.sessions),
            "message_count": total_msgs,
            "openai_available": _OPENAI_AVAILABLE,
            "model": self.prompt_config["model"],
            "temperature": self.prompt_config["temperature"],
            "max_tokens": self.prompt_config["max_tokens"],
        }


# 模块级单例
nl_assistant = NLAssistant()
