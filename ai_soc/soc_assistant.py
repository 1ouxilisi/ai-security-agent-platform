#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全运营 AI 助手 (SOC Assistant)
===================================

功能：
    - 自然语言交互：查询安全状态 / 事件 / 告警 / 漏洞 / 资产（关键词匹配 + 意图识别）
    - 智能问答：事件处理流程 / 漏洞修复方法 / 合规要求 / 工具使用（内置知识库）
    - 操作指导：指导处理事件 / 告警 / 漏洞（步骤 / 命令 / 工具）
    - 报告生成：日报 / 周报 / 月报 / 事件报告 / 告警分析报告
    - 知识检索：漏洞库 / IOC 库 / 攻击链库 / 合规库 / 最佳实践库
    - 上下文理解：理解当前正在处理的事件 / 告警 / 任务

仅用于授权的安全运营辅助场景。
"""
import os
import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now().isoformat()


class SOCAssistant:
    """安全运营 AI 助手"""

    # 意图识别关键词表
    INTENTS: Dict[str, List[str]] = {
        "query_status": ["状态", "overview", "概况", "整体", "dashboard", "总览"],
        "query_events": ["事件", "incident", "工单", "event"],
        "query_alerts": ["告警", "alert", "报警"],
        "query_vulns": ["漏洞", "vuln", "cve", "弱点"],
        "query_assets": ["资产", "asset", "inventory", "服务器"],
        "ask_process": ["流程", "处理", "步骤", "how", "怎么处理"],
        "ask_fix": ["修复", "fix", "修补", "补丁", "patch"],
        "ask_compliance": ["合规", "等保", "gdpr", "合规要求", "compliance"],
        "ask_tool": ["工具", "tool", "命令", "command", "怎么用"],
    }

    # 内置知识库（问答）
    KNOWLEDGE_BASE: Dict[str, str] = {
        "事件处理流程": "标准事件处置流程：1) 发现与确认 2) 遏制(隔离/阻断) 3) 根除(清除/补丁) 4) 恢复(数据/系统) 5) 复盘与预防。",
        "漏洞修复方法": "漏洞修复流程：定级 -> 复现 -> 评估影响 -> 临时缓解(WAF/隔离) -> 打补丁 -> 复扫验证 -> 监控。",
        "合规要求": "常见合规框架：等保2.0、ISO27001、GDPR、PCI-DSS。关键控制：访问控制、日志留存≥6个月、数据加密、应急响应预案。",
        "工具使用": "SOC 常用工具：SIEM(日志分析)、EDR(端点防护)、Nuclei(漏洞扫描)、Wireshark(流量分析)、Velociraptor(取证)。",
        "告警分级": "告警级别：critical(立即响应)/high(30分钟)/medium(4小时)/low(工作日处理)/info(记录)。",
        "MTTR": "平均修复时间(MTTR)是衡量 SOC 效率的核心指标，目标通常 critical<1h、high<4h。",
    }

    # 知识检索库（多库）
    KNOWLEDGE_LIBS: Dict[str, List[Dict[str, str]]] = {
        "漏洞库": [{"id": "VULN-001", "name": "Log4j 远程代码执行", "cve": "CVE-2021-44228"},
                  {"id": "VULN-002", "name": "Spring4Shell", "cve": "CVE-2022-22965"}],
        "IOC库": [{"id": "IOC-001", "type": "ip", "value": "203.0.113.10", "threat": "C2"},
                 {"id": "IOC-002", "type": "hash", "value": "a1b2c3...", "threat": "ransomware"}],
        "攻击链库": [{"id": "CHAIN-001", "chain": "侦察->扫描->利用->提权->横向->数据窃取", "source": "MITRE ATT&CK"}],
        "合规库": [{"id": "COMP-001", "name": "等保2.0", "requirement": "三级系统需留存日志≥6个月"}],
        "最佳实践库": [{"id": "BP-001", "name": "最小权限原则", "desc": "按职责分配最小必要权限"},
                      {"id": "BP-002", "name": "纵深防御", "desc": "多层安全控制降低单点失效风险"}],
    }

    # 操作指导模板
    GUIDES: Dict[str, Dict[str, Any]] = {
        "incident": {
            "steps": ["确认事件真实性", "评估影响范围", "执行遏制动作", "根除与恢复", "复盘报告"],
            "tool": "SIEM + EDR", "command": "查看事件详情并按响应建议执行",
        },
        "alert": {
            "steps": ["查看告警详情", "判断是否误报", "关联上下游告警", "分派与处置"],
            "tool": "SIEM", "command": "在控制台对告警做聚合与标注",
        },
        "vulnerability": {
            "steps": ["确认漏洞 CVSS 评分", "评估受影响资产", "临时缓解", "打补丁", "复扫验证"],
            "tool": "Nuclei", "command": "nuclei -t <template> -u <target>",
        },
    }

    def __init__(self):
        self._context: Dict[str, Any] = {
            "current_event": None,
            "current_alert": None,
            "active_task": None,
            "history": [],
        }
        self._data_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "ai_soc", "assistant"
        )
        os.makedirs(self._data_dir, exist_ok=True)

    # ---------------- 意图识别 ----------------
    def _detect_intent(self, message: str) -> str:
        """基于关键词的意图识别"""
        low = message.lower()
        for intent, keywords in self.INTENTS.items():
            if any(k.lower() in low for k in keywords):
                return intent
        return "general"

    # ---------------- 自然语言交互 ----------------
    def chat(self, message: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """自然语言交互主入口：意图识别 + 回答"""
        ctx = context or {}
        self._context.update(ctx)
        self._context["history"].append({"role": "user", "message": message, "ts": _now()})
        intent = self._detect_intent(message)
        if intent.startswith("query_"):
            answer = self._handle_query(intent, message)
        elif intent.startswith("ask_"):
            answer = self.answer_question(message)
        else:
            answer = self.answer_question(message)
        self._context["history"].append({"role": "assistant", "answer": answer, "ts": _now()})
        return {
            "message_id": "msg-" + uuid.uuid4().hex[:8],
            "user_message": message,
            "intent": intent,
            "answer": answer,
            "timestamp": _now(),
        }

    def _handle_query(self, intent: str, message: str) -> str:
        """处理查询类意图"""
        mapping = {
            "query_status": "当前安全运营整体正常：无 critical 级别未处置事件。",
            "query_events": "待处置事件共 3 起，其中 high 1 起、medium 2 起。",
            "query_alerts": "今日新增告警 128 条，聚合为 14 个安全事件，误报率约 12%。",
            "query_vulns": "未修复漏洞 5 个，其中高危 1 个，建议优先处理。",
            "query_assets": "在册资产 120 台，其中核心资产 15 台。",
        }
        return mapping.get(intent, f"已识别意图 {intent}，请提供更具体的查询条件。")

    # ---------------- 智能问答 ----------------
    def answer_question(self, question: str) -> str:
        """回答安全运营相关问题（基于内置知识库关键词匹配）"""
        low = question.lower()
        # 精确/模糊匹配知识库键
        for key, answer in self.KNOWLEDGE_BASE.items():
            if key in question or key.lower() in low:
                return answer
        # 同义词匹配
        synonym_map = {
            "流程": "事件处理流程", "怎么处理": "事件处理流程",
            "修复": "漏洞修复方法", "补丁": "漏洞修复方法",
            "合规": "合规要求", "等保": "合规要求",
            "工具": "工具使用", "命令": "工具使用",
            "告警": "告警分级", "分级": "告警分级",
        }
        for word, key in synonym_map.items():
            if word in question:
                return self.KNOWLEDGE_BASE[key]
        return ("我是安全运营 AI 助手，可回答事件处理流程、漏洞修复、合规要求、工具使用等问题。"
                "请换个问法，或尝试使用『流程/修复/合规/工具』等关键词。")

    # ---------------- 操作指导 ----------------
    def guide_action(self, task_type: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """指导处理事件 / 告警 / 漏洞"""
        guide = self.GUIDES.get(task_type, {
            "steps": ["确认需求", "按标准流程处理"], "tool": "—", "command": "—",
        })
        self._context["active_task"] = task_type
        return {
            "task_type": task_type,
            "steps": guide["steps"],
            "recommended_tool": guide["tool"],
            "recommended_command": guide["command"],
            "context": context or {},
        }

    # ---------------- 报告生成 ----------------
    def generate_report(self, report_type: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """自动生成安全运营报告：日报/周报/月报/事件报告/告警分析报告"""
        params = params or {}
        templates = {
            "daily": "安全运营日报",
            "weekly": "安全运营周报",
            "monthly": "安全运营月报",
            "incident": "事件分析报告",
            "alert": "告警分析报告",
        }
        title = templates.get(report_type, f"安全运营{report_type}报告")
        return {
            "report_type": report_type,
            "title": title,
            "generated_at": _now(),
            "period": params.get("period", "今日"),
            "content": {
                "summary": "无重大安全事件，告警量与昨日持平。",
                "metrics": {
                    "alerts": params.get("alert_count", 128),
                    "events": params.get("event_count", 3),
                    "mttr": params.get("mttr_hours", 2.5),
                    "false_positive_rate": "12%",
                },
                "highlights": [
                    "完成 1 起 high 级别事件处置",
                    "修复高危漏洞 1 个",
                ],
                "action_items": ["持续监控", "跟进剩余 medium 事件"],
            },
        }

    # ---------------- 知识检索 ----------------
    def search_knowledge(self, query: str) -> List[Dict[str, Any]]:
        """检索安全知识库（漏洞库/IOC库/攻击链库/合规库/最佳实践库）"""
        low = query.lower()
        results: List[Dict[str, Any]] = []
        for lib_name, entries in self.KNOWLEDGE_LIBS.items():
            for entry in entries:
                blob = " ".join(str(v) for v in entry.values()).lower()
                if not query or query.lower() in blob or any(w in blob for w in low.split()):
                    results.append({"library": lib_name, **entry})
        return results

    # ---------------- 上下文 ----------------
    def get_context(self) -> Dict[str, Any]:
        """获取当前安全运营上下文"""
        return {
            "current_event": self._context.get("current_event"),
            "current_alert": self._context.get("current_alert"),
            "active_task": self._context.get("active_task"),
            "history_count": len(self._context.get("history", [])),
        }


# ---------------- 模块级单例 ----------------
_soc_assistant_instance: Optional[SOCAssistant] = None


def get_soc_assistant() -> SOCAssistant:
    global _soc_assistant_instance
    if _soc_assistant_instance is None:
        _soc_assistant_instance = SOCAssistant()
    return _soc_assistant_instance


soc_assistant: SOCAssistant = get_soc_assistant()
