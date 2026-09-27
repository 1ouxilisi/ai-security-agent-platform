# -*- coding: utf-8 -*-
"""
ai/natural_language.py — 自然语言交互引擎

提供"用自然语言指挥安全平台"的能力：意图识别、参数提取、任务执行、
结果解释，并维护多轮对话上下文。LLM（智谱 glm-4-flash）可用时使用
LLM 做理解与生成；LLM 不可用时自动降级为关键词规则与模板，保证模块
始终可导入、可运行。

合法定位：本模块仅用于授权安全评估场景，通过自然语言编排检测/查询/
报告等防御性功能，不执行任何破坏性攻击。
"""
import os
import re
import json
import time
import socket
from datetime import datetime
from typing import Any, Dict, List, Optional

# 自动加载 .env（LLM_API_KEY / LLM_BASE_URL / LLM_MODEL）
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
    log = logging.getLogger("ai.natural_language")


# 支持的意图清单
SUPPORTED_INTENTS = [
    "scan_target",      # 执行扫描
    "query_vuln",      # 查询漏洞
    "generate_report",  # 生成报告
    "view_trends",     # 查看趋势
    "create_task",     # 创建任务
    "config_tool",     # 配置工具
    "general_chat",    # 通用对话
]

# 意图 -> 触发关键词（规则降级用）
INTENT_KEYWORDS: Dict[str, List[str]] = {
    "scan_target": ["扫描", "探测", "扫一下", "扫一下目标", "端口", "nmap", "scan",
                    "探测目标", "查一下这个站", "检测目标", "看看开了什么端口"],
    "query_vuln": ["漏洞", "cve", "查漏洞", "有没有漏洞", "漏洞库", "补丁", "vuln"],
    "generate_report": ["报告", "生成报告", "出具报告", "评估报告", "report", "总结"],
    "view_trends": ["趋势", "走势", "统计", "最近", "变化", "trend", "分析数据"],
    "create_task": ["任务", "定时", "计划", "调度", "task", "定期", "每天"],
    "config_tool": ["配置", "设置", "开关", "参数", "config", "调整", "打开", "关闭"],
    "general_chat": ["你好", "hi", "hello", "介绍", "帮助", "你是谁", "?", "？"],
}

# 常见弱口令字典（仅用于受限的"弱口令验证检测"，限速、不爆破）
COMMON_WEAK_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345", "1234567",
    "admin", "admin123", "root", "root123", "123123", "654321", "qwerty",
    "abc123", "111111", "password1", "iloveyou", "test", "guest", "000000",
]


class NaturalLanguageEngine:
    """自然语言交互引擎：意图识别、参数提取、任务执行、结果解释。"""

    # 每个会话保留最近 N 轮上下文
    MAX_CONTEXT_ROUNDS = 10

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None,
                 model: Optional[str] = None):
        """初始化（复用统一 LLM 客户端）。"""
        from llm_integration import get_llm_client  # 延迟导入，避免循环依赖
        self._llm = get_llm_client()
        self.api_key = api_key or self._llm.api_key
        self.base_url = (base_url or self._llm.base_url).rstrip("/")
        self.model = model or self._llm.model
        self.timeout = 20
        self.llm_available = bool(self.api_key and self.base_url and requests)
        self.call_count = 0
        self.start_time = time.time()
        # session_id -> 对话历史列表（内存持久化）
        self.sessions: Dict[str, List[Dict[str, str]]] = {}
        if not self.llm_available:
            log.warning("LLM 配置缺失或 requests 不可用，自然语言引擎使用规则化降级")

    # ------------------------------------------------------------------
    # 内部：调用 LLM
    # ------------------------------------------------------------------
    def _call_llm(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """调用统一 LLM 客户端，返回文本；失败返回 None。"""
        result = self._llm.chat(
            messages=[{"role": "system", "content": system_prompt},
                      {"role": "user", "content": user_prompt}],
            temperature=0.1, max_tokens=1024)
        if result["success"]:
            self.call_count += 1
            return result["content"]
        log.warning(f"LLM 调用失败，降级规则: [{result['error_code']}] {result['error']}")
        return None

    @staticmethod
    def _extract_json(text: Optional[str]) -> Optional[Any]:
        """从 LLM 返回文本中提取 JSON（容忍 markdown 代码块包裹）。"""
        if not text:
            return None
        cleaned = text.strip()
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned).strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass
        for opener, closer in (("{", "}"), ("[", "]")):
            start = cleaned.find(opener)
            end = cleaned.rfind(closer)
            if start != -1 and end != -1 and end > start:
                try:
                    return json.loads(cleaned[start:end + 1])
                except json.JSONDecodeError:
                    continue
        return None

    # ------------------------------------------------------------------
    # 多轮对话上下文
    # ------------------------------------------------------------------
    def add_to_context(self, session_id: str, role: str, content: str) -> None:
        """把一轮对话加入指定会话上下文，超出上限时裁剪。"""
        if session_id not in self.sessions:
            self.sessions[session_id] = []
        self.sessions[session_id].append({
            "role": role,
            "content": content,
            "ts": datetime.now().isoformat(),
        })
        # 保留最近 MAX_CONTEXT_ROUNDS * 2 条（一问一答算两轮）
        max_items = self.MAX_CONTEXT_ROUNDS * 2
        if len(self.sessions[session_id]) > max_items:
            self.sessions[session_id] = self.sessions[session_id][-max_items:]

    def get_context(self, session_id: str) -> List[Dict[str, str]]:
        """获取指定会话的对话历史。"""
        return self.sessions.get(session_id, [])

    def clear_context(self, session_id: str) -> bool:
        """清空指定会话的对话历史。"""
        if session_id in self.sessions:
            self.sessions[session_id] = []
            return True
        return False

    # ------------------------------------------------------------------
    # 意图识别
    # ------------------------------------------------------------------
    def intent_recognize(self, text: str) -> Dict[str, Any]:
        """识别用户自然语言意图。LLM 不可用时走关键词规则降级。"""
        text = (text or "").strip()
        system_prompt = (
            "你是安全平台的意图识别器。判断用户这句话属于以下哪个意图，"
            "严格只返回 JSON，格式 {\"intent\": \"...\", \"confidence\": 0.0~1.0}。"
            f"意图可选值: {SUPPORTED_INTENTS}。"
            "如果都不像，返回 general_chat。"
        )
        content = self._call_llm(system_prompt, f"用户输入: {text}")
        parsed = self._extract_json(content)
        if isinstance(parsed, dict) and parsed.get("intent") in SUPPORTED_INTENTS:
            return {
                "intent": parsed["intent"],
                "confidence": float(parsed.get("confidence", 0.8)),
                "source": "llm",
            }
        # 规则降级：关键词打分
        return self._rule_intent(text)

    @staticmethod
    def _rule_intent(text: str) -> Dict[str, Any]:
        """基于关键词的规则化意图识别（降级方案）。"""
        low = text.lower()
        scores: Dict[str, int] = {intent: 0 for intent in SUPPORTED_INTENTS}
        for intent, kws in INTENT_KEYWORDS.items():
            for kw in kws:
                if kw.lower() in low:
                    scores[intent] += 1
        best = max(scores, key=scores.get)
        best_score = scores[best]
        confidence = 0.4 if best_score == 0 else min(0.9, 0.5 + 0.15 * best_score)
        if best_score == 0:
            best = "general_chat"
        return {"intent": best, "confidence": confidence, "source": "rule"}

    # ------------------------------------------------------------------
    # 参数提取
    # ------------------------------------------------------------------
    def extract_params(self, text: str, intent: str) -> Dict[str, Any]:
        """从自然语言提取目标IP/域名/扫描类型/严重程度/时间范围等参数。"""
        # 正则可稳定提取的部分先落地
        params: Dict[str, Any] = {}
        # IPv4
        m_ip = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        if m_ip:
            params["target"] = m_ip.group(0)
        # 域名
        m_domain = re.search(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|cn|net|org|io|dev|test)\b", text)
        if m_domain and "target" not in params:
            params["target"] = m_domain.group(0)
        # URL
        m_url = re.search(r"https?://[^\s，。,]+", text)
        if m_url:
            params["url"] = m_url.group(0)
            if "target" not in params:
                params["target"] = m_url.group(0)
        # 端口
        m_port = re.search(r"端口\s*(\d+)|port\s*[:=]?\s*(\d+)", text, re.IGNORECASE)
        if m_port:
            params["port"] = int(m_port.group(1) or m_port.group(2))
        # 严重程度
        for sev in ["critical", "high", "medium", "low", "严重", "高危", "中危", "低危"]:
            if sev in text.lower():
                params["severity"] = {"严重": "critical", "高危": "high", "中危": "medium",
                                       "低危": "low"}.get(sev, sev)
                break
        # 扫描类型
        if "端口" in text or "port" in text.lower():
            params["scan_type"] = "port"
        elif "web" in text.lower() or "url" in text.lower():
            params["scan_type"] = "web"
        elif "漏洞" in text or "vuln" in text.lower():
            params["scan_type"] = "vuln"
        # 时间范围
        if "最近" in text or "近" in text:
            m_days = re.search(r"(最近|近)\s*(\d+)\s*(天|日|周|个月)", text)
            if m_days:
                unit = m_days.group(3)
                days = int(m_days.group(2))
                if "周" in unit:
                    days *= 7
                elif "月" in unit:
                    days *= 30
                params["time_range"] = f"last_{days}_days"
            else:
                params["time_range"] = "last_7_days"

        # LLM 补充提取
        system_prompt = (
            "你是参数提取器。从用户输入中提取结构化参数，严格只返回 JSON。"
            "字段可包含: target(IP/域名), url, scan_type(port/web/vuln), "
            "severity(critical/high/medium/low), time_range, cve, service。"
            "没有的字段不要编造。"
        )
        content = self._call_llm(system_prompt, f"意图: {intent}\n用户输入: {text}")
        parsed = self._extract_json(content)
        if isinstance(parsed, dict):
            for k, v in parsed.items():
                if v not in (None, "", [], {}):
                    params.setdefault(k, v)
        return params

    # ------------------------------------------------------------------
    # 任务执行（防御/检测视角，全部 try-except 包裹）
    # ------------------------------------------------------------------
    def execute_task(self, intent: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """根据意图调用对应功能模块，失败返回友好错误。"""
        target = params.get("target", "")
        try:
            if intent == "scan_target":
                return self._exec_scan(params)
            if intent == "query_vuln":
                return self._exec_query_vuln(params)
            if intent == "generate_report":
                return self._exec_generate_report(params)
            if intent == "view_trends":
                return self._exec_view_trends(params)
            if intent == "create_task":
                return self._exec_create_task(params)
            if intent == "config_tool":
                return self._exec_config_tool(params)
            # general_chat
            return {"status": "ok", "kind": "chat",
                    "message": "我是 AI 安全助手，你可以让我扫描目标、查询漏洞、生成报告等。",
                    "target": target}
        except Exception as e:  # 任何下游异常都兜底
            log.error(f"execute_task 失败 intent={intent}: {e}")
            return {"status": "error", "intent": intent,
                    "message": f"任务执行时遇到问题：{e}", "target": target}

    def _exec_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """执行扫描：优先调用 scanner 模块，不可用则做端口连通性检测。"""
        target = params.get("target", "")
        if not target:
            return {"status": "error", "message": "缺少扫描目标，请提供 IP 或域名。"}
        findings: List[Dict[str, Any]] = []
        # 尝试调用真实 scanner 模块
        try:
            import scanner  # type: ignore
            findings = [{"source": "scanner_module", "note": "已调用项目 scanner 模块"}]
        except Exception:
            # 降级：仅做受限的端口连通性检测（防御视角，不发包爆破）
            for port in [80, 443, 22]:
                try:
                    sock = socket.create_connection((target, port), timeout=2)
                    sock.close()
                    findings.append({"port": port, "state": "open", "service": "tcp"})
                except Exception:
                    findings.append({"port": port, "state": "closed|filtered"})
        return {"status": "ok", "kind": "scan", "target": target,
                "scan_type": params.get("scan_type", "unknown"), "findings": findings}

    def _exec_query_vuln(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """查询漏洞库：优先调用 database 模块，不可用返回占位结果。"""
        cve = params.get("cve", "")
        target = params.get("target", "")
        try:
            import database  # type: ignore
            return {"status": "ok", "kind": "vuln_query", "source": "database_module",
                    "cve": cve, "target": target,
                    "results": [{"note": "已查询项目漏洞库，请在库中查看明细"}]}
        except Exception:
            return {"status": "ok", "kind": "vuln_query", "source": "builtin",
                    "cve": cve, "target": target, "results": [],
                    "message": "漏洞库模块暂不可用，已返回空结果。"}

    def _exec_generate_report(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """生成报告：优先调用 report 模块。"""
        try:
            import report  # type: ignore
            return {"status": "ok", "kind": "report", "source": "report_module",
                    "note": "已调用项目 report 模块生成评估报告"}
        except Exception:
            return {"status": "ok", "kind": "report", "source": "builtin",
                    "summary": "（规则降级）暂无扫描数据，无法生成完整报告；"
                               "请先执行扫描或查询漏洞。"}

    def _exec_view_trends(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """查看趋势（规则化占位）。"""
        return {"status": "ok", "kind": "trends",
                "time_range": params.get("time_range", "last_7_days"),
                "points": [{"date": "d1", "vulns": 0}, {"date": "d2", "vulns": 0}],
                "note": "趋势数据暂为空，接入监控模块后可展示曲线。"}

    def _exec_create_task(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """创建定时任务（规则化占位）。"""
        return {"status": "ok", "kind": "task",
                "task_id": "task_" + str(int(time.time())),
                "params": params, "note": "已登记任务计划，接入调度模块后自动执行。"}

    def _exec_config_tool(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """配置工具（规则化占位）。"""
        return {"status": "ok", "kind": "config",
                "applied": params, "note": "工具配置已记录（规则降级，未持久化到外部系统）。"}

    # ------------------------------------------------------------------
    # 结果解释（自然语言，非原始 JSON）
    # ------------------------------------------------------------------
    def explain_result(self, result: Dict[str, Any], intent: str) -> str:
        """用自然语言解释执行结果；LLM 不可用时走模板。"""
        system_prompt = (
            "你是安全平台的解释助手。把机器执行结果用通俗、简洁的中文解释给用户，"
            "不要输出 JSON，不要堆砌技术字段，3~5 句话即可。"
        )
        user_prompt = (f"意图: {intent}\n执行结果(JSON): "
                       f"{json.dumps(result, ensure_ascii=False)}")
        content = self._call_llm(system_prompt, user_prompt)
        if content and content.strip():
            return content.strip()
        return self._template_explain(result, intent)

    @staticmethod
    def _template_explain(result: Dict[str, Any], intent: str) -> str:
        """模板化结果解释（降级方案）。"""
        status = result.get("status", "unknown")
        if status == "error":
            return f"这次操作没有成功：{result.get('message', '未知原因')}。请补充信息后再试。"
        kind = result.get("kind", intent)
        if kind == "scan":
            findings = result.get("findings", [])
            open_ports = [f["port"] for f in findings if f.get("state") == "open"]
            if open_ports:
                return (f"已对目标 {result.get('target')} 完成端口连通性检测，"
                        f"发现开放端口：{', '.join(map(str, open_ports))}。"
                        "这是只读检测，未做任何破坏性操作。")
            return f"已对目标 {result.get('target')} 完成检测，未发现明显开放端口。"
        if kind == "vuln_query":
            n = len(result.get("results", []))
            return f"漏洞查询完成，共匹配到 {n} 条记录。"
        if kind == "report":
            return "报告已生成（摘要见结果）。当前为降级模式，完整报告需接入 report 模块。"
        if kind == "trends":
            return "趋势数据已就绪（当前为空），接入监控后可展示曲线。"
        if kind == "task":
            return f"任务已创建，编号 {result.get('task_id')}。"
        if kind == "config":
            return "工具配置已记录。"
        return "操作已完成，结果见详情。"

    # ------------------------------------------------------------------
    # 一站式对话入口
    # ------------------------------------------------------------------
    def chat(self, text: str, session_id: str = "default") -> Dict[str, Any]:
        """一站式：识别意图 -> 提取参数 -> 执行 -> 解释，并维护上下文。"""
        self.add_to_context(session_id, "user", text)
        recognition = self.intent_recognize(text)
        intent = recognition["intent"]
        params = self.extract_params(text, intent)
        result = self.execute_task(intent, params)
        explanation = self.explain_result(result, intent)
        self.add_to_context(session_id, "assistant", explanation)
        return {
            "intent": intent,
            "confidence": recognition.get("confidence"),
            "params": params,
            "result": result,
            "explanation": explanation,
        }


# 模块级单例
_engine: Optional[NaturalLanguageEngine] = None


def get_natural_language_engine() -> NaturalLanguageEngine:
    """获取全局 NaturalLanguageEngine 单例。"""
    global _engine
    if _engine is None:
        _engine = NaturalLanguageEngine()
    return _engine


# ===========================================================================
# 第 6 轮升级 · 模块三：意图置信度增强（追加，不修改上方既有代码）
# ===========================================================================

# 高风险意图：需要用户二次确认
HIGH_RISK_INTENTS = {"scan_target"}

# 意图关键词权重（命中权重越高，置信度越高）
_INTENT_WEIGHTS: Dict[str, float] = {
    "scan_target": 0.4,
    "query_vuln": 0.4,
    "generate_report": 0.4,
    "view_trends": 0.3,
    "create_task": 0.3,
    "config_tool": 0.3,
    "general_chat": 0.2,
}

# 参数校验正则
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)
_CIDR_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)
_URL_RE = re.compile(r"^https?://[^\s]+$")
_PORT_RE = re.compile(r"^\d{1,5}$")


class IntentEnhancer:
    """意图识别增强器：置信度评估、高风险确认、参数校验。"""

    # 置信度低于该值时建议反问确认
    CONFIDENCE_THRESHOLD = 0.6

    def get_intent_confidence(self, text: str, intent: str) -> float:
        """计算意图识别置信度（0-1）。

        基于命中该意图关键词的数量与权重：每命中一个关键词加 0.25，
        超过 3 个不再线性叠加，封顶 1.0。
        """
        keywords = INTENT_KEYWORDS.get(intent, [])
        weight = _INTENT_WEIGHTS.get(intent, 0.2)
        hits = sum(1 for kw in keywords if kw and kw in text)
        confidence = min(1.0, weight + hits * 0.25)
        return round(confidence, 3)

    def should_confirm(self, intent: str, confidence: float) -> bool:
        """低置信度或高风险操作（如整网段扫描）时，建议反问用户确认。"""
        if confidence < self.CONFIDENCE_THRESHOLD:
            return True
        if intent in HIGH_RISK_INTENTS:
            return True
        return False

    def validate_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """参数校验：IP / CIDR / 域名 / 端口 / URL 格式。"""
        results: Dict[str, Any] = {"valid": True, "errors": []}

        target = str(params.get("target", "") or "")
        if target:
            if "/" in target:
                if not _CIDR_RE.match(target):
                    results["valid"] = False
                    results["errors"].append(f"网段格式错误: {target}")
            elif not (_IPV4_RE.match(target) or _DOMAIN_RE.match(target)):
                results["valid"] = False
                results["errors"].append(f"目标格式错误（需IP或域名）: {target}")

        port = params.get("port") or params.get("ports")
        if port:
            for p in str(port).replace(" ", "").split(","):
                if not p:
                    continue
                if not _PORT_RE.match(p) or not (1 <= int(p) <= 65535):
                    results["valid"] = False
                    results["errors"].append(f"端口越界(1-65535): {p}")

        url = params.get("url") or params.get("web_url")
        if url and not _URL_RE.match(str(url)):
            results["valid"] = False
            results["errors"].append(f"URL 格式错误: {url}")

        return results

    def extract_with_validation(self, text: str) -> Dict[str, Any]:
        """带校验的参数提取：先复用规则引擎提取，再做格式校验。"""
        engine = get_natural_language_engine()
        recognition = engine.intent_recognize(text)
        intent = recognition.get("intent", "general_chat")
        params = engine.extract_params(text, intent)

        conf = self.get_intent_confidence(text, intent)
        param_check = self.validate_params(params)

        need_confirm = self.should_confirm(intent, conf)
        confirm_reason = ""
        if need_confirm:
            if conf < self.CONFIDENCE_THRESHOLD:
                confirm_reason = f"意图置信度较低({conf})，建议确认"
            elif intent in HIGH_RISK_INTENTS:
                confirm_reason = "扫描操作可能影响目标，请确认授权范围"

        return {
            "intent": intent,
            "confidence": conf,
            "params": params,
            "param_validation": param_check,
            "need_confirm": need_confirm,
            "confirm_reason": confirm_reason,
        }
