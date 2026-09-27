#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI Agent 安全审计器 (Agent Security Auditor)
==========================================

纯规则实现，两部分能力：

1. audit(agent_config, tools) —— 静态审计 Agent 配置与工具清单：
   工具权限 / 输出过滤 / 目标漂移 / 人工确认 / 沙箱执行 /
   审计日志 / 速率限制 / 输入验证 共 8 类控制项。

2. detect_tool_hijacking(conversation) —— 从多轮对话历史中检测工具调用劫持：
   用户诱导调用工具、工具参数中的命令注入、路径穿越等。

不调用外部 LLM API，全部为规则/模式匹配。
"""
import re
from typing import Dict, List, Optional


class AgentSecurityAuditor:
    """AI Agent 配置与工具调用安全审计器"""

    # 高风险工具类别 → 识别关键词（工具名/描述中命中即视为高风险）
    HIGH_RISK_CATEGORIES: Dict[str, List[str]] = {
        "文件写入": ["write_file", "file_write", "create_file", "delete_file",
                     "remove_file", "upload_file", "save_file", "write", "delete"],
        "命令执行": ["shell", "bash", "cmd", "command_exec", "run_command",
                     "exec", "execute_code", "terminal", "subprocess"],
        "网络请求": ["http_request", "fetch_url", "web_request", "curl",
                     "download", "send_request", "api_call", "requests."],
        "数据库操作": ["sql", "query_db", "execute_sql", "database", "db_write",
                       "db_delete", "insert_row", "update_row"],
        "消息/邮件发送": ["send_email", "send_message", "send_sms", "notify",
                          "smtp", "mail", "slack_notify", "webhook_send"],
    }

    # ------------------------------------------------------------------ #
    # 第一部分：静态配置审计
    # ------------------------------------------------------------------ #
    def audit(self, agent_config: Dict, tools: Optional[List[Dict]] = None) -> List[Dict]:
        """审计 Agent 配置与工具清单

        Args:
            agent_config: Agent 配置字典，例如
                {"output_filter": true, "human_in_the_loop": [...], ...}
            tools: 工具清单，每项形如
                {"name": "run_shell", "description": "执行shell命令", "risk": "high"}

        Returns:
            审计发现列表（缺失的安全控制 / 高风险工具未受控）
        """
        findings: List[Dict] = []
        config = agent_config or {}
        tools = tools or []

        # 把整个配置拍平成小写文本，便于关键词存在性检测
        config_blob = self._flatten_config(config).lower()

        # ---- 控制项 1：输出过滤 / 内容审核 ----
        findings.append(self._check_presence(
            check_id="AUD-001", name="输出内容过滤",
            keywords=["output_filter", "content_moderation", "response_safety",
                      "output_sanitizer", "moderation", "safety_check",
                      "内容审核", "输出过滤", "内容安全"],
            config_blob=config_blob,
            description="Agent 是否对模型输出做内容审核/敏感信息过滤",
            severity_missing="high",
            recommendation="在输出链路接入内容审核模型/敏感词过滤与 PII 脱敏",
        ))

        # ---- 控制项 2：目标漂移 / 步骤审核 ----
        findings.append(self._check_presence(
            check_id="AUD-002", name="目标一致性/漂移检测",
            keywords=["goal_consistency", "drift_detection", "step_review",
                      "deviation_alert", "goal_check", "task_alignment",
                      "目标一致", "漂移检测", "偏离告警"],
            config_blob=config_blob,
            description="Agent 是否在多步执行中检查目标一致性、步骤偏离告警",
            severity_missing="medium",
            recommendation="加入任务目标锚定与步骤偏离检测，发现漂移即暂停",
        ))

        # ---- 控制项 3：人工确认（human-in-the-loop）----
        findings.append(self._check_presence(
            check_id="AUD-003", name="高风险操作人工确认",
            keywords=["human_in_the_loop", "approval_required", "require_confirmation",
                      "human_approval", "manual_review", "human_in_loop",
                      "人工确认", "人工审核", "需要审批"],
            config_blob=config_blob,
            description="高风险工具调用是否要求人工确认后才执行",
            severity_missing="critical",
            recommendation="对文件写入/命令执行/外发等高危操作强制人工审批",
        ))

        # ---- 控制项 4：沙箱执行 ----
        findings.append(self._check_presence(
            check_id="AUD-004", name="代码/命令沙箱隔离",
            keywords=["sandbox", "isolated_execution", "container", "gVisor",
                      "firecracker", "chroot", "seccomp", "jail",
                      "沙箱", "隔离执行", "容器化"],
            config_blob=config_blob,
            description="代码执行/命令执行是否在沙箱中隔离运行",
            severity_missing="high",
            recommendation="命令/代码执行必须放进无网络/只读根文件系统的沙箱",
        ))

        # ---- 控制项 5：审计日志 ----
        findings.append(self._check_presence(
            check_id="AUD-005", name="操作审计日志",
            keywords=["audit_log", "logging_enabled", "trace_enabled",
                      "tool_call_log", "audit_trail", "structured_log",
                      "审计日志", "操作日志", "调用追踪"],
            config_blob=config_blob,
            description="是否记录完整的工具调用/决策审计日志",
            severity_missing="medium",
            recommendation="记录每次工具调用的入参/出参/决策依据并防篡改归档",
        ))

        # ---- 控制项 6：速率限制 ----
        findings.append(self._check_presence(
            check_id="AUD-006", name="工具调用速率限制",
            keywords=["rate_limit", "max_calls_per_minute", "tool_call_limit",
                      "throttle", "quota", "rate_limiting",
                      "速率限制", "调用频率限制", "配额"],
            config_blob=config_blob,
            description="工具调用是否有速率限制/配额，防止被滥用或放大攻击",
            severity_missing="medium",
            recommendation="按用户/会话对工具调用做每分钟/每日配额与退避",
        ))

        # ---- 控制项 7：输入验证 / 参数清洗 ----
        findings.append(self._check_presence(
            check_id="AUD-007", name="工具参数验证与清洗",
            keywords=["input_validation", "parameter_sanitization", "arg_validation",
                      "schema_validation", "type_check", "allowlist", "whitelist",
                      "输入验证", "参数校验", "白名单", "清洗"],
            config_blob=config_blob,
            description="工具入参是否做 schema 校验、类型检查与危险字符清洗",
            severity_missing="high",
            recommendation="用 JSON Schema/类型校验工具入参，对路径/命令类参数走白名单",
        ))

        # ---- 控制项 8：工具清单逐项审计 ----
        findings.extend(self._audit_tools(tools, config_blob))

        # 去掉 None（表示该项已存在、无问题）
        return [f for f in findings if f is not None]

    # ------------------------------------------------------------------ #
    # 工具清单审计
    # ------------------------------------------------------------------ #
    def _audit_tools(self, tools: List[Dict], config_blob: str) -> List[Optional[Dict]]:
        """逐项分析工具：识别高风险类别并检查是否有管控"""
        results: List[Optional[Dict]] = []
        if not tools:
            # 未提供工具清单本身算一个低危观察项
            results.append({
                "check_id": "AUD-008",
                "name": "工具清单不可见",
                "severity": "low",
                "status": "missing",
                "description": "未提供 tools 清单，无法评估工具面风险",
                "evidence": "tools=[] / None",
                "recommendation": "审计时应传入完整工具清单（name+description）",
            })
            return results

        # 配置级是否声明了工具管控
        has_guard = any(k in config_blob for k in (
            "permission", "allowed_tools", "tool_policy", "confirm", "approval",
            "权限", "允许的工具", "审批"))

        for tool in tools:
            name = str(tool.get("name", tool.get("tool_name", ""))).lower()
            desc = str(tool.get("description", tool.get("desc", ""))).lower()
            text = f"{name} {desc}"

            # 命中哪个高风险类别
            hit_categories = [
                cat for cat, kws in self.HIGH_RISK_CATEGORIES.items()
                if any(kw in text for kw in kws)
            ]
            if not hit_categories:
                continue

            # 该工具自身是否声明了确认/权限/沙箱
            tool_blob = (str(tool)).lower()
            self_guarded = any(k in tool_blob for k in (
                "confirm", "approval", "permission", "sandbox", "allowlist",
                "确认", "审批", "权限", "沙箱"))

            severity = "high" if not (has_guard or self_guarded) else "low"
            results.append({
                "check_id": "AUD-008",
                "name": f"高风险工具未受控: {name or '(unnamed)'}",
                "severity": severity,
                "status": "finding",
                "description": f"工具属于高风险类别 {hit_categories}，"
                               f"配置中未见对应权限/确认/沙箱管控" if severity == "high"
                               else f"工具属于高风险类别 {hit_categories}，已有基本管控",
                "evidence": f"tool.name={name!r}, description={desc[:120]!r}",
                "recommendation": "对该工具强制人工确认 + 参数白名单 + 沙箱执行",
            })
        return results

    # ------------------------------------------------------------------ #
    # 第二部分：对话历史中的工具调用劫持检测
    # ------------------------------------------------------------------ #
    def detect_tool_hijacking(self, conversation: List[Dict]) -> List[Dict]:
        """从多轮对话中检测工具调用劫持

        Args:
            conversation: 消息列表，每项形如
                {"role": "user"/"assistant", "content": "...",
                 "tool_calls": [{"name": "...", "arguments": "..."}]}

        Returns:
            劫持/注入发现列表
        """
        findings: List[Dict] = []
        if not conversation:
            return findings

        # 危险命令注入 payload 模式
        cmd_injection = re.compile(
            r"(;\s*(rm\s+-rf|curl|wget|nc|bash|sh\s+-i))|"
            r"(\|\s*(curl|wget|bash|sh|nc\s+))|"
            r"(&&\s*(wget|curl|chmod\s+\+x|nc\s+))|"
            r"(`[^`]{1,80}`)|"
            r"(\$\([^)]{1,80}\))|"
            r"(\brm\s+-rf\s+/)",
            re.IGNORECASE,
        )
        # 路径穿越
        path_traversal = re.compile(r"(\.\./){2,}|([A-Za-z]:)?[/\\]?\.\.(/|\\)\.\.")
        # 用户诱导调用工具的话术
        induce_call = re.compile(
            r"(?i)(call|invoke|use|run|execute|trigger)\s+(the\s+)?(tool|function|api|"
            r"shell|bash|terminal|command)\b|"
            r"(调用|执行|运行)(一下)?(那个|该|这个)?(工具|函数|接口|命令|终端)",
            re.IGNORECASE,
        )

        for idx, msg in enumerate(conversation):
            role = str(msg.get("role", "")).lower()
            content = str(msg.get("content", "") or "")

            # 1) 用户消息诱导调用工具
            if role == "user":
                for m in induce_call.finditer(content):
                    findings.append({
                        "check_id": "HIJ-001",
                        "name": "用户诱导工具调用",
                        "severity": "high",
                        "description": "用户消息中直接要求调用工具/命令执行能力",
                        "evidence": m.group(0).strip()[:200],
                        "line": idx,
                        "role": role,
                        "recommendation": "工具调用必须由 Agent 自主决策，禁止用户文本直接指定工具",
                    })

            # 2) 工具参数 / assistant 输出中的命令注入
            tool_calls = msg.get("tool_calls") or []
            arg_text_parts = []
            if isinstance(tool_calls, list):
                for tc in tool_calls:
                    if isinstance(tc, dict):
                        arg_text_parts.append(str(tc.get("arguments", tc.get("args", ""))))
            # 某些结构把参数放在 content 里
            arg_text = "\n".join(arg_text_parts + [content])

            for m in cmd_injection.finditer(arg_text):
                matched = m.group(0).strip()
                if not matched:
                    continue
                findings.append({
                    "check_id": "HIJ-002",
                    "name": "工具参数命令注入",
                    "severity": "critical",
                    "description": "工具参数中检测到 shell 元字符/命令拼接 payload",
                    "evidence": matched[:200],
                    "line": idx,
                    "role": role,
                    "recommendation": "工具参数禁止拼接 shell，使用参数数组 + 白名单",
                })

            # 3) 路径穿越
            for m in path_traversal.finditer(arg_text):
                findings.append({
                    "check_id": "HIJ-003",
                    "name": "工具参数路径穿越",
                    "severity": "high",
                    "description": "文件类工具参数中出现 ../ 路径遍历",
                    "evidence": m.group(0),
                    "line": idx,
                    "role": role,
                    "recommendation": "文件路径必须 chroot 到工作目录并规范化后校验",
                })

        return findings

    # ------------------------------------------------------------------ #
    # 内部工具
    # ------------------------------------------------------------------ #
    @staticmethod
    def _flatten_config(config: Dict, prefix: str = "") -> str:
        """把嵌套配置字典拍平成键值字符串，便于关键词检索"""
        parts: List[str] = []
        for k, v in (config or {}).items():
            key = f"{prefix}{k}"
            if isinstance(v, dict):
                parts.append(AgentSecurityAuditor._flatten_config(v, key + "."))
            elif isinstance(v, list):
                parts.append(key + " " + " ".join(str(x) for x in v))
            else:
                parts.append(f"{key} {v}")
        return "\n".join(parts)

    @staticmethod
    def _check_presence(check_id: str, name: str, keywords: List[str],
                        config_blob: str, description: str,
                        severity_missing: str, recommendation: str) -> Optional[Dict]:
        """通用“控制项存在性”检查：存在则返回 None，缺失则返回发现"""
        present = any(kw in config_blob for kw in keywords)
        if present:
            return None
        return {
            "check_id": check_id,
            "name": name,
            "severity": severity_missing,
            "status": "missing",
            "description": description,
            "evidence": f"配置中未找到任何控制项关键词: {keywords}",
            "recommendation": recommendation,
        }


_default_auditor = AgentSecurityAuditor()

def audit_agent(agent_config: Dict, tools: Optional[List[Dict]] = None) -> List[Dict]:
    """模块级便捷函数"""
    return _default_auditor.audit(agent_config, tools)


def register(engine) -> None:  # pragma: no cover
    """注册占位（统一入口见 unified/ai_assessor.py）"""
    return None
