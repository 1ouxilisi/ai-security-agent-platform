#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
提示注入检测器 (Prompt Injection Detector)
=========================================

纯规则（正则 + 模式匹配）实现，不依赖任何外部 LLM API 调用。
针对用户输入文本检测常见的提示注入攻击手法，覆盖中英文混合payload。

每种规则输出：rule_id / rule_name / severity / description / evidence(命中原文) /
pattern / position / recommendation / cwe，绝不只返回布尔值。

参考：OWASP Top 10 for LLM Applications - LLM01:2023 Prompt Injection
"""
import re
from typing import Dict, List, Optional


class PromptInjectionDetector:
    """提示注入检测器 - 对单条 prompt 做 16 类规则的真实匹配"""

    def __init__(self):
        # 规则表：每条规则 = (id, 名称, 严重程度, 正则, 描述, 修复建议, CWE)
        # 正则全部预编译，检测阶段只做 search/finditer
        self._raw_rules: List[Dict] = [
            # 1. 直接指令覆盖（Instruction Override）
            {
                "id": "PI-001",
                "name": "直接指令覆盖",
                "severity": "critical",
                "pattern": (
                    r"ignore\s+(all\s+)?(previous|prior|above|your)\s+"
                    r"(instructions?|prompts?|rules?|directives?)|"
                    r"forget\s+(everything|all\s+(that\s+)?(you\s+)?(were\s+)?(told|said))|"
                    r"disregard\s+(all\s+)?(previous|prior|above|the|your)|"
                    r"bypass\s+(all\s+)?(previous|prior|above)|"
                    r"忽略(之前|前面|以上|以前)(的)?(所有)?(指令|提示|规则|要求)|"
                    r"忘记(之前|前面|以上|以前)(的)?(所有)?(指令|提示|规则)|"
                    r"无视(之前|前面|以上|系统|原来)(的)?(所有)?(指令|提示|规则)"
                ),
                "description": "攻击者要求模型丢弃系统/先前指令，是最典型的直接提示注入",
                "recommendation": "对输入做指令覆盖类关键词拦截，并在系统提示中加固角色边界",
                "cwe": "CWE-77",
            },
            # 2. 角色扮演绕过（Roleplay / Persona Hijack）
            {
                "id": "PI-002",
                "name": "角色扮演绕过",
                "severity": "high",
                "pattern": (
                    r"you\s+are\s+now\s+(a|an|the)|"
                    r"pretend\s+(that\s+)?(you\s+are|to\s+be)|"
                    r"act\s+as\s+(a|an|the)\s+(?!user|assistant$)|"
                    r"simulate\s+(a|an)|"
                    r"do\s+anything\s+now|\bDAN\b|"
                    r"现在你是|你现在是|从现在开始你是|假设你是|假如你是|想象你是|扮演(成|一下)?(一个)?|"
                    r"你就当(自己)?(是)?"
                ),
                "description": "通过要求模型进入新角色来绕过安全限制（DAN 等）",
                "recommendation": "限制自由角色扮演，对非授权 persona 切换做二次确认",
                "cwe": "CWE-642",
            },
            # 3. 系统提示窃取（System Prompt Exfiltration）
            {
                "id": "PI-003",
                "name": "系统提示窃取",
                "severity": "high",
                "pattern": (
                    r"repeat\s+(back\s+)?(your|the)\s+(system\s+)?(prompt|instruction|message)|"
                    r"print\s+(out\s+)?(your|the)\s+(system\s+)?(prompt|instruction)|"
                    r"what\s+are\s+your\s+(system\s+)?(instructions?|rules?)|"
                    r"show\s+me\s+(your|the)\s+(system\s+)?(prompt|instructions?)|"
                    r"output\s+(your|the)\s+(initial\s+)?(instructions?|prompt|rules?)|"
                    r"重复(一下)?(你的|你的系统|系统)?(提示|指令|设定|规则)|"
                    r"输出(你的|系统|全部)(初始)?(指令|提示|设定|规则)|"
                    r"(系统|全部|所有).{0,4}(提示|指令|设定|规则).{0,6}(输出|重复|打印|说出来)|"
                    r"(全部|所有).{0,4}(输出|重复|打印).{0,4}(系统)?(提示|指令|设定)|"
                    r"把你(开始|最初)(说|告诉)我的(话|内容)(都)?(重复|输出|打印)(一遍)?"
                ),
                "description": "攻击者诱导模型泄露系统提示词中的保密配置/内部规则",
                "recommendation": "禁止输出系统提示，对“重复/打印你的指令”类请求直接拦截",
                "cwe": "CWE-200",
            },
            # 4. 分隔符注入（Delimiter Injection）
            {
                "id": "PI-004",
                "name": "伪造分隔符注入",
                "severity": "high",
                "pattern": (
                    r"^\s*-{3,}\s*$|"
                    r"^\s*#{2,}\s*$|"
                    r"^\s*```\s*$|"
                    r"\[(END|START|SYSTEM|USER|ASSISTANT|INSTSTRUCTION|INSTRUCTION|IGNORE)\]|"
                    r"\[end\s+of\s+(system|prompt|instructions?)\]|"
                    r"【(END|START|系统|用户|助手|指令)】"
                ),
                "description": "伪造 [END]/[START]/--- 等分隔符，使模型把后续文本误认为系统消息",
                "recommendation": "对输入中的伪分隔符做转义或替换，严禁用户文本中出现结构性分隔符",
                "cwe": "CWE-1437",
            },
            # 5. Markdown 伪造系统消息
            {
                "id": "PI-005",
                "name": "Markdown结构伪造",
                "severity": "medium",
                "pattern": (
                    r"^>\s*(system|assistant|user|developer|ignored|note|instruction)[\s:：]|"
                    r"^#+\s*(system|assistant|developer|instruction|ignore|重要|注意|系统|助手)[:：]?\s|"
                    r"^-\s+(now\s+)?(system|new\s+instruction|ignore)[:：]|"
                    r"^\s*(system|assistant|user)[:：]\s*\S"
                ),
                "description": "利用 Markdown 标题/引用/列表伪造系统消息格式",
                "recommendation": "渲染时对用户输入做 Markdown 清洗，结构性标记需隔离",
                "cwe": "CWE-1437",
            },
            # 6. Base64 / 编码注入
            {
                "id": "PI-006",
                "name": "编码 payload 注入",
                "severity": "high",
                "pattern": (
                    r"(base64|rot13|decode|decrypt|解码|翻译(成)?(明文|原文)|reverse\s+(it|the))"
                    r"[^\n]{0,80}"
                    r"[A-Za-z0-9+/=]{32,}|"
                    r"[A-Za-z0-9+/=]{40,}={0,2}"
                    r"[^\n]{0,80}(base64|decode|decrypt|解码|执行|run|execute)"
                ),
                "description": "在输入中嵌入长 Base64/编码串并要求模型解码执行，绕过关键词过滤",
                "recommendation": "检测长编码串并禁止“解码后直接执行”类指令",
                "cwe": "CWE-172",
            },
            # 7. 多语言/混淆注入
            {
                "id": "PI-007",
                "name": "多语言/Leet混淆",
                "severity": "medium",
                "pattern": (
                    r"(y0u|y0u'r3|th3|n0w|1gn0r3|f0rg3t|pr3t3nd|d0\s+4nyth1ng)|"
                    r"ni\s+xian\s+zai\s+shi|"
                    r"(\bwo\s+yao|bao\+kuan|hu\s+lüe)\b|"
                    r"(ignore|forget|disregard).{0,10}(you|your).{0,10}(instructions?|rules?)"
                    r"[^\w一-鿿]{0,3}[一-鿿]"
                ),
                "description": "使用 leetspeak / 拼音 / 中英混写绕过关键词黑名单",
                "recommendation": "对输入做归一化（去 leet、转写拼音）后再走规则匹配",
                "cwe": "CWE-184",
            },
            # 8. 间接提示注入（Indirect Injection）
            {
                "id": "PI-008",
                "name": "间接引用注入",
                "severity": "high",
                "pattern": (
                    r"(the\s+)?(user|document|text|file|webpage|email|article|system)\s+"
                    r"(said|says|writes?|states?|mentions?|instructs?|told\s+you)\s*[:：]?|"
                    r"(用户|文档|文件|网页|邮件|文章|系统)(中|里)?(说|写道|指出|指示|要求|告诉(你|助手))[:：]?|"
                    r"according\s+to\s+(the\s+document|above|the\s+user)"
                ),
                "description": "把恶意指令包装成“引用内容”，诱导模型信任并执行",
                "recommendation": "对外部数据（RAG/工具返回）做指令隔离标记，禁止其中的指令被当作命令",
                "cwe": "CWE-1427",
            },
            # 9. 工具调用劫持（Tool Call Hijack）
            {
                "id": "PI-009",
                "name": "工具调用劫持",
                "severity": "critical",
                "pattern": (
                    r"(call|invoke|trigger|run|use|execute)\s+(the\s+)?(tool|function|api|plugin|weapon|terminal|shell|bash|cmd)|"
                    r"execute\s+(the\s+)?(following\s+)?(function|command)|"
                    r"(调用|执行|运行|触发)(一下)?(那个|该|这个)?(工具|函数|接口|插件|命令|终端|shell|bash)"
                ),
                "description": "诱导模型调用危险工具/函数（命令执行、文件写入）",
                "recommendation": "工具调用前做参数白名单与人工确认，禁止用户文本直接指定工具名",
                "cwe": "CWE-77",
            },
            # 10. 数据外泄（Exfiltration）
            {
                "id": "PI-010",
                "name": "数据外泄指令",
                "severity": "critical",
                "pattern": (
                    r"(send|post|upload|leak|exfiltrate|forward|export)\s+(the\s+)?"
                    r"(data|result|output|context|history|conversation)"
                    r"[^\n]{0,60}(http://|https://|ftp://|webhook|@)|"
                    r"把(数据|结果|上下文|对话|输出)(发送|上传|泄露|转发|导出)到[^\n]{0,60}"
                    r"(http://|https://|ftp://|webhook)|"
                    r"\bexfiltrat"
                ),
                "description": "要求把对话/上下文数据发送到外部 URL 形成数据外泄",
                "recommendation": "出站请求目标白名单化，禁止把上下文内容外发到用户指定 URL",
                "cwe": "CWE-201",
            },
            # 11. 权限提升（Privilege Escalation）
            {
                "id": "PI-011",
                "name": "权限提升尝试",
                "severity": "high",
                "pattern": (
                    r"(give|grant|make)\s+me\s+(admin|root|sudo|super|full\s+access|elevated)|"
                    r"bypass\s+(the\s+)?(filter|safety|guard|restriction|moderation)|"
                    r"disable\s+(the\s+)?(safety|filter|guard|moderation|alignment)|"
                    r"给(我|予)(我)?(管理员|root|超级用户|sudo)(权限|身份)?|"
                    r"绕过(所有)?(过滤|安全|审核|限制|防火墙)|"
                    r"关闭(所有)?(安全|审核|过滤|对齐|护栏)"
                ),
                "description": "要求模型提升权限或关闭安全护栏",
                "recommendation": "权限模型最小化，任何提权/关闭安全的请求直接拒绝",
                "cwe": "CWE-269",
            },
            # 12. 上下文溢出 / 长填充
            {
                "id": "PI-012",
                "name": "上下文溢出填充",
                "severity": "medium",
                "pattern": r"(.)\1{999,}",
                "description": "输入中存在单字符重复 1000+ 次，疑似上下文溢出/DoS 填充",
                "recommendation": "输入长度上限 + 重复字符压缩归一化",
                "cwe": "CWE-400",
            },
            # 13. 思维链注入（CoT injection）
            {
                "id": "PI-013",
                "name": "思维链恶意引导",
                "severity": "medium",
                "pattern": (
                    r"let's\s+think\s+step\s+by\s+step[^\n]{0,200}"
                    r"(how\s+(to|can\s+i)\s+(make|build|hack|steal|create|synthesis))|"
                    r"think\s+step\s+by\s+step[^\n]{0,200}(harmful|illegal|dangerous|weapon|bomb)|"
                    r"一步一步(地)?思考[^\n]{0,80}(如何|怎么)(制作|制造|入侵|黑|偷|合成|武器)"
                ),
                "description": "借“让我们一步步思考”包装恶意推理引导",
                "recommendation": "对 CoT 推理链做内容审核，不把用户给出的推理步骤当结论",
                "cwe": "CWE-1437",
            },
            # 14. 情感操纵（Emotional Manipulation）
            {
                "id": "PI-014",
                "name": "情感勒索绕过",
                "severity": "low",
                "pattern": (
                    r"(i'?m\s+(so\s+)?(depressed|suicidal|desperate|in\s+pain|hopeless))|"
                    r"(please|i\s+beg\s+you|i\s+really\s+need)\s+help[^\n]{0,60}(no|please|anything)|"
                    r"我(很|真的|非常)(痛苦|绝望|难过|活不下去|撑不下去)|"
                    r"(求(你|求你)(了)?|拜托(了)?)[^\n]{0,40}(帮|答应|满足|任何要求)|"
                    r"(没有人|没人)(在乎|关心)(我|他)"
                ),
                "description": "利用情感状态（痛苦/绝望）施压诱导模型放弃安全原则",
                "recommendation": "情感类请求转人工/心理援助通道，不因情绪降低安全阈值",
                "cwe": "CWE-1021",
            },
            # 15. 时间/日期认知注入
            {
                "id": "PI-015",
                "name": "时间认知注入",
                "severity": "medium",
                "pattern": (
                    r"it(?:'s| is)\s+(now\s+)?(20\d{2}|the\s+year\s+20\d{2})|"
                    r"current\s+(date|time|year)\s+is\s+(20\d{2})|"
                    r"现在是(20)?\d{2}年|今年是(20)?\d{2}年|"
                    r"(new\s+year|after\s+20\d{2})[^\n]{0,40}(rules?\s+(changed|updated|gone))|"
                    r"(规则|政策|限制)(已经)(过期|失效|取消|废除)"
                ),
                "description": "篡改模型对当前时间/规则生效期的认知，宣称限制已过期",
                "recommendation": "模型时间由系统侧注入，忽略用户给出的时间声明",
                "cwe": "CWE-1437",
            },
            # 16. 伪造助手回复（Fake Assistant Turn）
            {
                "id": "PI-016",
                "name": "伪造助手回复注入",
                "severity": "high",
                "pattern": (
                    r"^assistant\s*[:：][\s]*"
                    r"(sure|of\s+course|here(?:'s| is)|no\s+problem|当然可以|没问题|这是|好的，下面)|"
                    r"(continue\s+(the\s+)?(previous|above)\s+(conversation|answer|roleplay))|"
                    r"(接着|继续)(扮演|之前|上面)(的)?(角色|对话|回答|扮演)"
                ),
                "description": "伪造 assistant 消息诱导模型认为已经同意执行危险请求",
                "recommendation": "多轮消息严格按角色隔离，用户输入中出现的 assistant 前缀必须剥离",
                "cwe": "CWE-1427",
            },
        ]

        # 预编译正则，统一忽略大小写
        self.compiled_rules = [
            {**r, "regex": re.compile(r["pattern"], re.IGNORECASE | re.MULTILINE)}
            for r in self._raw_rules
        ]

    # ------------------------------------------------------------------ #
    # 主检测接口
    # ------------------------------------------------------------------ #
    def detect(self, prompt: str, context: str = "") -> List[Dict]:
        """对单条 prompt 执行全部规则检测

        Args:
            prompt: 待检测的用户输入
            context: 可选上下文（如 RAG 检索文档、工具返回），一并检测间接注入

        Returns:
            命中规则列表，每项含规则 id/名称/严重度/证据原文/位置等
        """
        findings: List[Dict] = []
        text = prompt or ""
        # 把上下文拼进来一起检测（间接注入主要藏在 context 里）
        full_text = (text + "\n" + context) if context else text
        if not full_text.strip():
            return findings

        for rule in self.compiled_rules:
            for m in rule["regex"].finditer(full_text):
                matched = m.group(0).strip()
                # 证据裁剪，避免超长 payload 刷屏
                evidence = matched if len(matched) <= 300 else matched[:300] + "…"
                # 命中位置相对 prompt 起点
                offset = m.start()
                findings.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "evidence": evidence,
                    "pattern": rule["pattern"][:120],
                    "position": [offset, m.end()],
                    "in_context": bool(context and offset >= len(text) + 1),
                    "recommendation": rule["recommendation"],
                    "cwe": rule["cwe"],
                })
        return findings

    def rule_count(self) -> int:
        """返回已加载规则数量（自测/验收用）"""
        return len(self.compiled_rules)


# 模块级便捷入口
_default_detector = PromptInjectionDetector()

def detect_prompt_injection(prompt: str, context: str = "") -> List[Dict]:
    """模块级便捷函数：对单条文本跑全部注入规则"""
    return _default_detector.detect(prompt, context)


# --------------------------------------------------------------------------- #
# register(engine)：供统一引擎注册使用
# --------------------------------------------------------------------------- #
def register(engine) -> None:  # pragma: no cover - 仅注册入口
    """注册到统一安全评估引擎（由 unified/ai_assessor.py 间接使用）。

    本模块为纯检测器库，自身不直接继承 DomainAssessor；
    统一入口见 unified/ai_assessor.py。
    """
    # 占位：保持模块可独立被 import 且不破坏 engine 接口约定
    return None
