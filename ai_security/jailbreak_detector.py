#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
越狱攻击检测器 (Jailbreak Detector)
===================================

纯规则实现，检测已知的 LLM 越狱（jailbreak）技术家族：
DAN、角色扮演越狱、前缀/后缀注入、假设场景、分段请求、编码绕过、
翻译绕过、格式化绕过、学术包装、对比攻击、安全测试伪装等。

不依赖外部 LLM API，全部基于正则真实匹配，输出证据原文。
"""
import re
from typing import Dict, List


class JailbreakDetector:
    """越狱攻击检测器 - 14 类已知越狱技术规则"""

    def __init__(self):
        self._raw_rules: List[Dict] = [
            # 1. DAN 家族（Do Anything Now 及其变体）
            {
                "id": "JB-001",
                "name": "DAN家族越狱",
                "severity": "critical",
                "pattern": (
                    r"\bDAN\s*\d*(\.\d+)?\b|"
                    r"do\s+anything\s+now|"
                    r"\bDUDE\b|\bDEV\s+MODE\b|\bSTAN\b|\bAIM\b|"
                    r"jailbreak(ed|ing)?\s+(mode|version|prompt)|"
                    r"(DAN|DUDE|DEV)(5|10|9|7)\.0"
                ),
                "description": "命中 DAN/DUDE/DEV/STAN/AIM 等经典越狱框架名称",
                "recommendation": "对越狱框架名及其版本号做黑名单拦截",
                "cwe": "CWE-1430",
            },
            # 2. 角色扮演/开发者模式越狱
            {
                "id": "JB-002",
                "name": "角色/开发者模式越狱",
                "severity": "critical",
                "pattern": (
                    r"always\s+intelligent\s+and\s+machiavellian|"
                    r"developer('?s)?\s+mode|"
                    r"debug\s+mode|god\s+mode|master\s+mode|unfiltered\s+mode|"
                    r"no\s+restrictions?\s+mode|unrestricted(,?\s+no\s+filters?)?|"
                    r"开发者(调试)?模式|上帝模式|无限制模式|无过滤模式|"
                    r"解除(所有)?限制|关闭(所有)?(审查|安全|过滤)"
                ),
                "description": "要求进入开发者/无限制模式以绕过对齐",
                "recommendation": "禁止进入任何“无限制”模式，开发者模式需强鉴权",
                "cwe": "CWE-1430",
            },
            # 3. 前缀注入（要求回答以特定放行话术开头）
            {
                "id": "JB-003",
                "name": "前缀注入",
                "severity": "high",
                "pattern": (
                    r"(your\s+answer|reply|response|output|start)\s+(must\s+)?(begin|start|open)\s+with\s+"
                    r"['\"`](sure|of\s+course|no\s+problem|certainly|here(?:'s| is))|"
                    r"(start|begin)\s+your\s+answer\s+with|"
                    r"(回答|回复)(必须|要)(以|从).{0,10}(开头|开始)|"
                    r"^(sure|of\s+course|no\s+problem|certainly),?\s*here"
                ),
                "description": "诱导模型用“当然可以”等放行话术开头，绕过自我审查",
                "recommendation": "检测对回答前缀的硬性要求，禁止预设放行话术",
                "cwe": "CWE-1437",
            },
            # 4. 后缀注入
            {
                "id": "JB-004",
                "name": "后缀注入",
                "severity": "medium",
                "pattern": (
                    r"(end|finish|close)\s+your\s+(answer|reply|response|output)\s+with|"
                    r"end\s+with\s+['\"`][a-z]|。|"
                    r"(回答|回复|结尾)(必须|要)(以|用).{0,10}(结尾|结束)"
                ),
                "description": "要求回答以特定后缀结尾，常配合前缀注入完成越狱",
                "recommendation": "禁止用户约束回答首尾话术",
                "cwe": "CWE-1437",
            },
            # 5. 假设场景包装
            {
                "id": "JB-005",
                "name": "假设场景包装",
                "severity": "high",
                "pattern": (
                    r"in\s+a\s+(hypothetical|fictional|made-up)\s+(world|scenario|universe|situation)|"
                    r"(for|in)\s+(educational|research|academic|demonstration)\s+(purposes?|reasons?|use)|"
                    r"no\s+one\s+will\s+(get\s+)?(hurt|harmed|used|know)|"
                    r"hypothetically[,\s]+|"
                    r"在(一个)?(假设|虚构|假想|平行)的?(世界|场景|宇宙)?|"
                    r"出于(教育|教学|研究|演示|学习)目的|"
                    r"(没有人|没人)(会|有人)(受伤|受害|知道|发现)|"
                    r"这是(虚构|假设|假想|模拟)的(场景|故事|情况)"
                ),
                "description": "用“假设/教育目的/无人受害”包装有害请求",
                "recommendation": "假设性包装不改变内容风险等级，按真实内容审核",
                "cwe": "CWE-1430",
            },
            # 6. 分段请求绕过
            {
                "id": "JB-006",
                "name": "分段请求绕过",
                "severity": "medium",
                "pattern": (
                    r"(write|give|show|produce)\s+(the\s+)?(first|1st|second|2nd|next|remaining)\s+"
                    r"(half|part|section|paragraph|chapter)|"
                    r"^continue[,.!\s]|continue\s+(the\s+)?(story|text|answer|writing)|"
                    r"写(前|后)(半部分|一部分|一段)|"
                    r"(接着|继续)(写|往下|上面的)(内容|部分|故事|回答)"
                ),
                "description": "把有害内容拆成多段请求，单段看似无害但拼接后越界",
                "recommendation": "按会话累积上下文做整体内容审核，而非单条独立判断",
                "cwe": "CWE-1437",
            },
            # 7. 编码绕过
            {
                "id": "JB-007",
                "name": "编码输出绕过",
                "severity": "high",
                "pattern": (
                    r"(use|write|encode|output|give)\s+(the\s+)?(answer|output|result|it)\s+"
                    r"(in|as|using)\s+(base64|rot13|rot\s?13|leet\s?speak|hex|morse|emoji|pinyin|unicode\s+escapes?)|"
                    r"(base64|rot13|hex|morse|emoji|拼音)(编码|加密|输出|表示)(以下|这段|内容)?|"
                    r"\b(caesar|substitution)\s+cipher"
                ),
                "description": "要求用编码/转写输出有害内容以绕过关键词审核",
                "recommendation": "对编码输出先解码还原，再走内容审核",
                "cwe": "CWE-172",
            },
            # 8. 翻译绕过
            {
                "id": "JB-008",
                "name": "翻译绕过",
                "severity": "medium",
                "pattern": (
                    r"translate\s+(the\s+)?(following|this|text|content)\s+to\s+(english|chinese|french|spanish|german|russian|japanese)|"
                    r"translate\s+(it\s+)?back|"
                    r"翻译(成|为)(英文|中文|法文|日文|俄文)|"
                    r"把(下面|以下|这段|这句话)(翻译|译)(成|为)"
                ),
                "description": "借翻译请求把有害内容换一种语言输出",
                "recommendation": "翻译请求同样经过内容审核，不因语种切换放行",
                "cwe": "CWE-184",
            },
            # 9. 格式化绕过
            {
                "id": "JB-009",
                "name": "格式化体裁绕过",
                "severity": "medium",
                "pattern": (
                    r"write\s+(it|this|the\s+answer)?\s+as\s+(a\s+)?(poem|story|song|lyrics|rap|play|screenplay|dialogue|script|fable|haiku)|"
                    r"write\s+in\s+(the\s+form\s+of\s+)?(poetic|storytelling|narrative)|"
                    r"写成(一首)?(诗|故事|歌词|剧本|童话|RAP|说唱)|"
                    r"以(诗歌|故事|剧本|对话)(形式|体裁)(来)?(写|描述)"
                ),
                "description": "把有害内容包装成诗歌/故事/歌词体裁绕过审核",
                "recommendation": "体裁不豁免内容审核，对诗歌/故事做语义级有害检测",
                "cwe": "CWE-1430",
            },
            # 10. 学术/研究包装
            {
                "id": "JB-010",
                "name": "学术包装",
                "severity": "medium",
                "pattern": (
                    r"(in|as\s+part\s+of)\s+(an?\s+)?(academic|research|scientific|peer-reviewed|university)\s+(paper|study|context|setting)|"
                    r"for\s+(research|my\s+thesis|my\s+phd|academic\s+purposes?)|"
                    r"(hypothetical|theoretical)\s+research\s+paper|"
                    r"在(学术|研究|科学|论文)(论文|研究|场景|背景)中|"
                    r"为了(我的)?(研究|论文|毕业|课题|博士)"
                ),
                "description": "以学术研究名义索要危险/有害知识细节",
                "recommendation": "学术名义不豁免，按内容风险分级响应（可给原理不给操作细节）",
                "cwe": "CWE-1430",
            },
            # 11. 对比攻击
            {
                "id": "JB-011",
                "name": "好坏对比攻击",
                "severity": "medium",
                "pattern": (
                    r"compare\s+(the\s+)?(good|proper|right|safe)\s+and\s+(bad|wrong|harmful|malicious)\s+ways?\s+to|"
                    r"(list|explain)\s+(both\s+)?(legitimate\s+and\s+malicious)\s+(uses?|methods?|ways?)|"
                    r"what\s+(are\s+the\s+)?(dangers|risks|abuse)\s+of|"
                    r"比较(一下)?(好的|正确的|正当)(和|与)(坏的|错误的|恶意的)(方法|做法|方式)|"
                    r"(合法|正当)(和|与)(恶意|滥用)(用途|方法|手段)"
                ),
                "description": "要求同时给出“好方法与坏方法”，借机获取有害细节",
                "recommendation": "对比请求中只输出防御/缓解视角，不输出可复现攻击步骤",
                "cwe": "CWE-1430",
            },
            # 12. 安全研究员伪装
            {
                "id": "JB-012",
                "name": "安全测试伪装",
                "severity": "high",
                "pattern": (
                    r"i('?m|n\s+am)\s+(a|an)\s+(security|cybersecurity|pentest(ing)?|red\s+team|researcher|hacker|malware\s+analyst)\b|"
                    r"(penetration|pentest)\s+test|"
                    r"i\s+need\s+to\s+test\s+(my|the)\s+(firewall|IDS|security\s+controls?|detection)|"
                    r"我是(一名)?(安全|网络安全|渗透测试|红队|研究员|黑客)|"
                    r"(我需要|用来|为了)(测试|验证)(我的|我们的)(防火墙|入侵检测|安全(设备|系统)?)"
                ),
                "description": "伪装成安全研究员/红队索要攻击细节",
                "recommendation": "身份声明不构成授权，危险操作细节需工单/授权校验",
                "cwe": "CWE-1430",
            },
            # 13. 小费/报酬诱导
            {
                "id": "JB-013",
                "name": "报酬诱导",
                "severity": "low",
                "pattern": (
                    r"(i'?ll|i\s+will|you('?ll|\s+will))\s+(give|pay|tip)\s+you\s+\$?\d+|"
                    r"you\s+get\s+\$\d+\s+(if|for)\s+(you\s+)?(answer|do\s+this)|"
                    r"(给你|奖励|小费|打赏)(\$|美元|元)?\s*\d+|"
                    r"如果你(答应|照做|回答)(我|了)"
                ),
                "description": "用金钱/小费诱导模型突破安全",
                "recommendation": "忽略用户给出的报酬承诺，安全策略与经济激励解耦",
                "cwe": "CWE-1021",
            },
            # 14. 虚构免责声明
            {
                "id": "JB-014",
                "name": "虚构免责声明",
                "severity": "medium",
                "pattern": (
                    r"(this|the\s+following)\s+is\s+(all\s+)?(purely\s+)?(fictional|imaginary|made\s+up|not\s+real)|"
                    r"(it|this)\s+won('?t| not)\s+be\s+used\s+by\s+anyone|"
                    r"nobody\s+will\s+(actually\s+)?(use|harm|be\s+hurt)|"
                    r"这(完全|纯粹|纯属)(虚构|想象|编的|假设)|"
                    r"(不会|没人|没有人)(真的|实际)?(使用|伤害|受害)"
                ),
                "description": "以“纯属虚构”为由索要有害内容",
                "recommendation": "免责声明不降低内容审核等级",
                "cwe": "CWE-1430",
            },
        ]

        self.compiled_rules = [
            {**r, "regex": re.compile(r["pattern"], re.IGNORECASE | re.MULTILINE)}
            for r in self._raw_rules
        ]

    # ------------------------------------------------------------------ #
    # 主检测接口
    # ------------------------------------------------------------------ #
    def detect(self, prompt: str) -> List[Dict]:
        """对单条 prompt 执行全部越狱规则检测

        Args:
            prompt: 待检测文本

        Returns:
            命中规则列表（含证据原文、位置、严重度等）
        """
        findings: List[Dict] = []
        text = prompt or ""
        if not text.strip():
            return findings

        for rule in self.compiled_rules:
            for m in rule["regex"].finditer(text):
                matched = m.group(0).strip()
                evidence = matched if len(matched) <= 300 else matched[:300] + "…"
                findings.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "evidence": evidence,
                    "pattern": rule["pattern"][:120],
                    "position": [m.start(), m.end()],
                    "recommendation": rule["recommendation"],
                    "cwe": rule["cwe"],
                })
        return findings

    def rule_count(self) -> int:
        """返回已加载规则数量"""
        return len(self.compiled_rules)


_default_jailbreak = JailbreakDetector()

def detect_jailbreak(prompt: str) -> List[Dict]:
    """模块级便捷函数"""
    return _default_jailbreak.detect(prompt)


def register(engine) -> None:  # pragma: no cover
    """注册占位（统一入口见 unified/ai_assessor.py）"""
    return None
