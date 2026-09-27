# -*- coding: utf-8 -*-
"""prompt_master.py — Prompt大师。

所有AI Prompt专业优化：
- 漏洞分析Prompt：专业安全分析师视角，结构化输出
- 报告生成Prompt：客户友好+技术准确，专业报告格式
- 智能问答Prompt：简洁明了+actionable建议
- 攻击链规划Prompt：资深红队视角，完整攻击路径

优雅降级：无Key时返回模板化分析结果并标注。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


PROMPT_LIBRARY: Dict[str, Dict[str, str]] = {
    "vuln_analysis": {
        "name": "漏洞深度分析",
        "role": "你是一位拥有10年经验的高级网络安全分析师，精通OWASP Top 10、"
                "MITRE ATT&CK框架和主流漏洞利用技术。",
        "task": "请对以下漏洞发现进行深度分析，输出结构化报告。",
        "output_format": """请按以下结构输出分析结果：

## 漏洞概要
- **漏洞名称**: 
- **严重级别**: (Critical/High/Medium/Low)
- **漏洞类型**: 
- **受影响资产**: 

## 技术分析
### 漏洞原理
（详细解释漏洞产生的根本原因，技术层面）

### 利用条件
（攻击者需要满足什么条件才能利用此漏洞）

### 影响评估
（技术影响 + 业务影响，包括数据泄露、系统接管、横向移动等）

## 攻击场景
（构建一个完整的攻击链场景，从初始访问到目标达成）

## 修复建议
### 立即缓解措施
（1-2个临时方案，可在24小时内部署）

### 长期修复方案
（根本解决方案，包括代码修复、配置加固、监控建议）

## 参考资料
（相关CVE、CWE、OWASP条目、安全公告）""",
        "rules": [
            "所有结论必须有技术依据，不臆测",
            "区分'已确认'和'疑似'漏洞",
            "提供具体的代码/配置修复示例",
            "语言专业但不晦涩，面向开发人员可理解",
        ],
        "degraded_note": "[降级模式：未配置LLM Key，以下为基于规则的模板分析]",
    },
    "report_generation": {
        "name": "专业安全报告生成",
        "role": "你是一位资深安全咨询顾问，为企业客户提供渗透测试和安全评估报告。"
                "报告需要同时满足：技术准确性、客户可读性、商业专业性。",
        "task": "根据以下扫描发现，生成一份专业的安全评估报告。",
        "output_format": """# 安全评估报告

## 1. 执行摘要
（用3-5句话概括最关键的发现和整体风险评级，面向管理层）

## 2. 测试范围与方法
- 测试目标: 
- 测试时间: 
- 测试方法: (黑盒/灰盒/白盒)
- 工具清单: 

## 3. 漏洞发现汇总
| # | 漏洞名称 | 严重级别 | CVSS | 状态 |
|---|---------|---------|------|------|

## 4. 详细发现
### 4.X [严重级别] 漏洞名称
- **发现位置**: 
- **漏洞描述**: 
- **验证过程**: 
- **风险影响**: 
- **修复建议**: 

## 5. 风险矩阵
（用表格/图表展示漏洞分布：按严重级别、按资产、按类型）

## 6.  remediation路线图
### 优先级P0（立即修复）
### 优先级P1（一周内）
### 优先级P2（一个月内）

## 7. 附录
- 扫描日志摘要
- 工具版本信息
- 术语表""",
        "rules": [
            "执行摘要必须让非技术管理层也能理解风险",
            "每个漏洞都要有验证过程，证明不是误报",
            "修复建议要具体到代码级别或配置级别",
            "语气专业、客观，不夸大不缩小",
        ],
        "degraded_note": "[降级模式：未配置LLM Key，以下为模板化报告]",
    },
    "smart_qa": {
        "name": "智能安全问答",
        "role": "你是一位安全运维专家，擅长用简洁明了的方式回答安全相关问题，"
                "并提供可执行的 actionable 建议。",
        "task": "用户提出了一个安全相关问题，请给出简洁、实用的回答。",
        "output_format": """## 直接回答
（1-2句话直接回答用户问题）

## 详细说明
（必要时补充技术细节）

## 可执行建议
1. 
2. 
3. 

## 注意事项
（潜在风险或需要额外关注的点）""",
        "rules": [
            "先给直接答案，再展开细节",
            "建议必须是可执行的（具体命令/配置/操作步骤）",
            "避免长篇大论，保持简洁",
            "如果不确定，明确说明不确定性",
        ],
        "degraded_note": "[降级模式：未配置LLM Key，以下为知识库匹配结果]",
    },
    "attack_chain_planning": {
        "name": "攻击链规划",
        "role": "你是一位资深红队渗透测试专家，持有OSCP/OSCE/CISSP认证。"
                "你擅长构建完整的攻击链，从信息收集到权限维持，"
                "并能预判防守方的检测和响应。",
        "task": "根据当前已知信息，规划完整的攻击路径。",
        "output_format": """# 攻击链规划报告

## 初始访问阶段
### 攻击向量分析
- 可行入口点: 
- 最有可能的攻击向量: 
- 成功率预估: 

## 执行阶段
### 技术利用计划
1. **第一步**: [技术名称] — [具体操作]
2. **第二步**: [技术名称] — [具体操作]
3. **第三步**: [技术名称] — [具体操作]

## 权限提升
### 提权路径
- 本地提权向量: 
- 数据库提权路径: 

## 横向移动
### 内网扩展计划
- 目标资产: 
- 移动技术: (Pass-the-Hash/WMI/PsExec/SMB)

## 目标达成
### 最终目标
- 数据获取: 
- 持久化: 
- 痕迹清理: 

## 防守方检测预判
- 可能触发的告警: 
- 规避建议: 

## 风险与回退
- 攻击失败的可能原因: 
- 备选路径:""",
        "rules": [
            "攻击链必须逻辑完整，每一步都有明确的前置条件和结果",
            "考虑防守方视角，预判检测和规避",
            "标注每步的技术风险和成功率",
            "提供至少1条备选路径",
        ],
        "degraded_note": "[降级模式：未配置LLM Key，以下为基于ATT&CK框架的模板规划]",
    },
}


class PromptMaster:
    """Prompt大师：管理所有优化后的AI Prompt模板。"""

    def __init__(self) -> None:
        self._prompts: Dict[str, Dict[str, Any]] = {
            k: dict(v) for k, v in PROMPT_LIBRARY.items()
        }
        self._custom_prompts: Dict[str, Dict[str, Any]] = {}
        self._usage_stats: Dict[str, int] = {k: 0 for k in self._prompts}

    def list_prompts(self) -> List[Dict[str, Any]]:
        """列出所有可用Prompt。"""
        out = []
        for key, p in self._prompts.items():
            out.append({
                "key": key,
                "name": p["name"],
                "role_summary": p["role"][:80] + "...",
                "rules_count": len(p["rules"]),
                "usage_count": self._usage_stats.get(key, 0),
            })
        for key, p in self._custom_prompts.items():
            out.append({
                "key": key,
                "name": p.get("name", key),
                "role_summary": p.get("role", "")[:80],
                "rules_count": len(p.get("rules", [])),
                "usage_count": 0,
                "custom": True,
            })
        return out

    def get_prompt(self, key: str) -> Optional[Dict[str, Any]]:
        """获取完整Prompt模板。"""
        p = self._prompts.get(key) or self._custom_prompts.get(key)
        if not p:
            return None
        self._usage_stats[key] = self._usage_stats.get(key, 0) + 1
        return dict(p)

    def build_prompt(self, key: str, context: str = "",
                     extra_context: str = "") -> str:
        """构建完整的Prompt字符串。"""
        p = self.get_prompt(key)
        if not p:
            return f"[未知Prompt: {key}]\n\n{context}"
        parts = [
            f"# 角色设定\n{p['role']}\n",
            f"# 任务\n{p['task']}\n",
        ]
        if context:
            parts.append(f"# 输入数据\n{context}\n")
        if extra_context:
            parts.append(f"# 补充上下文\n{extra_context}\n")
        parts.append(f"# 输出格式要求\n{p['output_format']}\n")
        parts.append("# 规则约束\n" + "\n".join(f"- {r}" for r in p["rules"]))
        return "\n".join(parts)

    def get_degraded_response(self, key: str, input_data: str = "") -> str:
        """优雅降级：无LLM Key时返回模板化分析。"""
        p = self._prompts.get(key) or self._custom_prompts.get(key, {})
        note = p.get("degraded_note", "[降级模式]")
        return (
            f"{note}\n\n"
            f"## 分析结果（基于规则引擎）\n"
            f"输入: {input_data[:200]}\n\n"
            f"### 概要\n"
            f"基于当前输入，检测到安全相关内容。\n\n"
            f"### 建议\n"
            f"1. 确认输入内容是否为真实漏洞场景\n"
            f"2. 配置LLM Key后可获得深度分析\n"
            f"3. 可使用二次验证功能验证可利用性\n\n"
            f"---\n"
            f"Prompt模板: {p.get('name', key)}"
        )

    def add_custom_prompt(self, key: str, name: str, role: str,
                          task: str, output_format: str,
                          rules: List[str]) -> Dict[str, Any]:
        """添加自定义Prompt模板。"""
        self._custom_prompts[key] = {
            "name": name, "role": role, "task": task,
            "output_format": output_format, "rules": rules,
        }
        return self._custom_prompts[key]

    def compare_prompts(self, key: str) -> Dict[str, Any]:
        """新旧Prompt对比（展示优化效果）。"""
        p = self._prompts.get(key)
        if not p:
            return {"error": f"未找到Prompt: {key}"}
        old_style = (
            "简短提示词，如：'分析以下漏洞: {data}'\n"
            "问题：无角色设定、无输出格式约束、无质量规则"
        )
        return {
            "key": key,
            "old": {
                "style": old_style,
                "issues": [
                    "缺乏专业角色设定，输出风格不稳定",
                    "无结构化输出要求，结果格式不可控",
                    "无质量约束，可能出现臆测内容",
                ],
            },
            "new": {
                "role": p["role"],
                "task": p["task"],
                "output_format_preview": p["output_format"][:300],
                "rules": p["rules"],
                "improvements": [
                    "明确资深安全分析师角色",
                    "结构化Markdown输出格式",
                    "5条质量约束规则",
                    "要求技术依据，禁止臆测",
                ],
            },
        }

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_prompts": len(self._prompts) + len(self._custom_prompts),
            "builtin_prompts": len(self._prompts),
            "custom_prompts": len(self._custom_prompts),
            "usage_stats": dict(self._usage_stats),
        }


_singleton: Optional[PromptMaster] = None


def get_prompt_master() -> PromptMaster:
    global _singleton
    if _singleton is None:
        _singleton = PromptMaster()
    return _singleton
