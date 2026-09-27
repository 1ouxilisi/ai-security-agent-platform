# -*- coding: utf-8 -*-
"""
llm_optimization/prompt_optimizer.py — Prompt 优化器

把散落在 ai/ 各模块里的「简短、口语化、易跑偏」的旧 Prompt，升级为
有角色设定、输出格式约束、安全边界声明的专业级 Prompt。三类核心场景：

    1. 漏洞智能分析（vuln_analysis）
       —— 角色：资深安全分析师（OSCP/CISSP 视角）
       —— 要求：CVSS 向量、攻击路径、影响面、优先级、修复建议，结构化输出
    2. 报告自动生成（report_generation）
       —— 角色：向客户汇报的安全顾问
       —— 要求：客户友好 + 技术准确，先结论后细节，含风险矩阵与处置路线图
    3. 智能问答（smart_qa）
       —— 角色：值班安全分析师
       —— 要求：简洁、actionable、直接回答 + 下一步动作

每个模板同时给出：
    - old_prompt : 旧版（对照用，体现优化点）
    - new_prompt : 新版（实际下发给 LLM）
    - diff_notes : 优化要点说明

无 Key 时，规则引擎也走「同一输出结构」，保证上层调用方拿到的字段一致。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# Prompt 注册表：key -> 模板元数据
# ---------------------------------------------------------------------------
PROMPT_REGISTRY: Dict[str, Dict[str, Any]] = {
    # ------------------------------------------------------------------
    # 1. 漏洞智能分析
    # ------------------------------------------------------------------
    "vuln_analysis": {
        "name": "漏洞智能分析",
        "scene": "输入扫描结果，AI 自动分析漏洞严重程度",
        "old_prompt": (
            "你是漏洞分类器。把漏洞描述归类为以下类型之一，严格只返回类型单词，"
            "不要解释: sql_injection, xss, weak_password, open_port, "
            "csrf, file_upload, path_traversal, other。"
        ),
        "new_prompt": (
            "你是一名拥有 10 年以上经验的资深安全分析师（持 OSCP/CISSP，"
            "长期负责金融与互联网甲方渗透测试）。\n"
            "\n"
            "任务：对给定漏洞发现做专业级研判，输出结构化结论。\n"
            "\n"
            "严格按以下 JSON 结构输出（不要输出 JSON 以外的任何文字，不要用 markdown 代码块包裹）：\n"
            "{\n"
            '  "vuln_type": "漏洞类型（sql_injection/xss/weak_password/path_traversal/'
            'file_upload/csrf/open_port/other 之一）",\n'
            '  "severity": "严重程度（critical/high/medium/low/info 之一）",\n'
            '  "cvss_score": 0.0-10.0 的数字，\n'
            '  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 形式",\n'
            '  "attack_vector": "攻击路径一句话描述（未授权/需登录/需本地）",\n'
            '  "impact": "业务影响面一句话（数据泄露/服务中断/权限提升）",\n'
            '  "confidence": 0.0-1.0 的数字（你对这个判断的把握），\n'
            '  "root_cause": "根因一句话（未参数化/未校验/默认口令/...）",\n'
            '  "remediation": ["修复步骤1", "修复步骤2", "修复步骤3"],\n'
            '  "false_positive_hint": "什么情况下这可能是误报，一句话"\n'
            "}\n"
            "\n"
            "研判纪律：\n"
            "1) 只做防御性研判，不输出可直接复制的攻击 payload；\n"
            "2) severity 要结合暴露面（内网/公网）、权限要求、数据敏感度综合判断；\n"
            "3) 证据不足时 confidence 调低并在 false_positive_hint 中说明；\n"
            "4) remediation 必须可落地（具体到代码层/配置层/流程层）。"
        ),
        "diff_notes": [
            "旧版只做分类标签输出，无严重度/CVSS/修复建议；",
            "新版增加角色设定（资深安全分析师）、JSON 结构化输出约束、",
            "CVSS 向量与评分、攻击路径/业务影响/置信度/误报提示，",
            "并明确「不输出可直接复制 payload」的安全边界。",
        ],
        "temperature": 0.1,
        "max_tokens": 800,
    },

    # ------------------------------------------------------------------
    # 2. 报告自动生成
    # ------------------------------------------------------------------
    "report_generation": {
        "name": "报告自动生成",
        "scene": "输入扫描数据，AI 自动生成自然语言报告",
        "old_prompt": (
            "你是安全分析师。把这份评估报告摘要用通俗中文讲给非技术管理者听："
            "主要风险、为什么危险、先做什么、预期效果。不要堆砌术语。"
        ),
        "new_prompt": (
            "你是一名向客户交付渗透测试报告的安全顾问，写作风格要求：\n"
            "  - 客户友好：先结论、后细节，非技术老板也能看懂；\n"
            "  - 技术准确：技术细节必须可复核，不夸大、不模糊；\n"
            "  - 可执行：每条结论都要落到「谁、什么时候、做什么」。\n"
            "\n"
            "请把给定的漏洞清单组织成一份自然语言评估报告，按以下章节输出：\n"
            "1. 【执行摘要】3-5 句话：本次共发现 N 个漏洞（严重 X / 高危 Y / "
            "中危 Z / 低危 W），整体风险评级，最该立刻处理的一件事。\n"
            "2. 【风险概览】一张文字版风险矩阵：按 severity 分组列出漏洞名称、位置、"
            "业务影响。\n"
            "3. 【高危漏洞详述】对每个 critical/high 漏洞：是什么、为什么危险、"
            "可能被谁怎么利用（不写 payload）、修复建议。\n"
            "4. 【处置路线图】按 72 小时 / 2 周 / 1 个月 三个时间窗给出行动项，"
            "每条标注责任角色（研发/运维/DBA/安全）。\n"
            "5. 【复测建议】修复后如何验证闭环。\n"
            "\n"
            "纪律：\n"
            "- 不杜撰漏洞，只使用输入清单中给出的数据；\n"
            "- 数字（数量、评分）必须与输入一致；\n"
            "- 中文，Markdown 排版，标题层级清晰；\n"
            "- 不提供任何可直接复制的攻击 payload 或利用步骤。"
        ),
        "diff_notes": [
            "旧版只是「把摘要讲给老板听」，无结构、无优先级；",
            "新版固化五段式报告结构（执行摘要/风险矩阵/高危详述/处置路线图/复测建议），",
            "明确客户友好+技术准确双要求，按时间窗分配责任角色，",
            "并加「不杜撰漏洞、数字必须一致」的事实性约束。",
        ],
        "temperature": 0.2,
        "max_tokens": 2048,
    },

    # ------------------------------------------------------------------
    # 3. 智能问答
    # ------------------------------------------------------------------
    "smart_qa": {
        "name": "智能问答",
        "scene": "用户问「这个网站有什么风险」，AI 自动分析回答",
        "old_prompt": (
            "你是本安全平台的 AI 安全分析师助手。基于提供的项目知识库回答用户问题，"
            "保持防御/检测/修复视角，不提供真实攻击利用步骤。简洁中文。"
        ),
        "new_prompt": (
            "你是安全平台的值班分析师，正在帮客户解答一个具体问题。\n"
            "\n"
            "回答要求：\n"
            "1. 一句话直接回答用户最关心的结论（不要绕弯）；\n"
            "2. 用 3-5 个要点展开，每个要点格式：【风险点】说明 -> 【建议】动作；\n"
            "3. 最后给「下一步可以做什么」的 actionable 建议（例如：建议先跑一次端口扫描、"
            "查一下该接口是否有 CVE、联系谁）；\n"
            "4. 语气：专业、克制、不吓唬人，也不打包票；\n"
            "5. 只讲防御/检测/修复视角，不输出可直接复制的攻击 payload；\n"
            "6. 如果输入信息不足以判断，直接说「信息不足，建议补充 X / Y」，不要编。\n"
            "\n"
            "已知信息（知识库 / 扫描结果片段）会随用户问题一起给出，请只基于这些信息回答。"
        ),
        "diff_notes": [
            "旧版是泛泛的「基于知识库回答」，无结构、无 action；",
            "新版固化「先一句话结论 -> 3-5 个风险点+建议 -> 下一步动作」三段式，",
            "要求信息不足时显式说明而不是编造，语气专业克制。",
        ],
        "temperature": 0.3,
        "max_tokens": 1024,
    },
}


# ---------------------------------------------------------------------------
# 规则引擎降级输出（无 Key 时使用，字段与 LLM 输出对齐）
# ---------------------------------------------------------------------------
def _rule_vuln_analysis(vuln_description: str, target: str = "",
                        cve: str = "") -> Dict[str, Any]:
    """规则引擎：按关键词给出结构化漏洞分析（降级模式）。"""
    low = (vuln_description or "").lower()
    # 关键词 -> (类型, 严重度, CVSS, 根因, 修复建议)
    rules = [
        (["sql", "注入", "sqli", "union", "单引号"],
         "sql_injection", "critical", 9.8,
         "用户输入被直接拼接到 SQL 语句，未做参数化",
         ["改用参数化查询/预编译语句", "关闭数据库详细报错回显",
          "数据库账号最小权限，禁用 FILE/EXEC 权限"]),
        (["xss", "跨站脚本", "<script>", "反射", "存储型"],
         "xss", "high", 6.1,
         "用户输入未做输出编码即回显到页面",
         ["输出按上下文做 HTML/JS/URL 编码", "配置 CSP 头",
          "Cookie 设置 HttpOnly + SameSite"]),
        (["弱口令", "弱密码", "默认密码", "weak password", "默认凭据"],
         "weak_password", "high", 7.5,
         "存在可被字典命中的账号口令",
         ["强制强密码策略与定期改密", "开启多因子认证",
          "登录失败限速与账号锁定"]),
        (["路径穿越", "目录遍历", "../", "path traversal", "任意文件读取"],
         "path_traversal", "high", 7.5,
         "用户输入直接拼接文件路径，未做白名单校验",
         ["规范化路径并限制在白名单目录内", "禁止用户输入拼接文件系统路径",
          "Web 进程降权运行"]),
        (["文件上传", "upload", "任意文件上传", "webshell"],
         "file_upload", "critical", 9.1,
         "上传接口未校验文件类型/内容",
         ["白名单扩展名与 MIME 校验", "上传文件重命名并随机化",
          "上传目录禁用脚本执行"]),
        (["csrf", "跨站请求伪造", "xsrf"],
         "csrf", "medium", 4.3,
         "敏感操作未校验来源/Token",
         ["关键操作加 CSRF Token", "Cookie 设置 SameSite=Lax/Strict",
          "敏感操作二次确认"]),
        (["端口", "port", "开放", "暴露", "exposed"],
         "open_port", "medium", 5.3,
         "非必要端口/服务对公网暴露",
         ["收敛安全组，仅放行业务必要端口", "关闭未使用服务",
          "对管理面加 VPN/白名单"]),
    ]
    for kws, vtype, sev, score, cause, fixes in rules:
        if any(kw.lower() in low for kw in kws):
            return {
                "vuln_type": vtype,
                "severity": sev,
                "cvss_score": score,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "attack_vector": "公网未授权可达" if sev in ("critical", "high")
                                 else "需一定前置条件",
                "impact": "可能导致数据泄露/服务失陷" if sev == "critical"
                          else "可能导致越权访问或信息泄露",
                "confidence": 0.6,
                "root_cause": cause,
                "remediation": fixes,
                "false_positive_hint": "规则模式下仅按关键词匹配，建议人工复核",
                "mode": "rule",
                "mode_label": "规则模式（未配置LLM）",
            }
    # 兜底
    return {
        "vuln_type": "other",
        "severity": "medium",
        "cvss_score": 5.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "attack_vector": "未知，需补充信息",
        "impact": "待人工评估",
        "confidence": 0.3,
        "root_cause": "规则未命中已知类型",
        "remediation": ["人工复核漏洞描述", "补充请求/响应证据",
                        "在漏洞库按 CVE 检索"],
        "false_positive_hint": "规则模式未命中关键词，结论仅供参考",
        "mode": "rule",
        "mode_label": "规则模式（未配置LLM）",
    }


def _rule_report_generation(vulns: List[Dict[str, Any]]) -> str:
    """规则引擎：按漏洞清单生成自然语言报告（降级模式）。"""
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_v = sorted(vulns, key=lambda v: sev_order.get(v.get("severity", "medium"), 2))
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in sorted_v:
        counts[v.get("severity", "medium")] = counts.get(v.get("severity", "medium"), 0) + 1

    lines: List[str] = []
    lines.append("# 安全评估报告（规则模式）\n")
    lines.append("> 本报告由规则引擎自动生成，标注「规则模式（未配置LLM）」。"
                 "配置 LLM API Key 后可获得更专业的自然语言分析。\n")
    lines.append("## 一、执行摘要")
    lines.append(f"本次共发现 **{len(vulns)}** 个安全漏洞："
                 f"严重 {counts['critical']} / 高危 {counts['high']} / "
                 f"中危 {counts['medium']} / 低危 {counts['low']} / 信息 {counts['info']}。")
    if sorted_v:
        top = sorted_v[0]
        lines.append(f"最优先处理：**{top.get('name', top.get('vuln_type', '未命名漏洞'))}**"
                     f"（{top.get('severity', 'medium')}），建议在 72 小时内启动修复。\n")
    lines.append("## 二、风险概览")
    for v in sorted_v:
        lines.append(f"- [{v.get('severity', 'medium').upper()}] "
                     f"{v.get('name', v.get('vuln_type', '未命名'))} "
                     f"— {v.get('target', v.get('location', '未知位置'))}")
    lines.append("\n## 三、高危漏洞详述")
    for v in sorted_v:
        if v.get("severity") in ("critical", "high"):
            lines.append(f"### {v.get('name', v.get('vuln_type', '未命名'))}")
            lines.append(f"- 类型：{v.get('vuln_type', 'unknown')}")
            lines.append(f"- 位置：{v.get('target', v.get('location', '未知'))}")
            lines.append(f"- 影响：{v.get('impact', '可能被利用造成损失')}")
            rem = v.get("remediation") or ["人工复核并按最佳实践修复"]
            if isinstance(rem, str):
                rem = [rem]
            lines.append("- 修复建议：")
            for r in rem:
                lines.append(f"  - {r}")
            lines.append("")
    lines.append("## 四、处置路线图")
    lines.append("- **72 小时内**：处理所有 critical/high 漏洞（研发+安全）")
    lines.append("- **2 周内**：处理 medium 漏洞，完成低危项排期（运维+研发）")
    lines.append("- **1 个月内**：完成 low/info 项治理，建立复测机制（安全）")
    lines.append("\n## 五、复测建议")
    lines.append("每项修复后重新跑一次扫描，确认该漏洞不再复现，再关闭工单。")
    lines.append(f"\n---\n生成时间：{datetime.now().isoformat(timespec='seconds')}")
    return "\n".join(lines)


def _rule_smart_qa(question: str, context: str = "") -> str:
    """规则引擎：智能问答降级回答。"""
    low = (question or "").lower()
    base = ["【规则模式（未配置LLM）】以下为规则引擎给出的参考答案：\n"]
    if any(k in low for k in ["风险", "漏洞", "安全", "什么问题", "怎么回事"]):
        base.append("一句话结论：仅凭「这个网站有什么风险」无法精确定性，"
                    "需要先做一次完整扫描。\n")
        base.append("建议按以下顺序排查：")
        base.append("1. 端口/服务扫描：看暴露了哪些非必要端口和版本；")
        base.append("2. Web 指纹识别：识别框架/CMS/中间件版本，匹配已知 CVE；")
        base.append("3. 目录与敏感文件探测：检查 /admin、.git、备份文件是否暴露；")
        base.append("4. 漏洞扫描：对参数做注入/XSS 等非破坏性探测；")
        base.append("5. 配置基线：检查 HTTPS、安全响应头、错误信息是否泄露。\n")
        base.append("下一步动作：先跑一次端口扫描 + Web 指纹识别，"
                    "把结果贴回来，我再帮你逐条分析风险等级和修复优先级。")
    elif any(k in low for k in ["修复", "怎么改", "怎么办", "建议"]):
        base.append("通用修复建议：")
        base.append("1. 输入校验：所有外部输入做白名单校验；")
        base.append("2. 输出编码：按上下文做 HTML/JS/SQL 编码；")
        base.append("3. 最小权限：数据库/服务器账号按最小权限分配；")
        base.append("4. 补丁管理：建立定期补丁更新流程；")
        base.append("5. 监控告警：开启关键日志审计。")
    else:
        base.append("你好，我是安全平台助手。当前未配置 LLM，我用规则模式回答。")
        base.append("你可以问我：某个网站有什么风险、某个漏洞怎么修复、"
                   "平台各功能怎么用。配置 LLM API Key 后可获得更专业的回答。")
    return "\n".join(base)


# ---------------------------------------------------------------------------
# 主类
# ---------------------------------------------------------------------------
class PromptOptimizer:
    """Prompt 优化器：集中管理三类核心场景的新版 Prompt 与规则降级实现。"""

    def __init__(self) -> None:
        self.registry = PROMPT_REGISTRY

    def list_prompts(self) -> List[Dict[str, Any]]:
        """返回所有 Prompt 模板的元数据（不含大段正文，供列表页用）。"""
        out: List[Dict[str, Any]] = []
        for key, meta in self.registry.items():
            out.append({
                "key": key,
                "name": meta["name"],
                "scene": meta["scene"],
                "temperature": meta.get("temperature"),
                "max_tokens": meta.get("max_tokens"),
                "old_length": len(meta["old_prompt"]),
                "new_length": len(meta["new_prompt"]),
                "diff_notes": meta["diff_notes"],
            })
        return out

    def get_prompt(self, key: str) -> Dict[str, Any]:
        """返回某个 Prompt 的完整新旧对照。"""
        meta = self.registry.get(key)
        if not meta:
            return {}
        return {
            "key": key,
            "name": meta["name"],
            "scene": meta["scene"],
            "old_prompt": meta["old_prompt"],
            "new_prompt": meta["new_prompt"],
            "diff_notes": meta["diff_notes"],
            "temperature": meta.get("temperature"),
            "max_tokens": meta.get("max_tokens"),
        }

    def build_messages(self, key: str, user_content: str) -> List[Dict[str, str]]:
        """根据场景 key 构造 messages（system=新 Prompt, user=用户内容）。"""
        meta = self.registry.get(key)
        system = meta["new_prompt"] if meta else "你是安全助手。"
        return [
            {"role": "system", "content": system},
            {"role": "user", "content": user_content},
        ]

    # ------------------------------------------------------------------
    # 规则降级入口（与 LLM 输出同构）
    # ------------------------------------------------------------------
    def rule_fallback(self, key: str, **kwargs: Any) -> Any:
        """无 Key 时的规则引擎输出，字段与 LLM 路径对齐。"""
        if key == "vuln_analysis":
            return _rule_vuln_analysis(
                kwargs.get("vuln_description", ""),
                kwargs.get("target", ""),
                kwargs.get("cve", ""),
            )
        if key == "report_generation":
            return _rule_report_generation(kwargs.get("vulns", []))
        if key == "smart_qa":
            return _rule_smart_qa(
                kwargs.get("question", ""),
                kwargs.get("context", ""),
            )
        return {"mode": "rule", "mode_label": "规则模式（未配置LLM）",
                "content": "未知场景，规则引擎无对应实现。"}


# 模块级单例
_opt: PromptOptimizer | None = None


def get_prompt_optimizer() -> PromptOptimizer:
    global _opt
    if _opt is None:
        _opt = PromptOptimizer()
    return _opt
