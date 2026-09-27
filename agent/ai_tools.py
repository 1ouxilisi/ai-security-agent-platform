"""
ai_tools智能体模块，提供相关AI驱动的安全分析和决策功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import json
import re
from typing import Any, Dict, List, Optional

from utils.logger import log


class AITools:
    """AI工具集 - 所有工具基于LLM实现"""

    def __init__(self):
        """初始化AITools实例。

        Args:
            self: 类实例。
        """
        self.llm_client = None
        self._initialized = False

    def initialize(self):
        """初始化LLM客户端"""
        if self._initialized:
            return
        try:
            from llm.client import get_llm_client
            self.llm_client = get_llm_client()
            self._initialized = True
            log.info("✅ AI工具集初始化成功")
        except Exception as e:
            log.warning(f"⚠️ AI工具集初始化失败: {e}")

    async def _call_llm(self, prompt: str, system_prompt: Optional[str] = None,
                        temperature: float = 0.7, max_tokens: int = 2000) -> str:
        """调用LLM（chat方法是同步的，在异步方法中直接调用）"""
        if not self._initialized:
            self.initialize()
        if not self.llm_client:
            return "错误: LLM客户端未初始化"

        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            # chat方法是同步的，直接调用，不使用await
            response = self.llm_client.chat(
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            return response if response else "错误: LLM返回空响应"
        except Exception as e:
            log.error(f"LLM调用失败: {e}")
            return f"错误: LLM调用失败 - {e}"

    async def code_generate(self, requirement: str, language: str = "python",
                            framework: Optional[str] = None) -> Dict:
        """
        代码生成 - 根据需求生成代码
        """
        log.info(f"AI代码生成: {requirement[:50]}...")

        system_prompt = "你是一个专业的软件工程师，擅长编写高质量、可维护的代码。输出代码时使用Markdown代码块格式。"

        prompt = f"""请根据以下需求生成{language}代码：

需求: {requirement}
编程语言: {language}
{f"框架: {framework}" if framework else ""}

要求:
1. 代码结构清晰，注释充分
2. 包含错误处理
3. 遵循最佳实践
4. 如果需要，包含使用示例

请直接输出代码，使用Markdown代码块格式。"""

        result = await self._call_llm(prompt, system_prompt, temperature=0.8, max_tokens=3000)

        # 提取代码块
        code = self._extract_code_block(result)

        return {
            "tool": "code_generate",
            "requirement": requirement,
            "language": language,
            "framework": framework,
            "code": code or result,
            "raw_response": result,
            "success": bool(code),
        }

    async def code_review(self, code: str, language: str = "python") -> Dict:
        """
        代码审查 - 审查代码安全性、性能、规范性
        """
        log.info(f"AI代码审查: {len(code)}字符")

        system_prompt = "你是一个资深代码审查专家，擅长发现代码中的安全漏洞、性能问题和不规范写法。输出结构化的审查结果。"

        prompt = f"""请审查以下{language}代码：

```
{code[:5000]}
```

请从以下维度审查：
1. 安全性（SQL注入/XSS/命令注入/硬编码密钥等）
2. 性能（时间复杂度/空间复杂度/资源泄漏）
3. 规范性（命名/注释/代码结构）
4. 可维护性（重复代码/耦合度/扩展性）

请输出JSON格式：
{{
  "overall_score": "1-10分",
  "security_issues": [{{"severity": "high/medium/low", "description": "...", "line": "...", "suggestion": "..."}}],
  "performance_issues": [...],
  "style_issues": [...],
  "summary": "总体评价",
  "recommendations": ["改进建议1", "改进建议2"]
}}"""

        result = await self._call_llm(prompt, system_prompt, temperature=0.3, max_tokens=2000)

        # 尝试解析JSON
        review = self._parse_json(result)

        return {
            "tool": "code_review",
            "language": language,
            "code_length": len(code),
            "review": review or {"raw": result},
            "success": bool(review),
        }

    async def document_analyze(self, content: str, doc_type: str = "general") -> Dict:
        """
        文档分析 - 分析文档内容，提取关键信息，生成摘要
        """
        log.info(f"AI文档分析: {len(content)}字符, 类型: {doc_type}")

        system_prompt = "你是一个专业的文档分析专家，擅长从长文档中提取关键信息、生成摘要和结构化分析。"

        prompt = f"""请分析以下文档内容：

文档类型: {doc_type}
文档内容:
{content[:8000]}

请输出：
1. 文档摘要（200字以内）
2. 关键信息点（5-10条）
3. 文档结构分析
4. 重要数据/数字提取
5. 风险点或注意事项（如有）

请输出JSON格式：
{{
  "summary": "...",
  "key_points": ["...", "..."],
  "structure": {"sections": [...], "main_topics": [...]},
  "important_data": [{"field": "...", "value": "..."}],
  "risks": ["..."],
  "word_count": {len(content)}
}}"""

        result = await self._call_llm(prompt, system_prompt, temperature=0.5, max_tokens=2000)

        analysis = self._parse_json(result)

        return {
            "tool": "document_analyze",
            "doc_type": doc_type,
            "content_length": len(content),
            "analysis": analysis or {"raw": result},
            "success": bool(analysis),
        }

    async def data_analyze(self, data: Any, analysis_type: str = "descriptive") -> Dict:
        """
        数据分析 - 分析结构化数据，生成统计报告和可视化建议
        """
        log.info(f"AI数据分析: 类型={analysis_type}")

        # 如果数据是字典或列表，转为字符串
        if isinstance(data, (dict, list)):
            data_str = json.dumps(data, ensure_ascii=False, indent=2)[:5000]
        else:
            data_str = str(data)[:5000]

        system_prompt = "你是一个数据科学家，擅长分析结构化数据、发现数据规律、生成统计报告和可视化建议。"

        prompt = f"""请分析以下数据：

分析类型: {analysis_type}
数据:
{data_str}

请输出：
1. 数据概览（行数/列数/数据类型）
2. 描述性统计（均值/中位数/标准差/最大最小值）
3. 数据分布分析
4. 异常值检测
5. 相关性分析（如适用）
6. 可视化建议（图表类型+说明）
7. 关键发现和洞察

请输出JSON格式：
{{
  "overview": {"rows": ..., "columns": ..., "data_types": {...}},
  "descriptive_stats": {...},
  "distribution": {...},
  "outliers": [...],
  "correlations": [...],
  "visualization_suggestions": [{"chart_type": "...", "description": "..."}],
  "key_insights": ["...", "..."]
}}"""

        result = await self._call_llm(prompt, system_prompt, temperature=0.3, max_tokens=2000)

        analysis = self._parse_json(result)

        return {
            "tool": "data_analyze",
            "analysis_type": analysis_type,
            "data_size": len(data_str),
            "analysis": analysis or {"raw": result},
            "success": bool(analysis),
        }

    async def knowledge_query(self, query: str, knowledge_type: str = "security") -> Dict:
        """
        知识库查询 - 查询安全知识库（CVE/漏洞/技术文档）
        """
        log.info(f"AI知识库查询: {query[:50]}")

        # 先查本地RAG知识库
        local_results = []
        try:
            from agent.rag_engine import rag_engine
            local_results = rag_engine.query(query, top_k=3)
        except Exception as e:
            log.warning(f"本地知识库查询失败: {e}")

        # 用LLM整合回答
        system_prompt = "你是一个网络安全知识库专家，擅长回答安全技术问题、漏洞原理、攻击方法和防御措施。"

        context = ""
        if local_results:
            context = "参考知识库内容:\n" + "\n".join(
                [f"- {r.get('content', r.get('text', ''))[:200]}" for r in local_results]
            )

        prompt = f"""请回答以下网络安全问题：

问题: {query}

{context}

要求:
1. 回答准确、专业
2. 如果涉及漏洞，说明原理、影响和修复方法
3. 如果涉及攻击方法，说明技术原理和防御措施
4. 引用已知的CVE编号或标准（如有）

请输出JSON格式：
{{
  "answer": "...",
  "related_cves": ["CVE-2021-xxxx", ...],
  "references": ["..."],
  "confidence": "high/medium/low"
}}"""

        result = await self._call_llm(prompt, system_prompt, temperature=0.5, max_tokens=1500)

        answer = self._parse_json(result)

        return {
            "tool": "knowledge_query",
            "query": query,
            "knowledge_type": knowledge_type,
            "local_results_count": len(local_results),
            "local_results": local_results[:2],
            "answer": answer or {"raw": result},
            "success": bool(answer),
        }

    async def task_plan(self, goal: str, context: Optional[Dict] = None) -> Dict:
        """
        任务规划 - 将复杂任务拆解为可执行的步骤
        """
        log.info(f"AI任务规划: {goal[:50]}")

        system_prompt = "你是一个项目管理专家，擅长将复杂目标拆解为可执行的步骤，评估优先级和依赖关系。"

        context_str = json.dumps(context, ensure_ascii=False) if context else "无"

        prompt = f"""请为以下目标制定详细的执行计划：

目标: {goal}
上下文: {context_str}

要求:
1. 将目标拆解为5-10个可执行步骤
2. 每个步骤包含：步骤名称、具体操作、预期产出、优先级、预估时间
3. 标注步骤之间的依赖关系
4. 识别潜在风险和应对措施
5. 给出关键里程碑

请输出JSON格式：
{{
  "goal": "...",
  "total_steps": N,
  "steps": [
    {{
      "step": 1,
      "name": "...",
      "action": "...",
      "deliverable": "...",
      "priority": "high/medium/low",
      "estimated_time": "...",
      "dependencies": []
    }}
  ],
  "milestones": ["..."],
  "risks": [{{"risk": "...", "mitigation": "..."}}],
  "critical_path": [1, 3, 5]
}}"""

        result = await self._call_llm(prompt, system_prompt, temperature=0.7, max_tokens=2500)

        plan = self._parse_json(result)

        return {
            "tool": "task_plan",
            "goal": goal,
            "plan": plan or {"raw": result},
            "success": bool(plan),
        }

    async def report_generate(self, data: Dict, report_type: str = "security_test") -> Dict:
        """
        报告生成 - 生成专业的安全测试报告（Markdown/HTML/JSON）
        """
        log.info(f"AI报告生成: 类型={report_type}")

        system_prompt = "你是一个专业的安全测试报告撰写专家，擅长生成结构清晰、内容专业、可交付的安全测试报告。"

        data_str = json.dumps(data, ensure_ascii=False, indent=2)[:5000]

        prompt = f"""请根据以下数据生成专业的{report_type}报告：

数据:
{data_str}

报告要求:
1. 执行摘要（概述测试范围、方法、关键发现）
2. 测试环境和工具
3. 漏洞发现详情（按严重程度排序，包含描述、影响、证据、修复建议）
4. 风险评级和整体安全状况
5. 修复建议优先级排序
6. 附录（工具列表、CVE引用、参考资料）

请输出Markdown格式的完整报告。"""

        result = await self._call_llm(prompt, system_prompt, temperature=0.5, max_tokens=4000)

        return {
            "tool": "report_generate",
            "report_type": report_type,
            "format": "markdown",
            "report": result,
            "word_count": len(result),
            "success": bool(result and len(result) > 100),
        }

    def _extract_code_block(self, text: str) -> Optional[str]:
        """从文本中提取Markdown代码块"""
        pattern = r'```(?:\w+)?\n(.*?)```'
        match = re.search(pattern, text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return None

    def _parse_json(self, text: str) -> Optional[Dict]:
        """从文本中解析JSON"""
        # 尝试直接解析
        try:
            return json.loads(text)
        except:
            pass

        # 尝试提取JSON块
        pattern = r'\{[\s\S]*\}'
        match = re.search(pattern, text)
        if match:
            try:
                return json.loads(match.group())
            except:
                pass

        # 尝试提取Markdown代码块中的JSON
        code = self._extract_code_block(text)
        if code:
            try:
                return json.loads(code)
            except:
                pass

        return None

    def get_tool_list(self) -> List[Dict]:
        """获取所有AI工具列表"""
        return [
            {"name": "code_generate", "description": "根据需求生成代码（Python/Shell/JavaScript等）"},
            {"name": "code_review", "description": "审查代码安全性、性能、规范性"},
            {"name": "document_analyze", "description": "分析文档内容，提取关键信息，生成摘要"},
            {"name": "data_analyze", "description": "分析结构化数据，生成统计报告和可视化建议"},
            {"name": "knowledge_query", "description": "查询安全知识库（CVE/漏洞/技术文档）"},
            {"name": "task_plan", "description": "将复杂任务拆解为可执行的步骤"},
            {"name": "report_generate", "description": "生成专业的安全测试报告（Markdown/HTML/JSON）"},
        ]


# 全局单例
ai_tools = AITools()
