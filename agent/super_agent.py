"""
super_agent智能体模块，提供相关AI驱动的安全分析和决策功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import asyncio
import json
import time
from typing import Any, Dict, List, Optional
from datetime import datetime

from utils.logger import log


class SuperAgent:
    """
    超级智能体 - 统一编排所有能力
    整合：33个安全工具 + 4个专业智能体 + ReAct引擎 + RAG + 报告增强 + POC验证 + AI工具集
    """

    def __init__(self):
        """初始化SuperAgent实例。

        Args:
            self: 类实例。
        """
        self.tools = {}
        self.agents = {}
        self.llm_client = None
        self.rag_engine = None
        self.report_enhancer = None
        self.poc_verifier = None
        self.ai_tools = None
        self.task_history = []
        self._initialized = False

    async def initialize(self):
        """初始化所有组件"""
        if self._initialized:
            return

        log.info("超级智能体初始化中...")

        # 1. 加载LLM客户端
        try:
            from llm.client import get_llm_client
            self.llm_client = get_llm_client()
            log.info("✅ LLM客户端加载成功")
        except Exception as e:
            log.warning(f"⚠️ LLM客户端加载失败: {e}")

        # 2. 加载所有MCP工具
        try:
            from mcp_server.server import TOOL_DEFINITIONS
            self.tools = {t["name"]: t for t in TOOL_DEFINITIONS}
            log.info(f"✅ 加载 {len(self.tools)} 个安全工具")
        except Exception as e:
            log.warning(f"⚠️ 工具加载失败: {e}")

        # 3. 加载RAG引擎
        try:
            from agent.rag_engine import rag_engine
            self.rag_engine = rag_engine
            log.info("✅ RAG引擎加载成功")
        except Exception as e:
            log.warning(f"⚠️ RAG引擎加载失败: {e}")

        # 4. 加载报告增强器
        try:
            from agent.report_enhancer import report_enhancer
            self.report_enhancer = report_enhancer
            log.info("✅ 报告增强器加载成功")
        except Exception as e:
            log.warning(f"⚠️ 报告增强器加载失败: {e}")

        # 5. 加载POC验证器
        try:
            from agent.poc_verifier import poc_verifier
            self.poc_verifier = poc_verifier
            log.info("✅ POC验证器加载成功")
        except Exception as e:
            log.warning(f"⚠️ POC验证器加载失败: {e}")

        # 5.5 加载AI工具集
        try:
            from agent.ai_tools import ai_tools
            self.ai_tools = ai_tools
            self.ai_tools.initialize()
            log.info("✅ AI工具集加载成功")
        except Exception as e:
            log.warning(f"⚠️ AI工具集加载失败: {e}")

        # 6. 注册4个专业智能体
        self.agents = {
            "recon": {
                "name": "ReconAgent",
                "role": "侦察专家",
                "description": "信息收集、端口扫描、子域名枚举、指纹识别",
                "tools": ["port_scan", "dns_lookup", "http_headers", "subdomain_enumerate_all",
                          "subdomain_dns_bruteforce", "subdomain_certificate_transparency"],
            },
            "exploit": {
                "name": "ExploitAgent",
                "role": "漏洞测试专家",
                "description": "SQL注入/XSS/SSRF/IDOR/命令注入/文件上传等漏洞测试",
                "tools": ["sql_injection_test", "xss_test", "ssrf_test", "idor_test",
                          "command_injection_test", "file_upload_test", "xxe_test", "directory_scan"],
            },
            "verification": {
                "name": "VerificationAgent",
                "role": "漏洞验证专家",
                "description": "深度验证、排除误报、生成PoC、漏洞复现",
                "tools": [],  # 使用POC验证器
            },
            "report": {
                "name": "ReportAgent",
                "role": "安全报告专家",
                "description": "整合结果、生成专业报告、CVSS评分、修复建议、参考链接",
                "tools": [],  # 使用报告增强器
            },
        }
        log.info(f"✅ 注册 {len(self.agents)} 个专业智能体")

        # 7. 注册AI工具集
        self.ai_tools = {
            "code_generate": {
                "name": "代码生成",
                "description": "根据需求生成代码（Python/Shell/JavaScript等）",
                "category": "ai",
            },
            "code_review": {
                "name": "代码审查",
                "description": "审查代码安全性、性能、规范性",
                "category": "ai",
            },
            "document_analyze": {
                "name": "文档分析",
                "description": "分析文档内容，提取关键信息，生成摘要",
                "category": "ai",
            },
            "data_analyze": {
                "name": "数据分析",
                "description": "分析结构化数据，生成统计报告和可视化建议",
                "category": "ai",
            },
            "knowledge_query": {
                "name": "知识库查询",
                "description": "查询安全知识库（CVE/漏洞/技术文档）",
                "category": "ai",
            },
            "task_plan": {
                "name": "任务规划",
                "description": "将复杂任务拆解为可执行的步骤",
                "category": "ai",
            },
            "report_generate": {
                "name": "报告生成",
                "description": "生成专业的安全测试报告（Markdown/HTML/JSON）",
                "category": "ai",
            },
        }
        log.info(f"✅ 注册 {len(self.ai_tools)} 个AI工具")

        self._initialized = True
        log.info("🎉 超级智能体初始化完成")

    async def execute(self, task: str, context: Optional[Dict] = None) -> Dict:
        """
        执行任务 - 统一入口
        接收自然语言指令，自动规划、选择工具、执行、生成报告
        """
        if not self._initialized:
            await self.initialize()

        start_time = time.time()
        task_id = f"super-{int(time.time())}"

        log.info(f"🚀 超级智能体接收任务: {task[:100]}")

        result = {
            "task_id": task_id,
            "task": task,
            "start_time": datetime.now().isoformat(),
            "status": "running",
            "steps": [],
            "findings": [],
            "final_report": None,
        }

        try:
            # 步骤1: 任务分析和规划
            log.info("📋 步骤1: 任务分析和规划")
            plan = await self._analyze_and_plan(task)
            result["steps"].append({"step": 1, "name": "任务规划", "result": plan})

            # 步骤2: 选择合适的智能体和工具
            log.info("🎯 步骤2: 选择智能体和工具")
            selected = self._select_agents_and_tools(plan)
            result["steps"].append({"step": 2, "name": "智能体/工具选择", "result": selected})

            # 步骤3: 执行任务（调用工具/智能体）
            log.info("⚙️ 步骤3: 执行任务")
            execution_result = await self._execute_task(plan, selected, context)
            result["steps"].append({"step": 3, "name": "任务执行", "result": execution_result})
            result["findings"] = execution_result.get("findings", [])

            # 步骤4: POC验证（如果有漏洞发现）
            if result["findings"]:
                log.info("🔍 步骤4: POC验证")
                poc_result = await self._verify_findings(result["findings"])
                result["steps"].append({"step": 4, "name": "POC验证", "result": poc_result})
                result["findings"] = poc_result.get("verified_findings", result["findings"])

            # 步骤5: 生成增强报告
            log.info("📝 步骤5: 生成增强报告")
            task_data = {
                "task_id": task_id,
                "target": plan.get("target", "N/A"),
                "task_type": plan.get("task_type", "custom"),
                "description": task,
                "started_at": start_time,
                "completed_at": time.time(),
            }
            report = self.report_enhancer.generate_enhanced_report(task_data, result["findings"]) if self.report_enhancer else {"findings": result["findings"]}
            result["final_report"] = report
            result["steps"].append({"step": 5, "name": "报告生成", "result": "报告已生成"})

            result["status"] = "completed"
            result["end_time"] = datetime.now().isoformat()
            result["duration_seconds"] = round(time.time() - start_time, 2)

            log.info(f"✅ 超级智能体任务完成: {task_id}, 耗时: {result['duration_seconds']}秒")

        except Exception as e:
            log.error(f"❌ 超级智能体任务失败: {e}")
            result["status"] = "failed"
            result["error"] = str(e)
            result["end_time"] = datetime.now().isoformat()
            result["duration_seconds"] = round(time.time() - start_time, 2)

        self.task_history.append(result)
        return result

    async def _analyze_and_plan(self, task: str) -> Dict:
        """分析任务并生成执行计划"""
        # 基于规则的快速分析（不依赖LLM）
        plan = {
            "original_task": task,
            "task_type": "custom",
            "target": None,
            "subtasks": [],
            "estimated_tools": [],
        }

        task_lower = task.lower()

        # 识别任务类型（支持中英文关键词，按优先级排序）
        report_keywords = ["报告", "report", "总结", "summary", "生成报告", "导出报告", "export report"]
        recon_keywords = ["扫描", "scan", "端口", "port", "信息收集", "侦察", "recon", "指纹", "fingerprint", "枚举", "enumerate", "子域名", "subdomain"]
        exploit_keywords = ["漏洞", "vuln", "注入", "injection", "xss", "sql注入", "ssrf", "渗透", "pentest", "攻击", "exploit", "利用", "检测漏洞", "vulnerability"]
        code_keywords = ["代码", "code", "编程", "程序", "脚本", "script", "开发", "develop", "写代码", "write code"]
        analysis_keywords = ["分析", "analyze", "数据", "data", "文档", "document", "解读", "interpret"]

        if any(k in task_lower for k in report_keywords):
            plan["task_type"] = "report"
        elif any(k in task_lower for k in recon_keywords):
            plan["task_type"] = "recon"
        elif any(k in task_lower for k in exploit_keywords):
            plan["task_type"] = "exploit"
        elif any(k in task_lower for k in code_keywords):
            plan["task_type"] = "code"
        elif any(k in task_lower for k in analysis_keywords):
            plan["task_type"] = "analysis"

        # 提取目标（IP/域名/URL）- 不使用\b，适配中文上下文
        import re
        ip_pattern = r'(?:\d{1,3}\.){3}\d{1,3}'
        domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        url_pattern = r'https?://[^\s]+'

        ip_match = re.search(ip_pattern, task)
        domain_match = re.search(domain_pattern, task)
        url_match = re.search(url_pattern, task)

        if url_match:
            plan["target"] = url_match.group()
        elif ip_match:
            plan["target"] = ip_match.group()
        elif domain_match:
            plan["target"] = domain_match.group()

        # 生成子任务
        if plan["task_type"] == "recon":
            plan["subtasks"] = ["端口扫描", "服务识别", "子域名枚举", "HTTP头分析"]
            plan["estimated_tools"] = ["port_scan", "dns_lookup", "http_headers", "subdomain_enumerate_all"]
        elif plan["task_type"] == "exploit":
            plan["subtasks"] = ["信息收集", "漏洞扫描", "漏洞验证", "报告生成"]
            plan["estimated_tools"] = ["port_scan", "directory_scan", "sql_injection_test", "xss_test"]
        elif plan["task_type"] == "code":
            plan["subtasks"] = ["需求分析", "代码生成", "代码审查"]
            plan["estimated_tools"] = ["code_generate", "code_review"]
        else:
            plan["subtasks"] = ["任务分析", "执行", "结果整理"]

        # 如果有LLM，用LLM增强规划（更智能的任务拆解）
        if self.llm_client and self.llm_client.is_available:
            try:
                llm_plan = await self._llm_task_plan(task, plan)
                if llm_plan:
                    plan.update(llm_plan)
                    plan["planner"] = "llm_enhanced"
                    log.info(f"LLM增强规划成功: {plan['task_type']}, {len(plan.get('subtasks', []))}个子任务")
                    return plan
            except Exception as e:
                log.warning(f"LLM规划失败，回退规则匹配: {e}")

        plan["planner"] = "rule_based"
        return plan

    async def _llm_task_plan(self, task: str, base_plan: Dict) -> Optional[Dict]:
        """使用LLM进行智能任务规划"""
        system_prompt = """你是一个网络安全测试任务规划专家。根据用户的自然语言指令，生成详细的执行计划。
你需要：
1. 识别任务类型（recon侦察/exploit漏洞测试/report报告/code代码/analysis分析/custom）
2. 提取目标（IP/域名/URL）
3. 拆解为3-8个可执行子任务
4. 推荐使用的工具（从33个安全工具中选择）
5. 评估优先级和预估时间

可用工具包括：port_scan, dns_lookup, http_headers, subdomain_enumerate_all, directory_scan, sql_injection_test, xss_test, ssrf_test, idor_test, command_injection_test, file_upload_test, xxe_test, cve_lookup等。

请严格输出JSON格式，不要包含其他文字。"""

        prompt = f"""用户任务: {task}
基础分析结果:
- 任务类型: {base_plan.get('task_type', 'unknown')}
- 目标: {base_plan.get('target', '未识别')}

请生成详细执行计划，输出JSON:
{{
  "task_type": "recon/exploit/report/code/analysis/custom",
  "target": "目标地址或null",
  "subtasks": ["子任务1", "子任务2", "子任务3"],
  "recommended_tools": ["工具1", "工具2"],
  "priority": "high/medium/low",
  "estimated_time": "预估时间",
  "risk_level": "low/medium/high",
  "notes": "注意事项"
}}"""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ]

        response = self.llm_client.chat(messages=messages, temperature=0.3, max_tokens=1500)
        if not response:
            return None

        # 解析JSON
        import re
        import json
        # 尝试直接解析
        try:
            return json.loads(response)
        except:
            pass
        # 尝试提取JSON块
        match = re.search(r'\{[\s\S]*\}', response)
        if match:
            try:
                return json.loads(match.group())
            except:
                pass
        return None

    def _select_agents_and_tools(self, plan: Dict) -> Dict:
        """根据计划选择合适的智能体和工具"""
        selected = {
            "agents": [],
            "tools": [],
            "ai_tools": [],
        }

        task_type = plan.get("task_type", "custom")

        # 选择智能体
        if task_type == "recon":
            selected["agents"].append(self.agents["recon"])
        elif task_type == "exploit":
            selected["agents"].append(self.agents["recon"])
            selected["agents"].append(self.agents["exploit"])
            selected["agents"].append(self.agents["verification"])
        elif task_type == "report":
            selected["agents"].append(self.agents["report"])

        # 所有任务都需要报告智能体
        if self.agents["report"] not in selected["agents"]:
            selected["agents"].append(self.agents["report"])

        # 选择工具
        for tool_name in plan.get("estimated_tools", []):
            if tool_name in self.tools:
                selected["tools"].append({"name": tool_name, "description": self.tools[tool_name].get("description", "")})
            elif tool_name in self.ai_tools:
                selected["ai_tools"].append(self.ai_tools[tool_name])

        return selected

    async def _execute_task(self, plan: Dict, selected: Dict, context: Optional[Dict] = None) -> Dict:
        """执行任务 - 调用工具和智能体"""
        execution_result = {
            "plan": plan,
            "selected": selected,
            "tool_results": {},
            "findings": [],
            "errors": [],
        }

        target = plan.get("target")
        if not target:
            execution_result["errors"].append("未识别到目标地址，无法执行扫描类任务")
            return execution_result

        # 执行端口扫描（侦察类任务）
        if plan.get("task_type") in ["recon", "exploit"] and "port_scan" in [t["name"] for t in selected["tools"]]:
            try:
                log.info(f"执行端口扫描: {target}")
                port_tool = self.tools.get("port_scan")
                if port_tool:
                    handler = port_tool["handler"]
                    port_result = handler(target=target, ports="1-1000")
                    if asyncio.iscoroutine(port_result):
                        port_result = await port_result
                    execution_result["tool_results"]["port_scan"] = port_result
                    # 提取发现
                    for port in port_result.get("open_ports", []):
                        execution_result["findings"].append({
                            "type": "port_open",
                            "name": f"端口{port}开放",
                            "severity": "info",
                            "port": port,
                            "service": port_result.get("services", {}).get(str(port), "Unknown"),
                            "target": target,
                        })
            except Exception as e:
                execution_result["errors"].append(f"端口扫描失败: {e}")

        # 执行HTTP头分析
        if plan.get("task_type") in ["recon", "exploit"]:
            try:
                log.info(f"执行HTTP头分析: {target}")
                http_tool = self.tools.get("http_headers")
                if http_tool:
                    url = target if target.startswith("http") else f"http://{target}"
                    handler = http_tool["handler"]
                    http_result = handler(url=url)
                    if asyncio.iscoroutine(http_result):
                        http_result = await http_result
                    execution_result["tool_results"]["http_headers"] = http_result
            except Exception as e:
                execution_result["errors"].append(f"HTTP头分析失败: {e}")

        # 执行目录扫描（漏洞测试类任务）
        if plan.get("task_type") == "exploit":
            try:
                log.info(f"执行目录扫描: {target}")
                dir_tool = self.tools.get("directory_scan")
                if dir_tool:
                    url = target if target.startswith("http") else f"http://{target}"
                    handler = dir_tool["handler"]
                    dir_result = handler(url=url)
                    if asyncio.iscoroutine(dir_result):
                        dir_result = await dir_result
                    execution_result["tool_results"]["directory_scan"] = dir_result
            except Exception as e:
                execution_result["errors"].append(f"目录扫描失败: {e}")

        return execution_result

    async def _verify_findings(self, findings: List[Dict]) -> Dict:
        """POC验证漏洞发现"""
        if not self.poc_verifier or not findings:
            return {"verified_findings": findings, "verification_rate": "N/A"}

        try:
            # 只验证非info级别的发现
            verifiable = [f for f in findings if f.get("severity") != "info"]
            if not verifiable:
                return {"verified_findings": findings, "verification_rate": "N/A", "note": "无可验证漏洞"}

            result = await self.poc_verifier.verify_batch(verifiable)
            verified = [r["finding"] for r in result["results"] if r["verified"]]
            false_positives = [r["finding"] for r in result["results"] if r["false_positive"]]
            unconfirmed = [r["finding"] for r in result["results"] if not r["verified"] and not r["false_positive"]]

            # 保留info级别的发现 + 验证通过的
            final_findings = [f for f in findings if f.get("severity") == "info"] + verified + unconfirmed

            return {
                "verified_findings": final_findings,
                "verification_rate": result["verification_rate"],
                "verified_count": result["verified"],
                "false_positive_count": result["false_positives"],
                "unconfirmed_count": result["unconfirmed"],
            }
        except Exception as e:
            log.warning(f"POC验证失败: {e}")
            return {"verified_findings": findings, "verification_rate": "failed", "error": str(e)}

    def get_capabilities(self) -> Dict:
        """获取超级智能体的所有能力"""
        # 即使未初始化也返回数据，不报错
        return {
            "total_tools": len(self.tools),
            "total_agents": len(self.agents),
            "total_ai_tools": len(self.ai_tools),
            "tools": list(self.tools.keys()),
            "agents": {k: v["name"] for k, v in self.agents.items()} if self.agents else {},
            "ai_tools": list(self.ai_tools.keys()),
            "task_types": ["recon", "exploit", "report", "code", "analysis", "custom"],
            "initialized": self._initialized,
        }

    def get_task_history(self, limit: int = 10) -> List[Dict]:
        """获取任务历史"""
        return self.task_history[-limit:]


# 全局单例
super_agent = SuperAgent()
