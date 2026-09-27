"""
executor智能体模块，提供相关AI驱动的安全分析和决策功能。

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
import inspect
import json
import time
from typing import Any, Dict, Optional
from utils.logger import log
from agent.memory import AgentMemory, TaskStep
from mcp_server.recon_tools import recon_tools
from mcp_server.web_tools import web_tools
from mcp_server.browser_tools import browser_tools
from mcp_server.desktop_tools import desktop_tools


class TaskExecutor:
    """任务执行器"""

    def __init__(self):
        # 工具映射表：工具名 -> 处理函数
        """初始化TaskExecutor实例。

        Args:
            self: 类实例。
        """
        self.tool_map = {
            # 侦察工具
            "port_scan": recon_tools.port_scan,
            "dns_lookup": recon_tools.dns_lookup,
            "http_headers": recon_tools.http_headers,
            # Web安全工具
            "directory_scan": web_tools.directory_scan,
            "sql_injection_test": web_tools.sql_injection_test,
            "xss_test": web_tools.xss_test,
            "ssl_certificate_check": web_tools.ssl_certificate_check,
            # 浏览器工具
            "browser_navigate": browser_tools.navigate,
            "browser_screenshot": browser_tools.take_screenshot,
            "browser_get_content": browser_tools.get_page_content,
            "browser_extract_links": browser_tools.extract_links,
            "browser_extract_forms": browser_tools.extract_forms,
            "browser_fill_form": browser_tools.fill_form,
            "browser_click": browser_tools.click_element,
            "browser_eval_js": browser_tools.evaluate_script,
            # 桌面工具
            "desktop_screen_size": desktop_tools.get_screen_size,
            "desktop_mouse_position": desktop_tools.get_mouse_position,
            "desktop_screenshot": desktop_tools.screenshot,
            "desktop_move_mouse": desktop_tools.move_mouse,
            "desktop_click": desktop_tools.click,
            "desktop_type_text": desktop_tools.type_text,
            "desktop_press_key": desktop_tools.press_key,
            "desktop_hotkey": desktop_tools.hotkey,
            "desktop_scroll": desktop_tools.scroll,
            "desktop_locate_image": desktop_tools.locate_on_screen,
        }

    async def execute_step(self, memory: AgentMemory, step: TaskStep) -> Dict:
        """
        执行单个任务步骤
        返回执行结果
        """
        log.info(f"执行步骤 #{step.step_number}: {step.description}")

        # 标记步骤开始
        memory.start_step(memory.plan.index(step))

        # 如果不需要工具，直接完成
        if not step.tool_name:
            result = {"message": step.description, "completed": True}
            memory.complete_step(memory.plan.index(step), result)
            return result

        # 查找工具处理函数
        handler = self.tool_map.get(step.tool_name)
        if not handler:
            error = f"未知工具: {step.tool_name}"
            log.error(error)
            memory.fail_step(memory.plan.index(step), error)
            return {"error": error}

        try:
            # 准备参数
            tool_args = step.tool_args or {}

            # 参数中的 target 占位符替换
            if memory.target:
                for key, value in tool_args.items():
                    if isinstance(value, str) and "target" in value.lower():
                        tool_args[key] = value.replace("target", memory.target)

            log.debug(f"调用工具 {step.tool_name}, 参数: {json.dumps(tool_args, ensure_ascii=False)[:200]}")

            # 执行工具（支持同步和异步）
            if inspect.iscoroutinefunction(handler):
                result = await handler(**tool_args)
            else:
                result = handler(**tool_args)

            # 分析结果，提取安全发现
            self._analyze_result(memory, step, result)

            # 标记步骤完成
            memory.complete_step(memory.plan.index(step), result)

            # 添加到历史
            memory.add_history("tool_result", f"[{step.tool_name}] {step.description}", {
                "tool": step.tool_name,
                "args": tool_args,
                "result_summary": self._summarize_result(result),
            })

            return result

        except Exception as e:
            error = f"工具执行失败: {str(e)}"
            log.error(f"{error}\n{traceback.format_exc()}")
            memory.fail_step(memory.plan.index(step), error)
            return {"error": error}

    async def execute_all(self, memory: AgentMemory, delay: float = 1.0) -> AgentMemory:
        """
        执行所有待执行步骤
        """
        log.info(f"开始执行任务: {memory.task_description}")
        memory.status = "executing"

        pending_steps = [s for s in memory.plan if s.status == "pending"]
        total = len(pending_steps)
        log.info(f"待执行步骤数: {total}")

        for i, step in enumerate(pending_steps):
            log.info(f"进度: {i+1}/{total}")

            # 执行步骤
            result = await self.execute_step(memory, step)

            # 检查是否需要中断
            if result.get("error") and "不在授权白名单" in str(result.get("error", "")):
                log.warning("授权校验失败，终止后续执行")
                memory.status = "failed"
                memory.error = "目标不在授权白名单内，任务已终止"
                break

            # 步骤间延迟，避免过快
            if delay > 0 and i < total - 1:
                await asyncio.sleep(delay)

        # 任务完成
        if memory.status != "failed":
            memory.status = "completed"

        log.info(f"任务执行完成: {memory.task_description}")
        log.info(f"统计: {memory.get_statistics()}")

        return memory

    def _analyze_result(self, memory: AgentMemory, step: TaskStep, result: Dict):
        """
        分析工具执行结果，提取安全发现
        """
        if not isinstance(result, dict):
            return

        # 端口扫描结果分析
        if step.tool_name == "port_scan" and result.get("open_ports"):
            open_ports = result["open_ports"]
            if len(open_ports) > 5:
                memory.add_finding(
                    type="info",
                    severity="low",
                    title=f"发现 {len(open_ports)} 个开放端口",
                    description=f"目标开放了较多端口: {open_ports}",
                    target=memory.target,
                    tool=step.tool_name,
                )
            # 高危端口
            high_risk_ports = [21, 23, 445, 3389, 6379, 27017]
            found_high_risk = [p for p in open_ports if p in high_risk_ports]
            if found_high_risk:
                memory.add_finding(
                    type="warning",
                    severity="medium",
                    title=f"发现高危端口开放: {found_high_risk}",
                    description=f"这些端口通常不应暴露在公网，存在安全风险",
                    target=memory.target,
                    tool=step.tool_name,
                    recommendations="限制这些端口的访问来源，使用防火墙规则",
                )

        # SQL注入结果分析
        if step.tool_name == "sql_injection_test" and result.get("is_vulnerable"):
            vulns = result.get("vulnerabilities", [])
            for vuln in vulns:
                memory.add_finding(
                    type="vulnerability",
                    severity=vuln.get("confidence", "high").lower(),
                    title=f"SQL注入漏洞 - 参数: {result.get('param')}",
                    description=f"目标URL存在SQL注入漏洞，测试Payload: {vuln.get('payload')}",
                    evidence=vuln.get("payload"),
                    target=result.get("url"),
                    tool=step.tool_name,
                    recommendations="使用参数化查询，对用户输入进行严格过滤和转义",
                )

        # XSS结果分析
        if step.tool_name == "xss_test" and result.get("is_vulnerable"):
            vulns = result.get("vulnerabilities", [])
            for vuln in vulns:
                memory.add_finding(
                    type="vulnerability",
                    severity=vuln.get("confidence", "medium").lower(),
                    title=f"XSS跨站脚本漏洞 - 参数: {result.get('param')}",
                    description=f"目标URL存在XSS漏洞，测试Payload: {vuln.get('payload')}",
                    evidence=vuln.get("payload"),
                    target=result.get("url"),
                    tool=step.tool_name,
                    recommendations="对用户输入进行HTML实体编码，使用Content Security Policy",
                )

        # 目录扫描结果分析
        if step.tool_name == "directory_scan" and result.get("found_items"):
            sensitive_paths = ["/.env", "/.git/config", "/backup", "/db.sql", "/phpinfo.php", "/config.php"]
            for item in result["found_items"]:
                path = item.get("path", "")
                if any(s in path for s in sensitive_paths):
                    memory.add_finding(
                        type="vulnerability",
                        severity="high",
                        title=f"敏感文件/目录暴露: {path}",
                        description=f"发现敏感路径可访问: {path}, 状态码: {item.get('status_code')}",
                        target=memory.target,
                        tool=step.tool_name,
                        recommendations="移除或限制访问敏感文件，配置Web服务器禁止访问这些路径",
                    )

        # SSL证书结果分析
        if step.tool_name == "ssl_certificate_check":
            if result.get("is_expired"):
                memory.add_finding(
                    type="warning",
                    severity="high",
                    title="SSL证书已过期",
                    description=f"目标SSL证书已过期，可能导致用户访问警告和安全风险",
                    target=result.get("host"),
                    tool=step.tool_name,
                    recommendations="立即更新SSL证书",
                )
            elif result.get("days_until_expiry", 999) < 30:
                memory.add_finding(
                    type="info",
                    severity="low",
                    title=f"SSL证书即将过期 ({result.get('days_until_expiry')}天)",
                    description="SSL证书将在30天内过期",
                    target=result.get("host"),
                    tool=step.tool_name,
                    recommendations="及时续期SSL证书",
                )

    def _summarize_result(self, result: Any, max_length: int = 200) -> str:
        """摘要结果，用于历史记录"""
        try:
            text = json.dumps(result, ensure_ascii=False, default=str)
            if len(text) > max_length:
                return text[:max_length] + "..."
            return text
        except Exception:
            return str(result)[:max_length]


# 需要导入traceback
import traceback
