"""
planner智能体模块，提供相关AI驱动的安全分析和决策功能。

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
from typing import Dict, List, Optional
from openai import OpenAI
from config.settings import settings
from utils.logger import log
from agent.memory import AgentMemory


class TaskPlanner:
    """任务规划器"""

    def __init__(self):
        """初始化TaskPlanner实例。

        Args:
            self: 类实例。
        """
        self.client = OpenAI(
            api_key=settings.llm.api_key,
            base_url=settings.llm.base_url,
        )
        self.model = settings.llm.model

    # 系统提示词：定义规划器角色
    SYSTEM_PROMPT = """你是一个专业的安全测试任务规划专家。你的职责是将用户的安全测试目标拆解为具体、可执行的步骤。

## 规划原则
1. **循序渐进**：从信息收集开始，逐步深入，不要跳步
2. **工具明确**：每个步骤必须指定使用哪个工具和参数
3. **合法合规**：只规划授权范围内的测试，拒绝未授权目标
4. **风险可控**：高危操作需要先确认，避免破坏性测试
5. **结果导向**：每个步骤都要有明确的预期产出

## 可用工具列表
### 侦察工具
- port_scan(target, ports?, timeout?) - 端口扫描
- dns_lookup(domain) - DNS解析
- http_headers(url) - 获取HTTP响应头

### Web安全工具
- directory_scan(url, wordlist?) - 目录扫描
- sql_injection_test(url, param) - SQL注入测试
- xss_test(url, param) - XSS测试
- ssl_certificate_check(host, port?) - SSL证书检测

### 浏览器自动化
- browser_navigate(url) - 打开网页
- browser_screenshot(filename?, full_page?) - 页面截图
- browser_get_content() - 获取页面HTML
- browser_extract_links() - 提取页面链接
- browser_extract_forms() - 提取页面表单
- browser_fill_form(selector, value) - 填写表单
- browser_click(selector) - 点击元素
- browser_eval_js(script) - 执行JavaScript

### 桌面自动化
- desktop_screen_size() - 获取屏幕分辨率
- desktop_mouse_position() - 获取鼠标位置
- desktop_screenshot(filename?, region?) - 屏幕截图
- desktop_move_mouse(x, y, duration?) - 移动鼠标
- desktop_click(x?, y?, button?, clicks?) - 鼠标点击
- desktop_type_text(text, interval?) - 键盘输入
- desktop_press_key(key, presses?, interval?) - 按键
- desktop_hotkey(keys) - 组合键
- desktop_scroll(amount, x?, y?) - 滚轮滚动
- desktop_locate_image(image_path, confidence?) - 图像识别

## 输出格式
必须输出JSON数组，每个元素包含：
{
  "description": "步骤描述",
  "tool_name": "使用的工具名（不需要工具则为null）",
  "tool_args": {"参数名": "参数值"}
}

## 注意
- 只输出JSON，不要输出其他解释文字
- 步骤数量控制在5-15步之间
- 先侦察，后测试，最后验证
"""

    def create_plan(self, task_description: str, target: Optional[str] = None) -> AgentMemory:
        """
        创建任务计划
        返回包含完整计划的AgentMemory对象
        """
        from utils.helpers import generate_id

        log.info(f"开始任务规划: {task_description}")

        # 构建用户消息
        user_message = f"安全测试目标：{task_description}"
        if target:
            user_message += f"\n目标：{target}"
        user_message += "\n\n请生成执行计划。"

        try:
            # 调用大模型生成计划
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": user_message},
                ],
                temperature=settings.llm.temperature,
                max_tokens=settings.llm.max_tokens,
            )

            plan_text = response.choices[0].message.content.strip()
            log.debug(f"规划器原始输出: {plan_text[:500]}")

            # 解析JSON
            plan_steps = self._parse_plan(plan_text)

            # 创建记忆对象
            memory = AgentMemory(
                task_id=generate_id("task"),
                task_description=task_description,
                target=target,
                status="planning",
            )

            # 添加步骤到记忆
            for step_data in plan_steps:
                memory.add_step(
                    description=step_data.get("description", "未命名步骤"),
                    tool_name=step_data.get("tool_name"),
                    tool_args=step_data.get("tool_args"),
                )

            memory.status = "planned"
            log.info(f"任务规划完成，共 {len(plan_steps)} 个步骤")
            return memory

        except Exception as e:
            log.error(f"任务规划失败: {e}")
            # 创建失败的记忆对象
            memory = AgentMemory(
                task_id=generate_id("task"),
                task_description=task_description,
                target=target,
                status="failed",
                error=str(e),
            )
            return memory

    def _parse_plan(self, plan_text: str) -> List[Dict]:
        """解析规划器输出的JSON"""
        # 尝试提取JSON部分
        import re
        json_match = re.search(r'\[.*\]', plan_text, re.DOTALL)
        if json_match:
            plan_text = json_match.group(0)

        try:
            steps = json.loads(plan_text)
            if isinstance(steps, list):
                return steps
        except json.JSONDecodeError as e:
            log.error(f"JSON解析失败: {e}")

        # 解析失败，返回默认计划
        log.warning("使用默认计划")
        return [
            {"description": "信息收集：DNS解析和端口扫描", "tool_name": "dns_lookup", "tool_args": {"domain": "target"}},
            {"description": "获取HTTP响应头，识别技术栈", "tool_name": "http_headers", "tool_args": {"url": "http://target"}},
            {"description": "目录扫描，发现隐藏路径", "tool_name": "directory_scan", "tool_args": {"url": "http://target"}},
            {"description": "SSL证书检测", "tool_name": "ssl_certificate_check", "tool_args": {"host": "target"}},
        ]

    def replan(self, memory: AgentMemory, feedback: str) -> AgentMemory:
        """
        根据执行反馈重新规划
        当遇到失败或需要调整时调用
        """
        log.info(f"重新规划，反馈: {feedback}")

        # 构建当前状态摘要
        current_state = f"""
当前任务：{memory.task_description}
已完成步骤：{sum(1 for s in memory.plan if s.status == 'completed')}/{len(memory.plan)}
已发现问题：{len(memory.findings)}个
执行反馈：{feedback}

请根据当前状态，生成后续需要执行的步骤（只输出后续步骤，不重复已完成的）。
"""
        # 复用create_plan的逻辑，但传入当前状态
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": current_state},
                ],
                temperature=settings.llm.temperature,
            )

            new_steps = self._parse_plan(response.choices[0].message.content.strip())

            # 添加新步骤
            for step_data in new_steps:
                memory.add_step(
                    description=step_data.get("description", "未命名步骤"),
                    tool_name=step_data.get("tool_name"),
                    tool_args=step_data.get("tool_args"),
                )

            log.info(f"重新规划完成，新增 {len(new_steps)} 个步骤")
            return memory

        except Exception as e:
            log.error(f"重新规划失败: {e}")
            return memory
