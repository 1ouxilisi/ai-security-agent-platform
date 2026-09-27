# AI决策引擎：大模型如何自动规划渗透测试流程

## 一、传统渗透测试的痛点

传统渗透测试是"人驱动"的：
1. 人工侦察，记录资产
2. 人工判断哪些资产值得深入测试
3. 手动选择工具和payload
4. 手动分析结果，决定下一步

这个流程的问题是：**严重依赖个人经验**。同一个目标，新手和老手的测试结果可能差10倍。

AI决策引擎的目标是：让大模型代替人做"决策"，工具只负责"执行"。

## 二、AI决策引擎的设计思路

核心思想：**ReAct模式**（Reasoning + Acting）

```
观察(Observation) → 思考(Thought) → 行动(Action) → 观察(Observation) → ...
```

每一轮循环：
1. AI观察当前状态（已发现的资产、漏洞、测试进度）
2. AI思考下一步应该做什么
3. AI调用工具执行动作
4. AI观察工具返回的结果
5. 重复，直到达到目标或达到最大轮次

## 三、工具定义（Function Calling）

AI能调用的工具用OpenAPI格式定义：

```python
TOOLS = [
    {
        "name": "nmap_scan",
        "description": "扫描目标IP的端口和服务",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标IP或域名"},
                "ports": {"type": "string", "description": "端口范围，如top1000"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "nuclei_scan",
        "description": "用Nuclei模板扫描URL漏洞",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]}
            },
            "required": ["url"]
        }
    },
    {
        "name": "sqlmap_test",
        "description": "测试URL参数是否存在SQL注入",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "param": {"type": "string"}
            },
            "required": ["url", "param"]
        }
    },
    {
        "name": "generate_report",
        "description": "生成最终渗透测试报告",
        "parameters": {
            "type": "object",
            "properties": {
                "format": {"type": "string", "enum": ["html", "pdf", "markdown"]}
            }
        }
    }
]
```

## 四、决策循环实现

```python
async def ai_pentest(target: str, max_rounds: int = 10) -> PentestResult:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"开始对 {target} 进行渗透测试"}
    ]
    
    vulns_found = []
    
    for round_num in range(max_rounds):
        # AI思考并决定调用哪个工具
        response = await ai_chat_with_tools(messages, TOOLS)
        
        if response.tool_calls:
            for tool_call in response.tool_calls:
                # 执行工具
                tool_result = await execute_tool(
                    tool_call.name, 
                    tool_call.arguments
                )
                
                # 把结果返回给AI
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": str(tool_result)
                })
                
                # 记录发现的漏洞
                if tool_call.name in ["nuclei_scan", "sqlmap_test"]:
                    vulns_found.extend(tool_result.vulns)
        else:
            # AI没有调用工具，说明测试完成
            break
    
    return PentestResult(target=target, vulns=vulns_found, rounds=round_num)
```

## 五、System Prompt设计

System Prompt是AI决策引擎的灵魂，决定了AI的行为模式：

```
你是一个专业的渗透测试AI助手。你的任务是对目标进行系统化的安全测试。

工作流程：
1. 先侦察：用nmap_scan和subfinder了解目标资产
2. 再扫描：用nuclei_scan对发现的URL进行漏洞扫描
3. 深验证：对可疑漏洞用sqlmap_test等工具深度验证
4. 出报告：测试完成后调用generate_report

规则：
- 每次只调用一个工具，根据结果决定下一步
- 优先测试高危端口和常见漏洞
- 发现漏洞后要验证是否为误报
- 最多执行10轮，超时自动生成报告
- 所有操作必须在授权范围内进行
```

## 六、多Agent协作

单Agent有局限：一个大模型既要做侦察又要做扫描还要做分析，容易混乱。我的解决方案是**多Agent协作**：

```
┌─────────────┐
│  协调者Agent  │  分配任务、汇总结果
└──────┬──────┘
       │
   ┌───┴───┬──────────┐
   ↓       ↓          ↓
┌─────┐ ┌─────┐  ┌─────┐
│侦察  │ │扫描  │  │验证  │
│Agent│ │Agent│  │Agent│
└─────┘ └─────┘  └─────┘
```

每个Agent有独立的System Prompt和工具集，协调者负责调度。

## 七、实战效果

对同一个目标的测试对比：

| 指标 | 人工测试 | 单Agent | 多Agent |
|------|---------|---------|---------|
| 耗时 | 4小时 | 25分钟 | 12分钟 |
| 发现漏洞 | 15个 | 11个 | 14个 |
| 误报率 | 5% | 18% | 8% |
| 覆盖度 | 高 | 中 | 高 |

多Agent在速度和覆盖度上接近人工水平，误报率也控制得很好。

## 八、局限和改进方向

当前AI决策引擎的局限：
1. **上下文窗口限制**：测试过程太长会超出token限制
2. **工具调用错误**：AI偶尔会传错参数
3. **复杂漏洞利用**：需要链式利用的漏洞AI还搞不定

改进方向：
1. 用RAG把历史测试案例喂给AI
2. 增加工具调用的参数校验
3. 引入"反思"机制：AI每轮结束后自我评估

## 九、小结

AI决策引擎是整个平台的大脑。它不替代工具，而是替代"人"做决策。把ReAct模式、Function Calling、多Agent协作用好，就能实现真正的自动化渗透测试。

下一篇分享移动安全分析：如何自动化分析APK的安全风险。

---

*本文是「AI安全渗透测试实战」系列的第4篇。完整课程包含12章40节，从环境搭建到完整平台开发。*
