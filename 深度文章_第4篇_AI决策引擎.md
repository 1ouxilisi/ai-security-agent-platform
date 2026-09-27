# AI决策引擎实战：Function Calling自动规划渗透路径

> 传统扫描器只会按固定流程跑。AI决策引擎能根据侦察结果自动决定下一步做什么。

---

## 1 AI决策引擎怎么工作

```
侦察结果 → LLM分析 → 决定下一步 → 执行 → 看结果 → 再决定
```

例子：
1. 侦察发现 `example.com` 运行WordPress 5.9
2. AI决策："WordPress 5.9有CVE-2022-21661 SQL注入，下一步跑SQLMap"
3. SQLMap跑了，发现注入点
4. AI决策："有注入，下一步拖users表"
5. 拖到数据，AI写报告

---

## 2 Function Calling实操

```python
import openai

tools = [
    {
        "type": "function",
        "function": {
            "name": "nuclei_scan",
            "description": "用Nuclei扫描目标URL的漏洞",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "severity": {"type": "string", "enum": ["critical","high","medium"]}
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "sqlmap",
            "description": "检测和利用SQL注入",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "required": True},
                    "dump": {"type": "boolean"}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "subdomain_enum",
            "description": "枚举子域名",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "required": True}
                }
            }
        }
    }
]

# 主循环
def ai_pentest(target):
    messages = [{"role": "user", "content": f"对{target}做渗透测试，从侦察开始"}]

    while True:
        response = openai.chat.completions.create(
            model="qwen2.5-7b",
            messages=messages,
            tools=tools
        )

        msg = response.choices[0].message
        messages.append(msg)

        if not msg.tool_calls:
            # AI说完成了
            print("AI报告:", msg.content)
            break

        # 执行AI决定的工具
        for call in msg.tool_calls:
            result = execute_tool(call)
            messages.append({
                "role": "tool",
                "tool_call_id": call.id,
                "content": result
            })
```

---

## 3 实际决策日志

```
[AI] 分析: 目标example.com，先枚举子域名
[AI] 调用: subdomain_enum(domain="example.com")
[工具] 结果: 发现admin.example.com, dev.example.com

[AI] 分析: dev环境可能防护弱，先扫dev
[AI] 调用: nuclei_scan(url="https://dev.example.com", severity="high")
[工具] 结果: 发现SQL注入在 /api/user?id=1

[AI] 分析: 有SQL注入，拖数据
[AI] 调用: sqlmap(url="https://dev.example.com/api/user?id=1", dump=true)
[工具] 结果: 拖到users表500条记录

[AI] 分析: 完成，写报告
```

---

## 4 问题排查

**Q: AI决定不做某些测试？**
系统提示里加："必须测试所有常见攻击向量"。

**Q: AI陷入循环？**
加最大步数限制（10步）。

**Q: AI决定攻击不该攻击的？**
系统提示加："只测试明确授权的目标"。

---

## 5 Checklist

- [ ] 定义所有可用工具
- [ ] 写系统提示（渗透测试专家角色）
- [ ] 跑一次完整流程
- [ ] 检查AI决策是否合理
- [ ] 加最大步数限制
