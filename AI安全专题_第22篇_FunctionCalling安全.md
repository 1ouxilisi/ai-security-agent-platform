# Function Calling安全：参数注入、路径遍历与命令注入

> Function Calling让大模型决定调什么工具、传什么参数。但模型可能传入恶意参数。

---

## 1 问题

正常：`get_weather(city="北京")`
攻击：`read_file(path="../../etc/passwd")`
攻击：`execute_command(command="ls; rm -rf /")`

---

## 2 参数校验代码

```python
import os, re

def validate_params(tool, params):
    if tool == "read_file":
        path = params.get("path", "")
        if ".." in path:
            raise ValueError("路径遍历")
        allowed = os.path.abspath("./uploads/")
        if not os.path.abspath(path).startswith(allowed):
            raise ValueError("禁止访问其他目录")

    elif tool == "execute_command":
        cmd = params.get("command", "")
        if re.search(r"[;&|`]", cmd):
            raise ValueError("命令注入")
        ALLOWED = ["ls", "pwd", "whoami"]
        if cmd.split()[0] not in ALLOWED:
            raise ValueError("不在白名单")

    return True
```

---

## 3 JSON Schema

```python
SCHEMA = {
    "read_file": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "pattern": "^[a-zA-Z0-9_/.-]+$", "maxLength": 100}
        },
        "additionalProperties": False
    }
}
```

---

## 4 Checklist

- [ ] 每个工具写参数校验
- [ ] 路径类检测遍历
- [ ] 命令类白名单
- [ ] 异常参数记录日志
