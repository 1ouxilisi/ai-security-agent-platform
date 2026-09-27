import os
import re

files_to_fix = [
    "./agent/base_agent.py",
    "./agent/executor.py",
    "./agent/react_engine.py",
    "./mcp_server/server.py",
    "./plugins/manager.py",
    "./tests/test_suite.py",
]

fixed_count = 0
for filepath in files_to_fix:
    if not os.path.exists(filepath):
        print(f"跳过不存在: {filepath}")
        continue
    content = open(filepath, encoding="utf-8").read()
    if "asyncio.iscoroutinefunction" not in content:
        print(f"无需修复: {filepath}")
        continue
    
    # 替换asyncio.iscoroutinefunction为inspect.iscoroutinefunction
    content = content.replace("asyncio.iscoroutinefunction", "inspect.iscoroutinefunction")
    
    # 确保导入了inspect
    if "import inspect" not in content:
        # 在import asyncio后面添加import inspect
        if "import asyncio" in content:
            content = content.replace("import asyncio", "import asyncio\nimport inspect")
        else:
            # 在文件开头添加
            content = "import inspect\n" + content
    
    open(filepath, "w", encoding="utf-8", newline="\n").write(content)
    print(f"已修复: {filepath}")
    fixed_count += 1

print(f"\n总计修复: {fixed_count}个文件")
