# -*- coding: utf-8 -*-
"""批量注册高价值模块到 app_lite.py"""
import re

APP_PATH = r"E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent\app_lite.py"

with open(APP_PATH, "r", encoding="utf-8") as f:
    content = f.read()

# 要注册的模块列表 (模块名, 路由变量名)
MODULES = [
    ("api_server.api_security_routes", "api_security_router"),
    ("api_server.compliance_routes", "compliance_router"),
    ("api_server.soc_routes", "soc_router"),
    ("api_server.soc_center_routes", "soc_center_router"),
    ("api_server.soc_deep_routes", "soc_deep_router"),
    ("api_server.soc_pro_routes", "soc_pro_router"),
    ("api_server.cloud_security_v2_routes", "cloud_v2_router"),
    ("api_server.cloud_security_real_routes", "cloud_real_router"),
    ("api_server.cloud_native_security_routes", "cloud_native_router"),
    ("api_server.container_security_routes", "container_router"),
    ("api_server.soar_routes", "soar_router"),
    ("api_server.soar_deep_routes", "soar_deep_router"),
    ("api_server.devsecops_routes", "devsecops_router"),
    ("api_server.devsecops_deep_routes", "devsecops_deep_router"),
    ("api_server.threat_hunt_routes", "threat_hunt_router"),
]

# 检查哪些已经注册
already = set(re.findall(r"from (api_server\.\w+_routes) import router as (\w+)", content))
already_mods = {m[0] for m in already}

imports_to_add = []
includes_to_add = []

for mod, var in MODULES:
    if mod not in already_mods:
        imports_to_add.append(f"try:\n    from {mod} import router as {var}\n    _ROUTERS.append({var})\nexcept Exception as _e:\n    print(f'[WARN] {mod} 注册失败: {_e}')")

if not imports_to_add:
    print("所有模块已注册，无需添加")
else:
    # 在 import 区域后添加 _ROUTERS 列表和 try-import
    # 找到最后一个 import router 行
    last_import = list(re.finditer(r"from api_server\.\w+_routes import router as \w+", content))[-1]
    insert_pos = last_import.end()

    # 添加 _ROUTERS 初始化和 try-import 块
    router_block = "\n\n# === 批量注册高价值模块（try-except容错） ===\n_ROUTERS = []\n" + "\n".join(imports_to_add) + "\n"

    content = content[:insert_pos] + router_block + content[insert_pos:]

    # 在 app.include_router 区域后添加批量注册
    last_include = list(re.finditer(r"app\.include_router\(\w+\)", content))[-1]
    include_pos = last_include.end()

    include_block = "\n\n# === 批量注册高价值模块 ===\nfor _r in _ROUTERS:\n    app.include_router(_r)\n"
    content = content[:include_pos] + include_block + content[include_pos:]

    with open(APP_PATH, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"已添加 {len(imports_to_add)} 个模块的注册:")
    for mod, var in MODULES:
        if mod not in already_mods:
            print(f"  + {mod}")
else:
    print("无需修改")
