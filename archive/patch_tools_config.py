# -*- coding: utf-8 -*-
"""为 config/tools_config.json 中每个工具增加 installed/version/last_check/install_methods 字段。
不删除任何现有字段。
"""
import io
import json

p = r"E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent\config\tools_config.json"
with io.open(p, "r", encoding="utf-8") as f:
    cfg = json.load(f)

DEFAULT_METHODS = ["pip", "download", "wsl", "chocolatey", "manual"]

# 每个工具支持的安装方式（覆盖默认）
TOOL_METHODS = {
    "nmap": ["download", "chocolatey", "manual"],
    "sqlmap": ["pip", "download", "wsl", "manual"],
    "nuclei": ["download", "manual"],
    "masscan": ["wsl", "manual"],
    "nikto": ["download", "wsl", "manual"],
    "metasploit": ["download", "manual"],
    "hashcat": ["download", "manual"],
    "dirsearch": ["download", "pip", "manual"],
    "hydra": ["wsl", "download", "manual"],
}

tools = cfg.setdefault("tools", {})
for name, tcfg in tools.items():
    if not isinstance(tcfg, dict):
        continue
    tcfg.setdefault("installed", False)
    tcfg.setdefault("version", "")
    tcfg.setdefault("last_check", "")
    tcfg.setdefault("install_methods", TOOL_METHODS.get(name, DEFAULT_METHODS))

with io.open(p, "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)

# 验证 JSON 有效
with io.open(p, "r", encoding="utf-8") as f:
    json.load(f)
print("tools_config.json updated and valid, tools=", list(tools.keys()))
