# -*- coding: utf-8 -*-
"""修复 integration.py 中 tool_is_available 的 subprocess 调用（capture_output 与 stdout 互斥）。"""
import io

p = r"E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent\tools\integration.py"
s = io.open(p, "r", encoding="utf-8").read()

old = ("            capture_output=True, timeout=15,\n"
       "            stdout=_subprocess_for_health.PIPE,\n"
       "            stderr=_subprocess_for_health.STDOUT,\n"
       "            text=True,")
new = ("            capture_output=True, timeout=15,\n"
       "            text=True,")

if old in s:
    io.open(p, "w", encoding="utf-8").write(s.replace(old, new, 1))
    print("FIXED LF")
else:
    old2 = old.replace("\n", "\r\n")
    if old2 in s:
        io.open(p, "w", encoding="utf-8").write(s.replace(old2, new.replace("\n", "\r\n"), 1))
        print("FIXED CRLF")
    else:
        print("NOT FOUND")
