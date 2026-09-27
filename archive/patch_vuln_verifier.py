# -*- coding: utf-8 -*-
"""一次性补丁：在 tools/vuln_verifier.py 的漏洞报告字典中增加 verification_status 字段。"""
import io

p = r"E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent\tools\vuln_verifier.py"
with io.open(p, "r", encoding="utf-8") as f:
    s = f.read()

old = '"verified": v.verified,\n                    "false_positive": v.false_positive,'
new = ('"verified": v.verified,\n'
       '                    "verification_status": getattr(v, "verification_status", "unverified"),\n'
       '                    "false_positive": v.false_positive,')

if old in s:
    s2 = s.replace(old, new, 1)
    with io.open(p, "w", encoding="utf-8") as f:
        f.write(s2)
    print("PATCHED OK")
elif '"verification_status"' in s:
    print("ALREADY PATCHED")
else:
    print("PATTERN NOT FOUND - file may use CRLF")
    # 尝试 CRLF
    old_crlf = old.replace("\n", "\r\n")
    if old_crlf in s:
        new_crlf = new.replace("\n", "\r\n")
        s2 = s.replace(old_crlf, new_crlf, 1)
        with io.open(p, "w", encoding="utf-8") as f:
            f.write(s2)
        print("PATCHED OK (CRLF)")
    else:
        # 打印附近内容以便排查
        idx = s.find('"verified": v.verified')
        print("idx=", idx)
        print(repr(s[idx-10:idx+200]))
