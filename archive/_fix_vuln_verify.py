# -*- coding: utf-8 -*-
import os
filepath = r"E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent\api_server\vuln_verification_routes.py"
with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

# 修复1: list_verification_methods 使用 .get() 避免KeyError
old1 = '''return _ok({"methods": {k: {"name": v["name"], "method": v["method"], "payload_count": len(v["payloads"]), "indicator_count": len(v["indicators"])} for k, v in VERIFICATION_METHODS.items()}, "total": len(VERIFICATION_METHODS)})'''
new1 = '''return _ok({"methods": {k: {"name": v.get("name", k), "method": v.get("method", ""), "payload_count": len(v.get("payloads", v.get("files", []))), "indicator_count": len(v.get("indicators", []))} for k, v in VERIFICATION_METHODS.items()}, "total": len(VERIFICATION_METHODS)})'''
if old1 in content:
    content = content.replace(old1, new1)
    print("修复1: list_verification_methods KeyError 已修复")
else:
    print("修复1: 未找到目标字符串")

# 修复2: INSERT语句指定列名
old2 = '''conn.execute("""INSERT INTO vulnerabilities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (vuln_id, fingerprint, req.target, req.url, req.vuln_type, req.severity,
             req.title or f"{req.vuln_type} - {req.url}", req.description, req.evidence,
             0, confidence, 0, 0, json.dumps(req.params, ensure_ascii=False),
             json.dumps(req.request_data, ensure_ascii=False), req.response_snippet,
             now, "", json.dumps(req.tags, ensure_ascii=False)))'''
new2 = '''conn.execute("""INSERT INTO vulnerabilities (id,fingerprint,target,url,vuln_type,severity,title,description,evidence,cvss,confidence,verified,false_positive,params,request_data,response_snippet,created_at,verified_at,tags) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (vuln_id, fingerprint, req.target, req.url, req.vuln_type, req.severity,
             req.title or f"{req.vuln_type} - {req.url}", req.description, req.evidence,
             0, confidence, 0, 0, json.dumps(req.params, ensure_ascii=False),
             json.dumps(req.request_data, ensure_ascii=False), req.response_snippet,
             now, "", json.dumps(req.tags, ensure_ascii=False)))'''
if old2 in content:
    content = content.replace(old2, new2)
    print("修复2: INSERT列数不匹配 已修复")
else:
    print("修复2: 未找到目标字符串")

with open(filepath, "w", encoding="utf-8") as f:
    f.write(content)
print("文件已保存")
