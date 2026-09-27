# -*- coding: utf-8 -*-
"""R29 鏂瑰悜2 绉诲姩绔畨鍏ㄦ繁搴?鈥?鍔熻兘鍐掔儫娴嬭瘯"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

ok = 0
fail = 0
def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1; print(f"  [PASS] {name} {extra}")
    else:
        fail += 1; print(f"  [FAIL] {name} {extra}")

print("="*60)
print("1. 鏍稿績妯″潡鐙珛 import")
from mobile_security_deep import android_deep, ios_deep, harmonyos_deep
from mobile_security_deep import mobile_vuln_poc, privacy_compliance, mobile_test_eval
from mobile_security_deep import mobile_security_dashboard
check("7鏍稿績妯″潡import", True)

print("\n2. Android 鐪熷疄鍒嗘瀽")
ae = android_deep.get_android_engine()
man = ae.analyze_manifest()
check("Manifest瑙ｆ瀽缁勪欢鏁?, man["component_count"] > 0, f"={man['component_count']}")
check("璇嗗埆瀵煎嚭缁勪欢", man["exposed_components"] > 0, f"={man['exposed_components']}")
check("璇嗗埆鍗遍櫓鏉冮檺", man["dangerous_count"] > 0, f"={man['dangerous_count']}")
code = 'String k="stripe_api_key_here"; webView.addJavascriptInterface(b,"b");'
cs = ae.scan_code(code)
check("纭紪鐮佸瘑閽ユ娴?, cs["hardcoded_count"] >= 1, f"={cs['hardcoded_count']}")
check("WebView妗CE妫€娴?, cs["webview_rce_risk"] is True)
net = ae.analyze_network("http://api.x.com; trustAllCerts();")
check("鏄庢枃HTTP妫€娴?, net["cleartext_count"] >= 1)
check("SSL淇′换鎵€鏈夋娴?, net["trust_all_certs"] is True)
rt = ae.analyze_runtime("if(exists('/system/bin/su')) die();")
check("root妫€娴嬭瘑鍒?, rt["root_detection"] is True)
fa = ae.full_assessment("com.demo.shop")
check("Android缁煎悎璇勪及鏈夎瘎鍒?, 0 <= fa["security_score"] <= 100, f"score={fa['security_score']}")

print("\n3. iOS 鐪熷疄鍒嗘瀽")
ie = ios_deep.get_ios_engine()
pl = ie.analyze_info_plist()
check("plist闅愮鏉冮檺璇嗗埆", pl["privacy_permission_count"] >= 1, f"={pl['privacy_permission_count']}")
check("ATS鍏抽棴璇嗗埆", pl["ats"]["arbitrary_loads_allowed"] is True)
ic = ie.scan_code('NSString* k=@"stripe_api_key_here"; dlopen("/tmp/t.dylib",0);')
check("iOS纭紪鐮佹娴?, ic["hardcoded_count"] >= 1)
check("dylib娉ㄥ叆璇嗗埆", ic["dynamic_library_injection"] is True)
ir = ie.analyze_runtime('if exists("/Applications/Cydia.app") exit(); ptrace(PT_DENY_ATTACH,0,0,0);')
check("iOS瓒婄嫳妫€娴嬭瘑鍒?, ir["jailbreak_detection"] is True)
check("iOS鍙嶈皟璇曡瘑鍒?, ir["anti_debug"] is True)

print("\n4. 楦胯挋鐪熷疄鍒嗘瀽")
he = harmonyos_deep.get_harmonyos_engine()
cfg = he.analyze_module_config()
check("module.json5鏉冮檺瑙ｆ瀽", cfg["permission_count"] >= 1, f"={cfg['permission_count']}")
check("鍒嗗竷寮忚兘鍔涘０鏄庤瘑鍒?, cfg["distributed_capability_declared"] is True)
hc = he.scan_code("const apiKey='stripe_api_key_here'; eval(x);")
check("楦胯挋纭紪鐮佹娴?, hc["hardcoded_count"] >= 1)
check("楦胯挋eval娉ㄥ叆璇嗗埆", hc["eval_risk"] is True)

print("\n5. 婕忔礊搴?POC")
ve = mobile_vuln_poc.get_vuln_poc_engine()
vl = ve.list_vulns()
check("婕忔礊搴撴潯鐩暟", len(vl) >= 10, f"={len(vl)}")
check("鍚湡瀹濩VE", any(v["cve"].startswith("CVE-") for v in vl))
check("鍚玈tagefright", any("Stagefright" in v["title"] for v in vl))
check("鍚獸ORCEDENTRY", any("FORCEDENTRY" in v["title"] for v in vl))
sc = ve.run_scan("com.demo.shop", "娣卞害鎵弿")
check("鎵弿鎶ュ憡鐢熸垚", sc["summary"]["total"] > 0, f"={sc['summary']['total']}")
pr = ve.prioritize()
check("浼樺厛绾ф帓搴忔湁鎺掑悕", pr[0]["rank"] == 1)

print("\n6. 闅愮鍚堣")
pe = privacy_compliance.get_privacy_engine()
pi = pe.identify_personal_info("鎵嬫満13812345678 韬唤璇?30102199001011234 閭a@b.com 閾惰鍗?222020200112233445")
check("璇嗗埆鎵嬫満鍙?, "鎵嬫満鍙? in pi["detected_types"])
check("璇嗗埆韬唤璇?, "韬唤璇佸彿" in pi["detected_types"])
check("璇嗗埆閭", "閭" in pi["detected_types"])
sd = pe.scan_sdks("import com.umeng.analytics.MobclickAgent; import com.google.firebase.FA;")
check("SDK璇嗗埆", sd["sdk_count"] >= 1, f"={sd['sdk_count']}")
check("璺ㄥSDK璇嗗埆", len(sd["overseas_sdks"]) >= 1, f"={sd['overseas_sdks']}")
cr = pe.compliance_report("娴嬭瘯App")
check("鍚堣鎶ュ憡鐢熸垚", 0 <= cr["compliance_score"] <= 100, f"score={cr['compliance_score']}")

print("\n7. 娴嬭瘯璇勬祴")
te = mobile_test_eval.get_test_eval_engine()
ev = te.evaluate("娴嬭瘯App")
check("璇勬祴鎵撳垎", ev["scores"]["缁煎悎璇勫垎"] > 0)
check("OWASP Top10", len(te.owasp_top10()) == 10)
check("鏍囧噯搴?, len(te.standards()) >= 5)
plan = te.plan_test("娴嬭瘯App")
check("娴嬭瘯璁″垝鐢熸垚", plan["case_count"] >= 8)

print("\n8. 鎺у埗鍙拌仛鍚?)
db = mobile_security_dashboard.get_dashboard()
ov = db.get_overview()
check("鎬昏鏁版嵁", ov["apps_tracked"] > 0)
check("鍛婅鐢熸垚", len(db.list_alerts()) >= 3)
rs = db.resolve_alert(db.list_alerts()[0]["alert_id"])
check("鍛婅澶勭悊", rs["status"] == "resolved")

print("\n9. 璺敱鏂囦欢")
import api_server.mobile_security_deep_routes as rt
check("璺敱import", True)
check("绔偣鏁?=50", len(rt.router.routes) >= 50, f"={len(rt.router.routes)}")

print("\n" + "="*60)
print(f"缁撴灉: {ok} PASS / {fail} FAIL")
sys.exit(1 if fail else 0)
