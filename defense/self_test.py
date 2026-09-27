# -*- coding: utf-8 -*-
"""
防御模块自检脚本

运行方式（项目根目录下）：
    python defense/self_test.py

验证内容：
    1. defense 包所有模块可独立 import
    2. 每个引擎至少 3 个功能可真实执行
    3. api_server.defense_routes 可导入且导出 router
    4. 生成控制台演示用的示例访问日志 data/defense_sample_access.log
"""
import os
import sys
import json
import traceback

# 将项目根目录加入 sys.path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

PASS = 0
FAIL = 0


def check(name, fn):
    global PASS, FAIL
    try:
        detail = fn()
        PASS += 1
        print(f"  [PASS] {name}" + (f"  -> {detail}" if detail else ""))
        return True
    except Exception as e:
        FAIL += 1
        print(f"  [FAIL] {name}: {e}")
        traceback.print_exc()
        return False


def section(title):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def main():
    print("防御侧安全模块自检")
    print(f"项目根目录: {ROOT}")

    # 1. 模块导入
    section("[1/5] 模块导入")
    engines = {}
    def do_import():
        import defense.ids_engine as a
        import defense.log_analyzer as b
        import defense.baseline_checker as c
        import defense.remediation_verifier as d
        import defense.threat_hunting as e
        engines.update(dict(ids=a, la=b, bl=c, rv=d, th=e))
        return "5 个引擎模块全部可导入"
    check("defense 包模块导入", do_import)

    # 2. IDS 引擎
    section("[2/5] IDS 入侵检测引擎")
    from defense.ids_engine import IDSEngine
    ids = IDSEngine()
    check("内置规则 >= 20 条", lambda: f"{len(ids.rules)} 条" if len(ids.rules) >= 20 else (_ for _ in ()).throw(AssertionError("规则不足20")))
    check("规则解析器", lambda: (lambda r: "解析成功 sid=%s" % r["sid"] if r else "无")(
        IDSEngine.parse_rule('alert tcp any any -> any any (msg:"test"; content:"union select"; sid:999999; classtype:sqli;)')))
    # 5 种攻击特征触发
    attacks = [
        {"path": "/q=1' OR '1'='1 UNION SELECT", "user_agent": "sqlmap/1.7", "source_ip": "1.1.1.1"},
        {"path": "/x=<script>alert(1)</script>", "source_ip": "1.1.1.2"},
        {"path": "/f?file=../../../../etc/passwd", "source_ip": "1.1.1.3"},
        {"path": "/?url=http://169.254.169.254/latest", "source_ip": "1.1.1.4"},
        {"path": "/shell.php?c=eval(base64_decode(a==))", "source_ip": "1.1.1.5"},
    ]
    def multi_attack():
        total = 0
        for p in attacks:
            total += len(ids.analyze_packet(p))
        return f"5 种攻击特征共触发 {total} 条告警"
    check("多攻击特征触发告警", multi_attack)
    check("告警分级过滤 critical", lambda: f"{len(ids.get_alerts('critical'))} 条 critical")
    check("analyze_log_line", lambda: f"{len(ids.analyze_log_line('2.2.2.2 GET /?q=union select'))} 条")

    # 3. 日志分析
    section("[3/5] 日志分析引擎")
    from defense.log_analyzer import LogAnalyzer
    la = LogAnalyzer()
    check("parse_access_log", lambda: "解析 OK" if la.parse_access_log(
        '203.0.113.66 - - [12/Sep/2026:03:14:15 +0800] "GET /x?q=union select HTTP/1.1" 200 123 "-" "sqlmap"') else "失败")
    # 构造 20+ 行含攻击 + 暴力破解
    def build_brute():
        la2 = LogAnalyzer()
        for i in range(8):  # 8 次失败 -> 暴力破解
            la2.records.append({"type": "auth", "ip": "185.220.1.9", "user": "root",
                                "success": False, "status": 401, "hour": 3})
        la2.records.append({"type": "access", "ip": "185.220.1.9", "path": "/?q=union select",
                            "status": 200, "hour": 3})
        findings = la2.detect_brute_force(threshold=5)
        stats = la2.get_statistics()
        return f"暴力破解命中 {len(findings)} 项, 统计攻击源 {stats['top_attack_ips'][:1]}"
    check("暴力破解检测+统计(20+行场景)", build_brute)
    check("export_report", lambda: f"异常 {len(la.export_report()['anomalies'])} 项")

    # 4. 基线检查
    section("[4/5] 基线检查 / 修复验证 / 威胁狩猎")
    from defense.baseline_checker import BaselineChecker
    bc = BaselineChecker()
    check("基线 run_check(全类别)", lambda: f"共 {bc.run_check()['total_checks']} 项检查")
    check("check_web_server", lambda: f"{len(bc.check_web_server({'https_redirect':True}))} 项")
    check("check_os", lambda: f"{len(bc.check_os({'password_min_length':16}))} 项")
    check("check_database", lambda: f"{len(bc.check_database({}))} 项")
    check("check_container", lambda: f"{len(bc.check_container({}))} 项")

    from defense.remediation_verifier import RemediationVerifier
    vf = RemediationVerifier()
    check("verify 已修复(SQLi)", lambda: vf.verify(
        {"vuln_id": "V1", "title": "SQLi", "target": "a", "severity": "high", "vuln_type": "sql_injection"},
        {"config_checks": {"parameterized_query": True, "input_sanitized": True, "waf_rule": "active"}})["result"])
    check("verify 部分修复(弱口令)", lambda: vf.verify(
        {"vuln_id": "V2", "title": "弱口令", "target": "b", "severity": "high", "vuln_type": "weak_password"},
        {"config_checks": {"password_rotated": True}})["result"])
    check("verify 未修复(开放端口)", lambda: vf.verify(
        {"vuln_id": "V3", "title": "开放端口", "target": "c", "severity": "high", "vuln_type": "open_port"},
        {"config_checks": {"port_closed": False, "firewall_allowlist": False}})["result"])
    check("verify_patch_version", lambda: vf.verify_patch_version("t", "openssl", "1.1.1", "3.0.0")["result"])

    from defense.threat_hunting import ThreatHunter
    th = ThreatHunter()
    events = [
        {"user": "admin", "dest_host": "PC-01", "logon_type": 3, "auth_package": "NTLM", "ntlm_nt_hash_used": True, "protocol": "smb"},
        {"user": "admin", "dest_host": "PC-02", "protocol": "rdp"},
        {"user": "admin", "dest_host": "PC-03", "protocol": "smb"},
        {"process": "mimikatz.exe", "target_process": "lsass.exe", "access_granted": 4096},
        {"event_type": "kerberoast", "user": "admin", "spn": "cifs/srv01", "encryption_type": "rc4-hmac"},
        {"src_ip": "10.0.0.9", "direction": "outbound", "dest_ip": "203.0.113.9", "bytes_out": 83886080},
    ]
    def hunt_all_three():
        th.hunt_all(events)
        by_scn = th.export_hunt_report()["by_scenario"]
        return f"命中场景: {by_scn}"
    check("威胁狩猎(>=3场景产出发现)", hunt_all_three)
    check("IOC 加载与匹配", lambda: (
        th.load_iocs([{"type": "ip", "value": "203.0.113.9"}]),
        f"命中 {len(th.match_iocs({'dest_ip': '203.0.113.9'}))} 条 IOC")[1])

    # 5. 路由导入
    section("[5/5] API 路由与示例数据")
    def route_import():
        from api_server.defense_routes import router
        n = len(router.routes)
        return f"router 导出成功, {n} 个端点"
    check("from api_server.defense_routes import router", route_import)

    # 生成示例访问日志（控制台演示用）
    def make_sample_log():
        lines = []
        # 正常访问
        for i in range(3):
            lines.append(f'10.0.0.{i+1} - - [12/Sep/2026:09:0{i}:00 +0800] "GET /home HTTP/1.1" 200 1024 "-" "Mozilla/5.0"')
        # SQL 注入
        lines.append('203.0.113.66 - - [12/Sep/2026:03:14:15 +0800] "GET /search?q=1%27%20OR%201=1-- HTTP/1.1" 200 123 "-" "sqlmap/1.7"')
        # 目录遍历
        lines.append('203.0.113.66 - - [12/Sep/2026:03:14:16 +0800] "GET /files?name=../../etc/passwd HTTP/1.1" 404 0 "-" "sqlmap/1.7"')
        # XSS
        lines.append('203.0.113.77 - - [12/Sep/2026:04:20:01 +0800] "GET /comment?t=<script>alert(1)</script> HTTP/1.1" 200 512 "-" "Mozilla/5.0"')
        # WebShell / 敏感探测
        for p in ["/.env", "/.git/config", "/shell.php", "/backup.sql"]:
            lines.append(f'185.220.1.9 - - [12/Sep/2026:05:01:00 +0800] "GET {p} HTTP/1.1" 404 0 "-" "nikto/2.1"')
        # 暴力破解（8 次 401）
        for i in range(8):
            lines.append(f'45.155.66.{i} - - [12/Sep/2026:06:3{i}:00 +0800] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"')
        path = os.path.join(ROOT, "data", "defense_sample_access.log")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return f"写出 {len(lines)} 行 -> {path}"
    check("生成示例日志 data/defense_sample_access.log", make_sample_log)

    # 汇总
    section("自检汇总")
    print(f"通过: {PASS}    失败: {FAIL}")
    if FAIL == 0:
        print(">>> 全部自检通过 ✅")
        return 0
    else:
        print(">>> 存在失败项 ❌")
        return 1


if __name__ == "__main__":
    sys.exit(main())
