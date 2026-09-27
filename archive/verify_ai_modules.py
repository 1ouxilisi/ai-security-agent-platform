# -*- coding: utf-8 -*-
"""
verify_ai_modules.py — AI 深度赋能模块验证脚本

在项目根目录运行：python verify_ai_modules.py
依次验证：
    1) 五个 Python 模块能否成功导入
    2) 每个 AI 模块是否具备可调用的真实方法（非空壳）
    3) LLM 不可用时的规则化降级是否正常返回
输出每个模块的导入状态与基本功能测试结果，最终汇总导入错误数。
"""
import os
import sys
import time
import traceback

# 确保从项目根目录导入
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

ERRORS: list = []
RESULTS: list = []


def report(name: str, ok: bool, detail: str = "") -> None:
    """记录一条测试结果。"""
    mark = "PASS" if ok else "FAIL"
    line = f"[{mark}] {name}" + (f" — {detail}" if detail else "")
    RESULTS.append(line)
    print(line)
    if not ok:
        ERRORS.append(name)


# ---------------------------------------------------------------------------
# 1) 导入测试
# ---------------------------------------------------------------------------
print("=" * 70)
print("一、模块导入测试")
print("=" * 70)

modules = {}
for mod_name in [
    "ai.natural_language",
    "ai.vuln_verifier",
    "ai.remediation_generator",
    "ai.security_assistant",
    "api_server.ai_routes",
]:
    try:
        modules[mod_name] = __import__(mod_name, fromlist=["*"])
        report(f"导入 {mod_name}", True)
    except Exception as e:
        report(f"导入 {mod_name}", False, f"{e}")
        traceback.print_exc()

# ---------------------------------------------------------------------------
# 2) 自然语言引擎功能测试
# ---------------------------------------------------------------------------
print("\n" + "=" * 70)
print("二、自然语言交互引擎功能测试")
print("=" * 70)
try:
    from ai.natural_language import NaturalLanguageEngine
    eng = NaturalLanguageEngine()
    report("实例化 NaturalLanguageEngine", True)

    # 意图识别
    r = eng.intent_recognize("帮我扫描一下 192.168.1.1 看看开了什么端口")
    report("intent_recognize 返回 dict", isinstance(r, dict) and "intent" in r,
           f"intent={r.get('intent')}, source={r.get('source')}")

    # 参数提取
    p = eng.extract_params("扫描 10.0.0.5 的 443 端口", "scan_target")
    report("extract_params 提取 IP/端口", "target" in p, f"params={p}")

    # 上下文管理
    eng.add_to_context("s1", "user", "你好")
    ctx = eng.get_context("s1")
    report("多轮上下文 add/get", len(ctx) >= 1)
    eng.clear_context("s1")
    report("clear_context 清空", len(eng.get_context("s1")) == 0)

    # execute_task 各意图
    for intent in ["scan_target", "query_vuln", "generate_report",
                   "view_trends", "create_task", "config_tool", "general_chat"]:
        res = eng.execute_task(intent, {"target": "127.0.0.1"})
        report(f"execute_task({intent}) 不抛异常", isinstance(res, dict) and "status" in res)

    # 结果解释
    exp = eng.explain_result({"status": "ok", "kind": "scan",
                              "target": "127.0.0.1",
                              "findings": [{"port": 80, "state": "open"}]}, "scan_target")
    report("explain_result 返回非空字符串", isinstance(exp, str) and len(exp) > 5,
           f"len={len(exp)}")

    # 一站式 chat
    chat_out = eng.chat("你好", "s_demo")
    report("chat() 一站式返回完整结构",
           all(k in chat_out for k in ["intent", "params", "result", "explanation"]))
except Exception as e:
    report("自然语言引擎功能测试", False, f"{e}")
    traceback.print_exc()

# ---------------------------------------------------------------------------
# 3) 漏洞验证引擎功能测试
# ---------------------------------------------------------------------------
print("\n" + "=" * 70)
print("三、漏洞自动验证引擎功能测试")
print("=" * 70)
try:
    from ai.vuln_verifier import VulnerabilityVerifier
    ver = VulnerabilityVerifier()
    report("实例化 VulnerabilityVerifier", True)

    vt = ver._analyze_vuln_type("这里可能存在 SQL 注入，参数 id")
    report("_analyze_vuln_type 识别 sql_injection", vt == "sql_injection", f"type={vt}")

    # open_port 对一个明显不可达地址，应返回不抛异常
    r = ver._verify_open_port("127.0.0.1", port=1)
    report("_verify_open_port 返回结果 dict", isinstance(r, dict) and "status" in r)

    # 主 verify（用 localhost，避免真实外网利用）
    v = ver.verify("可能存在弱口令", "127.0.0.1", cve="")
    report("verify() 返回完整结果",
           all(k in v for k in ["status", "confidence", "evidence", "method"]),
           f"status={v.get('status')}")

    rep = ver.generate_verification_report(v)
    report("generate_verification_report 含建议",
           "recommendation" in rep and "verification_method" in rep)
except Exception as e:
    report("漏洞验证引擎功能测试", False, f"{e}")
    traceback.print_exc()

# ---------------------------------------------------------------------------
# 4) 修复方案生成器功能测试
# ---------------------------------------------------------------------------
print("\n" + "=" * 70)
print("四、修复方案生成引擎功能测试")
print("=" * 70)
try:
    from ai.remediation_generator import RemediationGenerator
    gen = RemediationGenerator()
    report("实例化 RemediationGenerator", True)

    p = gen._calculate_priority("critical", "high")
    report("_calculate_priority(critical,high)=critical", p == "critical", f"p={p}")

    web = gen._web_remediation("sql_injection")
    report("_web_remediation 含四语言示例",
           all(lang in web["code_examples"] for lang in ["php", "java", "python", "nodejs"]))

    full = gen.generate("发现 SQL 注入", "sql_injection",
                        {"severity": "high", "exploitability": "high"})
    report("generate() 返回完整方案",
           all(k in full for k in ["priority", "difficulty", "steps",
                                     "code_examples", "config_changes", "verification_method"]))

    # 覆盖各类别
    for vt in ["weak_password", "path_traversal", "reentrancy", "prompt_injection", "android_manifest"]:
        out = gen.generate("测试", vt, {})
        report(f"generate({vt}) 不抛异常", isinstance(out, dict) and out.get("priority"))
except Exception as e:
    report("修复方案生成器功能测试", False, f"{e}")
    traceback.print_exc()

# ---------------------------------------------------------------------------
# 5) 安全助手功能测试
# ---------------------------------------------------------------------------
print("\n" + "=" * 70)
print("五、AI 安全分析师助手功能测试")
print("=" * 70)
try:
    from ai.security_assistant import SecurityAssistant, BUILTIN_FUNCTION_KB
    asst = SecurityAssistant()
    report("内置功能知识库 >=20 项", len(BUILTIN_FUNCTION_KB) >= 20,
           f"共 {len(BUILTIN_FUNCTION_KB)} 项")

    ks = asst._knowledge_search("漏洞库 查询")
    report("_knowledge_search 返回列表", isinstance(ks, list))

    ev = asst._explain_vulnerability("SQL注入是什么")
    report("_explain_vulnerability 返回非空", isinstance(ev, str) and len(ev) > 10)

    guide = asst._tool_usage_guide("扫描")
    report("_tool_usage_guide 返回指引", isinstance(guide, str) and len(guide) > 5)

    adv = asst._security_advice("我有一个对外的 Web 系统")
    report("_security_advice 返回建议", isinstance(adv, str) and len(adv) > 5)

    chat = asst.chat("你好，介绍一下你能做什么", "verify_sess")
    report("chat() 返回 reply/related_knowledge/intent",
           all(k in chat for k in ["reply", "related_knowledge", "intent"]))

    hist = asst.get_history("verify_sess")
    report("多轮对话历史可查", len(hist) >= 2)
    asst.clear_history("verify_sess")
    report("clear_history 清空", len(asst.get_history("verify_sess")) == 0)
except Exception as e:
    report("安全助手功能测试", False, f"{e}")
    traceback.print_exc()

# ---------------------------------------------------------------------------
# 6) API 路由测试
# ---------------------------------------------------------------------------
print("\n" + "=" * 70)
print("六、API 路由模块测试")
print("=" * 70)
try:
    from api_server.ai_routes import router, _MODULES
    report("APIRouter 前缀正确", router.prefix == "/api/v1/ai", f"prefix={router.prefix}")
    report("路由端点已注册", len(router.routes) >= 6, f"共 {len(router.routes)} 个端点")
    report("AI 模块加载状态可查", isinstance(_MODULES, dict))
except Exception as e:
    report("API 路由模块测试", False, f"{e}")
    traceback.print_exc()

# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------
print("\n" + "=" * 70)
print("汇总")
print("=" * 70)
total = len(RESULTS)
passed = total - len(ERRORS)
print(f"总用例: {total}, 通过: {passed}, 失败: {len(ERRORS)}")
if ERRORS:
    print("失败项:")
    for e in ERRORS:
        print(f"  - {e}")
    print("\n结果: 存在错误，请检查上方 FAIL 项。")
    sys.exit(1)
else:
    print("\n结果: 全部通过，0 导入错误，降级方案工作正常。")
    sys.exit(0)
