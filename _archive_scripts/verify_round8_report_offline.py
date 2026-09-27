#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI Hacking Agent 第8轮升级验证脚本
- 报告模板自定义 (template_engine / style_presets / template_manager增强 / routes / console)
- 离线模式 (rules_engine / ai_fallback / local_knowledge / routes)
"""
import os
import sys
import importlib

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

PASS, FAIL = "PASS", "FAIL"
results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{PASS if ok else FAIL}] {name} {('- ' + detail) if detail else ''}")


def count_routes(router):
    return len([r for r in router.routes])


def main():
    print("=" * 60)
    print("第8轮验证: 报告模板自定义 + 离线模式")
    print("=" * 60)

    # 1. 模块导入
    try:
        from reporting import template_engine
        check("导入 reporting.template_engine", True)
    except Exception as e:
        check("导入 reporting.template_engine", False, str(e)); return

    try:
        from reporting import style_presets
        check("导入 reporting.style_presets", True)
    except Exception as e:
        check("导入 reporting.style_presets", False, str(e))

    try:
        from reporting.template_manager import EnhancedTemplateManager, PRESET_TEMPLATES
        check("导入 reporting.template_manager(增强)", True, f"预定义模板{len(PRESET_TEMPLATES)}个")
    except Exception as e:
        check("导入 reporting.template_manager(增强)", False, str(e))

    # 2. template_engine 9章节 + 渲染
    eng = template_engine.ReportTemplateEngine()
    secs = eng.get_default_sections()
    check("template_engine 9个章节定义", len(secs) == 9, f"实际{len(secs)}")
    sample = {
        "project_name": "测试项目", "client_name": "测试客户",
        "analyst": "测试员", "risk_score": "7.0",
        "targets": ["https://example.com"],
        "vuln_list": [{"severity": "high", "name": "SQLi", "target": "x", "location": "y", "description": "d"}],
        "key_findings": ["发现SQL注入"],
    }
    rendered = eng.render_report({"sections": secs, "style_vars": {}}, sample)
    check("render_report 渲染完整报告", isinstance(rendered, dict) and len(rendered) >= 5,
          f"章节{len(rendered)}")
    check("封面渲染", "cover" in rendered and "测试项目" in rendered.get("cover", ""))
    check("目录渲染", "toc" in rendered and "目录" in rendered.get("toc", ""))

    # 3. style_presets 5个预设
    presets = style_presets.list_presets()
    check("style_presets 5个样式预设", len(presets) == 5, f"实际{len(presets)}")
    css = style_presets.generate_css(style_presets.get_preset("tech_blue")["style_vars"])
    check("generate_css 生成CSS", "0066CC" in css or "font-family" in css)

    # 4. EnhancedTemplateManager 功能
    etm = EnhancedTemplateManager()
    check("EnhancedTemplateManager 5预定义模板", len(etm.list_all_templates()) >= 5,
          f"{len(etm.list_all_templates())}")
    created = etm.create_template({"name": "测试模板", "description": "v"})
    check("create_template", "id" in created)
    exp = etm.export_template(created["id"])
    check("export_template", "测试模板" in exp)
    new_id = etm.import_template(exp)
    check("import_template", new_id != created["id"])
    prev = etm.preview_template("standard_report", sample)
    check("preview_template", "测试项目" in prev or "html" in prev.lower())
    etm.delete_template(created["id"])
    etm.delete_template(new_id)

    # 5. report_template_routes router 端点数
    try:
        from api_server.report_template_routes import router as rt_router
        n = count_routes(rt_router)
        check("report_template_routes router >=13端点", n >= 13, f"实际{n}")
    except Exception as e:
        check("导入 report_template_routes", False, str(e)); n = 0

    # 6. offline 模块
    try:
        from offline.rules_engine import RuleEngine, _rules
        engine = RuleEngine()
        check("导入 offline.rules_engine", True, f"规则{len(_rules)}条")
        cats = set(r["category"] for r in _rules.values())
        check("rules_engine >=15条规则覆盖10+类型", len(_rules) >= 15 and len(cats) >= 10,
              f"规则{len(_rules)} 类别{len(cats)}")
        # 测试一条规则命中
        test_resp = {"status_code": 500, "headers": {"Server": "Apache/2.4.29"},
                     "body": "You have an error in your SQL syntax; MySQL",
                     "response_time": 0.5, "content_length": 200}
        hits = engine.apply_rules(test_resp)
        check("apply_rules 命中SQL错误规则", any(h["rule_id"] == "sql_error_detection" for h in hits),
              f"命中{[h['rule_id'] for h in hits]}")
        st = engine.get_stats()
        check("规则统计 get_stats", "total_rules" in st)
    except Exception as e:
        check("offline.rules_engine", False, str(e))

    try:
        from offline.ai_fallback import AIFallbackManager
        fm = AIFallbackManager()
        fm.set_mode("local")
        check("ai_fallback 切local模式", fm.get_current_mode() == "local")
        fm.set_mode("ai")
        check("ai_fallback 切ai模式", fm.get_current_mode() == "ai")
        fm.set_mode("hybrid")
        check("ai_fallback 切hybrid模式", fm.get_current_mode() == "hybrid")
        res = fm.process_request({"body": "uid=0(root)"})
        check("process_request 处理请求", "source" in res, f"source={res.get('source')}")
        st = fm.get_status()
        check("get_status 完整状态", "current_mode" in st and "local_rules_count" in st)
    except Exception as e:
        check("offline.ai_fallback", False, str(e))

    try:
        from offline.local_knowledge import LocalKnowledge
        lk = LocalKnowledge()
        st = lk.get_stats()
        check("local_knowledge 20漏洞+15工具+10最佳实践",
              st["vulnerabilities"] >= 20 and st["tools"] >= 15 and st["best_practices"] >= 10,
              f"{st}")
        res = lk.search("SQL注入")
        check("knowledge.search 搜索", len(res) > 0, f"{len(res)}条")
    except Exception as e:
        check("offline.local_knowledge", False, str(e))

    # 7. offline_routes router 端点数
    try:
        from api_server.offline_routes import router as off_router
        n2 = count_routes(off_router)
        check("offline_routes router >=8端点", n2 >= 8, f"实际{n2}")
    except Exception as e:
        check("导入 offline_routes", False, str(e)); n2 = 0

    # 8. HTML 非空
    html_path = os.path.join(ROOT, "api_server", "report_template_console.html")
    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()
    check("report_template_console.html 非空且结构完整",
          len(html) > 1000 and "<html" in html.lower() and "</html>" in html.lower()
          and "报告模板编辑器" in html, f"{len(html)}字符")

    # 汇总
    print("=" * 60)
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print(f"验证结果: {passed}/{total} 通过")
    print(f"report_template_routes 端点数: {n}")
    print(f"offline_routes 端点数: {n2}")
    print("=" * 60)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
