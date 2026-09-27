# -*- coding: utf-8 -*-
"""V2 统一平台控制台交付物验证脚本。

检查项：
    1. 三个交付文件是否存在
    2. HTML 基本结构（doctype/head/body/title/script/style）
    3. 关键功能标记（onboarding / command-palette / theme / lang / svg-chart）
    4. HTML 无外部 http(s) 资源引用（script/link/img/url()）
    5. ui_config.json 合法性 + 必需配置项 + 导航 >=10 项 + 步骤 >=5
    6. onboarding_routes 可导入 + 3 个端点已注册
    7. i18n 翻译键 >=50
    8. HTML 文件大小 < 80KB
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
HTML = os.path.join(ROOT, "api_server", "platform_console_v2.html")
ROUTES = os.path.join(ROOT, "api_server", "onboarding_routes.py")
CFG = os.path.join(ROOT, "config", "ui_config.json")

passed = 0
failed = 0


def check(name, ok, detail=""):
    global passed, failed
    tag = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
    line = "[%s] %s" % (tag, name)
    if detail:
        line += "  ->  " + detail
    print(line)


# ---------- 1. 文件存在性 ----------
for p in (HTML, ROUTES, CFG):
    check("文件存在: %s" % os.path.basename(p), os.path.exists(p), p)

# ---------- 2/3/4/7/8. HTML 内容检查 ----------
html = ""
if os.path.exists(HTML):
    with open(HTML, "r", encoding="utf-8") as f:
        html = f.read()

check("HTML DOCTYPE", "<!DOCTYPE HTML>" in html.upper())
check("HTML <head>/<body> 结构", "<head>" in html and "</body>" in html)
check("页面标题正确", "统一安全平台 V2" in html and "<title>" in html)
check("内联 <style>", "<style>" in html)
check("内联 <script>", "<script>" in html and "</script>" in html)
check("UTF-8 声明", 'charset="UTF-8"' in html or "charset=utf-8" in html.lower())

check("新手引导标记 (onboarding)", "onboarding" in html and "obSteps" in html and "onboarding_completed" in html)
check("引导遮罩/高亮框", 'id="ob-highlight"' in html and 'id="ob-pop"' in html and "ob-skip" in html)
check("引导从 API 加载步骤", "/api/v1/onboarding/steps" in html)
check("命令面板 Ctrl+K", "palette" in html and '"k"' in html.lower() or "'k'" in html or '==="k"' in html or "key===\"k\"" in html or "e.key===\"k\"" in html)
check("命令面板键盘导航", "ArrowDown" in html and "ArrowUp" in html and "Enter" in html and "Escape" in html)
check("命令列表 >=9 项", html.count('{id:"') >= 9)
check("CSS 变量主题切换", ":root" in html and '[data-theme="dark"]' in html and "ui_theme" in html)
check("主题色板 (bg #0f172a / #1e293b / #f8fafc)", "#0f172a" in html and "#1e293b" in html and "#f8fafc" in html)
check("多语言字典 zh/en", "I18N={" in html and "zh:{" in html and "en:{" in html and "ui_lang" in html)
# i18n 键计数：统计 zh 块内的顶层 key
zh_block = re.search(r"zh:\{(.*?)\}\s*,\s*en:\{", html, re.S)
zh_keys = 0
if zh_block:
    zh_keys = len(re.findall(r"[A-Za-z_][A-Za-z0-9_]*:", zh_block.group(1)))
check("i18n 翻译键 >=50", zh_keys >= 50, "实际 %d 键" % zh_keys)
check("SVG 折线图函数", "lineChartSVG" in html and "<path" in html)
check("SVG 环形图函数", "donutSVG" in html and "A" in html)
check("SVG 横向柱状图函数", "hBarSVG" in html and "rect" in html)
check("分析 API 调用", "/api/v1/analytics/summary" in html
      and "/api/v1/analytics/trends/vulnerabilities" in html
      and "/api/v1/analytics/distribution/severity" in html
      and "/api/v1/analytics/top/targets" in html)
check("报告 API 调用", "/api/v1/reporting/generate" in html
      and "/api/v1/reporting/formats" in html
      and "/api/v1/reporting/templates" in html)
check("fetch 超时处理 (AbortController)", "AbortController" in html and "abort" in html)
check("空状态提示文案", "empty_ana" in html and "暂无数据" in html)
check("响应式 <768px", "768" in html)
# 外部资源检查：script/link/img 标签不得出现 http
ext_script = re.findall(r'<script[^>]+src=["\']https?://', html, re.I)
ext_link = re.findall(r'<link[^>]+href=["\']https?://', html, re.I)
ext_img = re.findall(r'<img[^>]+src=["\']https?://', html, re.I)
css_url = re.findall(r'url\(["\']?https?://', html, re.I)
check("无外部 script/link/img/url() 引用", not (ext_script or ext_link or ext_img or css_url),
      "script=%d link=%d img=%d cssurl=%d" % (len(ext_script), len(ext_link), len(ext_img), len(css_url)))

# 文件大小
size = os.path.getsize(HTML) if os.path.exists(HTML) else 0
check("HTML 文件 < 80KB", size < 80 * 1024, "%.1f KB" % (size / 1024))

# ---------- 5. ui_config.json ----------
cfg = None
if os.path.exists(CFG):
    try:
        with open(CFG, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        check("ui_config.json 合法 JSON", True)
    except Exception as e:
        check("ui_config.json 合法 JSON", False, str(e))
if isinstance(cfg, dict):
    check("default_theme / default_language", cfg.get("default_theme") == "light" and cfg.get("default_language") == "zh")
    steps = cfg.get("onboarding_steps", [])
    check("onboarding_steps >=5 步", isinstance(steps, list) and len(steps) >= 5, "实际 %d 步" % len(steps))
    if steps:
        need = {"id", "title_zh", "title_en", "description_zh", "description_en", "target_selector", "position"}
        miss = need - set(steps[0].keys())
        check("每步含全部字段", not miss, "缺: %s" % miss if miss else "OK")
    nav = cfg.get("navigation", [])
    check("navigation >=10 项", isinstance(nav, list) and len(nav) >= 10, "实际 %d 项" % len(nav))
    if nav:
        need = {"id", "label_zh", "label_en", "icon", "path", "order"}
        miss = need - set(nav[0].keys())
        check("导航项含全部字段", not miss, "缺: %s" % miss if miss else "OK")
    sc = cfg.get("shortcuts", {})
    check("快捷键配置完整", all(k in sc for k in ("ctrl+k", "ctrl+n", "ctrl+r", "ctrl+d", "ctrl+/")),
          "keys=%s" % list(sc.keys()))

# ---------- 6. onboarding_routes 导入 ----------
sys.path.insert(0, ROOT)
try:
    from api_server.onboarding_routes import router  # noqa: E402
    check("onboarding_routes 导入成功", True)
    paths = {getattr(r, "path", "") for r in router.routes}
    check("路由前缀 /api/v1/onboarding", any("/api/v1/onboarding" in p for p in paths), str(paths))
    for sub in ("/status", "/complete", "/steps"):
        check("端点 GET/POST %s" % sub, any(p.endswith(sub) for p in paths), str(paths))
except Exception as e:
    check("onboarding_routes 导入成功", False, repr(e))

# ---------- 汇总 ----------
print("=" * 60)
print("总计: %d 通过, %d 失败" % (passed, failed))
print("HTML 文件大小: %s bytes (%.1f KB)" % (size, size / 1024))
sys.exit(0 if failed == 0 else 1)
