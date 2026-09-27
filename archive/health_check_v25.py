# -*- coding: utf-8 -*-
"""第25轮升级后全面体检检查脚本"""
import os, sys, importlib, ast, glob, json
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

def check_modules_import():
    """检查所有模块导入"""
    print("\n" + "="*60)
    print("【1/8】模块导入检查")
    print("="*60)
    
    # 扫描所有包目录
    packages = []
    for item in os.listdir(PROJECT_ROOT):
        item_path = os.path.join(PROJECT_ROOT, item)
        if os.path.isdir(item_path) and os.path.exists(os.path.join(item_path, "__init__.py")):
            packages.append(item)
    
    # 排除不需要检查的目录
    exclude = ["data", "logs", "node_modules", ".git", "__pycache__", "venv", ".venv"]
    packages = [p for p in packages if p not in exclude]
    
    total = 0
    passed = 0
    failed = []
    
    for pkg in sorted(packages):
        # 扫描包内所有.py文件
        py_files = glob.glob(os.path.join(PROJECT_ROOT, pkg, "**", "*.py"), recursive=True)
        for py_file in py_files:
            rel_path = os.path.relpath(py_file, PROJECT_ROOT)
            mod_name = rel_path.replace(os.sep, ".").replace(".py", "")
            if mod_name.endswith(".__init__"):
                mod_name = mod_name[:-9]
            
            total += 1
            try:
                importlib.import_module(mod_name)
                passed += 1
            except Exception as e:
                failed.append((mod_name, str(e)))
    
    # 检查api_server下的路由文件
    route_files = glob.glob(os.path.join(PROJECT_ROOT, "api_server", "*_routes.py"))
    for route_file in route_files:
        mod_name = "api_server." + os.path.basename(route_file).replace(".py", "")
        total += 1
        try:
            importlib.import_module(mod_name)
            passed += 1
        except Exception as e:
            failed.append((mod_name, str(e)))
    
    print(f"  检查模块总数: {total}")
    print(f"  导入成功: {passed}")
    print(f"  导入失败: {len(failed)}")
    if failed:
        print("\n  失败模块列表:")
        for mod, err in failed[:20]:
            print(f"    - {mod}: {err[:100]}")
        if len(failed) > 20:
            print(f"    ... 还有 {len(failed)-20} 个失败模块")
    
    return len(failed) == 0, total, passed, len(failed)


def check_api_routes():
    """检查所有API路由"""
    print("\n" + "="*60)
    print("【2/8】API路由检查")
    print("="*60)
    
    # 扫描所有路由文件
    route_files = glob.glob(os.path.join(PROJECT_ROOT, "api_server", "*_routes.py"))
    total_routes = 0
    route_details = []
    
    for route_file in sorted(route_files):
        mod_name = "api_server." + os.path.basename(route_file).replace(".py", "")
        try:
            mod = importlib.import_module(mod_name)
            router = getattr(mod, "router", None)
            if router:
                routes = getattr(router, "routes", [])
                cnt = len(routes)
                total_routes += cnt
                route_details.append((mod_name, cnt))
        except Exception as e:
            route_details.append((mod_name, f"ERROR: {str(e)[:50]}"))
    
    print(f"  路由文件总数: {len(route_files)}")
    print(f"  API端点总数: {total_routes}")
    print("\n  各路由文件端点数:")
    for name, cnt in route_details:
        if isinstance(cnt, int):
            print(f"    {name}: {cnt} 个端点")
        else:
            print(f"    {name}: {cnt}")
    
    return True, total_routes


def check_frontend_pages():
    """检查所有前端页面"""
    print("\n" + "="*60)
    print("【3/8】前端页面检查")
    print("="*60)
    
    html_files = glob.glob(os.path.join(PROJECT_ROOT, "api_server", "*_console.html"))
    html_files += glob.glob(os.path.join(PROJECT_ROOT, "api_server", "*_console*.html"))
    
    total = 0
    valid = 0
    invalid = []
    total_size = 0
    
    for html_file in sorted(html_files):
        total += 1
        try:
            with open(html_file, "r", encoding="utf-8") as f:
                content = f.read()
            size = len(content)
            total_size += size
            
            has_html = "<html" in content.lower()
            has_script = "<script" in content.lower()
            has_css = "<style" in content.lower() or "class=" in content
            
            if has_html and has_script and size > 5000:
                valid += 1
            else:
                invalid.append((os.path.basename(html_file), f"size={size}, html={has_html}, script={has_script}"))
        except Exception as e:
            invalid.append((os.path.basename(html_file), str(e)))
    
    print(f"  前端页面总数: {total}")
    print(f"  有效页面数: {valid}")
    print(f"  无效页面数: {len(invalid)}")
    print(f"  总大小: {total_size/1024:.1f} KB")
    
    if invalid:
        print("\n  无效页面列表:")
        for name, reason in invalid:
            print(f"    - {name}: {reason}")
    
    return len(invalid) == 0, total, valid


def check_databases():
    """检查所有数据库"""
    print("\n" + "="*60)
    print("【4/8】数据库检查")
    print("="*60)
    
    db_files = glob.glob(os.path.join(PROJECT_ROOT, "data", "*.db"))
    db_files += glob.glob(os.path.join(PROJECT_ROOT, "data", "*.db3"))
    db_files += glob.glob(os.path.join(PROJECT_ROOT, "data", "*.sqlite"))
    db_files += glob.glob(os.path.join(PROJECT_ROOT, "data", "*.sqlite3"))
    
    total = 0
    valid = 0
    total_size = 0
    db_details = []
    
    for db_file in sorted(db_files):
        total += 1
        size = os.path.getsize(db_file)
        total_size += size
        
        try:
            import sqlite3
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            table_count = len(tables)
            
            # 检查每个表的记录数
            total_records = 0
            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM '{table[0]}'")
                    total_records += cursor.fetchone()[0]
                except:
                    pass
            
            conn.close()
            valid += 1
            db_details.append((os.path.basename(db_file), size, table_count, total_records))
        except Exception as e:
            db_details.append((os.path.basename(db_file), size, "ERROR", str(e)[:50]))
    
    print(f"  数据库文件总数: {total}")
    print(f"  有效数据库数: {valid}")
    print(f"  总大小: {total_size/1024/1024:.2f} MB")
    
    if db_details:
        print("\n  数据库详情:")
        for name, size, tables, records in db_details:
            if isinstance(tables, int):
                print(f"    - {name}: {size/1024:.1f}KB, {tables}表, {records}条记录")
            else:
                print(f"    - {name}: {size/1024:.1f}KB, {tables}: {records}")
    
    return True, total, valid


def check_config_files():
    """检查所有配置文件"""
    print("\n" + "="*60)
    print("【5/8】配置文件检查")
    print("="*60)
    
    config_patterns = ["*.yaml", "*.yml", "*.json", "*.ini", "*.cfg", "*.conf", "*.env", "*.toml"]
    config_files = []
    for pattern in config_patterns:
        config_files += glob.glob(os.path.join(PROJECT_ROOT, pattern))
        config_files += glob.glob(os.path.join(PROJECT_ROOT, "config", pattern))
        config_files += glob.glob(os.path.join(PROJECT_ROOT, "api_server", pattern))
    
    # 去重
    config_files = list(set(config_files))
    
    total = 0
    valid = 0
    invalid = []
    
    for config_file in sorted(config_files):
        # 跳过node_modules和venv
        if "node_modules" in config_file or "venv" in config_file or ".git" in config_file:
            continue
        
        total += 1
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                content = f.read()
            
            ext = os.path.splitext(config_file)[1].lower()
            if ext in [".yaml", ".yml"]:
                try:
                    import yaml
                    yaml.safe_load(content)
                    valid += 1
                except:
                    invalid.append((os.path.basename(config_file), "YAML解析失败"))
            elif ext == ".json":
                try:
                    json.loads(content)
                    valid += 1
                except:
                    invalid.append((os.path.basename(config_file), "JSON解析失败"))
            else:
                valid += 1  # 其他格式不做严格解析
        except Exception as e:
            invalid.append((os.path.basename(config_file), str(e)[:50]))
    
    print(f"  配置文件总数: {total}")
    print(f"  有效配置数: {valid}")
    print(f"  无效配置数: {len(invalid)}")
    
    if invalid:
        print("\n  无效配置列表:")
        for name, reason in invalid:
            print(f"    - {name}: {reason}")
    
    return len(invalid) == 0, total, valid


def check_code_quality():
    """检查代码质量"""
    print("\n" + "="*60)
    print("【6/8】代码质量检查")
    print("="*60)
    
    # 扫描所有Python文件
    py_files = glob.glob(os.path.join(PROJECT_ROOT, "**", "*.py"), recursive=True)
    # 排除不需要检查的目录
    py_files = [f for f in py_files if "node_modules" not in f and "venv" not in f and ".git" not in f and "__pycache__" not in f]
    
    total_files = len(py_files)
    total_lines = 0
    syntax_errors = []
    future_imports = 0
    try_imports = 0
    clean_functions = 0
    
    for py_file in py_files:
        try:
            with open(py_file, "r", encoding="utf-8") as f:
                content = f.read()
            lines = content.count("\n") + 1
            total_lines += lines
            
            # 语法检查
            try:
                ast.parse(content)
            except SyntaxError as e:
                syntax_errors.append((os.path.relpath(py_file, PROJECT_ROOT), str(e)))
            
            # 检查from __future__ import
            if "from __future__ import" in content:
                future_imports += 1
            
            # 检查try-import
            if "try:" in content and "import" in content:
                try_imports += 1
            
            # 检查_clean函数
            if "_clean" in content or "def _clean" in content:
                clean_functions += 1
                
        except Exception as e:
            syntax_errors.append((os.path.relpath(py_file, PROJECT_ROOT), str(e)))
    
    print(f"  Python文件总数: {total_files}")
    print(f"  总代码行数: {total_lines}")
    print(f"  语法错误数: {len(syntax_errors)}")
    print(f"  含from __future__ import的文件: {future_imports} ({future_imports/total_files*100:.1f}%)")
    print(f"  含try-import的文件: {try_imports} ({try_imports/total_files*100:.1f}%)")
    print(f"  含_clean函数的文件: {clean_functions} ({clean_functions/total_files*100:.1f}%)")
    
    if syntax_errors:
        print("\n  语法错误列表:")
        for name, err in syntax_errors[:10]:
            print(f"    - {name}: {err[:100]}")
        if len(syntax_errors) > 10:
            print(f"    ... 还有 {len(syntax_errors)-10} 个语法错误")
    
    return len(syntax_errors) == 0, total_files, total_lines, len(syntax_errors)


def check_security_issues():
    """检查安全问题"""
    print("\n" + "="*60)
    print("【7/8】安全问题检查")
    print("="*60)
    
    # 扫描常见安全问题
    py_files = glob.glob(os.path.join(PROJECT_ROOT, "**", "*.py"), recursive=True)
    py_files = [f for f in py_files if "node_modules" not in f and "venv" not in f and ".git" not in f and "__pycache__" not in f]
    
    issues = {
        "hardcoded_passwords": [],
        "hardcoded_keys": [],
        "sql_injection_risk": [],
        "unsafe_eval": [],
        "weak_crypto": [],
        "debug_mode": [],
        "insecure_deserialization": [],
    }
    
    for py_file in py_files:
        try:
            with open(py_file, "r", encoding="utf-8") as f:
                content = f.read()
            rel_path = os.path.relpath(py_file, PROJECT_ROOT)
            
            # 硬编码密码
            if "password" in content.lower() and ("=" in content or ":" in content):
                for line in content.split("\n"):
                    if "password" in line.lower() and ("=" in line or ":" in line) and not line.strip().startswith("#"):
                        if "get" not in line.lower() and "os.environ" not in line and "config" not in line.lower():
                            issues["hardcoded_passwords"].append((rel_path, line.strip()[:80]))
                            break
            
            # 硬编码密钥
            if "api_key" in content.lower() or "secret_key" in content.lower() or "private_key" in content.lower():
                for line in content.split("\n"):
                    if ("api_key" in line.lower() or "secret_key" in line.lower() or "private_key" in line.lower()) and "=" in line:
                        if not line.strip().startswith("#") and "os.environ" not in line and "getenv" not in line:
                            issues["hardcoded_keys"].append((rel_path, line.strip()[:80]))
                            break
            
            # SQL注入风险
            if "execute(" in content and "%" in content and "SELECT" in content.upper():
                for line in content.split("\n"):
                    if "execute(" in line and "%" in line and not line.strip().startswith("#"):
                        issues["sql_injection_risk"].append((rel_path, line.strip()[:80]))
                        break
            
            # 不安全eval
            if "eval(" in content:
                for line in content.split("\n"):
                    if "eval(" in line and not line.strip().startswith("#"):
                        issues["unsafe_eval"].append((rel_path, line.strip()[:80]))
                        break
            
            # 弱加密
            if "md5(" in content or "sha1(" in content:
                for line in content.split("\n"):
                    if ("md5(" in line or "sha1(" in line) and not line.strip().startswith("#"):
                        issues["weak_crypto"].append((rel_path, line.strip()[:80]))
                        break
            
            # 调试模式
            if "debug=True" in content or "debug = True" in content:
                for line in content.split("\n"):
                    if "debug=True" in line or "debug = True" in line:
                        if not line.strip().startswith("#"):
                            issues["debug_mode"].append((rel_path, line.strip()[:80]))
                            break
            
            # 不安全反序列化
            if "pickle.loads" in content or "pickle.load(" in content:
                for line in content.split("\n"):
                    if "pickle.loads" in line or "pickle.load(" in line:
                        if not line.strip().startswith("#"):
                            issues["insecure_deserialization"].append((rel_path, line.strip()[:80]))
                            break
        except:
            pass
    
    total_issues = sum(len(v) for v in issues.values())
    
    print(f"  安全问题总数: {total_issues}")
    for issue_type, issue_list in issues.items():
        print(f"    - {issue_type}: {len(issue_list)} 个")
    
    if total_issues > 0:
        print("\n  安全问题详情（前10个）:")
        count = 0
        for issue_type, issue_list in issues.items():
            for file, line in issue_list:
                if count < 10:
                    print(f"    [{issue_type}] {file}: {line}")
                    count += 1
    
    # 安全评分
    if total_issues == 0:
        security_score = 100
    elif total_issues < 5:
        security_score = 90
    elif total_issues < 20:
        security_score = 80
    elif total_issues < 50:
        security_score = 70
    else:
        security_score = 60
    
    print(f"\n  安全评分: {security_score}/100")
    
    return total_issues == 0, total_issues, security_score


def check_app_integration():
    """检查app.py集成"""
    print("\n" + "="*60)
    print("【8/8】app.py集成检查")
    print("="*60)
    
    try:
        # 清除缓存
        for mod in list(sys.modules.keys()):
            if mod.startswith("api_server") or mod.startswith("advanced_threat") or mod.startswith("cloud_native_security") or mod.startswith("security_metrics_deep") or mod.startswith("globalization"):
                del sys.modules[mod]
        
        from api_server.app import app
        routes = getattr(app, "routes", [])
        total_routes = len(routes)
        
        # 检查第25轮路由
        r25_prefixes = ["/api/v1/advanced-threat", "/api/v1/cloud-native-security", "/api/v1/security-metrics", "/api/v1/globalization"]
        r25_pages = ["/advanced-threat", "/cloud-native-security", "/security-metrics", "/globalization"]
        
        r25_routes_found = 0
        r25_pages_found = 0
        
        for prefix in r25_prefixes:
            found = any(prefix in getattr(r, "path", "") for r in routes)
            if found:
                r25_routes_found += 1
        
        for page in r25_pages:
            found = any(getattr(r, "path", "") == page for r in routes)
            if found:
                r25_pages_found += 1
        
        print(f"  app.py导入: 成功")
        print(f"  总路由数: {total_routes}")
        print(f"  第25轮API路由: {r25_routes_found}/4 已注册")
        print(f"  第25轮前端页面: {r25_pages_found}/4 已注册")
        
        # 检查所有轮次路由
        all_rounds = [
            ("第5轮", "/api/v1/ai"),
            ("第9轮SOC", "/api/v1/soc"),
            ("第11轮云安全", "/api/v1/cloud-security-v2"),
            ("第17轮威胁狩猎", "/api/v1/threat-hunt"),
            ("第20轮部署", "/api/v1/deploy"),
            ("第21轮License", "/api/v1/license-system"),
            ("第22轮Demo", "/api/v1/demo-mode"),
            ("第23轮AI智能", "/api/v1/ai-intelligence"),
            ("第24轮红蓝对抗", "/api/v1/red-blue-team"),
            ("第25轮UEBA", "/api/v1/advanced-threat"),
        ]
        
        print("\n  各轮次路由注册状态:")
        for round_name, prefix in all_rounds:
            found = any(prefix in getattr(r, "path", "") for r in routes)
            print(f"    {round_name}: {'✓' if found else '✗'}")
        
        return True, total_routes, r25_routes_found, r25_pages_found
    except Exception as e:
        print(f"  app.py导入失败: {e}")
        import traceback
        traceback.print_exc()
        return False, 0, 0, 0


def generate_health_report(results):
    """生成全面体检报告"""
    print("\n" + "="*60)
    print("全面体检报告")
    print("="*60)
    
    report = {
        "检查时间": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "项目名称": "AI Hacking Agent",
        "检查结果": {}
    }
    
    # 1. 模块导入
    mod_ok, mod_total, mod_passed, mod_failed = results[0]
    report["检查结果"]["模块导入"] = {
        "状态": "PASS" if mod_ok else "FAIL",
        "总数": mod_total,
        "成功": mod_passed,
        "失败": mod_failed,
        "成功率": f"{mod_passed/mod_total*100:.1f}%" if mod_total > 0 else "N/A"
    }
    
    # 2. API路由
    api_ok, api_total = results[1]
    report["检查结果"]["API路由"] = {
        "状态": "PASS",
        "端点总数": api_total
    }
    
    # 3. 前端页面
    page_ok, page_total, page_valid = results[2]
    report["检查结果"]["前端页面"] = {
        "状态": "PASS" if page_ok else "FAIL",
        "总数": page_total,
        "有效": page_valid,
        "有效率": f"{page_valid/page_total*100:.1f}%" if page_total > 0 else "N/A"
    }
    
    # 4. 数据库
    db_ok, db_total, db_valid = results[3]
    report["检查结果"]["数据库"] = {
        "状态": "PASS",
        "总数": db_total,
        "有效": db_valid
    }
    
    # 5. 配置文件
    config_ok, config_total, config_valid = results[4]
    report["检查结果"]["配置文件"] = {
        "状态": "PASS" if config_ok else "FAIL",
        "总数": config_total,
        "有效": config_valid
    }
    
    # 6. 代码质量
    code_ok, code_files, code_lines, code_errors = results[5]
    report["检查结果"]["代码质量"] = {
        "状态": "PASS" if code_ok else "FAIL",
        "Python文件数": code_files,
        "总代码行数": code_lines,
        "语法错误数": code_errors
    }
    
    # 7. 安全问题
    sec_ok, sec_total, sec_score = results[6]
    report["检查结果"]["安全问题"] = {
        "状态": "PASS" if sec_ok else "WARN",
        "问题总数": sec_total,
        "安全评分": f"{sec_score}/100"
    }
    
    # 8. app集成
    app_ok, app_routes, r25_routes, r25_pages = results[7]
    report["检查结果"]["app集成"] = {
        "状态": "PASS" if app_ok else "FAIL",
        "总路由数": app_routes,
        "第25轮API路由": f"{r25_routes}/4",
        "第25轮前端页面": f"{r25_pages}/4"
    }
    
    # 总体评分
    all_pass = all([mod_ok, api_ok, page_ok, db_ok, config_ok, code_ok, app_ok])
    overall_score = 0
    if mod_ok: overall_score += 15
    if api_ok: overall_score += 15
    if page_ok: overall_score += 10
    if db_ok: overall_score += 10
    if config_ok: overall_score += 10
    if code_ok: overall_score += 15
    if sec_ok: overall_score += 10
    else: overall_score += sec_score / 10
    if app_ok: overall_score += 15
    
    report["总体评分"] = f"{overall_score:.1f}/100"
    report["总体结果"] = "ALL PASS" if all_pass else "HAS ISSUES"
    
    # 打印报告
    print(f"\n  检查时间: {report['检查时间']}")
    print(f"  项目名称: {report['项目名称']}")
    print(f"\n  检查项详情:")
    for check_name, check_data in report["检查结果"].items():
        status = check_data["状态"]
        status_icon = "✓" if status == "PASS" else ("⚠" if status == "WARN" else "✗")
        print(f"    {status_icon} {check_name}: {status}")
        for k, v in check_data.items():
            if k != "状态":
                print(f"        {k}: {v}")
    
    print(f"\n  总体评分: {report['总体评分']}")
    print(f"  总体结果: {report['总体结果']}")
    
    # 保存报告
    report_path = os.path.join(PROJECT_ROOT, "HEALTH_CHECK_REPORT_v25.0.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# AI Hacking Agent 全面体检报告 v25.0\n\n")
        f.write(f"**检查时间**: {report['检查时间']}\n")
        f.write(f"**项目名称**: {report['项目名称']}\n")
        f.write(f"**总体评分**: {report['总体评分']}\n")
        f.write(f"**总体结果**: {report['总体结果']}\n\n")
        f.write("## 检查项详情\n\n")
        for check_name, check_data in report["检查结果"].items():
            f.write(f"### {check_name}\n\n")
            for k, v in check_data.items():
                f.write(f"- **{k}**: {v}\n")
            f.write("\n")
        f.write("## 总结\n\n")
        f.write(f"第25轮升级后全面体检完成，总体评分 **{report['总体评分']}**，总体结果 **{report['总体结果']}**。\n\n")
        f.write("### 核心指标\n\n")
        f.write(f"- API端点总数: **{api_total}**\n")
        f.write(f"- 总代码行数: **{code_lines}**\n")
        f.write(f"- 前端页面总数: **{page_total}**\n")
        f.write(f"- 模块导入成功率: **{mod_passed/mod_total*100:.1f}%**\n")
        f.write(f"- 语法错误数: **{code_errors}**\n")
        f.write(f"- 安全评分: **{sec_score}/100**\n")
    
    print(f"\n  体检报告已保存: {report_path}")
    
    return report


def main():
    print("="*60)
    print("AI Hacking Agent 第25轮升级后全面体检")
    print("="*60)
    
    results = []
    
    # 1. 模块导入检查
    results.append(check_modules_import())
    
    # 2. API路由检查
    results.append(check_api_routes())
    
    # 3. 前端页面检查
    results.append(check_frontend_pages())
    
    # 4. 数据库检查
    results.append(check_databases())
    
    # 5. 配置文件检查
    results.append(check_config_files())
    
    # 6. 代码质量检查
    results.append(check_code_quality())
    
    # 7. 安全问题检查
    results.append(check_security_issues())
    
    # 8. app集成检查
    results.append(check_app_integration())
    
    # 生成报告
    report = generate_health_report(results)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
