# -*- coding: utf-8 -*-
"""AI Hacking Agent 全面体检脚本 v2.0"""
import os, sys, ast, re, json, importlib, traceback, glob
from pathlib import Path
from collections import defaultdict
from datetime import datetime

PROJECT_ROOT = Path(r"E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent")
sys.path.insert(0, str(PROJECT_ROOT))

REPORT_DIR = PROJECT_ROOT / "reports"
REPORT_DIR.mkdir(exist_ok=True)
REPORT_JSON = REPORT_DIR / "health_check_20260916.json"

results = {
    "check_time": datetime.now().isoformat(),
    "project_root": str(PROJECT_ROOT),
    "summary": {},
    "module_import": {"passed": [], "failed": [], "total": 0},
    "api_routes": {"total": 0, "duplicates": [], "prefix_conflicts": [], "errors": []},
    "frontend_pages": {"existing": [], "missing": [], "js_errors": []},
    "database": {"files": [], "missing": [], "errors": []},
    "config_files": {"existing": [], "missing": [], "issues": []},
    "code_quality": {"total_py": 0, "syntax_errors": [], "warnings": []},
    "security": {"hardcoded_secrets": [], "vulnerabilities": []},
    "dependencies": {"installed": [], "missing": [], "optional_missing": []},
    "fixes_applied": [],
}

# ============================================================
# 1. 模块导入检查
# ============================================================
print("=" * 70)
print("【1/8】模块导入检查")
print("=" * 70)

CORE_MODULE_DIRS = [
    "advanced_threat", "cloud_native_security", "security_metrics", "globalization",
    "red_blue_team", "soar_deep", "data_security_deep", "developer_ecosystem",
    "security_llm", "devsecops_deep", "soc_deep", "security_training_deep",
    "security_kg", "fuzzing_platform", "binary_reverse", "web3_security",
    "real_tools_deep", "real_validation", "performance_deep", "ux_docs_deep",
    "data_lake_deep", "mobile_security_deep", "api_security_lifecycle", "emerging_comm_security",
    # 其他常见模块
    "soc", "vuln_management", "monitoring", "ai", "saas", "hudong",
    "red_team", "blue_team", "purple_team", "compliance",
    "tools", "scanners", "utils", "models", "schemas",
    "api_server", "auth", "core", "services", "repositories",
]

def check_module_imports():
    failed = []
    passed = []
    total = 0
    
    for dir_name in CORE_MODULE_DIRS:
        dir_path = PROJECT_ROOT / dir_name
        if not dir_path.exists():
            continue
        if not dir_path.is_dir():
            continue
        
        # 找所有.py文件（非__init__.py，非_test）
        py_files = list(dir_path.glob("*.py"))
        for py_file in py_files:
            if py_file.name.startswith("_") and py_file.name != "__init__.py":
                continue
            if "test" in py_file.name.lower():
                continue
            
            rel_path = py_file.relative_to(PROJECT_ROOT)
            mod_name = str(rel_path).replace("\\", "/").replace("/", ".")
            if mod_name.endswith(".py"):
                mod_name = mod_name[:-3]
            if mod_name.endswith(".__init__"):
                mod_name = mod_name[:-9]
            
            total += 1
            try:
                importlib.import_module(mod_name)
                passed.append(mod_name)
            except Exception as e:
                err_type = type(e).__name__
                err_msg = str(e)[:200]
                failed.append({"module": mod_name, "error": err_type, "message": err_msg})
    
    results["module_import"]["total"] = total
    results["module_import"]["passed"] = [f"  [OK] {m}" for m in passed[:50]]
    results["module_import"]["failed"] = failed
    results["module_import"]["passed_count"] = len(passed)
    results["module_import"]["failed_count"] = len(failed)
    
    print(f"  总计: {total} 个模块")
    print(f"  通过: {len(passed)}")
    print(f"  失败: {len(failed)}")
    if failed:
        print("  失败详情:")
        for f in failed[:20]:
            print(f"    - {f['module']}: {f['error']}: {f['message'][:80]}")

check_module_imports()

# ============================================================
# 2. 代码质量检查 - py_compile所有.py文件
# ============================================================
print("\n" + "=" * 70)
print("【2/8】代码质量检查 - 语法检查")
print("=" * 70)

def check_code_quality():
    syntax_errors = []
    total_py = 0
    
    # 遍历所有.py文件（排除虚拟环境、缓存、node_modules等）
    exclude_dirs = {".venv", "venv", "__pycache__", "node_modules", ".git", 
                    "data", "logs", "uploads", "temp", "tmp", "backups"}
    
    for root, dirs, files in os.walk(PROJECT_ROOT):
        # 排除目录
        dirs[:] = [d for d in dirs if d not in exclude_dirs and not d.startswith(".")]
        
        for f in files:
            if not f.endswith(".py"):
                continue
            if f.startswith("test_") or f.endswith("_test.py"):
                continue
            
            filepath = Path(root) / f
            rel_path = str(filepath.relative_to(PROJECT_ROOT))
            total_py += 1
            
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                    source = fh.read()
                compile(source, str(filepath), "exec")
            except SyntaxError as e:
                syntax_errors.append({
                    "file": rel_path,
                    "line": e.lineno,
                    "error": str(e.msg),
                    "offset": e.offset
                })
            except Exception as e:
                syntax_errors.append({
                    "file": rel_path,
                    "line": 0,
                    "error": f"{type(e).__name__}: {str(e)[:100]}",
                    "offset": 0
                })
    
    results["code_quality"]["total_py"] = total_py
    results["code_quality"]["syntax_errors"] = syntax_errors
    
    print(f"  总.py文件数: {total_py}")
    print(f"  语法错误: {len(syntax_errors)}")
    if syntax_errors:
        for e in syntax_errors[:10]:
            print(f"    - {e['file']}:{e['line']} - {e['error']}")

check_code_quality()

# ============================================================
# 3. 前端页面检查
# ============================================================
print("\n" + "=" * 70)
print("【3/8】前端页面检查")
print("=" * 70)

def check_frontend():
    api_server_dir = PROJECT_ROOT / "api_server"
    html_files = list(api_server_dir.glob("*.html")) if api_server_dir.exists() else []
    
    existing = []
    missing = []
    js_errors = []
    
    for html_file in html_files:
        name = html_file.name
        size = html_file.stat().st_size
        existing.append({"name": name, "size": size})
        
        # 检查基本结构
        try:
            with open(html_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            issues = []
            if "<script" not in content.lower():
                issues.append("缺少script标签")
            if "<html" not in content.lower():
                issues.append("缺少html标签")
            if len(content) < 5000:
                issues.append(f"文件过小({size}字节)")
            
            if issues:
                js_errors.append({"file": name, "issues": issues})
        except Exception as e:
            js_errors.append({"file": name, "issues": [f"读取失败: {str(e)[:50]}"]})
    
    results["frontend_pages"]["existing"] = existing
    results["frontend_pages"]["missing"] = missing
    results["frontend_pages"]["js_errors"] = js_errors
    results["frontend_pages"]["total"] = len(existing)
    results["frontend_pages"]["issues_count"] = len(js_errors)
    
    print(f"  HTML文件总数: {len(existing)}")
    print(f"  有问题的页面: {len(js_errors)}")
    if js_errors:
        for e in js_errors[:10]:
            print(f"    - {e['file']}: {e['issues']}")

check_frontend()

# ============================================================
# 4. 数据库检查
# ============================================================
print("\n" + "=" * 70)
print("【4/8】数据库检查")
print("=" * 70)

def check_database():
    data_dir = PROJECT_ROOT / "data"
    db_files = []
    errors = []
    
    if data_dir.exists():
        for ext in ["*.db", "*.sqlite", "*.sqlite3"]:
            db_files.extend(data_dir.glob(ext))
    
    results["database"]["files"] = [f.name for f in db_files]
    results["database"]["errors"] = errors
    
    print(f"  数据库文件数: {len(db_files)}")
    for f in db_files:
        size = f.stat().st_size
        print(f"    - {f.name}: {size/1024:.1f} KB")

check_database()

# ============================================================
# 5. 配置文件检查
# ============================================================
print("\n" + "=" * 70)
print("【5/8】配置文件检查")
print("=" * 70)

def check_config():
    config_files = [
        ".env", "config.yaml", "config.yml", "requirements.txt",
        "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
        "pyproject.toml", "setup.py", "setup.cfg", "pytest.ini",
        ".gitignore", "README.md",
    ]
    
    existing = []
    missing = []
    issues = []
    
    for cfg in config_files:
        path = PROJECT_ROOT / cfg
        if path.exists():
            size = path.stat().st_size
            existing.append({"name": cfg, "size": size})
            
            # 检查requirements.txt
            if cfg == "requirements.txt":
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        deps = [l.strip() for l in f.readlines() if l.strip() and not l.startswith("#")]
                    print(f"    requirements.txt: {len(deps)} 个依赖")
                except Exception as e:
                    issues.append(f"requirements.txt读取失败: {e}")
        else:
            missing.append(cfg)
    
    results["config_files"]["existing"] = existing
    results["config_files"]["missing"] = missing
    results["config_files"]["issues"] = issues
    
    print(f"  存在: {len(existing)} 个")
    print(f"  缺失: {len(missing)} 个")
    if missing:
        for m in missing:
            print(f"    - {m}")

check_config()

# ============================================================
# 6. 安全问题检查 - 硬编码密钥
# ============================================================
print("\n" + "=" * 70)
print("【6/8】安全问题检查 - 硬编码密钥/密码")
print("=" * 70)

def check_security():
    # 常见密钥模式
    patterns = [
        (r'(?:api_key|apikey|API_KEY)\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "API Key硬编码"),
        (r'(?:secret|SECRET)\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "Secret硬编码"),
        (r'(?:password|PASSWORD|passwd)\s*=\s*["\']([^"\']{6,})["\']', "密码硬编码"),
        (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', "私钥硬编码"),
        (r'sk_[a-zA-Z0-9]{20,}', "Stripe/支付密钥"),
        (r'ghp_[a-zA-Z0-9]{30,}', "GitHub Token"),
        (r'AKIA[A-Z0-9]{16}', "AWS Access Key"),
        (r'(?:token|TOKEN)\s*=\s*["\']([a-zA-Z0-9_\-\.]{30,})["\']', "Token硬编码"),
    ]
    
    exclude_dirs = {".venv", "venv", "__pycache__", "node_modules", ".git", 
                    "data", "logs", "uploads", "reports", "docs"}
    
    findings = []
    count = 0
    
    for root, dirs, files in os.walk(PROJECT_ROOT):
        dirs[:] = [d for d in dirs if d not in exclude_dirs and not d.startswith(".")]
        
        for f in files:
            if not f.endswith((".py", ".js", ".html", ".yaml", ".yml", ".json", ".env")):
                continue
            if "test" in f.lower() or "example" in f.lower():
                continue
            
            filepath = Path(root) / f
            rel_path = str(filepath.relative_to(PROJECT_ROOT))
            
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
                
                for pattern, desc in patterns:
                    matches = re.finditer(pattern, content)
                    for m in matches:
                        line_num = content[:m.start()].count("\n") + 1
                        matched_text = m.group(0)[:60]
                        findings.append({
                            "file": rel_path,
                            "line": line_num,
                            "type": desc,
                            "match": matched_text
                        })
                        count += 1
            except:
                pass
    
    results["security"]["hardcoded_secrets"] = findings[:50]  # 只记录前50个
    results["security"]["total_findings"] = count
    
    print(f"  硬编码密钥/密码发现: {count} 处")
    if findings:
        for f in findings[:15]:
            print(f"    - {f['file']}:{f['line']} [{f['type']}] {f['match'][:40]}...")

check_security()

# ============================================================
# 7. 依赖检查
# ============================================================
print("\n" + "=" * 70)
print("【7/8】依赖检查")
print("=" * 70)

def check_deps():
    # 常见依赖列表
    common_deps = [
        "fastapi", "uvicorn", "pydantic", "pydantic_settings",
        "sqlalchemy", "pymysql", "redis", "httpx", "requests",
        "numpy", "pandas", "sklearn", "matplotlib",
        "jinja2", "python-multipart", "python-jose", "passlib",
        "python-dotenv", "yaml", "aiofiles", "websockets",
        "celery", "pika", "kafka", "elasticsearch",
        "pillow", "openpyxl", "python-docx", "reportlab",
        "cryptography", "jwt", "bcrypt",
    ]
    
    installed = []
    missing = []
    
    for dep in common_deps:
        try:
            importlib.import_module(dep)
            installed.append(dep)
        except ImportError:
            missing.append(dep)
    
    results["dependencies"]["installed"] = installed
    results["dependencies"]["missing"] = missing
    
    print(f"  已安装: {len(installed)} 个")
    print(f"  缺失: {len(missing)} 个")
    if missing:
        print(f"    缺失列表: {', '.join(missing)}")

check_deps()

# ============================================================
# 8. API路由检查
# ============================================================
print("\n" + "=" * 70)
print("【8/8】API路由检查")
print("=" * 70)

def check_api_routes():
    try:
        for mod in list(sys.modules.keys()):
            if mod.startswith("api_server") or mod.startswith("data_lake") or mod.startswith("mobile_security") or mod.startswith("api_security") or mod.startswith("emerging_comm"):
                del sys.modules[mod]
        
        from api_server.app import app
        routes = getattr(app, "routes", [])
        
        # 统计
        api_routes = []
        page_routes = []
        path_counts = defaultdict(int)
        
        for r in routes:
            path = getattr(r, "path", "")
            methods = getattr(r, "methods", set())
            name = getattr(r, "name", "")
            
            if path.startswith("/api/"):
                api_routes.append({"path": path, "methods": list(methods) if methods else [], "name": name})
                path_counts[path] += 1
            else:
                page_routes.append({"path": path, "methods": list(methods) if methods else [], "name": name})
        
        # 重复路由
        duplicates = {p: c for p, c in path_counts.items() if c > 1}
        
        results["api_routes"]["total"] = len(api_routes)
        results["api_routes"]["page_count"] = len(page_routes)
        results["api_routes"]["duplicates"] = [{"path": p, "count": c} for p, c in duplicates.items()]
        results["api_routes"]["total_routes"] = len(routes)
        
        print(f"  总路由数: {len(routes)}")
        print(f"  API路由数: {len(api_routes)}")
        print(f"  页面路由数: {len(page_routes)}")
        print(f"  重复路由: {len(duplicates)}")
        if duplicates:
            for p, c in list(duplicates.items())[:10]:
                print(f"    - {p}: {c}次")
                
    except Exception as e:
        results["api_routes"]["errors"].append(str(e))
        print(f"  检查失败: {e}")

check_api_routes()

# ============================================================
# 汇总
# ============================================================
print("\n" + "=" * 70)
print("【体检汇总】")
print("=" * 70)

summary = {
    "module_import": {"total": results["module_import"]["total"], "passed": results["module_import"]["passed_count"], "failed": results["module_import"]["failed_count"]},
    "code_quality": {"total_py": results["code_quality"]["total_py"], "syntax_errors": len(results["code_quality"]["syntax_errors"])},
    "frontend_pages": {"total": results["frontend_pages"]["total"], "issues": results["frontend_pages"]["issues_count"]},
    "database": {"files": len(results["database"]["files"])},
    "config_files": {"existing": len(results["config_files"]["existing"]), "missing": len(results["config_files"]["missing"])},
    "security": {"hardcoded_secrets": results["security"]["total_findings"]},
    "dependencies": {"installed": len(results["dependencies"]["installed"]), "missing": len(results["dependencies"]["missing"])},
    "api_routes": {"total": results["api_routes"].get("total_routes", 0), "api": results["api_routes"].get("total", 0), "duplicates": len(results["api_routes"].get("duplicates", []))},
}

results["summary"] = summary

for k, v in summary.items():
    status = "✅" if not (isinstance(v, dict) and v.get("failed", 0) > 0) else "❌"
    print(f"  {status} {k}: {v}")

# 保存JSON报告
with open(REPORT_JSON, "w", encoding="utf-8") as f:
    json.dump(results, f, ensure_ascii=False, indent=2, default=str)

print(f"\n  JSON报告已保存: {REPORT_JSON}")
print(f"  体检完成!")
