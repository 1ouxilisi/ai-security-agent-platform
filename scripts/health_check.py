# -*- coding: utf-8 -*-
"""系统健康检查脚本（可独立运行）。

用法：
    python scripts/health_check.py

检查项：
    1. Python 版本（要求 3.8+）
    2. 关键依赖包是否可导入
    3. 数据库文件是否存在
    4. 安全工具是否在 PATH / 配置路径
    5. API 服务是否在线（/api/platform/health，超时 3s）
    6. 前端 HTML 文件是否存在、非空、含 UTF-8 meta
    7. 常见错误：核心模块导入、.env 配置、空白页（<500 字节）

输出彩色报告（绿 PASS / 红 FAIL / 黄 WARN），末尾给出修复建议。
退出码：全部通过=0，有警告=1，有错误=2。
"""
import importlib
import os
import shutil
import sys

# 项目根目录加入 sys.path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# ---------- 彩色输出（Windows 终端启用 ANSI） ----------
if os.name == "nt":
    os.system("")  # 开启 VT100 处理

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

_passed = 0
_failed = 0
_warned = 0
_suggestions = []


def pass_(msg):
    global _passed
    _passed += 1
    print(f"{GREEN}[PASS]{RESET} {msg}")


def fail(msg, suggest=""):
    global _failed
    _failed += 1
    print(f"{RED}[FAIL]{RESET} {msg}")
    if suggest:
        _suggestions.append(suggest)


def warn(msg, suggest=""):
    global _warned
    _warned += 1
    print(f"{YELLOW}[WARN]{RESET} {msg}")
    if suggest:
        _suggestions.append(suggest)


def header(title):
    print(f"\n{CYAN}== {title} =={RESET}")


# ---------- 1. Python 版本 ----------
def check_python():
    header("1. Python 版本")
    v = sys.version_info
    cur = f"{v.major}.{v.minor}.{v.micro}"
    if v >= (3, 8):
        pass_(f"Python {cur}（要求 >=3.8）")
    else:
        fail(f"Python 版本过低：{cur}，需要 3.8+", "升级 Python 到 3.8 及以上版本")


# ---------- 2. 依赖包 ----------
def check_deps():
    header("2. 关键依赖包")
    required = ["fastapi", "uvicorn", "pydantic", "dotenv", "requests", "starlette"]
    missing = []
    for pkg in required:
        try:
            importlib.import_module(pkg)
            pass_(f"依赖 {pkg} 可导入")
        except Exception as e:
            missing.append(pkg)
            fail(f"依赖 {pkg} 缺失/导入失败：{e}")
    if missing:
        _suggestions.append("运行 pip install " + " ".join(missing) + " 安装缺失依赖")


# ---------- 3. 数据库文件 ----------
def check_database():
    header("3. 数据库文件")
    db_path = os.path.join(ROOT, "data", "ai_hacking_agent.db")
    if os.path.exists(db_path) and os.path.getsize(db_path) > 0:
        pass_(f"数据库存在：data/ai_hacking_agent.db（{os.path.getsize(db_path)} 字节）")
    else:
        fail("数据库文件 data/ai_hacking_agent.db 缺失或为空",
             "首次启动服务会自动初始化数据库；或运行 python scripts/fix_common_issues.py")


# ---------- 4. 安全工具 ----------
def check_tools():
    header("4. 安全工具可用性")
    tools = ["nmap", "nuclei", "sqlmap", "nikto", "masscan", "msfconsole", "hashcat", "dirsearch"]
    avail = 0
    for t in tools:
        path = shutil.which(t)
        if path:
            avail += 1
            pass_(f"工具 {t} 可用：{path}")
        else:
            warn(f"工具 {t} 不在 PATH 中", None)
    if avail == 0:
        warn("未检测到任何安全工具，扫描功能将受限",
             "安装 nmap/nuclei 等工具并加入 PATH，或在 config/tools_config.json 中配置路径")
    else:
        print(f"  -> 可用工具 {avail}/{len(tools)}")


# ---------- 5. API 服务 ----------
def check_api():
    header("5. API 服务连通性")
    try:
        import requests
        try:
            r = requests.get("http://localhost:8000/api/platform/health", timeout=3)
            if r.status_code == 200:
                data = r.json()
                pass_(f"API 在线，状态：{data.get('status', 'unknown')}")
            else:
                warn(f"API 返回异常状态码：{r.status_code}", "检查 API 服务日志")
        except requests.exceptions.ConnectionError:
            warn("API 服务未运行（localhost:8000 连接失败）",
                 "启动服务：python -m uvicorn api_server.app:app --host 0.0.0.0 --port 8000")
        except Exception as e:
            warn(f"API 探测异常：{e}", "确认 API 服务已启动且端口为 8000")
    except Exception as e:
        warn(f"requests 不可用，跳过 API 探测：{e}")


# ---------- 6. 前端 HTML ----------
def check_html():
    header("6. 前端页面文件")
    api_dir = os.path.join(ROOT, "api_server")
    htmls = [f for f in os.listdir(api_dir) if f.endswith(".html")]
    if not htmls:
        fail("api_server 目录下未找到任何 HTML 文件")
        return
    bad = []
    for name in sorted(htmls):
        p = os.path.join(api_dir, name)
        size = os.path.getsize(p)
        try:
            with open(p, "r", encoding="utf-8") as f:
                head = f.read(4096)
        except Exception as e:
            fail(f"{name} 读取失败：{e}")
            bad.append(name)
            continue
        if size < 500:
            fail(f"{name} 可能是空白页（仅 {size} 字节）",
                 f"{name} 文件过小，疑似损坏，运行 python scripts/fix_common_issues.py")
            bad.append(name)
        elif "charset" not in head.lower() and "utf-8" not in head.lower():
            warn(f"{name} 未声明 UTF-8 编码 meta",
                 f"为 {name} 添加 <meta charset=\"UTF-8\">")
        else:
            pass_(f"{name} OK（{size} 字节）")


# ---------- 7. 常见错误 ----------
def check_common_errors():
    header("7. 常见错误排查")
    # 核心模块导入
    core_modules = [
        "api_server.app", "api_server.platform_routes", "utils.logger",
        "utils.database", "config.settings",
    ]
    for mod in core_modules:
        try:
            importlib.import_module(mod)
            pass_(f"核心模块 {mod} 可导入")
        except Exception as e:
            fail(f"核心模块 {mod} 导入失败：{e}",
                 f"检查 {mod} 相关依赖或语法错误")
    # .env 配置
    env_path = os.path.join(ROOT, ".env")
    if os.path.exists(env_path):
        pass_(".env 配置文件存在")
        # 关键配置项
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                content = f.read()
            for key in ["LLM_API_KEY", "DATABASE_URL"]:
                if key in content:
                    pass_(f"配置项 {key} 已设置")
                else:
                    warn(f"配置项 {key} 未在 .env 中找到",
                         f"在 .env 中补充 {key}=...")
        except Exception as e:
            warn(f".env 读取失败：{e}")
    else:
        warn(".env 不存在", "从 .env.example 复制：copy .env.example .env")


def main():
    print(f"{CYAN}AI 安全测试平台 · 系统健康检查{RESET}")
    print(f"项目根目录：{ROOT}")
    check_python()
    check_deps()
    check_database()
    check_tools()
    check_api()
    check_html()
    check_common_errors()

    header("汇总")
    print(f"  {GREEN}通过 {_passed}{RESET}  "
          f"{YELLOW}警告 {_warned}{RESET}  "
          f"{RED}失败 {_failed}{RESET}")

    if _suggestions:
        print(f"\n{CYAN}== 修复建议 =={RESET}")
        seen = set()
        for s in _suggestions:
            if s and s not in seen:
                print(f"  - {s}")
                seen.add(s)

    if _failed > 0:
        code = 2
    elif _warned > 0:
        code = 1
    else:
        code = 0
    print(f"\n退出码：{code}")
    return code


if __name__ == "__main__":
    sys.exit(main())
