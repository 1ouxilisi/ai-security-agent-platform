#!/usr/bin/env python3
"""AI Hacking Agent 一键安装配置向导。

用法: python setup_wizard.py
"""
import os
import sys
import shutil
import subprocess
import secrets


def print_banner():
    print("=" * 60)
    print("  AI Hacking Agent - 一键安装配置向导")
    print("=" * 60)
    print()


def check_python():
    """检查Python版本"""
    print("[1/6] 检查Python环境...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 10):
        print(f"  ❌ Python版本过低: {version.major}.{version.minor}，需要3.10+")
        return False
    print(f"  ✅ Python版本: {version.major}.{version.minor}.{version.micro}")
    return True


def create_venv():
    """创建虚拟环境"""
    print("\n[2/6] 创建虚拟环境...")
    if os.path.exists("venv"):
        print("  ⚠️  虚拟环境已存在，跳过")
        return True
    try:
        subprocess.check_call([sys.executable, "-m", "venv", "venv"])
        print("  ✅ 虚拟环境创建成功")
        return True
    except Exception as e:
        print(f"  ⚠️  虚拟环境创建失败: {e}，将使用系统Python")
        return False


def install_dependencies():
    """安装依赖"""
    print("\n[3/6] 安装项目依赖...")
    
    # 确定pip命令
    if os.name == "nt":
        pip_cmd = ["venv\\Scripts\\python.exe", "-m", "pip"]
    else:
        pip_cmd = ["venv/bin/python", "-m", "pip"]
    
    if not os.path.exists(pip_cmd[0]):
        pip_cmd = [sys.executable, "-m", "pip"]
    
    try:
        # 升级pip
        subprocess.check_call(pip_cmd + ["install", "--upgrade", "pip"])
        # 安装依赖
        subprocess.check_call(pip_cmd + ["install", "-r", "requirements.txt"])
        print("  ✅ 依赖安装完成")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  ❌ 依赖安装失败: {e}")
        return False


def configure_env():
    """配置环境变量"""
    print("\n[4/6] 配置环境变量...")
    
    if os.path.exists(".env"):
        print("  ⚠️  .env文件已存在，跳过配置")
        print("     如需重新配置，请删除.env文件后重新运行向导")
        return True
    
    # 复制模板
    if os.path.exists(".env.example"):
        shutil.copy(".env.example", ".env")
    else:
        # 创建基础.env
        with open(".env", "w", encoding="utf-8") as f:
            f.write("# AI Hacking Agent 配置文件\n")
            f.write("# 请填写以下配置项\n\n")
            f.write("# LLM配置\n")
            f.write("LLM_API_KEY=\n")
            f.write("LLM_BASE_URL=https://api.deepseek.com/v1\n")
            f.write("LLM_MODEL=deepseek-chat\n\n")
            f.write("# API鉴权\n")
            f.write("API_AUTH_ENABLED=true\n")
            generated_api_key = secrets.token_urlsafe(32)
            f.write(f"API_AUTH_KEY={generated_api_key}\n\n")
            f.write("# 日志\n")
            f.write("LOG_LEVEL=INFO\n")
    
    print("  ✅ .env配置文件已创建")
    print()
    print("  请编辑 .env 文件，至少配置以下内容：")
    print("  - LLM_API_KEY: 你的大模型API密钥")
    print("  - LLM_BASE_URL: API地址（如使用DeepSeek则为默认值）")
    print("  - LLM_MODEL: 模型名称")
    print()
    
    # 询问是否立即编辑
    try:
        choice = input("  是否现在打开.env文件进行编辑？(y/n): ").strip().lower()
        if choice == "y":
            if os.name == "nt":
                os.startfile(".env")
            elif sys.platform == "darwin":
                subprocess.call(["open", ".env"])
            else:
                subprocess.call(["nano", ".env"])
    except (KeyboardInterrupt, EOFError):
        pass
    
    return True


def create_directories():
    """创建必要的数据目录"""
    print("\n[5/6] 创建数据目录...")
    dirs = ["data", "logs", "scan_results", "reports", "data/vuln_management"]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        # 创建.gitkeep
        gitkeep = os.path.join(d, ".gitkeep")
        if not os.path.exists(gitkeep):
            open(gitkeep, "w").close()
    print("  ✅ 数据目录创建完成")


def verify_installation():
    """验证安装"""
    print("\n[6/6] 验证安装...")
    
    # 验证Python模块导入
    try:
        if os.name == "nt":
            python_cmd = "venv\\Scripts\\python.exe"
        else:
            python_cmd = "venv/bin/python"
        if not os.path.exists(python_cmd):
            python_cmd = sys.executable
        
        result = subprocess.run(
            [python_cmd, "-c", "import config.settings; import api_server.app; print('OK')"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and "OK" in result.stdout:
            print("  ✅ 核心模块导入成功")
        else:
            print(f"  ⚠️  模块导入警告: {result.stderr[:100]}")
    except Exception as e:
        print(f"  ⚠️  验证跳过: {e}")
    
    print()
    print("=" * 60)
    print("  🎉 安装配置完成！")
    print("=" * 60)
    print()
    print("  启动方式：")
    if os.name == "nt":
        print("  Windows:  start.bat")
    else:
        print("  Linux/Mac: ./start.sh")
    print()
    print("  访问地址：")
    print("  - 主控制台: http://127.0.0.1:8000/console-v7")
    print("  - API文档: http://127.0.0.1:8000/docs")
    print("  - 健康检查: http://127.0.0.1:8000/health")
    print()


def main():
    print_banner()
    
    # 切换到脚本所在目录
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    if not check_python():
        print("\n❌ 环境检查失败，请安装Python 3.10+后重试")
        sys.exit(1)
    
    create_venv()
    install_dependencies()
    configure_env()
    create_directories()
    verify_installation()


if __name__ == "__main__":
    main()
