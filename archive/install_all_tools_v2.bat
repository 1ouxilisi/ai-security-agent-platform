@echo off
chcp 65001 >nul
REM ============================================================
REM AI Hacking Agent - 一键安装所有工具 v2
REM 特性：
REM   1. 自动检测已安装工具，只安装缺失的
REM   2. 检测 WSL，提示是否在 WSL 中安装 Linux 工具
REM   3. 国内镜像优先（pip 清华源）
REM   4. 安装后自动验证（--version）
REM   5. 生成安装报告（控制台 + data\tool_install_report.txt）
REM   6. 部分失败不中断
REM ============================================================

setlocal ENABLEDELAYEDEXPANSION
cd /d "%~dp0"

echo ============================================================
echo  AI Hacking Agent - 工具一键安装 v2
echo ============================================================
echo.

REM ---- 0. 设置 pip 国内镜像 ----
echo [0/5] 配置 pip 清华镜像源...
python -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple >nul 2>&1
if errorlevel 1 (
    echo   [WARN] pip 镜像配置失败，继续使用默认源
) else (
    echo   [OK] pip 已切换到清华镜像
)
echo.

REM ---- 1. 检测 WSL ----
echo [1/5] 检测 WSL 可用性...
where wsl >nul 2>&1
if errorlevel 1 (
    echo   [INFO] 未检测到 WSL，跳过 Linux 工具安装
    set WSL_AVAILABLE=0
) else (
    wsl --status >nul 2>&1
    if errorlevel 1 (
        echo   [INFO] WSL 命令存在但未就绪，跳过
        set WSL_AVAILABLE=0
    ) else (
        echo   [OK] 检测到 WSL
        set /p INSTALL_WSL="是否在 WSL 中安装 Linux 工具？(y/N): "
        set WSL_AVAILABLE=1
    )
)
echo.

REM ---- 2. 调用 Python 检测脚本，列出缺失工具 ----
echo [2/5] 检测工具安装状态...
if not exist data mkdir data
python tools\detect_missing_tools_v2.py > data\tool_install_report.txt
type data\tool_install_report.txt
echo.

REM ---- 3. 安装 pip 类工具（sqlmap / wfuzz / impacket / bloodhound） ----
echo [3/5] 安装 pip 类工具...
for %%T in (sqlmap wfuzz impacket bloodhound) do (
    echo   - 安装 %%T
    python -m pip install %%T -i https://pypi.tuna.tsinghua.edu.cn/simple --quiet
    if errorlevel 1 (
        echo     [FAIL] %%T 安装失败，继续下一个
    ) else (
        echo     [OK] %%T
    )
)
echo.

REM ---- 4. WSL 中安装 Linux 工具（如用户同意） ----
if /i "!WSL_AVAILABLE!"=="1" (
    if /i "!INSTALL_WSL!"=="y" (
        echo [4/5] 在 WSL 中安装 Linux 工具...
        wsl -- bash -c "sudo apt update && sudo apt install -y masscan nikto hydra dirb john"
        if errorlevel 1 (
            echo     [WARN] 部分 WSL 工具安装失败
        ) else (
            echo     [OK] WSL 工具安装完成
        )
    ) else (
        echo [4/5] 用户跳过 WSL 工具安装
    )
) else (
    echo [4/5] WSL 不可用，跳过
)
echo.

REM ---- 5. 安装后自动验证 + 生成报告 ----
echo [5/5] 安装后验证并生成报告...
python -c "import sys; sys.path.insert(0,'.'); from tools.tool_installer import ToolInstaller; r=ToolInstaller().generate_install_report(); print('Installed:', r['installed_count'], '/', r['total']); print('Missing:', ', '.join(r['missing']))" >> data\tool_install_report.txt 2>&1
type data\tool_install_report.txt
echo.
echo ============================================================
echo  安装流程结束。报告见 data\tool_install_report.txt
echo ============================================================
endlocal
