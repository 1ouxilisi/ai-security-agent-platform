@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
REM ===========================================================================
REM  AI Hacking Agent - 一键安装全部安全工具 (Windows)
REM  国内镜像源优先: Gitee 镜像 / 清华 PyPI / ghproxy 加速
REM  仅用于授权的安全测试环境。
REM ===========================================================================

cd /d "%~dp0"
set "TOOLS_DIR=%USERPROFILE%\tools"
if not exist "%TOOLS_DIR%" mkdir "%TOOLS_DIR%"
echo [*] 工具安装目录: %TOOLS_DIR%
echo.

REM ---------------------------------------------------------------------------
REM 1. nmap
REM ---------------------------------------------------------------------------
echo [1/8] 安装 nmap ...
where winget >nul 2>nul
if %errorlevel%==0 (
    winget install --id Insecure.Nmap -e --accept-source-agreements --accept-package-agreements
) else (
    echo     [!] 未找到 winget，请手动下载: https://nmap.org/download.html
)
where nmap >nul 2>nul && echo     [OK] nmap 已在 PATH 中 || echo     [WARN] nmap 未检测到，如已安装请重启终端
echo.

REM ---------------------------------------------------------------------------
REM 2. nuclei
REM ---------------------------------------------------------------------------
echo [2/8] 安装 nuclei ...
where go >nul 2>nul
if %errorlevel%==0 (
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
) else (
    echo     [i] 未检测到 Go，建议从以下地址下载预编译二进制:
    echo         https://github.com/projectdiscovery/nuclei/releases
    echo         国内加速: https://ghproxy.com/https://github.com/projectdiscovery/nuclei/releases
    echo     将 nuclei.exe 放到 %TOOLS_DIR%\
)
where nuclei >nul 2>nul && echo     [OK] nuclei 已在 PATH 中 || echo     [WARN] nuclei 未检测到
echo.

REM ---------------------------------------------------------------------------
REM 3. sqlmap (Gitee 国内镜像)
REM ---------------------------------------------------------------------------
echo [3/8] 安装 sqlmap ...
if not exist "%TOOLS_DIR%\sqlmap\sqlmap.py" (
    where git >nul 2>nul
    if !errorlevel!==0 (
        git clone --depth 1 https://gitee.com/mirrors/sqlmap.git "%TOOLS_DIR%\sqlmap"
    ) else (
        echo     [!] 未安装 git，请先安装 git: https://git-scm.com/download/win
    )
) else (
    echo     [i] sqlmap 已存在，跳过 clone
)
if exist "%TOOLS_DIR%\sqlmap\sqlmap.py" (
    echo     [OK] sqlmap 已就位: %TOOLS_DIR%\sqlmap\sqlmap.py
) else (
    echo     [WARN] sqlmap 安装失败
)
echo.

REM ---------------------------------------------------------------------------
REM 4. nikto (需要 Strawberry Perl)
REM ---------------------------------------------------------------------------
echo [4/8] 安装 nikto ...
where perl >nul 2>nul
if !errorlevel! neq 0 (
    echo     [!] 未检测到 Perl，nikto 依赖 Strawberry Perl:
    echo         下载地址: https://strawberryperl.com/
)
if not exist "%TOOLS_DIR%\nikto\program\nikto.pl" (
    where git >nul 2>nul
    if !errorlevel!==0 (
        git clone --depth 1 https://gitee.com/mirrors/nikto.git "%TOOLS_DIR%\nikto"
    )
) else (
    echo     [i] nikto 已存在，跳过 clone
)
if exist "%TOOLS_DIR%\nikto\program\nikto.pl" (
    echo     [OK] nikto 已就位: %TOOLS_DIR%\nikto\program\nikto.pl
) else (
    echo     [WARN] nikto 未就绪
)
echo.

REM ---------------------------------------------------------------------------
REM 5. masscan (Windows 推荐 WSL)
REM ---------------------------------------------------------------------------
echo [5/8] masscan ...
where masscan >nul 2>nul
if !errorlevel!==0 (
    echo     [OK] masscan 已在 PATH 中
) else (
    where wsl >nul 2>nul
    if !errorlevel!==0 (
        echo     [i] 检测到 WSL，如需在 WSL 中安装 masscan，请执行:
        echo         wsl --install
        echo         wsl sudo apt update ^&^& wsl sudo apt install -y masscan
    ) else (
        echo     [!] Windows 原生 masscan 较少，推荐 WSL:
        echo         1) wsl --install
        echo         2) wsl sudo apt update ^&^& wsl sudo apt install -y masscan
    )
)
echo.

REM ---------------------------------------------------------------------------
REM 6. metasploit
REM ---------------------------------------------------------------------------
echo [6/8] metasploit ...
echo     [i] 请从官方下载 Windows 安装包或使用 WSL:
echo         https://www.metasploit.com/download
echo     启动 RPC 服务（本项目仅使用信息收集模块）:
echo         msfrpcd -P 你的强密码 -S -a 127.0.0.1 -p 55553
echo.

REM ---------------------------------------------------------------------------
REM 7. hashcat
REM ---------------------------------------------------------------------------
echo [7/8] 安装 hashcat ...
if not exist "%TOOLS_DIR%\hashcat\hashcat.exe" (
    where curl >nul 2>nul
    if !errorlevel!==0 (
        echo     [i] 请手动下载预编译版: https://hashcat.net/hashcat/
        echo         解压到 %TOOLS_DIR%\hashcat\
    )
) else (
    echo     [OK] hashcat 已就位
)
where hashcat >nul 2>nul && echo     [OK] hashcat 已在 PATH 中 || echo     [WARN] hashcat 未检测到
echo.

REM ---------------------------------------------------------------------------
REM 8. dirsearch (Gitee 镜像 + 清华 PyPI)
REM ---------------------------------------------------------------------------
echo [8/8] 安装 dirsearch ...
if not exist "%TOOLS_DIR%\dirsearch\dirsearch.py" (
    where git >nul 2>nul
    if !errorlevel!==0 (
        git clone --depth 1 https://gitee.com/mirrors/dirsearch.git "%TOOLS_DIR%\dirsearch"
    )
) else (
    echo     [i] dirsearch 已存在，跳过 clone
)
if exist "%TOOLS_DIR%\dirsearch\dirsearch.py" (
    echo     [OK] dirsearch 已就位
    pip install -r "%TOOLS_DIR%\dirsearch\requirements.txt" -i https://pypi.tuna.tsinghua.edu.cn/simple
) else (
    echo     [WARN] dirsearch 未就绪
)
echo.

REM ---------------------------------------------------------------------------
REM 环境变量：将工具目录加入用户 PATH（持久化）
REM ---------------------------------------------------------------------------
echo [*] 配置用户 PATH ...
echo %PATH% | findstr /i /c:"%TOOLS_DIR%" >nul
if errorlevel 1 (
    setx PATH "%PATH%;%TOOLS_DIR%" >nul
    echo     [OK] 已将 %TOOLS_DIR% 追加到用户 PATH（新终端生效）
) else (
    echo     [i] PATH 中已包含 %TOOLS_DIR%
)
REM 当前会话也临时加入
set "PATH=%PATH%;%TOOLS_DIR%"
echo.

REM ---------------------------------------------------------------------------
REM 运行工具健康检查
REM ---------------------------------------------------------------------------
echo [*] 运行工具健康检查 ...
python -m tools.tool_health_check

echo.
echo [*] 全部安装流程结束。若个别工具显示缺失，请按上方指引手动安装后重开终端。
endlocal
