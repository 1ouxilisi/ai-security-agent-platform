@echo off
chcp 65001 >nul
title AI Hacking Agent - 安全工具一键安装
color 0B

echo ========================================
echo   AI Hacking Agent 安全工具一键安装
echo   支持: sqlmap / nikto / masscan / perl
echo ========================================
echo.

:: 设置工具安装目录
set TOOLS_DIR=%USERPROFILE%\tools
if not exist "%TOOLS_DIR%" mkdir "%TOOLS_DIR%"
echo [信息] 工具安装目录: %TOOLS_DIR%
echo.

:: ============================================
:: 1. 安装 sqlmap
:: ============================================
echo [1/4] 安装 sqlmap...
if exist "%TOOLS_DIR%\sqlmap\sqlmap.py" (
    echo [OK] sqlmap 已安装，跳过
) else (
    echo [信息] 正在下载 sqlmap...
    echo [信息] 尝试 GitHub 源...
    powershell -Command "try { Invoke-WebRequest -Uri 'https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip' -OutFile '%TOOLS_DIR%\sqlmap.zip' -UseBasicParsing -TimeoutSec 60; Write-Host '下载成功' } catch { Write-Host 'GitHub失败，尝试Gitee...'; try { Invoke-WebRequest -Uri 'https://gitee.com/mirrors/sqlmap/repository/archive/master.zip' -OutFile '%TOOLS_DIR%\sqlmap.zip' -UseBasicParsing -TimeoutSec 60; Write-Host 'Gitee下载成功' } catch { Write-Host '下载失败，请手动下载'; exit 1 } }"
    if exist "%TOOLS_DIR%\sqlmap.zip" (
        echo [信息] 正在解压...
        powershell -Command "Expand-Archive -Path '%TOOLS_DIR%\sqlmap.zip' -DestinationPath '%TOOLS_DIR%' -Force; if (Test-Path '%TOOLS_DIR%\sqlmap-master') { Rename-Item -Path '%TOOLS_DIR%\sqlmap-master' -NewName 'sqlmap' }"
        del "%TOOLS_DIR%\sqlmap.zip"
        if exist "%TOOLS_DIR%\sqlmap\sqlmap.py" (
            echo [OK] sqlmap 安装成功
        ) else (
            echo [错误] sqlmap 解压失败，请手动安装
        )
    )
)
echo.

:: ============================================
:: 2. 安装 Strawberry Perl (nikto依赖)
:: ============================================
echo [2/4] 安装 Strawberry Perl (nikto 依赖)...
where perl >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Perl 已安装，跳过
) else (
    echo [信息] 正在下载 Strawberry Perl...
    echo [信息] 下载地址: https://strawberryperl.com/download/5.32.1.1/strawberry-perl-5.32.1.1-64bit.msi
    echo [提示] 文件较大（约150MB），请耐心等待...
    powershell -Command "try { Invoke-WebRequest -Uri 'https://strawberryperl.com/download/5.32.1.1/strawberry-perl-5.32.1.1-64bit.msi' -OutFile '%TEMP%\strawberry-perl.msi' -UseBasicParsing -TimeoutSec 300; Write-Host '下载成功' } catch { Write-Host '下载失败，请手动下载安装 Strawberry Perl'; exit 1 }"
    if exist "%TEMP%\strawberry-perl.msi" (
        echo [信息] 正在安装 Strawberry Perl（需要管理员权限）...
        msiexec /i "%TEMP%\strawberry-perl.msi" /qn /norestart
        del "%TEMP%\strawberry-perl.msi"
        echo [OK] Strawberry Perl 安装完成（可能需要重启终端）
    )
)
echo.

:: ============================================
:: 3. 安装 nikto
:: ============================================
echo [3/4] 安装 nikto...
if exist "%TOOLS_DIR%\nikto\nikto.pl" (
    echo [OK] nikto 已安装，跳过
) else (
    echo [信息] 正在下载 nikto...
    powershell -Command "try { Invoke-WebRequest -Uri 'https://github.com/sullo/nikto/archive/refs/heads/master.zip' -OutFile '%TOOLS_DIR%\nikto.zip' -UseBasicParsing -TimeoutSec 60; Write-Host '下载成功' } catch { Write-Host 'GitHub失败，尝试Gitee...'; try { Invoke-WebRequest -Uri 'https://gitee.com/mirrors/nikto/repository/archive/master.zip' -OutFile '%TOOLS_DIR%\nikto.zip' -UseBasicParsing -TimeoutSec 60; Write-Host 'Gitee下载成功' } catch { Write-Host '下载失败，请手动下载'; exit 1 } }"
    if exist "%TOOLS_DIR%\nikto.zip" (
        echo [信息] 正在解压...
        powershell -Command "Expand-Archive -Path '%TOOLS_DIR%\nikto.zip' -DestinationPath '%TOOLS_DIR%' -Force; if (Test-Path '%TOOLS_DIR%\nikto-master') { Rename-Item -Path '%TOOLS_DIR%\nikto-master' -NewName 'nikto' }"
        del "%TOOLS_DIR%\nikto.zip"
        if exist "%TOOLS_DIR%\nikto\program\nikto.pl" (
            echo [OK] nikto 安装成功
        ) else (
            echo [警告] nikto 解压完成，但路径可能不同，请检查
        )
    )
)
echo.

:: ============================================
:: 4. 安装 masscan
:: ============================================
echo [4/4] 安装 masscan...
where masscan >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] masscan 已安装，跳过
) else (
    echo [信息] masscan Windows 预编译版本较少
    echo [信息] 推荐方案:
    echo   1. 使用 WSL (Windows Subsystem for Linux):
    echo      wsl --install
    echo      wsl sudo apt install masscan
    echo   2. 或手动下载 Windows 预编译版
    echo      https://github.com/robertdavidgraham/masscan/releases
    echo.
    echo [提示] masscan 为可选工具，不影响核心功能
)
echo.

:: ============================================
:: 创建工具包装脚本
:: ============================================
echo ========================================
echo   创建工具命令包装脚本
echo ========================================
echo.

:: sqlmap 包装脚本
if not exist "%TOOLS_DIR%\sqlmap.bat" (
    echo @echo off > "%TOOLS_DIR%\sqlmap.bat"
    echo python "%TOOLS_DIR%\sqlmap\sqlmap.py" %%* >> "%TOOLS_DIR%\sqlmap.bat"
    echo [OK] 已创建 sqlmap.bat 包装脚本
)

:: nikto 包装脚本
if not exist "%TOOLS_DIR%\nikto.bat" (
    echo @echo off > "%TOOLS_DIR%\nikto.bat"
    echo perl "%TOOLS_DIR%\nikto\program\nikto.pl" %%* >> "%TOOLS_DIR%\nikto.bat"
    echo [OK] 已创建 nikto.bat 包装脚本
)

echo.
echo ========================================
echo   安装完成！
echo ========================================
echo.
echo [重要] 请确保以下目录在系统 PATH 中:
echo   %TOOLS_DIR%
echo.
echo [检查] 当前 PATH 状态:
echo %PATH% | findstr /C:"%TOOLS_DIR%" >nul
if %errorlevel% equ 0 (
    echo   [OK] %TOOLS_DIR% 已在 PATH 中
) else (
    echo   [警告] %TOOLS_DIR% 未在 PATH 中
    echo   [操作] 请手动添加到系统环境变量 PATH
    echo   或运行以下命令（需要管理员权限）:
    echo   setx PATH "%%PATH%%;%TOOLS_DIR%"
)
echo.
echo [验证] 重新打开终端后运行:
echo   sqlmap --version
echo   nikto -Version
echo   nmap --version
echo   nuclei --version
echo.
pause
