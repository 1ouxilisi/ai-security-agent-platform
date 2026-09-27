# -*- coding: utf-8 -*-
"""
install_guide.py — 外部工具安装引导。

为每个工具提供 Windows(winget/choco/scoop)/Linux(apt/yum/dnf/pacman)/macOS(brew)
多平台安装命令、验证步骤、常见问题、依赖关系与离线包链接。
"""

from __future__ import annotations

from typing import Any, Dict, List


# --------------------------------------------------------------------------- #
# 安装命令矩阵
# windows: [{manager, command}]
# linux:   [{manager, command, distro}]
# macos:   [{manager, command}]
# --------------------------------------------------------------------------- #
INSTALL_COMMANDS: Dict[str, Dict[str, Any]] = {
    "nmap": {
        "windows": [
            {"manager": "winget", "command": "winget install Insecure.Nmap"},
            {"manager": "choco", "command": "choco install nmap -y"},
            {"manager": "scoop", "command": "scoop install nmap"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install nmap", "distro": "debian/ubuntu"},
            {"manager": "yum", "command": "sudo yum install nmap", "distro": "rhel/centos"},
            {"manager": "dnf", "command": "sudo dnf install nmap", "distro": "fedora"},
            {"manager": "pacman", "command": "sudo pacman -S nmap", "distro": "arch"},
        ],
        "macos": [{"manager": "brew", "command": "brew install nmap"}],
        "verify": "nmap --version",
        "dependencies": [],
        "offline": "https://nmap.org/download.html",
        "faq": [
            {"q": "Windows 上 nmap 提示缺少 NPCAP",
             "a": "安装时勾选 Npcap 组件，或单独下载 Npcap installer 安装。"},
            {"q": "普通用户扫描返回权限错误",
             "a": "需要以管理员/root 身份运行 SYN 扫描；Connect 扫描不需要特权。"},
        ],
    },
    "masscan": {
        "windows": [
            {"manager": "scoop", "command": "scoop install masscan"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install masscan", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install masscan"}],
        "verify": "masscan --version",
        "dependencies": ["libpcap"],
        "offline": "https://github.com/robertdavidgraham/masscan/releases",
        "faq": [{"q": "扫描丢包严重", "a": "降低 --rate 参数，例如 --rate=1000。"}],
    },
    "zmap": {
        "windows": [],
        "linux": [
            {"manager": "apt", "command": "sudo apt install zmap", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install zmap"}],
        "verify": "zmap --version",
        "dependencies": ["libpcap", "gengetopt"],
        "offline": "https://github.com/zmap/zmap/releases",
        "faq": [{"q": "需要 root 权限", "a": "zmap 发送 raw 包必须以 root 运行。"}],
    },
    "msfconsole": {
        "windows": [
            {"manager": "choco", "command": "choco install metasploit -y"},
        ],
        "linux": [
            {"manager": "apt", "command": "curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfinstall | sudo bash", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install metasploit"}],
        "verify": "msfconsole --version",
        "dependencies": ["postgresql"],
        "offline": "https://www.metasploit.com/download",
        "faq": [{"q": "数据库初始化失败", "a": "执行 msfdb init 初始化 PostgreSQL。"}],
    },
    "sqlmap": {
        "windows": [
            {"manager": "choco", "command": "choco install sqlmap -y"},
            {"manager": "scoop", "command": "scoop install sqlmap"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install sqlmap", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install sqlmap"}],
        "verify": "sqlmap --version",
        "dependencies": ["python3"],
        "offline": "https://github.com/sqlmapproject/sqlmap/releases",
        "faq": [{"q": "Windows 下找不到 sqlmap 命令", "a": "用 git clone 后执行 python sqlmap.py。"}],
    },
    "nikto": {
        "windows": [
            {"manager": "choco", "command": "choco install nikto -y"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install nikto", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install nikto"}],
        "verify": "nikto -Version",
        "dependencies": ["perl"],
        "offline": "https://cirt.net/nikto2",
        "faq": [],
    },
    "wpscan": {
        "windows": [],
        "linux": [
            {"manager": "apt", "command": "sudo gem install wpscan", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install wpscanteam/tap/wpscan"}],
        "verify": "wpscan --version",
        "dependencies": ["ruby"],
        "offline": "https://github.com/wpscanteam/wpscan/releases",
        "faq": [{"q": "API token 缺失", "a": "访问 wpscan.com 注册免费 token。"}],
    },
    "gobuster": {
        "windows": [
            {"manager": "scoop", "command": "scoop install gobuster"},
            {"manager": "choco", "command": "choco install gobuster -y"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install gobuster", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install gobuster"}],
        "verify": "gobuster --version",
        "dependencies": ["go"],
        "offline": "https://github.com/OJ/gobuster/releases",
        "faq": [],
    },
    "dirb": {
        "windows": [],
        "linux": [
            {"manager": "apt", "command": "sudo apt install dirb", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install dirb"}],
        "verify": "dirb",
        "dependencies": [],
        "offline": "http://dirb.sourceforge.net/",
        "faq": [],
    },
    "dirsearch": {
        "windows": [
            {"manager": "pip", "command": "pip install dirsearch"},
        ],
        "linux": [
            {"manager": "pip", "command": "pip3 install dirsearch"},
        ],
        "macos": [{"manager": "pip", "command": "pip3 install dirsearch"}],
        "verify": "dirsearch --version",
        "dependencies": ["python3"],
        "offline": "https://github.com/maurosoria/dirsearch/releases",
        "faq": [],
    },
    "hydra": {
        "windows": [
            {"manager": "choco", "command": "choco install thc-hydra -y"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install hydra", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install hydra"}],
        "verify": "hydra -h",
        "dependencies": [],
        "offline": "https://github.com/vanhauser-thc/thc-hydra/releases",
        "faq": [{"q": "被杀毒软件拦截", "a": "hydra 是渗透工具，需加白名单。"}],
    },
    "john": {
        "windows": [
            {"manager": "choco", "command": "choco install john -y"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install john", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install john"}],
        "verify": "john --list=build-info",
        "dependencies": [],
        "offline": "https://www.openwall.com/john/",
        "faq": [],
    },
    "hashcat": {
        "windows": [
            {"manager": "choco", "command": "choco install hashcat -y"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install hashcat", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install hashcat"}],
        "verify": "hashcat --version",
        "dependencies": ["opencl", "cuda"],
        "offline": "https://hashcat.net/hashcat/",
        "faq": [{"q": "GPU 识别失败", "a": "安装显卡驱动与 OpenCL/CUDA 运行时。"}],
    },
    "medusa": {
        "windows": [],
        "linux": [
            {"manager": "apt", "command": "sudo apt install medusa", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install medusa"}],
        "verify": "medusa -h",
        "dependencies": [],
        "offline": "https://github.com/jmk-foofus/medusa",
        "faq": [],
    },
    "aircrack-ng": {
        "windows": [
            {"manager": "choco", "command": "choco install aircrack-ng -y"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install aircrack-ng", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install aircrack-ng"}],
        "verify": "aircrack-ng --help",
        "dependencies": ["libpcap", "无线网卡（支持监听模式）"],
        "offline": "https://www.aircrack-ng.org/downloads.html",
        "faq": [{"q": "网卡不支持 monitor 模式", "a": "需更换支持的网卡（如 Alfa 系列）。"}],
    },
    "airodump-ng": {
        "windows": [{"manager": "choco", "command": "choco install aircrack-ng -y"}],
        "linux": [
            {"manager": "apt", "command": "sudo apt install aircrack-ng", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install aircrack-ng"}],
        "verify": "airodump-ng --help",
        "dependencies": ["aircrack-ng"],
        "offline": "https://www.aircrack-ng.org/",
        "faq": [],
    },
    "aireplay-ng": {
        "windows": [{"manager": "choco", "command": "choco install aircrack-ng -y"}],
        "linux": [
            {"manager": "apt", "command": "sudo apt install aircrack-ng", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install aircrack-ng"}],
        "verify": "aireplay-ng --help",
        "dependencies": ["aircrack-ng"],
        "offline": "https://www.aircrack-ng.org/",
        "faq": [],
    },
    "kismet": {
        "windows": [],
        "linux": [
            {"manager": "apt", "command": "sudo apt install kismet", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install kismet"}],
        "verify": "kismet --version",
        "dependencies": ["libpcap", "无线网卡"],
        "offline": "https://www.kismetwireless.net/",
        "faq": [],
    },
    "jadx": {
        "windows": [
            {"manager": "scoop", "command": "scoop install jadx"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install jadx", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install jadx"}],
        "verify": "jadx --version",
        "dependencies": ["java"],
        "offline": "https://github.com/skylot/jadx/releases",
        "faq": [{"q": "提示需要 JDK", "a": "安装 OpenJDK 11 或以上版本。"}],
    },
    "apktool": {
        "windows": [
            {"manager": "scoop", "command": "scoop install apktool"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install apktool", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install apktool"}],
        "verify": "apktool --version",
        "dependencies": ["java"],
        "offline": "https://apktool.org/",
        "faq": [],
    },
    "frida": {
        "windows": [
            {"manager": "pip", "command": "pip install frida-tools"},
        ],
        "linux": [
            {"manager": "pip", "command": "pip3 install frida-tools"},
        ],
        "macos": [{"manager": "pip", "command": "pip3 install frida-tools"}],
        "verify": "frida --version",
        "dependencies": ["python3"],
        "offline": "https://github.com/frida/frida/releases",
        "faq": [{"q": "Android 端 frida-server 未运行", "a": "推送 frida-server 到设备并启动。"}],
    },
    "objection": {
        "windows": [{"manager": "pip", "command": "pip install objection"}],
        "linux": [{"manager": "pip", "command": "pip3 install objection"}],
        "macos": [{"manager": "pip", "command": "pip3 install objection"}],
        "verify": "objection --version",
        "dependencies": ["frida"],
        "offline": "https://github.com/sensepost/objection/releases",
        "faq": [],
    },
    "drozer": {
        "windows": [
            {"manager": "pip", "command": "pip install drozer"},
        ],
        "linux": [{"manager": "pip", "command": "pip3 install drozer"}],
        "macos": [{"manager": "pip", "command": "pip3 install drozer"}],
        "verify": "drozer --version",
        "dependencies": ["python2 (legacy)"],
        "offline": "https://github.com/FSecureLABS/drozer/releases",
        "faq": [{"q": "依赖 Python2", "a": "drozer 已停止维护，建议改用 objection。"}],
    },
    "ghidra": {
        "windows": [
            {"manager": "choco", "command": "choco install ghidra -y"},
        ],
        "linux": [],
        "macos": [{"manager": "brew", "command": "brew install ghidra"}],
        "verify": "ghidraRun",
        "dependencies": ["JDK 17+"],
        "offline": "https://github.com/NationalSecurityAgency/ghidra/releases",
        "faq": [{"q": "启动慢", "a": "修改 support/ghidraRun 增加 JVM 堆内存。"}],
    },
    "r2": {
        "windows": [
            {"manager": "scoop", "command": "scoop install radare2"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install radare2", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install radare2"}],
        "verify": "r2 -v",
        "dependencies": [],
        "offline": "https://github.com/radareorg/radare2/releases",
        "faq": [],
    },
    "binwalk": {
        "windows": [
            {"manager": "pip", "command": "pip install binwalk"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install binwalk", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install binwalk"}],
        "verify": "binwalk --version",
        "dependencies": ["python3"],
        "offline": "https://github.com/ReFirmLabs/binwalk/releases",
        "faq": [],
    },
    "strings": {
        "windows": [
            {"manager": "scoop", "command": "scoop install strings"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install binutils", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install binutils"}],
        "verify": "strings --version",
        "dependencies": [],
        "offline": "https://www.gnu.org/software/binutils/",
        "faq": [],
    },
    "objdump": {
        "windows": [
            {"manager": "scoop", "command": "scoop install x86_64-w64-mingw34-binutils"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install binutils", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install binutils"}],
        "verify": "objdump --version",
        "dependencies": [],
        "offline": "https://www.gnu.org/software/binutils/",
        "faq": [],
    },
    "volatility": {
        "windows": [
            {"manager": "pip", "command": "pip install volatility3"},
        ],
        "linux": [{"manager": "pip", "command": "pip3 install volatility3"}],
        "macos": [{"manager": "pip", "command": "pip3 install volatility3"}],
        "verify": "vol --help",
        "dependencies": ["python3"],
        "offline": "https://www.volatilityfoundation.org/releases",
        "faq": [{"q": "找不到 profile", "a": "使用 vol3 的 symbol 自动下载。"}],
    },
    "autopsy": {
        "windows": [
            {"manager": "choco", "command": "choco install autopsy -y"},
        ],
        "linux": [],
        "macos": [],
        "verify": "autopsy",
        "dependencies": ["java"],
        "offline": "https://www.autopsy.com/download/",
        "faq": [],
    },
    "tshark": {
        "windows": [
            {"manager": "choco", "command": "choco install wireshark -y"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install tshark", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install wireshark"}],
        "verify": "tshark --version",
        "dependencies": [],
        "offline": "https://www.wireshark.org/download.html",
        "faq": [{"q": "权限提示", "a": "将当前用户加入 wireshark 组。"}],
    },
    "wireshark": {
        "windows": [
            {"manager": "choco", "command": "choco install wireshark -y"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install wireshark", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install --cask wireshark"}],
        "verify": "wireshark --version",
        "dependencies": [],
        "offline": "https://www.wireshark.org/download.html",
        "faq": [],
    },
    "docker": {
        "windows": [
            {"manager": "winget", "command": "winget install Docker.DockerDesktop"},
            {"manager": "choco", "command": "choco install docker-desktop -y"},
        ],
        "linux": [
            {"manager": "apt", "command": "curl -fsSL https://get.docker.com | sudo sh", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install --cask docker"}],
        "verify": "docker --version",
        "dependencies": [],
        "offline": "https://www.docker.com/products/docker-desktop/",
        "faq": [{"q": "Windows 需要 WSL2", "a": "启用 WSL2 后再安装 Docker Desktop。"}],
    },
    "docker-compose": {
        "windows": [
            {"manager": "choco", "command": "choco install docker-compose -y"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install docker-compose-plugin", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install docker-compose"}],
        "verify": "docker-compose --version",
        "dependencies": ["docker"],
        "offline": "https://github.com/docker/compose/releases",
        "faq": [],
    },
    "kubectl": {
        "windows": [
            {"manager": "choco", "command": "choco install kubernetes-cli -y"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install kubectl", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install kubectl"}],
        "verify": "kubectl version --client",
        "dependencies": [],
        "offline": "https://kubernetes.io/docs/tasks/tools/",
        "faq": [],
    },
    "trivy": {
        "windows": [
            {"manager": "choco", "command": "choco install trivy -y"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install trivy", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install trivy"}],
        "verify": "trivy --version",
        "dependencies": ["docker（可选）"],
        "offline": "https://github.com/aquasecurity/trivy/releases",
        "faq": [],
    },
    "helm": {
        "windows": [
            {"manager": "choco", "command": "choco install kubernetes-helm -y"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install helm", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install helm"}],
        "verify": "helm version",
        "dependencies": ["kubectl"],
        "offline": "https://github.com/helm/helm/releases",
        "faq": [],
    },
    "semgrep": {
        "windows": [
            {"manager": "pip", "command": "pip install semgrep"},
        ],
        "linux": [{"manager": "pip", "command": "pip3 install semgrep"}],
        "macos": [{"manager": "brew", "command": "brew install semgrep"}],
        "verify": "semgrep --version",
        "dependencies": ["python3"],
        "offline": "https://github.com/semgrep/semgrep/releases",
        "faq": [{"q": "Windows 上原生版缺失", "a": "推荐使用 WSL2 运行 semgrep。"}],
    },
    "sonar-scanner": {
        "windows": [
            {"manager": "choco", "command": "choco install sonar-scanner -y"},
        ],
        "linux": [],
        "macos": [{"manager": "brew", "command": "brew install sonar-scanner"}],
        "verify": "sonar-scanner --version",
        "dependencies": ["java"],
        "offline": "https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/scanners/sonarscanner/",
        "faq": [],
    },
    "gitleaks": {
        "windows": [
            {"manager": "choco", "command": "choco install gitleaks -y"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install gitleaks", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install gitleaks"}],
        "verify": "gitleaks version",
        "dependencies": ["git"],
        "offline": "https://github.com/gitleaks/gitleaks/releases",
        "faq": [],
    },
    "python3": {
        "windows": [
            {"manager": "winget", "command": "winget install Python.Python.3.14"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install python3 python3-pip", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install python@3.14"}],
        "verify": "python --version",
        "dependencies": [],
        "offline": "https://www.python.org/downloads/",
        "faq": [],
    },
    "pip": {
        "windows": [
            {"manager": "python", "command": "python -m ensurepip --upgrade"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install python3-pip", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install python"}],
        "verify": "pip --version",
        "dependencies": ["python3"],
        "offline": "https://pip.pypa.io/en/stable/installation/",
        "faq": [],
    },
    "git": {
        "windows": [
            {"manager": "winget", "command": "winget install Git.Git"},
            {"manager": "choco", "command": "choco install git -y"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install git", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install git"}],
        "verify": "git --version",
        "dependencies": [],
        "offline": "https://git-scm.com/downloads",
        "faq": [],
    },
    "curl": {
        "windows": [
            {"manager": "winget", "command": "winget install cURL.cURL"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install curl", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install curl"}],
        "verify": "curl --version",
        "dependencies": [],
        "offline": "https://curl.se/download.html",
        "faq": [],
    },
    "wget": {
        "windows": [
            {"manager": "choco", "command": "choco install wget -y"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install wget", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install wget"}],
        "verify": "wget --version",
        "dependencies": [],
        "offline": "https://www.gnu.org/software/wget/",
        "faq": [],
    },
    "openssl": {
        "windows": [
            {"manager": "choco", "command": "choco install openssl -y"},
        ],
        "linux": [
            {"manager": "apt", "command": "sudo apt install openssl", "distro": "debian/ubuntu"},
        ],
        "macos": [{"manager": "brew", "command": "brew install openssl"}],
        "verify": "openssl version",
        "dependencies": [],
        "offline": "https://www.openssl.org/source/",
        "faq": [],
    },
}


def get_guide(tool: str) -> Dict[str, Any]:
    return INSTALL_COMMANDS.get(tool, {
        "windows": [], "linux": [], "macos": [],
        "verify": "", "dependencies": [], "offline": "", "faq": [],
    })


def get_all_guides() -> Dict[str, Dict[str, Any]]:
    return INSTALL_COMMANDS


def missing_guides(missing_tools: List[str]) -> List[Dict[str, Any]]:
    out = []
    for name in missing_tools:
        g = get_guide(name)
        if not g:
            continue
        out.append({"tool": name, **g})
    return out
