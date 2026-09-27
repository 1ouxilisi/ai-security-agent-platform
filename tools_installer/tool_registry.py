# -*- coding: utf-8 -*-
"""
tools_installer/tool_registry.py — 安全工具注册表

集中维护所有需要一键安装的安全工具元数据：
  - 分类、描述、官网
  - Windows 安装命令（choco / scoop / pip / npm / docker pull）
  - 版本探测命令与参数
  - 依赖关系
  - Python 库 / Docker 镜像 单独分类
纯数据 + 查询函数，不执行任何外部命令。
"""
from __future__ import annotations

from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# 工具分类
# ---------------------------------------------------------------------------
TOOL_CATEGORIES: Dict[str, str] = {
    "scanner": "扫描类",
    "injection": "注入类",
    "exploit": "漏洞利用",
    "intranet": "内网渗透",
    "web": "Web 信息收集",
    "forensics": "取证分析",
    "supply_chain": "供应链安全",
    "devsecops": "DevSecOps",
    "mobile": "移动安全",
    "cloud": "云安全",
    "container": "容器安全",
    "base": "基础环境",
}

PYTHON_LIB_CATEGORIES: Dict[str, str] = {
    "cloud_sdk": "云 SDK",
    "container": "容器",
    "network": "网络",
    "security": "安全",
    "data": "数据分析",
    "web": "Web 框架",
    "misc": "其他",
}

DOCKER_IMAGE_CATEGORIES: Dict[str, str] = {
    "web_lab": "Web 靶场",
    "intranet_lab": "内网靶场",
    "security_tool": "安全工具",
    "log_analysis": "日志分析",
    "middleware": "中间件",
}


# ---------------------------------------------------------------------------
# 原生安全工具（二进制 / 命令行）
# 每项字段说明：
#   name/display/category/description/website
#   detect_cmd: 用于探测是否安装并取版本的命令（list，例如 ["nmap","--version"]）
#   version_regex: 从输出里提取版本号的正则（简单字符串匹配优先）
#   install: Windows 下的安装方式
#       {"method": "choco"|"scoop"|"pip"|"npm"|"docker", "package": "...", "cmd": "..."}
#   deps: 依赖的其他工具名（detect_cmd[0]）
# ---------------------------------------------------------------------------
def _t(name: str, display: str, category: str, desc: str, website: str,
       detect: List[str], install: Dict[str, str],
       deps: List[str] | None = None) -> Dict[str, Any]:
    return {
        "name": name,
        "display": display,
        "category": category,
        "description": desc,
        "website": website,
        "detect_cmd": detect,
        "version_flags": detect[1:] if len(detect) > 1 else [],
        "install": install,
        "deps": deps or [],
    }


NATIVE_TOOLS: List[Dict[str, Any]] = [
    # 扫描类
    _t("nmap", "Nmap", "scanner", "端口扫描与服务识别", "https://nmap.org",
       ["nmap", "--version"], {"method": "choco", "package": "nmap",
       "cmd": "choco install nmap -y"}),
    _t("nuclei", "Nuclei", "scanner", "基于模板的快速漏洞扫描", "https://nuclei.projectdiscovery.io",
       ["nuclei", "-version"], {"method": "go", "package": "nuclei",
       "cmd": "go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"}),
    _t("nikto", "Nikto", "scanner", "Web 服务器扫描器", "https://cirt.net/nikto2",
       ["nikto", "-Version"], {"method": "choco", "package": "nikto",
       "cmd": "choco install nikto -y"}),
    _t("gobuster", "GoBuster", "scanner", "目录/DNS/vhost 爆破", "https://github.com/OJ/gobuster",
       ["gobuster", "version"], {"method": "go", "package": "gobuster",
       "cmd": "go install github.com/OJ/gobuster/v3@latest"}),
    _t("ffuf", "FFuF", "scanner", "Web fuzz 工具", "https://github.com/ffuf/ffuf",
       ["ffuf", "-V"], {"method": "go", "package": "ffuf",
       "cmd": "go install github.com/ffuf/ffuf/v2@latest"}),
    _t("masscan", "Masscan", "scanner", "大规模异步端口扫描", "https://github.com/robertdavidgraham/masscan",
       ["masscan", "--version"], {"method": "choco", "package": "masscan",
       "cmd": "choco install masscan -y"}),
    _t("whatweb", "WhatWeb", "scanner", "Web 技术栈识别", "https://github.com/urbanadventurer/WhatWeb",
       ["whatweb", "--version"], {"method": "gem", "package": "whatweb",
       "cmd": "gem install whatweb"}),
    # 注入类
    _t("sqlmap", "sqlmap", "injection", "SQL 自动化注入工具", "https://sqlmap.org",
       ["sqlmap", "--version"], {"method": "pip", "package": "sqlmap",
       "cmd": "pip install sqlmap"}),
    _t("commix", "Commix", "injection", "命令注入自动化", "https://github.com/commixproject/commix",
       ["commix", "--version"], {"method": "git", "package": "commix",
       "cmd": "git clone https://github.com/commixproject/commix.git C:\\tools\\commix"}),
    _t("xsser", "XSSer", "injection", "XSS 漏洞自动化检测", "https://github.com/epsylon/xsser",
       ["xsser", "--version"], {"method": "pip", "package": "xsser",
       "cmd": "pip install xsser"}),
    # 漏洞利用
    _t("searchsploit", "SearchSploit", "exploit", "Exploit-DB 本地搜索", "https://www.exploit-db.com",
       ["searchsploit", "-V"], {"method": "choco", "package": "exploitdb",
       "cmd": "choco install exploitdb -y"}),
    _t("hydra", "Hydra", "exploit", "在线密码爆破", "https://github.com/vanhauser-thc/thc-hydra",
       ["hydra", "-h"], {"method": "choco", "package": "hydra",
       "cmd": "choco install hydra -y"}),
    _t("medusa", "Medusa", "exploit", "并行登录暴力破解", "https://github.com/jmk-foofus/medusa",
       ["medusa", "-h"], {"method": "choco", "package": "medusa",
       "cmd": "choco install medusa -y"}),
    # 内网
    _t("impacket", "Impacket", "intranet", "网络协议工具集（python 库 + 脚本）", "https://github.com/fortra/impacket",
       ["impacket-smbexec", "-h"], {"method": "pip", "package": "impacket",
       "cmd": "pip install impacket"}),
    _t("evil-winrm", "Evil-WinRM", "intranet", "WinRM 后渗透shell", "https://github.com/Hackplayers/evil-winrm",
       ["evil-winrm", "-h"], {"method": "gem", "package": "evil-winrm",
       "cmd": "gem install evil-winrm"}),
    # Web 信息收集
    _t("curl", "curl", "web", "HTTP 传输工具", "https://curl.se",
       ["curl", "--version"], {"method": "choco", "package": "curl",
       "cmd": "choco install curl -y"}),
    _t("wget", "Wget", "web", "文件下载工具", "https://www.gnu.org/software/wget/",
       ["wget", "--version"], {"method": "choco", "package": "wget",
       "cmd": "choco install wget -y"}),
    _t("httpx", "httpx-cli", "web", "批量 Web 探测（projectdiscovery）", "https://github.com/projectdiscovery/httpx",
       ["httpx", "-version"], {"method": "go", "package": "httpx",
       "cmd": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"}),
    _t("subfinder", "Subfinder", "web", "子域名发现", "https://github.com/projectdiscovery/subfinder",
       ["subfinder", "-version"], {"method": "go", "package": "subfinder",
       "cmd": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"}),
    _t("assetfinder", "assetfinder", "web", "资产发现", "https://github.com/tomnomnom/assetfinder",
       ["assetfinder", "--help"], {"method": "go", "package": "assetfinder",
       "cmd": "go install github.com/tomnomnom/assetfinder@latest"}),
    _t("amass", "Amass", "web", "攻击面映射", "https://github.com/owasp-amass/amass",
       ["amass", "-version"], {"method": "choco", "package": "amass",
       "cmd": "choco install amass -y"}),
    # 取证
    _t("tshark", "tshark", "forensics", "命令行抓包分析", "https://www.wireshark.org",
       ["tshark", "--version"], {"method": "choco", "package": "wireshark",
       "cmd": "choco install wireshark -y"},
       deps=["npcap"]),
    _t("binwalk", "Binwalk", "forensics", "固件分析", "https://github.com/ReFirmLabs/binwalk",
       ["binwalk", "--version"], {"method": "pip", "package": "binwalk",
       "cmd": "pip install binwalk"}),
    _t("exiftool", "ExifTool", "forensics", "元数据查看", "https://exiftool.org",
       ["exiftool", "-ver"], {"method": "choco", "package": "exiftool",
       "cmd": "choco install exiftool -y"}),
    # 供应链
    _t("syft", "Syft", "supply_chain", "软件物料清单生成", "https://github.com/anchore/syft",
       ["syft", "version"], {"method": "choco", "package": "syft",
       "cmd": "choco install syft -y"}),
    _t("grype", "Grype", "supply_chain", "漏洞扫描器", "https://github.com/anchore/grype",
       ["grype", "version"], {"method": "choco", "package": "grype",
       "cmd": "choco install grype -y"}),
    _t("trivy", "Trivy", "supply_chain", "容器/文件系统/IaC 漏洞扫描", "https://github.com/aquasecurity/trivy",
       ["trivy", "--version"], {"method": "choco", "package": "trivy",
       "cmd": "choco install trivy -y"}),
    # DevSecOps
    _t("semgrep", "Semgrep", "devsecops", "静态代码扫描", "https://semgrep.dev",
       ["semgrep", "--version"], {"method": "pip", "package": "semgrep",
       "cmd": "pip install semgrep"}),
    _t("gitleaks", "Gitleaks", "devsecops", "密钥泄露扫描", "https://github.com/gitleaks/gitleaks",
       ["gitleaks", "version"], {"method": "choco", "package": "gitleaks",
       "cmd": "choco install gitleaks -y"}),
    _t("checkov", "Checkov", "devsecops", "IaC 扫描", "https://www.checkov.io",
       ["checkov", "--version"], {"method": "pip", "package": "checkov",
       "cmd": "pip install checkov"}),
    # 移动
    _t("apktool", "Apktool", "mobile", "APK 反编译", "https://ibotpeaches.github.io/Apktool/",
       ["apktool", "--version"], {"method": "choco", "package": "apktool",
       "cmd": "choco install apktool -y"}),
    _t("jadx", "JADX", "mobile", "Dex 反编译", "https://github.com/skylot/jadx",
       ["jadx", "--version"], {"method": "choco", "package": "jadx",
       "cmd": "choco install jadx -y"}),
    _t("frida", "frida", "mobile", "动态插桩框架", "https://frida.re",
       ["frida", "--version"], {"method": "pip", "package": "frida-tools",
       "cmd": "pip install frida-tools"}),
    _t("mitmproxy", "mitmproxy", "mobile", "中间人代理", "https://mitmproxy.org",
       ["mitmproxy", "--version"], {"method": "pip", "package": "mitmproxy",
       "cmd": "pip install mitmproxy"}),
    # 云
    _t("aws", "AWS CLI", "cloud", "阿里云命令行", "https://aws.amazon.com/cli/",
       ["aws", "--version"], {"method": "choco", "package": "awscli",
       "cmd": "choco install awscli -y"}),
    _t("az", "Azure CLI", "cloud", "Azure 命令行", "https://docs.microsoft.com/cli/azure",
       ["az", "--version"], {"method": "choco", "package": "azure-cli",
       "cmd": "choco install azure-cli -y"}),
    _t("aliyun", "阿里云 CLI", "cloud", "阿里云命令行", "https://github.com/aliyun/aliyun-cli",
       ["aliyun", "version"], {"method": "choco", "package": "aliyun-cli",
       "cmd": "choco install aliyun-cli -y"}),
    # 容器
    _t("docker", "Docker", "container", "容器运行时", "https://www.docker.com",
       ["docker", "--version"], {"method": "choco", "package": "docker-desktop",
       "cmd": "choco install docker-desktop -y"}),
    # 基础环境
    _t("git", "Git", "base", "版本控制", "https://git-scm.com",
       ["git", "--version"], {"method": "choco", "package": "git",
       "cmd": "choco install git -y"}),
    _t("python", "Python", "base", "Python 运行时", "https://www.python.org",
       ["python", "--version"], {"method": "choco", "package": "python",
       "cmd": "choco install python -y"}),
    _t("node", "Node.js", "base", "Node.js 运行时", "https://nodejs.org",
       ["node", "--version"], {"method": "choco", "package": "nodejs",
       "cmd": "choco install nodejs -y"}),
    _t("jq", "jq", "base", "JSON 处理", "https://stedolan.github.io/jq/",
       ["jq", "--version"], {"method": "choco", "package": "jq",
       "cmd": "choco install jq -y"}),
    _t("7z", "7-Zip", "base", "压缩解压", "https://www.7-zip.org",
       ["7z"], {"method": "choco", "package": "7zip",
       "cmd": "choco install 7zip -y"}),
    _t("openssl", "OpenSSL", "base", "加密工具", "https://www.openssl.org",
       ["openssl", "version"], {"method": "choco", "package": "openssl",
       "cmd": "choco install openssl -y"}),
]


# ---------------------------------------------------------------------------
# Python 库
# ---------------------------------------------------------------------------
PYTHON_LIBS: List[Dict[str, Any]] = [
    _t("boto3", "boto3", "cloud_sdk", "AWS SDK for Python", "https://boto3.amazonaws.com",
       ["python", "-c", "import boto3;print(boto3.__version__)"],
       {"method": "pip", "package": "boto3", "cmd": "pip install boto3"}),
    _t("azure-identity", "azure-identity", "cloud_sdk", "Azure 身份库", "https://github.com/Azure/azure-sdk-for-python",
       ["python", "-c", "import azure.identity;print('ok')"],
       {"method": "pip", "package": "azure-identity", "cmd": "pip install azure-identity"}),
    _t("aliyun-python-sdk-core", "aliyun-python-sdk-core", "cloud_sdk", "阿里云 SDK 核心", "https://github.com/aliyun/aliyun-openapi-python-sdk",
       ["python", "-c", "import aliyunsdkcore;print('ok')"],
       {"method": "pip", "package": "aliyun-python-sdk-core",
       "cmd": "pip install aliyun-python-sdk-core"}),
    _t("kubernetes", "kubernetes", "container", "K8s Python 客户端", "https://github.com/kubernetes-client/python",
       ["python", "-c", "import kubernetes;print(kubernetes.__version__)"],
       {"method": "pip", "package": "kubernetes", "cmd": "pip install kubernetes"}),
    _t("docker", "docker SDK", "container", "Docker Python SDK", "https://docker-py.readthedocs.io",
       ["python", "-c", "import docker;print(docker.__version__)"],
       {"method": "pip", "package": "docker", "cmd": "pip install docker"}),
    _t("paramiko", "paramiko", "network", "SSH 协议库", "https://www.paramiko.org",
       ["python", "-c", "import paramiko;print(paramiko.__version__)"],
       {"method": "pip", "package": "paramiko", "cmd": "pip install paramiko"}),
    _t("requests", "requests", "network", "HTTP 库", "https://docs.python-requests.org",
       ["python", "-c", "import requests;print(requests.__version__)"],
       {"method": "pip", "package": "requests", "cmd": "pip install requests"}),
    _t("httpx", "httpx", "network", "异步 HTTP 库", "https://www.python-httpx.org",
       ["python", "-c", "import httpx;print(httpx.__version__)"],
       {"method": "pip", "package": "httpx", "cmd": "pip install httpx"}),
    _t("aiohttp", "aiohttp", "network", "异步 HTTP", "https://docs.aiohttp.org",
       ["python", "-c", "import aiohttp;print(aiohttp.__version__)"],
       {"method": "pip", "package": "aiohttp", "cmd": "pip install aiohttp"}),
    _t("scapy", "scapy", "network", "包操作库", "https://scapy.net",
       ["python", "-c", "import scapy;print(scapy.__version__)"],
       {"method": "pip", "package": "scapy", "cmd": "pip install scapy"}),
    _t("impacket", "impacket (py)", "security", "Impacket 库", "https://github.com/fortra/impacket",
       ["python", "-c", "import impacket;print('ok')"],
       {"method": "pip", "package": "impacket", "cmd": "pip install impacket"}),
    _t("frida", "frida (py)", "security", "frida 绑定", "https://frida.re",
       ["python", "-c", "import frida;print(frida.__version__)"],
       {"method": "pip", "package": "frida", "cmd": "pip install frida"}),
    _t("python-nmap", "python-nmap", "security", "nmap 封装", "https://xael.org/pages/python-nmap-en.html",
       ["python", "-c", "import nmap;print('ok')"],
       {"method": "pip", "package": "python-nmap", "cmd": "pip install python-nmap"}),
    _t("yara-python", "yara-python", "security", "YARA 绑定", "https://github.com/VirusTotal/yara-python",
       ["python", "-c", "import yara;print(yara.__version__)"],
       {"method": "pip", "package": "yara-python", "cmd": "pip install yara-python"}),
    _t("pandas", "pandas", "data", "数据分析", "https://pandas.pydata.org",
       ["python", "-c", "import pandas;print(pandas.__version__)"],
       {"method": "pip", "package": "pandas", "cmd": "pip install pandas"}),
    _t("numpy", "numpy", "data", "数值计算", "https://numpy.org",
       ["python", "-c", "import numpy;print(numpy.__version__)"],
       {"method": "pip", "package": "numpy", "cmd": "pip install numpy"}),
    _t("fastapi", "FastAPI", "web", "Web 框架", "https://fastapi.tiangolo.com",
       ["python", "-c", "import fastapi;print(fastapi.__version__)"],
       {"method": "pip", "package": "fastapi", "cmd": "pip install fastapi"}),
    _t("uvicorn", "uvicorn", "web", "ASGI 服务器", "https://www.uvicorn.org",
       ["python", "-c", "import uvicorn;print(uvicorn.__version__)"],
       {"method": "pip", "package": "uvicorn", "cmd": "pip install uvicorn"}),
    _t("pyyaml", "PyYAML", "misc", "YAML 解析", "https://pyyaml.org",
       ["python", "-c", "import yaml;print(yaml.__version__)"],
       {"method": "pip", "package": "pyyaml", "cmd": "pip install pyyaml"}),
    _t("rich", "rich", "misc", "终端美化", "https://rich.readthedocs.io",
       ["python", "-c", "import rich;print(rich.__version__)"],
       {"method": "pip", "package": "rich", "cmd": "pip install rich"}),
    _t("click", "click", "misc", "CLI 框架", "https://click.palletsprojects.com",
       ["python", "-c", "import click;print(click.__version__)"],
       {"method": "pip", "package": "click", "cmd": "pip install click"}),
    _t("tqdm", "tqdm", "misc", "进度条", "https://tqdm.github.io",
       ["python", "-c", "import tqdm;print(tqdm.__version__)"],
       {"method": "pip", "package": "tqdm", "cmd": "pip install tqdm"}),
    _t("psutil", "psutil", "misc", "系统监控", "https://github.com/giampaolo/psutil",
       ["python", "-c", "import psutil;print(psutil.__version__)"],
       {"method": "pip", "package": "psutil", "cmd": "pip install psutil"}),
]


# ---------------------------------------------------------------------------
# Docker 镜像
# ---------------------------------------------------------------------------
DOCKER_IMAGES: List[Dict[str, Any]] = [
    _t("dvwa", "DVWA", "web_lab", "Damn Vulnerable Web Application", "https://github.com/digininja/DVWA",
       ["docker", "image", "inspect", "vulnerables/web-dvwa"],
       {"method": "docker", "package": "vulnerables/web-dvwa",
       "cmd": "docker pull vulnerables/web-dvwa"}),
    _t("juice-shop", "Juice Shop", "web_lab", "OWASP Juice Shop", "https://owasp.org/www-project-juice-shop/",
       ["docker", "image", "inspect", "bkimminich/juice-shop"],
       {"method": "docker", "package": "bkimminich/juice-shop",
       "cmd": "docker pull bkimminich/juice-shop"}),
    _t("webgoat", "WebGoat", "web_lab", "OWASP WebGoat", "https://owasp.org/www-project-webgoat/",
       ["docker", "image", "inspect", "webgoat/webgoat"],
       {"method": "docker", "package": "webgoat/webgoat",
       "cmd": "docker pull webgoat/webgoat"}),
    _t("bwapp", "bWAPP", "web_lab", "buggy Web App", "https://www.itsecgames.com",
       ["docker", "image", "inspect", "raesene/bwapp"],
       {"method": "docker", "package": "raesene/bwapp",
       "cmd": "docker pull raesene/bwapp"}),
    _t("mutillidae", "Mutillidae", "web_lab", "OWASP Mutillidae II", "https://owasp.org/www-project-mutillidae/",
       ["docker", "image", "inspect", "citizenstig/nowasp"],
       {"method": "docker", "package": "citizenstig/nowasp",
       "cmd": "docker pull citizenstig/nowasp"}),
    _t("metasploitable2", "Metasploitable2", "intranet_lab", "故意脆弱的 Linux", "https://metasploit.com",
       ["docker", "image", "inspect", "tleemcjr/metasploitable2"],
       {"method": "docker", "package": "tleemcjr/metasploitable2",
       "cmd": "docker pull tleemcjr/metasploitable2"}),
    _t("kali", "Kali Linux", "security_tool", "Kali 官方容器", "https://www.kali.org",
       ["docker", "image", "inspect", "kalilinux/kali-rolling"],
       {"method": "docker", "package": "kalilinux/kali-rolling",
       "cmd": "docker pull kalilinux/kali-rolling"}),
    _t("parrot", "Parrot Security", "security_tool", "Parrot 容器", "https://www.parrotsec.org",
       ["docker", "image", "inspect", "parrotsec/security"],
       {"method": "docker", "package": "parrotsec/security",
       "cmd": "docker pull parrotsec/security"}),
    _t("elk", "ELK Stack", "log_analysis", "Elastic + Logstash + Kibana", "https://www.elastic.co",
       ["docker", "image", "inspect", "docker.elastic.co/elasticsearch/elasticsearch"],
       {"method": "docker", "package": "docker.elastic.co/elasticsearch/elasticsearch",
       "cmd": "docker pull docker.elastic.co/elasticsearch/elasticsearch:8.11.0"}),
    _t("wazuh", "Wazuh", "log_analysis", "SIEM 平台", "https://wazuh.com",
       ["docker", "image", "inspect", "wazuh/wazuh"],
       {"method": "docker", "package": "wazuh/wazuh",
       "cmd": "docker pull wazuh/wazuh"}),
    _t("nginx", "nginx", "middleware", "Web 服务器", "https://nginx.org",
       ["docker", "image", "inspect", "nginx"],
       {"method": "docker", "package": "nginx", "cmd": "docker pull nginx"}),
    _t("mysql", "MySQL", "middleware", "MySQL 数据库", "https://www.mysql.com",
       ["docker", "image", "inspect", "mysql"],
       {"method": "docker", "package": "mysql", "cmd": "docker pull mysql"}),
    _t("postgres", "PostgreSQL", "middleware", "PostgreSQL", "https://www.postgresql.org",
       ["docker", "image", "inspect", "postgres"],
       {"method": "docker", "package": "postgres", "cmd": "docker pull postgres"}),
    _t("redis", "Redis", "middleware", "Redis", "https://redis.io",
       ["docker", "image", "inspect", "redis"],
       {"method": "docker", "package": "redis", "cmd": "docker pull redis"}),
]


# ---------------------------------------------------------------------------
# 查询函数
# ---------------------------------------------------------------------------
def get_native_tools() -> List[Dict[str, Any]]:
    return NATIVE_TOOLS


def get_python_libs() -> List[Dict[str, Any]]:
    return PYTHON_LIBS


def get_docker_images() -> List[Dict[str, Any]]:
    return DOCKER_IMAGES


def get_categories() -> Dict[str, str]:
    return dict(TOOL_CATEGORIES)


def get_python_lib_categories() -> Dict[str, str]:
    return dict(PYTHON_LIB_CATEGORIES)


def get_docker_image_categories() -> Dict[str, str]:
    return dict(DOCKER_IMAGE_CATEGORIES)


def find_tool(name: str) -> Dict[str, Any] | None:
    for pool in (NATIVE_TOOLS, PYTHON_LIBS, DOCKER_IMAGES):
        for t in pool:
            if t["name"] == name:
                return t
    return None


def all_tools_grouped() -> Dict[str, List[Dict[str, Any]]]:
    """按分类分组返回原生工具。"""
    out: Dict[str, List[Dict[str, Any]]] = {c: [] for c in TOOL_CATEGORIES}
    for t in NATIVE_TOOLS:
        out.setdefault(t["category"], []).append(t)
    return out
