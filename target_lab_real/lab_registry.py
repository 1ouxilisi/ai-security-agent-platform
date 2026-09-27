# -*- coding: utf-8 -*-
"""
target_lab_real/lab_registry.py — 靶场注册表

维护所有可一键部署靶场的元数据：
  - 分类、难度、描述、官网
  - Docker 镜像名、暴露端口、环境变量
  - 启动命令
"""
from __future__ import annotations

from typing import Any, Dict, List

LAB_CATEGORIES: Dict[str, str] = {
    "web": "Web 漏洞靶场",
    "intranet": "内网渗透靶场",
    "redblue": "红蓝对抗靶场",
    "cloud": "云安全靶场",
    "container": "容器安全靶场",
    "mobile": "移动安全靶场",
    "ics": "工控 IoT 靶场",
    "forensics": "取证分析靶场",
    "log": "日志分析靶场",
    "other": "其他",
}


def _lab(lab_id: str, name: str, category: str, difficulty: str,
         desc: str, website: str, image: str, ports: Dict[int, int],
         env: Dict[str, str] | None = None,
         volumes: Dict[str, str] | None = None,
         health_path: str = "/",
         notes: str = "") -> Dict[str, Any]:
    return {
        "lab_id": lab_id,
        "name": name,
        "category": category,
        "difficulty": difficulty,
        "description": desc,
        "website": website,
        "image": image,
        # host_port -> container_port
        "ports": ports,
        "env": env or {},
        "volumes": volumes or {},
        "health_path": health_path,
        "notes": notes,
    }


LABS: List[Dict[str, Any]] = [
    _lab("dvwa", "DVWA", "web", "低",
         "Damn Vulnerable Web Application，经典 Web 漏洞练习",
         "https://github.com/digininja/DVWA",
         "vulnerables/web-dvwa", {8081: 80},
         notes="默认口令 admin/password"),
    _lab("juice-shop", "Juice Shop", "web", "中",
         "OWASP 官方故意脆弱 Node.js 应用",
         "https://owasp.org/www-project-juice-shop/",
         "bkimminich/juice-shop", {3001: 3000}),
    _lab("webgoat", "WebGoat", "web", "中",
         "OWASP WebGoat Java 漏洞训练",
         "https://owasp.org/www-project-webgoat/",
         "webgoat/webgoat", {8082: 8080}),
    _lab("bwapp", "bWAPP", "web", "低",
         "buggy Web 应用，含 100+ 漏洞",
         "https://www.itsecgames.com",
         "raesene/bwapp", {8083: 80}),
    _lab("mutillidae", "Mutillidae", "web", "低",
         "OWASP Mutillidae II",
         "https://owasp.org/www-project-mutillidae/",
         "citizenstig/nowasp", {8084: 80}),
    _lab("pikachu", "Pikachu", "web", "低",
         "Pikachu 中文 Web 漏洞靶场",
         "https://github.com/we45/pikachu",
         "pikachu/pikachu", {8085: 80}),
    _lab("metasploitable2", "Metasploitable2", "intranet", "高",
         "故意脆弱的 Linux，大量服务暴露",
         "https://sourceforge.net/projects/metasploitable/",
         "tleemcjr/metasploitable2", {
             2121: 21, 2222: 22, 2323: 23, 2525: 25, 5353: 53,
             8086: 80, 1399: 139, 4455: 445, 3307: 3306, 5433: 5432,
         }, notes="多端口暴露，慎用"),
    _lab("elk", "ELK Stack", "log", "中",
         "Elasticsearch + Logstash + Kibana",
         "https://www.elastic.co",
         "docker.elastic.co/elasticsearch/elasticsearch:8.11.0",
         {9200: 9200, 5601: 5601},
         env={"discovery.type": "single-node",
              "xpack.security.enabled": "false"}),
    _lab("wazuh", "Wazuh", "log", "高",
         "开源 SIEM/XDR 平台",
         "https://wazuh.com",
         "wazuh/wazuh", {443: 443, 1514: 1514, 1515: 1515, 1516: 1516}),
    _lab("vulhub", "Vulhub", "other", "中",
         "基于 Docker-Compose 的漏洞环境集合",
         "https://vulhub.org",
         "vulhub/vulhub", {8087: 80},
         notes="需进入具体漏洞目录执行 docker-compose up"),
    _lab("kali", "Kali Linux", "other", "中",
         "Kali 官方容器（仅命令行）",
         "https://www.kali.org",
         "kalilinux/kali-rolling", {},
         notes="无 Web 端口，用于工具练习"),
]


def list_labs() -> List[Dict[str, Any]]:
    return LABS


def get_lab(lab_id: str) -> Dict[str, Any] | None:
    for l in LABS:
        if l["lab_id"] == lab_id:
            return l
    return None


def list_categories() -> Dict[str, str]:
    return dict(LAB_CATEGORIES)


def labs_by_category() -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {c: [] for c in LAB_CATEGORIES}
    for l in LABS:
        out.setdefault(l["category"], []).append(l)
    return out
