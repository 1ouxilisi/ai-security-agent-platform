# -*- coding: utf-8 -*-
"""
asset_management.fingerprint - 资产指纹库

功能：
    - 内置 200+ 条指纹规则（Web 服务器 / 数据库 / 中间件 / 邮件 / 文件共享 /
      远程管理 / 操作系统 / 网络设备 / 安全设备 / IoT / Web 应用 / 框架 / CMS）
    - 根据扫描结果（端口 / 服务 / 横幅 / 证书 / HTTP 头 / 页面标题）匹配指纹
    - 识别服务类型与版本、操作系统、Web 应用 / 框架 / CMS

数据库表：am_fingerprint_rules
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.database import db
from utils.logger import log

# --------------------------------------------------------------------------- #
# 内置指纹规则：(category, name, match_type, match_pattern, version_pattern, desc)
#   category      : service / os / device / application
#   match_type    : port / banner / cert / title / header
#   match_pattern : 端口号或正则表达式（对 banner/header/title 做大小写不敏感匹配）
#   version_pattern : 从 banner 中提取版本号的正则（可空）
# --------------------------------------------------------------------------- #
BUILTIN_RULES: List[tuple] = [
    # ===================== Web 服务器 (service) =====================
    ("service", "Nginx", "banner", r"nginx(/\d+[\w\.]*)?", r"nginx/(\S+)", "Nginx Web服务器"),
    ("service", "Apache HTTPD", "banner", r"Apache(?:/(\S+))?", r"Apache/(\S+)", "Apache HTTP服务器"),
    ("service", "Apache Tomcat", "banner", r"Apache-Coyote", r"Apache-Coyote/(\S+)", "Tomcat中间件"),
    ("service", "Tomcat", "banner", r"Tomcat(?:/(\S+))?", r"Tomcat/(\S+)", "Apache Tomcat应用服务器"),
    ("service", "IIS", "banner", r"Microsoft-IIS/(\S+)", r"Microsoft-IIS/(\S+)", "微软IIS Web服务器"),
    ("service", "OpenResty", "banner", r"openresty", r"openresty/(\S+)", "OpenResty网关"),
    ("service", "LiteSpeed", "banner", r"LiteSpeed", r"LiteSpeed/(\S+)", "LiteSpeed Web服务器"),
    ("service", "Caddy", "banner", r"Caddy", r"Caddy/(\S+)", "Caddy Web服务器"),
    ("service", "Varnish", "banner", r"varnish", r"varnish/(\S+)", "Varnish缓存代理"),
    ("service", "HAProxy", "banner", r"HAProxy", r"HAProxy/(\S+)", "HAProxy负载均衡"),
    ("service", "ATS", "banner", r"ATS", r"Traffic-Server", "Apache Traffic Server"),
    ("service", "Lighttpd", "banner", r"lighttpd", r"lighttpd/(\S+)", "Lighttpd Web服务器"),
    ("service", "Jetty", "banner", r"Jetty", r"Jetty\((\S+)\)", "Jetty Servlet容器"),
    ("service", "JBoss", "banner", r"JBoss", r"JBoss\s*(\S+)", "JBoss应用服务器"),
    ("service", "WebLogic", "banner", r"WebLogic", r"WebLogic Server\s*(\S+)", "Oracle WebLogic"),
    ("service", "WebSphere", "banner", r"WebSphere", r"WebSphere\s*Application\s*Server", "IBM WebSphere"),
    ("service", "GlassFish", "banner", r"GlassFish", r"GlassFish\s*Server\s*Open\s*Edition\s*(\S+)", "GlassFish应用服务器"),
    ("service", "Undertow", "banner", r"Undertow", r"Undertow/(\S+)", "Undertow Web服务器"),
    ("service", "Gunicorn", "header", r"Server:\s*gunicorn", r"gunicorn/(\S+)", "Gunicorn WSGI服务器"),
    ("service", "uWSGI", "header", r"Server:\s*uWSGI", r"uWSGI/(\S+)", "uWSGI应用服务器"),
    ("service", "WSGIServer", "banner", r"WSGIServer", r"BaseHTTPServer", "Python WSGI开发服务器"),
    ("service", "WEBrick", "banner", r"WEBrick", r"WEBrick/(\S+)", "Ruby WEBrick服务器"),
    ("service", "Tengine", "banner", r"Tengine", r"Tengine", "Tengine(阿里Nginx分支)"),
    ("service", "BFE", "banner", r"BFE", r"BFE/", "百度BFE负载均衡"),
    ("service", "ATS Edge", "header", r"Via:\s*(\S+)\s*\(ApacheTrafficServer", r"ApacheTrafficServer/(\S+)", "ATS边缘节点"),

    # ===================== 数据库 (service) =====================
    ("service", "MySQL", "banner", r"MySQL", r"MySQL\s*(\d+\.\d+)", "MySQL数据库"),
    ("service", "MariaDB", "banner", r"MariaDB", r"MariaDB\s*(\d+\.\d+)", "MariaDB数据库"),
    ("service", "PostgreSQL", "banner", r"PostgreSQL", r"PostgreSQL\s*(\d+\.\d+)", "PostgreSQL数据库"),
    ("service", "Microsoft SQL Server", "banner", r"Microsoft SQL Server", r"SQL Server\s*(\S+)", "SQL Server数据库"),
    ("service", "Oracle TNS", "banner", r"TNSLSNR", r"TNSLSNR\s*for\s*(\S+)", "Oracle监听服务"),
    ("service", "Redis", "banner", r"redis", r"redis_version:(\S+)", "Redis缓存数据库"),
    ("service", "MongoDB", "banner", r"MongoDB", r"MongoDB\s*(\d+\.\d+)", "MongoDB文档数据库"),
    ("service", "Elasticsearch", "banner", r"elastic", r"Elasticsearch/(\S+)", "Elasticsearch搜索引擎"),
    ("service", "Memcached", "banner", r"memcached", r"memcached\s*(\S+)", "Memcached缓存"),
    ("service", "Cassandra", "banner", r"Cassandra", r"Cassandra", "Cassandra列式数据库"),
    ("service", "CouchDB", "banner", r"CouchDB", r"CouchDB/(\S+)", "CouchDB数据库"),
    ("service", "Neo4j", "banner", r"neo4j", r"neo4j/(\S+)", "Neo4j图数据库"),
    ("service", "InfluxDB", "banner", r"influxdb", r"InfluxDB/(\S+)", "InfluxDB时序数据库"),
    ("service", "RethinkDB", "banner", r"RethinkDB", r"RethinkDB", "RethinkDB数据库"),
    ("service", "DB2", "banner", r"DB2", r"DB2/", "IBM DB2数据库"),
    ("service", "Sybase", "banner", r"Sybase", r"Sybase", "Sybase数据库"),
    ("service", "SQLite", "banner", r"SQLite", r"SQLite\s*(\d+\.\d+)", "SQLite嵌入式数据库"),
    ("service", "ClickHouse", "banner", r"ClickHouse", r"ClickHouse\s*(\S+)", "ClickHouse分析型数据库"),
    ("service", "TiDB", "banner", r"TiDB", r"TiDB", "TiDB分布式数据库"),
    ("service", "OceanBase", "banner", r"OceanBase", r"OceanBase", "OceanBase分布式数据库"),

    # ===================== 中间件 (service) =====================
    ("service", "Kafka", "banner", r"kafka", r"kafka", "Kafka消息队列"),
    ("service", "RabbitMQ", "banner", r"RabbitMQ", r"RabbitMQ", "RabbitMQ消息队列"),
    ("service", "ActiveMQ", "banner", r"ActiveMQ", r"ActiveMQ/", "ActiveMQ消息队列"),
    ("service", "RocketMQ", "banner", r"RocketMQ", r"RocketMQ", "RocketMQ消息队列"),
    ("service", "NATS", "banner", r"NATS", r"NATS", "NATS消息系统"),
    ("service", "Zookeeper", "banner", r"zookeeper", r"zookeeper\s*version", "Zookeeper协调服务"),
    ("service", "etcd", "banner", r"etcd", r"etcd", "etcd键值存储"),
    ("service", "Consul", "banner", r"Consul", r"Consul\s*v(\S+)", "Consul服务发现"),
    ("service", "Nacos", "banner", r"Nacos", r"Nacos", "Nacos注册配置中心"),
    ("service", "Eureka", "banner", r"Eureka", r"Eureka", "Netflix Eureka注册中心"),
    ("service", "Spring Boot", "header", r"X-Application-Context", r"", "Spring Boot Actuator"),
    ("service", "Django", "header", r"Set-Cookie:\s*csrftoken", r"", "Django框架"),
    ("service", "Express", "header", r"X-Powered-By:\s*Express", r"Express", "Express.js框架"),
    ("service", "PHP-FPM", "banner", r"php-fpm", r"php-fpm", "PHP FastCGI进程管理器"),
    ("service", "gRPC", "banner", r"grpc", r"grpc", "gRPC服务"),

    # ===================== 邮件服务 (service) =====================
    ("service", "Postfix", "banner", r"Postfix", r"Postfix", "Postfix MTA"),
    ("service", "Sendmail", "banner", r"Sendmail", r"Sendmail\s*(\S+)", "Sendmail MTA"),
    ("service", "Exim", "banner", r"Exim", r"Exim\s*(\S+)", "Exim MTA"),
    ("service", "Dovecot", "banner", r"Dovecot", r"Dovecot", "Dovecot POP3/IMAP"),
    ("service", "Courier", "banner", r"Courier", r"Courier", "Courier邮件服务"),
    ("service", "Exchange", "banner", r"Exchange", r"Microsoft\s*Exchange", "Microsoft Exchange"),
    ("service", "hMailServer", "banner", r"hMailServer", r"hMailServer", "hMailServer邮件"),
    ("service", "Zimbra", "banner", r"Zimbra", r"Zimbra", "Zimbra协作邮件"),
    ("service", "IceWarp", "banner", r"IceWarp", r"IceWarp", "IceWarp邮件服务器"),

    # ===================== 文件共享 (service) =====================
    ("service", "vsftpd", "banner", r"vsftpd", r"vsftpd\s*(\S+)", "vsftpd FTP服务器"),
    ("service", "ProFTPD", "banner", r"ProFTPD", r"ProFTPD\s*(\S+)", "ProFTPD FTP服务器"),
    ("service", "Pure-FTPd", "banner", r"Pure-FTPd", r"Pure-FTPd", "Pure-FTPd FTP服务器"),
    ("service", "FileZilla", "banner", r"FileZilla", r"FileZilla", "FileZilla FTP服务端"),
    ("service", "Samba", "banner", r"Samba", r"Samba\s*(\S+)", "Samba SMB文件共享"),
    ("service", "NFS", "banner", r"NFS", r"NFS", "NFS网络文件系统"),
    ("service", "ProFTPD mod_sftp", "banner", r"mod_sftp", r"mod_sftp", "ProFTPD SFTP模块"),
    ("service", "MinIO", "banner", r"MinIO", r"MinIO", "MinIO对象存储"),

    # ===================== 远程管理 (service) =====================
    ("service", "OpenSSH", "banner", r"OpenSSH", r"OpenSSH[_\s](\S+)", "OpenSSH SSH服务"),
    ("service", "Dropbear", "banner", r"Dropbear", r"dropbear", "Dropbear SSH"),
    ("service", "telnetd", "banner", r"telnet", r"telnet", "Telnet远程终端"),
    ("service", "Microsoft RDP", "banner", r"Terminal Service", r"", "微软远程桌面RDP"),
    ("service", "VNC", "banner", r"VNC", r"VNC", "VNC远程桌面"),
    ("service", "xrdp", "banner", r"xrdp", r"xrdp", "Linux xrdp服务"),
    ("service", "Guacamole", "banner", r"Guacamole", r"Guacamole", "Apache Guacamole网关"),
    ("service", "TeamViewer", "banner", r"TeamViewer", r"TeamViewer", "TeamViewer远程"),
    ("service", "NoMachine", "banner", r"NoMachine", r"NoMachine", "NoMachine远程桌面"),

    # ===================== 操作系统 (os) =====================
    ("os", "Linux Ubuntu", "banner", r"Ubuntu", r"Ubuntu\s*(\S+)", "Ubuntu Linux"),
    ("os", "Linux Debian", "banner", r"Debian", r"Debian\s*(\S+)", "Debian Linux"),
    ("os", "Linux CentOS", "banner", r"CentOS", r"CentOS\s*(\S+)", "CentOS Linux"),
    ("os", "Linux RHEL", "banner", r"Red Hat", r"Red\s*Hat", "Red Hat Enterprise Linux"),
    ("os", "Linux Alpine", "banner", r"Alpine", r"Alpine", "Alpine Linux"),
    ("os", "Linux kernel 2.6", "banner", r"Linux 2\.6", r"Linux\s*(2\.6\.\S+)", "Linux内核2.6"),
    ("os", "Linux kernel 3.x", "banner", r"Linux 3\.", r"Linux\s*(3\.\d+)", "Linux内核3.x"),
    ("os", "Linux kernel 4.x", "banner", r"Linux 4\.", r"Linux\s*(4\.\d+)", "Linux内核4.x"),
    ("os", "Linux kernel 5.x", "banner", r"Linux 5\.", r"Linux\s*(5\.\d+)", "Linux内核5.x"),
    ("os", "Windows XP", "banner", r"Windows 5\.1", r"Windows\s*(\d+\.\d+)", "Windows XP"),
    ("os", "Windows 7", "banner", r"Windows 6\.1", r"", "Windows 7"),
    ("os", "Windows 10", "banner", r"Windows 10", r"Windows\s*(\S+)", "Windows 10"),
    ("os", "Windows Server 2008", "banner", r"Windows Server 2008", r"", "Windows Server 2008"),
    ("os", "Windows Server 2012", "banner", r"Windows Server 2012", r"", "Windows Server 2012"),
    ("os", "Windows Server 2016", "banner", r"Windows Server 2016", r"", "Windows Server 2016"),
    ("os", "Windows Server 2019", "banner", r"Windows Server 2019", r"", "Windows Server 2019"),
    ("os", "Windows Server 2022", "banner", r"Windows Server 2022", r"", "Windows Server 2022"),
    ("os", "FreeBSD", "banner", r"FreeBSD", r"FreeBSD\s*(\S+)", "FreeBSD操作系统"),
    ("os", "OpenBSD", "banner", r"OpenBSD", r"OpenBSD", "OpenBSD操作系统"),
    ("os", "macOS", "banner", r"Mac OS X", r"Mac\s*OS\s*X", "苹果macOS"),
    ("os", "VMware ESXi", "banner", r"ESXi", r"VMware\s*ESXi", "VMware ESXi虚拟化"),
    ("os", "Android", "banner", r"Android", r"Android\s*(\d+)", "Android移动系统"),
    ("os", "iOS", "banner", r"iPhone OS", r"iPhone\s*OS", "苹果iOS系统"),

    # ===================== 网络设备 (device) =====================
    ("device", "Cisco IOS", "banner", r"Cisco IOS", r"Cisco\s*IOS", "Cisco网络设备"),
    ("device", "Cisco ASA", "banner", r"ASAv", r"Cisco\s*Adaptative", "Cisco ASA防火墙"),
    ("device", "Huawei VRP", "banner", r"Huawei", r"VRP\s*(\S+)", "华为网络设备"),
    ("device", "H3C Comware", "banner", r"H3C", r"Comware", "H3C网络设备"),
    ("device", "Juniper Junos", "banner", r"JUNOS", r"JUNOS", "Juniper路由器"),
    ("device", "Fortinet FortiGate", "banner", r"FortiGate", r"FortiGate", "飞塔防火墙"),
    ("device", "Palo Alto", "banner", r"Palo Alto", r"Palo\s*Alto", "Palo Alto防火墙"),
    ("device", "F5 BIG-IP", "banner", r"BIG-IP", r"BIG-IP", "F5负载均衡"),
    ("device", "NetScaler", "banner", r"NetScaler", r"NetScaler", "Citrix NetScaler"),
    ("device", "A10 ACOS", "banner", r"AX\s*Series", r"ACOS", "A10负载均衡"),
    ("device", "TP-Link", "banner", r"TP-Link", r"TP-Link", "TP-Link家用路由器"),
    ("device", "D-Link", "banner", r"D-Link", r"D-Link", "D-Link网络设备"),
    ("device", "MikroTik RouterOS", "banner", r"RouterOS", r"RouterOS", "MikroTik路由系统"),
    ("device", "Ubiquiti UniFi", "banner", r"UniFi", r"UniFi", "Ubiquiti UniFi设备"),
    ("device", "OpenWrt", "banner", r"OpenWrt", r"OpenWrt", "OpenWrt嵌入式系统"),
    ("device", "PfSense", "banner", r"pfSense", r"pfSense", "PfSense防火墙"),
    ("device", "OPNsense", "banner", r"OPNsense", r"OPNsense", "OPNsense防火墙"),

    # ===================== 安全设备 (device) =====================
    ("device", "Snort IDS", "banner", r"Snort", r"Snort", "Snort入侵检测"),
    ("device", "Suricata", "banner", r"Suricata", r"Suricata", "Suricata NIDS"),
    ("device", "ModSecurity", "header", r"Mod_Security", r"ModSecurity", "ModSecurity WAF"),
    ("device", "Nginx WAF", "banner", r"NAXSI", r"NAXSI", "NAXSI WAF"),
    ("device", "Sangfor EDR", "banner", r"Sangfor", r"Sangfor", "深信服安全设备"),
    ("device", "奇安信网神", "banner", r"QAX", r"QAX", "奇安信安全设备"),
    ("device", "绿盟 NSFOCUS", "banner", r"NSFOCUS", r"NSFOCUS", "绿盟安全设备"),
    ("device", "安恒 DAS", "banner", r"DBAPPSecurity", r"DBAPPSecurity", "安恒安全设备"),
    ("device", "Check Point", "banner", r"Check Point", r"Check\s*Point", "Check Point防火墙"),
    ("device", "SonicWall", "banner", r"SonicWALL", r"SonicWALL", "SonicWall防火墙"),
    ("device", "WatchGuard", "banner", r"WatchGuard", r"WatchGuard", "WatchGuard防火墙"),

    # ===================== IoT 设备 (device) =====================
    ("device", "Huawei IPC", "banner", r"Huawei-IPC", r"Huawei", "华为网络摄像机"),
    ("device", "Hikvision DVR", "banner", r"Hikvision", r"Hikvision", "海康威视DVR"),
    ("device", "Dahua IPC", "banner", r"Dahua", r"Dahua", "大华摄像机"),
    ("device", "Axis Camera", "banner", r"Axis", r"AXIS", "Axis网络摄像机"),
    ("device", "TP-Link IPC", "banner", r"TP-LINK IP-CAM", r"TP-LINK", "TP-Link摄像头"),
    ("device", "Belkin WeMo", "banner", r"Belkin", r"Belkin", "Belkin智能家居"),
    ("device", " Philips Hue", "banner", r"Hue", r"Philips", "飞利浦Hue智能灯"),
    ("device", "MQTT Broker", "banner", r"MQTT", r"MQTT", "MQTT物联网消息代理"),
    ("device", "Modbus", "banner", r"Modbus", r"Modbus", "Modbus工业协议"),
    ("device", "Siemens S7", "banner", r"S7Comm", r"SIEMENS", "西门子S7 PLC"),
    ("device", "Schneider PLC", "banner", r"Schneider", r"Schneider", "施耐德PLC"),
    ("device", "Bosch Security", "banner", r"BOSCH", r"BOSCH", "博世安防设备"),
    ("device", "VxWorks", "banner", r"VxWorks", r"VxWorks\s*(\S+)", "VxWorks实时系统"),
    ("device", "BusyBox", "banner", r"BusyBox", r"BusyBox\s*(\S+)", "BusyBox嵌入式环境"),
    ("device", "Lighttpd IoT", "banner", r"GoAhead-Webs", r"GoAhead", "GoAhead嵌入式Web"),

    # ===================== Web 应用 / 框架 (application) =====================
    ("application", "WordPress", "banner", r"wp-content", r"", "WordPress CMS"),
    ("application", "Drupal", "banner", r"Drupal", r"Drupal\s*(\S+)", "Drupal CMS"),
    ("application", "Joomla", "banner", r"Joomla", r"Joomla!", "Joomla CMS"),
    ("application", "Discuz", "banner", r"Discuz", r"Discuz!", "Discuz论坛"),
    ("application", "phpBB", "banner", r"phpBB", r"phpBB", "phpBB论坛"),
    ("application", "DedeCMS", "banner", r"DedeCMS", r"DedeCMS", "织梦DedeCMS"),
    ("application", "EmpireCMS", "banner", r"EmpireCMS", r"EmpireCMS", "帝国CMS"),
    ("application", "PHPCMS", "banner", r"phpcms", r"PHPCMS", "PHPCMS"),
    ("application", "ThinkPHP", "banner", r"ThinkPHP", r"ThinkPHP", "ThinkPHP框架"),
    ("application", "Laravel", "header", r"Set-Cookie:\s*laravel_session", r"", "Laravel PHP框架"),
    ("application", "Symfony", "header", r"Set-Cookie:\s*symfony", r"", "Symfony PHP框架"),
    ("application", "CodeIgniter", "banner", r"CodeIgniter", r"CodeIgniter", "CodeIgniter框架"),
    ("application", "Yii", "banner", r"Yii\s", r"Yii", "Yii PHP框架"),
    ("application", "Django Admin", "title", r"Django site admin", r"", "Django管理后台"),
    ("application", "Flask", "header", r"Werkzeug", r"Werkzeug", "Flask/Werkzeug"),
    ("application", "Ruby on Rails", "header", r"X-Powered-By:\s*Phusion", r"", "Ruby on Rails"),
    ("application", "Laravel Nova", "banner", r"nova", r"", "Laravel Nova后台"),
    ("application", "Shiro", "header", r"rememberMe=deleteMe", r"", "Apache Shiro"),
    ("application", "Struts2", "banner", r"Struts", r"Struts", "Apache Struts2"),
    ("application", "Spring Framework", "header", r"X-Application-Context", r"", "Spring Framework"),
    ("application", "Jenkins", "banner", r"Jenkins", r"Jenkins\s*(\S+)", "Jenkins CI/CD"),
    ("application", "GitLab", "banner", r"GitLab", r"GitLab", "GitLab代码托管"),
    ("application", "Gitea", "banner", r"Gitea", r"Gitea", "Gitea代码托管"),
    ("application", "Grafana", "banner", r"Grafana", r"Grafana", "Grafana监控面板"),
    ("application", "Kibana", "banner", r"Kibana", r"Kibana", "Kibana日志分析"),
    ("application", "Zabbix", "banner", r"Zabbix", r"Zabbix", "Zabbix监控系统"),
    ("application", "Nagios", "banner", r"Nagios", r"Nagios", "Nagios监控"),
    ("application", "Prometheus", "banner", r"Prometheus", r"Prometheus", "Prometheus监控"),
    ("application", "Confluence", "banner", r"Confluence", r"Confluence", "Atlassian Confluence"),
    ("application", "Jira", "banner", r"JIRA", r"JIRA", "Atlassian Jira"),
    ("application", "phpMyAdmin", "banner", r"phpMyAdmin", r"phpMyAdmin", "phpMyAdmin管理工具"),
    ("application", "Adminer", "banner", r"Adminer", r"Adminer", "Adminer数据库管理"),
    ("application", "Webmin", "banner", r"Webmin", r"Webmin", "Webmin系统管理"),
    ("application", "PHPMyWind", "banner", r"PHPMyWind", r"", "PHPMyWind建站"),
    ("application", "Magento", "banner", r"Magento", r"Magento", "Magento电商"),
    ("application", "Shopify", "header", r"X-Shopify-Stage", r"", "Shopify电商"),
    ("application", "Drupal CMS", "banner", r"X-Generator:\s*Drupal", r"", "Drupal CMS"),
    ("application", "OpenCart", "banner", r"OpenCart", r"OpenCart", "OpenCart电商"),
    ("application", "PrestaShop", "banner", r"PrestaShop", r"PrestaShop", "PrestaShop电商"),
    ("application", "Liferay", "banner", r"Liferay", r"Liferay", "Liferay门户"),
    ("application", "Adobe AEM", "banner", r"CQApache", r"CQ", "Adobe Experience Manager"),
    ("application", "Nacos Console", "banner", r"nacos", r"Nacos", "Nacos控制台"),
    ("application", "SkyWalking", "banner", r"SkyWalking", r"SkyWalking", "SkyWalking APM"),
    ("application", "SonarQube", "banner", r"SonarQube", r"SonarQube", "SonarQube代码质量"),
    ("application", "Harbor", "banner", r"Harbor", r"Harbor", "Harbor镜像仓库"),
    ("application", "Portainer", "banner", r"Portainer", r"Portainer", "Portainer容器管理"),
    ("application", "Cockpit", "banner", r"cockpit", r"Project\s*Cockpit", "Cockpit服务器管理"),
    ("application", "Ansible AWX", "banner", r"AWX", r"AWX", "Ansible AWX/Tower"),
    ("application", "Rundeck", "banner", r"Rundeck", r"Rundeck", "Rundeck运维自动化"),
    ("application", "MantisBT", "banner", r"Mantis", r"Mantis", "Mantis缺陷跟踪"),
    ("application", "Redmine", "banner", r"Redmine", r"Redmine", "Redmine项目管理"),
    ("application", "Owncloud", "banner", r"ownCloud", r"ownCloud", "ownCloud网盘"),
    ("application", "Nextcloud", "banner", r"Nextcloud", r"Nextcloud", "Nextcloud网盘"),
    ("application", "Seafile", "banner", r"Seafile", r"Seafile", "Seafile网盘"),
    ("application", "Zammad", "banner", r"Zammad", r"Zammad", "Zammad客服系统"),
    ("application", "OTRS", "banner", r"OTRS", r"OTRS", "OTRS工单系统"),
    ("application", "Mattermost", "banner", r"Mattermost", r"Mattermost", "Mattermost聊天"),
    ("application", "Rocket.Chat", "banner", r"Rocket\.Chat", r"Rocket\.Chat", "Rocket.Chat"),
    ("application", "Discourse", "banner", r"discourse", r"Discourse", "Discourse论坛"),
    ("application", "NodeBB", "banner", r"NodeBB", r"NodeBB", "NodeBB论坛"),
    ("application", "Typecho", "banner", r"Typecho", r"Typecho", "Typecho博客"),
    ("application", "Halo", "banner", r"halo", r"Halo", "Halo博客系统"),
    ("application", "Gridea", "banner", r"Gridea", r"Gridea", "Gridea静态博客"),
    ("application", "Vue.js SPA", "header", r"X-Powered-By:\s*Vite", r"", "Vue/Vite前端应用"),
    ("application", "React SPA", "banner", r"react", r"", "React单页应用"),
    ("application", "Next.js", "header", r"X-Powered-By:\s*Next\.js", r"Next\.js", "Next.js框架"),
    ("application", "Nuxt.js", "header", r"X-Nuxt-State", r"", "Nuxt.js框架"),
    ("application", "ASP.NET", "header", r"X-Powered-By:\s*ASP\.NET", r"ASP\.NET", "微软ASP.NET"),
    ("application", "ASP.NET MVC", "header", r"X-AspNet-Version", r"ASP\.NET", "ASP.NET MVC"),
    ("application", "JSP", "header", r"Set-Cookie:\s*JSESSIONID", r"", "Java JSP应用"),
    ("application", "Tomcat Manager", "title", r"Apache Tomcat", r"", "Tomcat管理后台"),
    ("application", "WebLogic Console", "title", r"WebLogic Server", r"", "WebLogic控制台"),
    ("application", "WebSphere Console", "title", r"WebSphere", r"", "WebSphere控制台"),
    ("application", "Resin", "banner", r"Resin", r"Resin", "Caucho Resin"),
    ("application", "JBoss Console", "title", r"JBoss", r"", "JBoss管理控制台"),
    ("application", "OpenAM", "banner", r"OpenAM", r"OpenAM", "OpenAM身份认证"),
    ("application", "Keycloak", "banner", r"Keycloak", r"Keycloak", "Keycloak单点登录"),
    ("application", "Casdoor", "banner", r"Casdoor", r"Casdoor", "Casdoor身份认证"),
    ("application", "Apache APISIX", "banner", r"apisix", r"apisix", "Apache APISIX网关"),
    ("application", "Kong Gateway", "banner", r"Kong", r"Kong/", "Kong API网关"),
    ("application", "Zuul", "banner", r"Zuul", r"Zuul", "Netflix Zuul网关"),
    ("application", "Traefik", "banner", r"Traefik", r"Traefik", "Traefik反向代理"),
    ("application", "Envoy", "banner", r"envoy", r"envoy", "Envoy代理"),
    ("application", "Orange GW", "banner", r"orange", r"Orange", "Orange API网关"),
    ("application", "YApi", "banner", r"yapi", r"yapi", "YApi接口管理"),
    ("application", "Swagger UI", "banner", r"Swagger UI", r"", "Swagger接口文档"),
    ("application", "Knife4j", "banner", r"knife4j", r"knife4j", "Knife4j文档"),
    ("application", "Druid Console", "banner", r"Druid Stat", r"Druid", "Druid监控页"),
    ("application", "Spring Cloud", "banner", r"spring cloud", r"", "Spring Cloud微服务"),
    ("application", "ElasticJob", "banner", r"Elastic-Job", r"", "Elastic-Job调度"),
    ("application", "XXL-Job", "banner", r"xxl-job", r"xxl-job", "XXL-Job调度中心"),
    ("application", "PowerJob", "banner", r"powerjob", r"PowerJob", "PowerJob调度"),
    ("application", "SeaTable", "banner", r"Seafile", r"", "SeaTable表格"),
    ("application", "Jupyter", "banner", r"Jupyter", r"Jupyter", "Jupyter Notebook"),
    ("application", "Grafana Loki", "banner", r"Loki", r"loki", "Grafana Loki日志"),
    ("application", "WordPress xmlrpc", "banner", r"xmlrpc\.php", r"", "WordPress XMLRPC"),
    ("application", "PHPMyAdmin setup", "title", r"phpMyAdmin", r"", "phpMyAdmin安装页"),
    ("application", "Nacos unauth", "banner", r"/nacos/v1/auth", r"", "Nacos未授权接口"),
    ("application", "Druid unauth", "banner", r"/druid/index", r"", "Druid未授权监控"),
    ("application", "Spring Actuator", "banner", r"/actuator", r"", "Spring Actuator端点"),
    ("application", "Envoy admin", "banner", r"/stats", r"", "Envoy管理接口"),
    ("application", "Docker Registry", "banner", r"Docker-Distribution", r"Docker-Distribution", "Docker镜像仓库"),
    ("application", "etcd dashboard", "banner", r"etcdkeeper", r"etcdkeeper", "etcd可视化工具"),
    ("application", "CouchDB _utils", "banner", r"_utils", r"", "CouchDB Fauxton界面"),
    ("application", "Mongo Express", "banner", r"Mongo Express", r"MongoExpress", "MongoDB Web管理"),
    ("application", "Redis Commander", "banner", r"Redis Commander", r"", "Redis Web管理"),
    ("application", "RabbitMQ Manager", "banner", r"RabbitMQ Management", r"", "RabbitMQ管理界面"),
    ("application", "Kafka Manager", "banner", r"kafka-manager", r"", "Kafka管理工具"),
    ("application", "Zookeeper Admin", "banner", r"ZooKeeper\s*Admin", r"", "Zookeeper管理"),
    ("application", "MinIO Console", "banner", r"MinIO Browser", r"", "MinIO控制台"),
    ("application", "MinIO Admin", "banner", r"MinIO\s*Server", r"MinIO", "MinIO服务"),
    ("application", "Harbor UI", "banner", r"harbor-portal", r"", "Harbor镜像仓库界面"),
    ("application", "GitLab Runner", "banner", r"gitlab-runner", r"", "GitLab Runner"),
    ("application", "Grafana Admin", "title", r"Grafana", r"", "Grafana登录页"),
    ("application", "Kibana Console", "title", r"Kibana", r"", "Kibana控制台"),
    ("application", "Elasticsearch Head", "banner", r"elasticsearch-head", r"", "ES Head插件"),
    ("application", "Cerebro ES", "banner", r"cerebro", r"cerebro", "Elasticsearch Cerebro"),
    ("application", "Headscale", "banner", r"Headscale", r"Headscale", "Headscale控制端"),
    ("application", "WireGuard", "banner", r"WireGuard", r"WireGuard", "WireGuard VPN"),
    ("application", "OpenVPN", "banner", r"OpenVPN", r"OpenVPN", "OpenVPN服务"),
    ("application", "StrongSwan", "banner", r"strongSwan", r"strongSwan", "StrongSwan VPN"),
    ("application", "IPsec VPN", "banner", r"IPsec", r"IPsec", "IPsec VPN服务"),
    ("application", "Tailscale", "banner", r"Tailscale", r"Tailscale", "Tailscale组网"),
    ("application", "FRP", "banner", r"frps", r"frp", "FRP内网穿透"),
    ("application", "NGROK", "banner", r"ngrok", r"ngrok", "NGROK内网穿透"),
    ("application", "Stunnel", "banner", r"stunnel", r"stunnel", "Stunnel TLS隧道"),
    ("application", "HAProxy Stats", "banner", r"HAProxy Stats", r"", "HAProxy统计页"),
    ("application", "Keepalived", "banner", r"Keepalived", r"Keepalived", "Keepalived VIP管理"),
    ("application", "Corosync", "banner", r"corosync", r"corosync", "Corosync集群"),
    ("application", "Pacemaker", "banner", r"Pacemaker", r"Pacemaker", "Pacemaker集群资源"),
    ("application", "Heartbeat", "banner", r"Heartbeat", r"Heartbeat", "Heartbeat高可用"),
    ("application", "Prometheus Pushgateway", "banner", r"Pushgateway", r"", "Prometheus推送网关"),
    ("application", "Alertmanager", "banner", r"Alertmanager", r"Alertmanager", "Prometheus告警管理"),
    ("application", "Grafana Loki", "banner", r"loki", r"", "Loki日志聚合"),
    ("application", "Netdata", "banner", r"netdata", r"netdata", "Netdata监控"),
    ("application", "Telegraf", "banner", r"telegraf", r"telegraf", "Telegraf采集器"),
    ("application", "Node Exporter", "banner", r"node_exporter", r"", "Prometheus节点采集"),
    ("application", "cAdvisor", "banner", r"cAdvisor", r"cAdvisor", "容器监控"),
    ("application", "kube-state-metrics", "banner", r"kube-state-metrics", r"", "K8s状态指标"),
    ("application", "Kubernetes Dashboard", "banner", r"kubernetes-dashboard", r"", "K8s控制台"),
    ("application", "Helm", "banner", r"Helm", r"Helm", "Helm包管理"),
    ("application", "Traefik Dashboard", "title", r"Traefik", r"", "Traefik面板"),
    ("application", "Portainer Edge", "banner", r"Portainer", r"", "Portainer边缘"),
    ("application", "Rancher", "banner", r"Rancher", r"Rancher", "Rancher容器管理"),
    ("application", "OpenShift", "banner", r"OpenShift", r"OpenShift", "Red Hat OpenShift"),
    ("application", "Mesos", "banner", r"Mesos", r"Apache\s*Mesos", "Apache Mesos"),
    ("application", "Marathon", "banner", r"marathon", r"marathon", "Mesos Marathon"),
    ("application", "Nomad", "banner", r"Nomad", r"Nomad", "HashiCorp Nomad"),
    ("application", "Consul UI", "banner", r"Consul UI", r"", "Consul Web界面"),
    ("application", "Vault", "banner", r"Vault", r"Vault", "HashiCorp Vault"),
    ("application", "Terraform Cloud", "banner", r"Terraform", r"Terraform", "Terraform"),
    ("application", "Packer", "banner", r"Packer", r"Packer", "HashiCorp Packer"),
    ("application", "Vagrant", "banner", r"Vagrant", r"Vagrant", "HashiCorp Vagrant"),
    ("application", "MinIO Browser", "title", r"MinIO", r"", "MinIO对象存储浏览器"),
    ("application", "ElastAlert", "banner", r"elastalert", r"elastalert", "ElastAlert告警"),
    ("application", "Wazuh", "banner", r"Wazuh", r"Wazuh", "Wazuh SIEM"),
    ("application", "TheHive", "banner", r"TheHive", r"TheHive", "TheHive事件响应"),
    ("application", "MISP", "banner", r"MISP", r"MISP", "MISP威胁情报共享"),
    ("application", "Cortex", "banner", r"Cortex", r"Cortex", "TheHive Cortex分析"),
    ("application", "OpenCTI", "banner", r"OpenCTI", r"OpenCTI", "OpenCTI威胁平台"),
    ("application", "Maltiverse", "banner", r"Maltiverse", r"", "Maltiverse情报"),
    ("application", "VirusTotal", "banner", r"VirusTotal", r"VirusTotal", "VirusTotal"),
    ("application", "Shannon", "banner", r"Shannon", r"", "预留指纹项"),
]


class FingerprintManager:
    """资产指纹管理器"""

    def __init__(self) -> None:
        """初始化并批量灌入内置指纹规则。"""
        self._ensure_table()
        self._seed_builtin_rules()

    def _ensure_table(self) -> None:
        """创建指纹规则表。"""
        conn = db._get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS am_fingerprint_rules (
                    id TEXT PRIMARY KEY,
                    category TEXT,
                    name TEXT,
                    match_type TEXT,
                    match_pattern TEXT,
                    version_pattern TEXT,
                    description TEXT,
                    created_at TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fp_cat ON am_fingerprint_rules(category)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fp_type ON am_fingerprint_rules(match_type)")
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"创建指纹规则表失败: {e}")
        finally:
            conn.close()

    def _seed_builtin_rules(self) -> int:
        """初始化时批量插入内置规则（仅当表为空时）。返回插入条数。"""
        conn = db._get_connection()
        inserted = 0
        try:
            count = conn.execute("SELECT COUNT(*) FROM am_fingerprint_rules").fetchone()[0]
            if count > 0:
                return 0
            now = datetime.now().isoformat()
            for cat, name, mtype, pattern, vpattern, desc in BUILTIN_RULES:
                conn.execute("""
                    INSERT INTO am_fingerprint_rules
                        (id, category, name, match_type, match_pattern,
                         version_pattern, description, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (f"am-fp-{uuid.uuid4().hex[:10]}", cat, name, mtype,
                      pattern, vpattern, desc, now))
                inserted += 1
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"灌入指纹规则失败: {e}")
        finally:
            conn.close()
        return inserted

    # ------------------------------------------------------------------ #
    # 规则 CRUD
    # ------------------------------------------------------------------ #
    def list_rules(self, category: Optional[str] = None,
                   keyword: Optional[str] = None,
                   page: int = 1, page_size: int = 50) -> Dict[str, Any]:
        """列出指纹规则（按分类/关键词筛选 + 分页）。"""
        conn = db._get_connection()
        try:
            where, params = " WHERE 1=1 ", []
            if category:
                where += " AND category=?"
                params.append(category)
            if keyword:
                where += " AND (name LIKE ? OR description LIKE ?)"
                like = f"%{keyword}%"
                params.extend([like, like])
            total = conn.execute(
                f"SELECT COUNT(*) FROM am_fingerprint_rules {where}", params).fetchone()[0]
            start = (max(1, page) - 1) * max(1, page_size)
            rows = conn.execute(
                f"SELECT * FROM am_fingerprint_rules {where} ORDER BY category, name LIMIT ? OFFSET ?",
                params + [page_size, start]).fetchall()
            return {"total": total, "page": page, "page_size": page_size,
                    "items": [dict(r) for r in rows]}
        finally:
            conn.close()

    def create_rule(self, category: str, name: str, match_type: str,
                    match_pattern: str, version_pattern: str = "",
                    description: str = "") -> Dict[str, Any]:
        """新增指纹规则。"""
        rule_id = f"am-fp-{uuid.uuid4().hex[:10]}"
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO am_fingerprint_rules
                    (id, category, name, match_type, match_pattern,
                     version_pattern, description, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (rule_id, category, name, match_type, match_pattern,
                  version_pattern, description, datetime.now().isoformat()))
            conn.commit()
            return {"success": True, "id": rule_id}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def update_rule(self, rule_id: str, **fields) -> Dict[str, Any]:
        """更新指纹规则。"""
        allowed = {"category", "name", "match_type", "match_pattern",
                   "version_pattern", "description"}
        sets, params = [], []
        for k, v in fields.items():
            if k in allowed and v is not None:
                sets.append(f"{k}=?")
                params.append(v)
        if not sets:
            return {"success": False, "error": "无有效更新字段"}
        params.append(rule_id)
        conn = db._get_connection()
        try:
            conn.execute(
                f"UPDATE am_fingerprint_rules SET {', '.join(sets)} WHERE id=?", params)
            conn.commit()
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def delete_rule(self, rule_id: str) -> Dict[str, Any]:
        """删除指纹规则。"""
        conn = db._get_connection()
        try:
            conn.execute("DELETE FROM am_fingerprint_rules WHERE id=?", (rule_id,))
            conn.commit()
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def get_rule_stats(self) -> Dict[str, int]:
        """按分类统计规则数量。"""
        conn = db._get_connection()
        try:
            rows = conn.execute(
                "SELECT category, COUNT(*) AS cnt FROM am_fingerprint_rules GROUP BY category"
            ).fetchall()
            stats = {r["category"]: r["cnt"] for r in rows}
            stats["total"] = sum(stats.values())
            return stats
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 匹配
    # ------------------------------------------------------------------ #
    @staticmethod
    def _load_rules(conn) -> List[Dict[str, Any]]:
        rows = conn.execute("SELECT * FROM am_fingerprint_rules").fetchall()
        return [dict(r) for r in rows]

    def match_fingerprint(self, scan_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """根据扫描结果匹配指纹，返回按匹配度排序的候选。

        scan_result 可包含：port, banner, http_headers, http_title, cert,
        open_ports(list), ttl, window_size。
        """
        conn = db._get_connection()
        try:
            rules = self._load_rules(conn)
        finally:
            conn.close()

        banner = (scan_result.get("banner") or "").lower()
        headers = (scan_result.get("http_headers") or "").lower()
        title = (scan_result.get("http_title") or "").lower()
        cert = (scan_result.get("cert") or "").lower()
        port = scan_result.get("port")

        scored: List[Dict[str, Any]] = []
        for rule in rules:
            mtype = rule["match_type"]
            pattern = rule["match_pattern"] or ""
            score = 0.0
            version = None
            try:
                if mtype == "port":
                    try:
                        if int(pattern) == int(port):
                            score = 0.3
                    except Exception:
                        pass
                elif mtype == "banner":
                    if pattern.lower() in banner or re.search(pattern, banner, re.I):
                        score = 0.8
                elif mtype == "header":
                    text = headers if isinstance(headers, str) else json.dumps(headers)
                    if pattern.lower() in text or re.search(pattern, text, re.I):
                        score = 0.9
                elif mtype == "title":
                    if pattern.lower() in title or re.search(pattern, title, re.I):
                        score = 0.95
                elif mtype == "cert":
                    if pattern.lower() in cert:
                        score = 0.7
            except re.error:
                continue
            if score <= 0:
                continue
            # 版本提取
            vp = rule.get("version_pattern")
            if vp and score >= 0.8:
                source = banner if mtype != "header" else (headers if isinstance(headers, str) else "")
                m = re.search(vp, source, re.I)
                if m:
                    version = m.group(1) if m.groups() else m.group(0)
            scored.append({
                "rule_id": rule["id"], "category": rule["category"],
                "name": rule["name"], "match_type": mtype,
                "score": round(score, 2), "version": version,
                "description": rule["description"],
            })
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:20]

    def match_service(self, port: int = 0, banner: str = "",
                      http_headers: str = "") -> Dict[str, Any]:
        """识别服务类型和版本。"""
        candidates = self.match_fingerprint({
            "port": port, "banner": banner, "http_headers": http_headers})
        svc = [c for c in candidates if c["category"] == "service"]
        if not svc:
            return {"service": "unknown", "version": "", "confidence": 0.0,
                    "candidates": candidates[:5]}
        top = svc[0]
        return {"service": top["name"], "version": top.get("version") or "",
                "confidence": top["score"], "candidates": svc[:5]}

    def match_os(self, ttl: int = 0, window_size: int = 0,
                 open_ports: List[int] = None) -> Dict[str, Any]:
        """基于 TTL / 窗口大小 / 端口开放模式识别操作系统。"""
        # 启发式：TTL≈64 -> Linux/macOS；TTL≈128 -> Windows；TTL≈255 -> Network设备
        candidates: List[Dict[str, Any]] = []
        if ttl:
            if 60 <= ttl <= 64:
                candidates.append({"os": "Linux", "score": 0.8, "reason": f"TTL={ttl}≈64"})
            elif 120 <= ttl <= 128:
                candidates.append({"os": "Windows", "score": 0.8, "reason": f"TTL={ttl}≈128"})
            elif 250 <= ttl <= 255:
                candidates.append({"os": "Network Device", "score": 0.75,
                                   "reason": f"TTL={ttl}≈255"})
        if window_size:
            # Windows 默认窗口较大
            if window_size >= 64240:
                candidates.append({"os": "Windows", "score": 0.6,
                                   "reason": f"WindowSize={window_size}"})
            elif 5840 <= window_size <= 14600:
                candidates.append({"os": "Linux", "score": 0.5,
                                   "reason": f"WindowSize={window_size}"})
        ports = set(open_ports or [])
        if {135, 139, 445} & ports or 3389 in ports:
            candidates.append({"os": "Windows", "score": 0.7,
                               "reason": "开放MSRPC/SMB/RDP端口"})
        if 22 in ports and not ({135, 139, 445} & ports):
            candidates.append({"os": "Linux", "score": 0.5, "reason": "开放SSH"})
        # 汇总
        agg: Dict[str, float] = {}
        reasons: Dict[str, List[str]] = {}
        for c in candidates:
            agg[c["os"]] = agg.get(c["os"], 0) + c["score"]
            reasons.setdefault(c["os"], []).append(c["reason"])
        if not agg:
            return {"os": "unknown", "confidence": 0.0, "reasons": []}
        best = max(agg, key=agg.get)
        return {"os": best, "confidence": round(min(agg[best], 1.0), 2),
                "reasons": reasons.get(best, [])}

    def match_application(self, http_headers: str = "",
                          http_title: str = "",
                          banner: str = "") -> Dict[str, Any]:
        """识别 Web 应用 / 框架 / CMS。"""
        candidates = self.match_fingerprint({
            "http_headers": http_headers, "http_title": http_title, "banner": banner})
        apps = [c for c in candidates if c["category"] == "application"]
        if not apps:
            return {"application": "unknown", "confidence": 0.0, "candidates": []}
        top = apps[0]
        return {"application": top["name"], "version": top.get("version") or "",
                "confidence": top["score"], "candidates": apps[:5]}


# 全局单例
fingerprint_manager = FingerprintManager()
