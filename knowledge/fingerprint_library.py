#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fingerprint_library知识库模块，存储和管理相关安全知识、漏洞信息和攻击链数据。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import re
import json
import os
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import Counter

from utils.logger import log


@dataclass
class FingerprintRule:
    """指纹识别规则"""
    rule_id: str
    name: str
    category: str  # web_server/app_server/runtime/framework/cms/database/tool/platform/os/middleware
    vendor: str = ""
    product: str = ""
    version_pattern: str = ""  # 版本号提取正则
    match_headers: Dict[str, str] = field(default_factory=dict)  # Header匹配
    match_body: List[str] = field(default_factory=list)  # 响应体匹配（正则）
    match_cookies: List[str] = field(default_factory=list)  # Cookie匹配
    match_title: str = ""  # 页面标题匹配
    confidence: int = 80  # 置信度 0-100
    cpe: str = ""  # CPE标识
    related_vulns: List[str] = field(default_factory=list)  # 相关CVE
    description: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "category": self.category,
            "vendor": self.vendor,
            "product": self.product,
            "version_pattern": self.version_pattern,
            "match_headers": self.match_headers,
            "match_body": self.match_body,
            "match_cookies": self.match_cookies,
            "match_title": self.match_title,
            "confidence": self.confidence,
            "cpe": self.cpe,
            "related_vulns": self.related_vulns,
            "description": self.description,
            "tags": self.tags
        }


class FingerprintLibrary:
    """服务指纹识别库"""

    def __init__(self, data_dir: str = "data/knowledge/fingerprints"):
        """初始化FingerprintLibrary实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.rules: Dict[str, FingerprintRule] = {}
        os.makedirs(data_dir, exist_ok=True)
        self._load_rules()
        if not self.rules:
            self._init_default_rules()

    def _load_rules(self):
        """从文件加载规则"""
        rules_file = os.path.join(self.data_dir, "fingerprint_library.json")
        if os.path.exists(rules_file):
            try:
                with open(rules_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for rid, rdata in data.items():
                    self.rules[rid] = FingerprintRule(
                        rule_id=rdata["rule_id"],
                        name=rdata["name"],
                        category=rdata["category"],
                        vendor=rdata.get("vendor", ""),
                        product=rdata.get("product", ""),
                        version_pattern=rdata.get("version_pattern", ""),
                        match_headers=rdata.get("match_headers", {}),
                        match_body=rdata.get("match_body", []),
                        match_cookies=rdata.get("match_cookies", []),
                        match_title=rdata.get("match_title", ""),
                        confidence=rdata.get("confidence", 80),
                        cpe=rdata.get("cpe", ""),
                        related_vulns=rdata.get("related_vulns", []),
                        description=rdata.get("description", ""),
                        tags=rdata.get("tags", [])
                    )
            except Exception as e:
                log.error(f"加载指纹库失败: {e}")

    def _save_rules(self):
        """保存规则到文件"""
        rules_file = os.path.join(self.data_dir, "fingerprint_library.json")
        try:
            data = {rid: r.to_dict() for rid, r in self.rules.items()}
            with open(rules_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存指纹库失败: {e}")

    def _add_rule(self, **kwargs):
        """添加规则"""
        rule_id = f"fp-{len(self.rules)+1:04d}"
        rule = FingerprintRule(rule_id=rule_id, **kwargs)
        self.rules[rule_id] = rule
        return rule_id

    def _init_default_rules(self):
        """初始化200+默认指纹规则"""
        log.info("初始化200+默认指纹规则...")

        # ===== Web服务器 (30个) =====
        web_servers = [
            ("Nginx", "nginx", r"nginx/([\d.]+)", {"Server": "nginx"}, ["nginx"], "cpe:/a:nginx:nginx"),
            ("Apache HTTPD", "apache", r"Apache/([\d.]+)", {"Server": "Apache"}, ["Apache", "apache_httpd"], "cpe:/a:apache:http_server"),
            ("Microsoft IIS", "iis", r"IIS/([\d.]+)", {"Server": "IIS"}, ["Microsoft-IIS", "iis"], "cpe:/a:microsoft:iis"),
            ("LiteSpeed", "litespeed", r"LiteSpeed/([\d.]+)", {"Server": "LiteSpeed"}, ["LiteSpeed"], "cpe:/a:litespeedtech:litespeed_web_server"),
            ("Caddy", "caddy", r"caddy/([\d.]+)", {"Server": "caddy"}, ["Caddy"], "cpe:/a:caddyserver:caddy"),
            ("Tomcat", "tomcat", r"Apache-Coyote/([\d.]+)", {"Server": "Apache-Coyote"}, ["Apache Tomcat", "tomcat"], "cpe:/a:apache:tomcat"),
            ("Jetty", "jetty", r"Jetty\(([\d.]+)\)", {"Server": "Jetty"}, ["Jetty"], "cpe:/a:eclipse:jetty"),
            ("JBoss/WildFly", "jboss", "", {"Server": "JBoss"}, ["JBoss", "WildFly", "jboss"], "cpe:/a:redhat:jboss_enterprise_application_platform"),
            ("WebLogic", "weblogic", "", {"Server": "WebLogic"}, ["WebLogic", "weblogic"], "cpe:/a:oracle:weblogic_server"),
            ("WebSphere", "websphere", "", {"Server": "WebSphere"}, ["WebSphere"], "cpe:/a:ibm:websphere_application_server"),
            ("GlassFish", "glassfish", r"GlassFish Server Open Source Edition ([\d.]+)", {"Server": "GlassFish"}, ["GlassFish"], "cpe:/a:oracle:glassfish_server"),
            ("Gunicorn", "gunicorn", r"gunicorn/([\d.]+)", {"Server": "gunicorn"}, ["gunicorn"], "cpe:/a:gunicorn:gunicorn"),
            ("uWSGI", "uwsgi", "", {"Server": "uWSGI"}, ["uWSGI"], "cpe:/a:uwsgi:uwsgi"),
            ("Waitress", "waitress", r"waitress/([\d.]+)", {"Server": "waitress"}, ["waitress"], ""),
            ("Tornado", "tornado", r"TornadoServer/([\d.]+)", {"Server": "TornadoServer"}, ["Tornado"], "cpe:/a:tornadoweb:tornado"),
            ("Node.js", "nodejs", "", {"X-Powered-By": "Express"}, ["Node.js", "Express"], "cpe:/a:nodejs:node.js"),
            ("Go net/http", "go", "", {"Server": "Go-http-server"}, ["Go net/http"], ""),
            ("Rust Actix", "actix", r"actix-web/([\d.]+)", {"Server": "actix-web"}, ["actix-web"], ""),
            ("OpenResty", "openresty", r"openresty/([\d.]+)", {"Server": "openresty"}, ["OpenResty"], "cpe:/a:openresty:openresty"),
            ("Tengine", "tengine", r"Tengine/([\d.]+)", {"Server": "Tengine"}, ["Tengine"], ""),
            ("Cherokee", "cherokee", r"Cherokee/([\d.]+)", {"Server": "Cherokee"}, ["Cherokee"], ""),
            ("Hiawatha", "hiawatha", r"Hiawatha v([\d.]+)", {"Server": "Hiawatha"}, ["Hiawatha"], ""),
            ("Lighttpd", "lighttpd", r"lighttpd/([\d.]+)", {"Server": "lighttpd"}, ["lighttpd"], "cpe:/a:lighttpd:lighttpd"),
            ("Boa", "boa", r"Boa/([\d.]+)", {"Server": "Boa"}, ["Boa"], ""),
            ("Mongoose", "mongoose", r"Mongoose/([\d.]+)", {"Server": "Mongoose"}, ["Mongoose"], ""),
            ("Mongrel2", "mongrel2", "", {"Server": "Mongrel2"}, ["Mongrel2"], ""),
            ("Yaws", "yaws", r"Yaws/([\d.]+)", {"Server": "Yaws"}, ["Yaws"], ""),
            ("Cowboy", "cowboy", r"Cowboy/([\d.]+)", {"Server": "Cowboy"}, ["Cowboy"], ""),
            ("Puma", "puma", r"puma ([\d.]+)", {"Server": "puma"}, ["Puma"], "cpe:/a:puma:puma"),
        ]

        for name, vendor, ver_pat, headers, body_patterns, cpe in web_servers:
            self._add_rule(
                name=name, category="web_server", vendor=vendor, product=name,
                version_pattern=ver_pat, match_headers=headers, match_body=body_patterns,
                confidence=90, cpe=cpe, description=f"{name} Web服务器"
            )

        # ===== 应用服务器/中间件 (20个) =====
        app_servers = [
            ("Apache Tomcat", "apache", "tomcat", r"Apache Tomcat/([\d.]+)", ["Apache Tomcat", "tomcat"], "cpe:/a:apache:tomcat"),
            ("JBoss EAP", "redhat", "jboss", "", ["JBoss", "jboss"], "cpe:/a:redhat:jboss_enterprise_application_platform"),
            ("WildFly", "redhat", "wildfly", "", ["WildFly", "wildfly"], "cpe:/a:redhat:wildfly"),
            ("WebLogic Server", "oracle", "weblogic", "", ["WebLogic", "weblogic"], "cpe:/a:oracle:weblogic_server"),
            ("WebSphere AS", "ibm", "websphere", "", ["WebSphere", "websphere"], "cpe:/a:ibm:websphere_application_server"),
            ("GlassFish", "oracle", "glassfish", "", ["GlassFish", "glassfish"], "cpe:/a:oracle:glassfish_server"),
            ("Resin", "caucho", "resin", r"Resin/([\d.]+)", ["Resin"], "cpe:/a:caucho:resin"),
            ("Jetty", "eclipse", "jetty", "", ["Jetty", "jetty"], "cpe:/a:eclipse:jetty"),
            ("Undertow", "redhat", "undertow", "", ["Undertow"], "cpe:/a:redhat:undertow"),
            ("Geronimo", "apache", "geronimo", "", ["Geronimo"], "cpe:/a:apache:geronimo"),
            ("Struts2", "apache", "struts2", "", ["Struts2", "struts2", ".action"], "cpe:/a:apache:struts"),
            ("Spring Framework", "pivotal", "spring", "", ["Spring", "spring", "org.springframework"], "cpe:/a:pivotal:spring_framework"),
            ("Spring Boot", "pivotal", "spring_boot", "", ["Spring Boot", "spring-boot", "Whitelabel Error Page"], "cpe:/a:pivotal:spring_boot"),
            ("Django", "djangoproject", "django", r"Django/([\d.]+)", ["Django", "django", "csrftoken"], "cpe:/a:djangoproject:django"),
            ("Flask", "pallets", "flask", "", ["Flask", "flask", "Werkzeug"], "cpe:/a:pallets:flask"),
            ("Rails", "rubyonrails", "rails", "", ["Rails", "rails", "csrf-token"], "cpe:/a:rubyonrails:rails"),
            ("Laravel", "laravel", "laravel", "", ["Laravel", "laravel", "laravel_session"], "cpe:/a:laravel:laravel"),
            ("Symfony", "symfony", "symfony", "", ["Symfony", "symfony"], "cpe:/a:symfony:symfony"),
            ("CodeIgniter", "codeigniter", "codeigniter", "", ["CodeIgniter", "codeigniter", "ci_session"], "cpe:/a:codeigniter:codeigniter"),
            ("CakePHP", "cakephp", "cakephp", "", ["CakePHP", "cakephp", "cakephp"], "cpe:/a:cakephp:cakephp"),
        ]

        for name, vendor, product, ver_pat, body_patterns, cpe in app_servers:
            self._add_rule(
                name=name, category="app_server", vendor=vendor, product=product,
                version_pattern=ver_pat, match_body=body_patterns,
                confidence=75, cpe=cpe, description=f"{name} 应用服务器/框架"
            )

        # ===== CMS (30个) =====
        cms_list = [
            ("WordPress", "wordpress", "WordPress", r"WordPress ([\d.]+)", ["wp-content", "wp-includes", "wordpress"], ["wordpress_test_cookie", "wp_logged_in"], "cpe:/a:wordpress:wordpress"),
            ("Joomla", "joomla", "Joomla", r"Joomla! ([\d.]+)", ["joomla", "Joomla!", "com_"], ["joomla_session"], r"cpe:/a:joomla:joomla!"),
            ("Drupal", "drupal", "Drupal", r"Drupal ([\d.]+)", ["drupal", "Drupal", "sites/default"], ["SESS", "SSESS"], "cpe:/a:drupal:drupal"),
            ("Magento", "magento", "Magento", r"Magento/([\d.]+)", ["magento", "Magento", "mage-cache-sessid"], ["PHPSESSID", "mage-cache-sessid"], "cpe:/a:magento:magento"),
            ("Shopify", "shopify", "Shopify", "", ["shopify", "Shopify", "cdn.shopify.com"], ["_shopify_s"], "cpe:/a:shopify:shopify"),
            ("WooCommerce", "woocommerce", "WooCommerce", "", ["woocommerce", "WooCommerce", "woocommerce"], ["woocommerce"], "cpe:/a:woocommerce:woocommerce"),
            ("PrestaShop", "prestashop", "PrestaShop", r"PrestaShop™ ([\d.]+)", ["prestashop", "PrestaShop"], ["PrestaShop"], "cpe:/a:prestashop:prestashop"),
            ("OpenCart", "opencart", "OpenCart", "", ["opencart", "OpenCart", "route="], ["OCSESSID"], "cpe:/a:opencart:opencart"),
            ("TYPO3", "typo3", "TYPO3", r"TYPO3 ([\d.]+)", ["typo3", "TYPO3", "typo3conf"], ["be_typo_user", "fe_typo_user"], "cpe:/a:typo3:typo3"),
            ("Concrete5", "concrete5", "Concrete5", "", ["concrete5", "Concrete CMS", "concrete5"], ["CONCRETE5"], ""),
            ("Contao", "contao", "Contao", "", ["contao", "Contao", "contao"], ["PHPSESSID"], ""),
            ("SilverStripe", "silverstripe", "SilverStripe", "", ["SilverStripe", "silverstripe"], ["SilverStripe"], ""),
            ("ExpressionEngine", "ellislab", "ExpressionEngine", "", ["ExpressionEngine", "expressionengine"], ["exp_last_activity"], ""),
            ("Textpattern", "textpattern", "Textpattern", "", ["textpattern", "Textpattern"], ["txp_login"], ""),
            ("MODX", "modx", "MODX", "", ["MODX", "modx", "manager"], ["PHPSESSID"], ""),
            ("ProcessWire", "processwire", "ProcessWire", "", ["ProcessWire", "processwire"], ["wire"], ""),
            ("Umbraco", "umbraco", "Umbraco", r"Umbraco ([\d.]+)", ["umbraco", "Umbraco", "umbraco"], ["UMB_SESSION"], "cpe:/a:umbraco:umbraco"),
            ("Sitecore", "sitecore", "Sitecore", "", ["sitecore", "Sitecore", "sitecore"], ["ASP.NET_SessionId"], ""),
            ("Episerver", "episerver", "Episerver", "", ["EPiServer", "episerver"], [".ASPXAUTH"], ""),
            ("DNN", "dnnsoftware", "DotNetNuke", "", ["DotNetNuke", "DNN", "dnn"], ["DOTNETNUKE"], "cpe:/a:dnnsoftware:dotnetnuke"),
            ("Orchard", "orchardproject", "Orchard", "", ["Orchard", "orchard"], [""], ""),
            ("Ghost", "ghost", "Ghost", r"Ghost/([\d.]+)", ["Ghost", "ghost", "ghost-admin"], ["ghost-admin-api-session"], "cpe:/a:ghost:ghost"),
            ("Hugo", "gohugo", "Hugo", "", ["Hugo", "hugo", "generator"], [""], ""),
            ("Jekyll", "jekyll", "Jekyll", "", ["Jekyll", "jekyll", "jekyll"], [""], ""),
            ("Hexo", "hexo", "Hexo", "", ["Hexo", "hexo", "hexo"], [""], ""),
            ("Gatsby", "gatsby", "Gatsby", "", ["Gatsby", "gatsby", "gatsby"], [""], ""),
            ("Next.js", "vercel", "Next.js", "", ["Next.js", "next.js", "__next"], ["__next"], "cpe:/a:vercel:next.js"),
            ("Nuxt.js", "nuxt", "Nuxt.js", "", ["Nuxt.js", "nuxt", "__nuxt"], ["__nuxt"], ""),
            ("Strapi", "strapi", "Strapi", r"Strapi ([\d.]+)", ["Strapi", "strapi", "strapi"], ["jwt"], "cpe:/a:strapi:strapi"),
        ]

        for name, vendor, product, ver_pat, body_patterns, cookies, cpe in cms_list:
            self._add_rule(
                name=name, category="cms", vendor=vendor, product=product,
                version_pattern=ver_pat, match_body=body_patterns, match_cookies=cookies,
                confidence=80, cpe=cpe, description=f"{name} CMS系统"
            )

        # ===== 数据库 (25个) =====
        databases = [
            ("MySQL", "oracle", "mysql", "cpe:/a:oracle:mysql"),
            ("PostgreSQL", "postgresql", "postgresql", "cpe:/a:postgresql:postgresql"),
            ("MongoDB", "mongodb", "mongodb", "cpe:/a:mongodb:mongodb"),
            ("Redis", "redis", "redis", "cpe:/a:redis:redis"),
            ("Elasticsearch", "elastic", "elasticsearch", "cpe:/a:elastic:elasticsearch"),
            ("SQL Server", "microsoft", "sql_server", "cpe:/a:microsoft:sql_server"),
            ("Oracle Database", "oracle", "oracle_database", "cpe:/a:oracle:database"),
            ("MariaDB", "mariadb", "mariadb", "cpe:/a:mariadb:mariadb"),
            ("SQLite", "sqlite", "sqlite", "cpe:/a:sqlite:sqlite"),
            ("Cassandra", "apache", "cassandra", "cpe:/a:apache:cassandra"),
            ("CouchDB", "apache", "couchdb", "cpe:/a:apache:couchdb"),
            ("Neo4j", "neo4j", "neo4j", "cpe:/a:neo4j:neo4j"),
            ("InfluxDB", "influxdata", "influxdb", "cpe:/a:influxdata:influxdb"),
            ("DynamoDB", "amazon", "dynamodb", "cpe:/a:amazon:dynamodb"),
            ("Memcached", "memcached", "memcached", "cpe:/a:memcached:memcached"),
            ("RabbitMQ", "rabbitmq", "rabbitmq", "cpe:/a:rabbitmq:rabbitmq"),
            ("Kafka", "apache", "kafka", "cpe:/a:apache:kafka"),
            ("Zookeeper", "apache", "zookeeper", "cpe:/a:apache:zookeeper"),
            ("Solr", "apache", "solr", "cpe:/a:apache:solr"),
            ("Lucene", "apache", "lucene", "cpe:/a:apache:lucene"),
            ("HBase", "apache", "hbase", "cpe:/a:apache:hbase"),
            ("Hive", "apache", "hive", "cpe:/a:apache:hive"),
            ("Presto", "prestodb", "presto", "cpe:/a:prestodb:presto"),
            ("ClickHouse", "clickhouse", "clickhouse", "cpe:/a:clickhouse:clickhouse"),
            ("TiDB", "pingcap", "tidb", "cpe:/a:pingcap:tidb"),
        ]

        for name, vendor, product, cpe in databases:
            self._add_rule(
                name=name, category="database", vendor=vendor, product=product,
                match_body=[name, name.lower()], confidence=70, cpe=cpe,
                description=f"{name} 数据库"
            )

        # ===== 运行时/语言 (20个) =====
        runtimes = [
            ("PHP", "php", "php", r"PHP/([\d.]+)", {"X-Powered-By": "PHP"}, ["PHP", "php"], "cpe:/a:php:php"),
            ("Python", "python", "python", r"Python/([\d.]+)", {"Server": "Python"}, ["Python", "python"], "cpe:/a:python:python"),
            ("Ruby", "ruby", "ruby", r"Ruby/([\d.]+)", {"Server": "Ruby"}, ["Ruby", "ruby"], "cpe:/a:ruby:ruby"),
            ("Node.js", "nodejs", "nodejs", r"Node.js/([\d.]+)", {"X-Powered-By": "Node.js"}, ["Node.js", "node.js"], "cpe:/a:nodejs:node.js"),
            ("Go", "golang", "go", "", {"Server": "Go-http-server"}, ["Go", "golang"], "cpe:/a:golang:go"),
            ("Rust", "rust", "rust", "", {}, ["Rust", "rust"], "cpe:/a:rust:rust"),
            ("Java", "oracle", "java", r"Java/([\d._]+)", {"X-Powered-By": "Java"}, ["Java", "java", "JSESSIONID"], "cpe:/a:oracle:jre"),
            (".NET", "microsoft", "dotnet", r"\.NET CLR ([\d.]+)", {"X-Powered-By": "ASP.NET"}, [".NET", "ASP.NET", "dotnet"], "cpe:/a:microsoft:.net_framework"),
            ("ASP.NET Core", "microsoft", "aspnet_core", "", {"Server": "Kestrel"}, ["ASP.NET Core", "aspnetcore"], "cpe:/a:microsoft:asp.net_core"),
            ("Perl", "perl", "perl", r"Perl/([\d.]+)", {"Server": "Perl"}, ["Perl", "perl"], "cpe:/a:perl:perl"),
            ("Lua", "lua", "lua", "", {}, ["Lua", "lua"], "cpe:/a:lua:lua"),
            ("Erlang", "erlang", "erlang", "", {"Server": "Cowboy"}, ["Erlang", "erlang"], "cpe:/a:erlang:erlang"),
            ("Elixir", "elixir", "elixir", "", {}, ["Elixir", "elixir"], "cpe:/a:elixir:elixir"),
            ("Scala", "scala", "scala", "", {}, ["Scala", "scala"], "cpe:/a:scala:scala"),
            ("Kotlin", "jetbrains", "kotlin", "", {}, ["Kotlin", "kotlin"], "cpe:/a:jetbrains:kotlin"),
            ("Swift", "apple", "swift", "", {}, ["Swift", "swift"], "cpe:/a:apple:swift"),
            ("Dart", "dart", "dart", "", {}, ["Dart", "dart"], "cpe:/a:dart:dart"),
            ("Clojure", "clojure", "clojure", "", {}, ["Clojure", "clojure"], "cpe:/a:clojure:clojure"),
            ("Haskell", "haskell", "haskell", "", {}, ["Haskell", "haskell"], "cpe:/a:haskell:haskell"),
            ("ColdFusion", "adobe", "coldfusion", r"ColdFusion ([\d.]+)", {"Server": "ColdFusion"}, ["ColdFusion", "coldfusion"], "cpe:/a:adobe:coldfusion"),
        ]

        for name, vendor, product, ver_pat, headers, body_patterns, cpe in runtimes:
            self._add_rule(
                name=name, category="runtime", vendor=vendor, product=product,
                version_pattern=ver_pat, match_headers=headers, match_body=body_patterns,
                confidence=75, cpe=cpe, description=f"{name} 运行时"
            )

        # ===== 框架/库 (25个) =====
        frameworks = [
            ("React", "facebook", "react", ["react", "React", "react-dom"], "cpe:/a:facebook:react"),
            ("Vue.js", "vuejs", "vue", ["Vue.js", "vue", "vuejs"], "cpe:/a:vuejs:vue.js"),
            ("Angular", "angular", "angular", ["Angular", "angular", "ng-version"], "cpe:/a:angular:angular"),
            ("Svelte", "svelte", "svelte", ["Svelte", "svelte"], "cpe:/a:svelte:svelte"),
            ("jQuery", "jquery", "jquery", r"jQuery ([\d.]+)", ["jQuery", "jquery", "$.fn"], "cpe:/a:jquery:jquery"),
            ("Bootstrap", "twitter", "bootstrap", r"Bootstrap v([\d.]+)", ["Bootstrap", "bootstrap", "bootstrap.min.css"], "cpe:/a:twitter:bootstrap"),
            ("Tailwind CSS", "tailwindcss", "tailwind", ["tailwindcss", "tailwind", "Tailwind"], "cpe:/a:tailwindcss:tailwind_css"),
            ("Express.js", "expressjs", "express", ["Express", "express", "x-powered-by: express"], "cpe:/a:expressjs:express"),
            ("FastAPI", "tiangolo", "fastapi", ["FastAPI", "fastapi", "swagger-ui"], "cpe:/a:fastapi:fastapi"),
            ("Django REST Framework", "encode", "drf", ["Django REST framework", "rest_framework", "drf"], "cpe:/a:encode:django_rest_framework"),
            ("Spring MVC", "pivotal", "spring_mvc", ["Spring MVC", "spring-mvc", "org.springframework.web"], "cpe:/a:pivotal:spring_mvc"),
            ("MyBatis", "mybatis", "mybatis", ["MyBatis", "mybatis", "org.apache.ibatis"], "cpe:/a:mybatis:mybatis"),
            ("Hibernate", "hibernate", "hibernate", ["Hibernate", "hibernate", "org.hibernate"], "cpe:/a:hibernate:hibernate"),
            ("Struts", "apache", "struts", ["Struts", "struts", "org.apache.struts"], "cpe:/a:apache:struts"),
            ("Shiro", "apache", "shiro", ["Shiro", "shiro", "org.apache.shiro"], "cpe:/a:apache:shiro"),
            ("Log4j", "apache", "log4j", ["Log4j", "log4j", "org.apache.log4j"], "cpe:/a:apache:log4j"),
            ("Fastjson", "alibaba", "fastjson", ["fastjson", "Fastjson", "com.alibaba.fastjson"], "cpe:/a:alibaba:fastjson"),
            ("Jackson", "fasterxml", "jackson", ["Jackson", "jackson", "com.fasterxml.jackson"], "cpe:/a:fasterxml:jackson"),
            ("Gson", "google", "gson", ["Gson", "gson", "com.google.gson"], "cpe:/a:google:gson"),
            ("OkHttp", "square", "okhttp", ["OkHttp", "okhttp", "com.squareup.okhttp"], "cpe:/a:square:okhttp"),
            ("Retrofit", "square", "retrofit", ["Retrofit", "retrofit", "com.squareup.retrofit"], "cpe:/a:square:retrofit"),
            ("Axios", "axios", "axios", ["Axios", "axios", "axios/"], "cpe:/a:axios:axios"),
            ("Lodash", "lodash", "lodash", ["Lodash", "lodash", "lodash.js"], "cpe:/a:lodash:lodash"),
            ("Moment.js", "momentjs", "moment", ["Moment.js", "moment", "moment.js"], "cpe:/a:momentjs:moment.js"),
            ("Webpack", "webpack", "webpack", ["Webpack", "webpack", "webpack://"], "cpe:/a:webpack:webpack"),
        ]

        for item in frameworks:
            if len(item) == 5:
                name, vendor, product, body_patterns, cpe = item
                ver_pat = ""
            else:
                name, vendor, product, ver_pat, body_patterns, cpe = item
            self._add_rule(
                name=name, category="framework", vendor=vendor, product=product,
                version_pattern=ver_pat, match_body=body_patterns,
                confidence=65, cpe=cpe, description=f"{name} 框架/库"
            )

        # ===== 安全工具/WAF (15个) =====
        security_tools = [
            ("Cloudflare", "cloudflare", "cloudflare", {"Server": "cloudflare"}, ["cloudflare", "CF-RAY", "__cfduid"], "cpe:/a:cloudflare:cloudflare"),
            ("Akamai", "akamai", "akamai", {"Server": "Akamai"}, ["akamai", "Akamai", "aka_"], "cpe:/a:akamai:akamai"),
            ("AWS WAF", "amazon", "aws_waf", {}, ["aws-waf", "AWSWAF"], ""),
            ("ModSecurity", "trustwave", "modsecurity", {"Server": "ModSecurity"}, ["ModSecurity", "mod_security", "NOYB"], "cpe:/a:trustwave:modsecurity"),
            ("F5 BIG-IP", "f5", "bigip", {"Server": "BIG-IP"}, ["BIG-IP", "bigip", "F5"], "cpe:/a:f5:big-ip_application_security_manager"),
            ("Imperva", "imperva", "imperva", {}, ["Imperva", "imperva", "incapsula"], "cpe:/a:imperva:securesphere"),
            ("Sucuri", "sucuri", "sucuri", {"Server": "Sucuri"}, ["Sucuri", "sucuri", "sucuri-cloudproxy"], "cpe:/a:sucuri:sucuri"),
            ("Wordfence", "wordfence", "wordfence", {}, ["Wordfence", "wordfence", "wf_logout"], "cpe:/a:wordfence:wordfence"),
            ("Burp Suite", "portswigger", "burp", {}, ["Burp Suite", "burp"], "cpe:/a:portswigger:burp_suite"),
            ("Nmap", "nmap", "nmap", {}, ["Nmap", "nmap"], "cpe:/a:nmap:nmap"),
            ("Metasploit", "rapid7", "metasploit", {}, ["Metasploit", "metasploit"], "cpe:/a:rapid7:metasploit"),
            ("Sqlmap", "sqlmap", "sqlmap", {}, ["sqlmap", "Sqlmap"], "cpe:/a:sqlmap:sqlmap"),
            ("Nessus", "tenable", "nessus", {}, ["Nessus", "nessus"], "cpe:/a:tenable:nessus"),
            ("OpenVAS", "greenbone", "openvas", {}, ["OpenVAS", "openvas"], "cpe:/a:greenbone:openvas"),
            ("Snort", "cisco", "snort", {}, ["Snort", "snort"], "cpe:/a:snort:snort"),
        ]

        for name, vendor, product, headers, body_patterns, cpe in security_tools:
            self._add_rule(
                name=name, category="tool", vendor=vendor, product=product,
                match_headers=headers, match_body=body_patterns,
                confidence=80, cpe=cpe, description=f"{name} 安全工具/WAF"
            )

        # ===== 操作系统/平台 (20个) =====
        os_list = [
            ("Windows Server 2019", "microsoft", "windows_server_2019", "cpe:/o:microsoft:windows_server_2019"),
            ("Windows Server 2016", "microsoft", "windows_server_2016", "cpe:/o:microsoft:windows_server_2016"),
            ("Windows Server 2012", "microsoft", "windows_server_2012", "cpe:/o:microsoft:windows_server_2012"),
            ("Windows 10", "microsoft", "windows_10", "cpe:/o:microsoft:windows_10"),
            ("Windows 11", "microsoft", "windows_11", "cpe:/o:microsoft:windows_11"),
            ("Ubuntu", "canonical", "ubuntu", "cpe:/o:canonical:ubuntu_linux"),
            ("CentOS", "centos", "centos", "cpe:/o:centos:centos"),
            ("Debian", "debian", "debian", "cpe:/o:debian:debian_linux"),
            ("Red Hat Enterprise Linux", "redhat", "rhel", "cpe:/o:redhat:enterprise_linux"),
            ("Fedora", "fedoraproject", "fedora", "cpe:/o:fedoraproject:fedora"),
            ("Arch Linux", "archlinux", "arch", "cpe:/o:archlinux:arch_linux"),
            ("Alpine Linux", "alpinelinux", "alpine", "cpe:/o:alpinelinux:alpine_linux"),
            ("Kali Linux", "offensive-security", "kali", "cpe:/o:offensive-security:kali_linux"),
            ("macOS", "apple", "macos", "cpe:/o:apple:macos"),
            ("iOS", "apple", "ios", "cpe:/o:apple:iphone_os"),
            ("Android", "google", "android", "cpe:/o:google:android"),
            ("FreeBSD", "freebsd", "freebsd", "cpe:/o:freebsd:freebsd"),
            ("OpenBSD", "openbsd", "openbsd", "cpe:/o:openbsd:openbsd"),
            ("Solaris", "oracle", "solaris", "cpe:/o:oracle:solaris"),
            ("AIX", "ibm", "aix", "cpe:/o:ibm:aix"),
        ]

        for name, vendor, product, cpe in os_list:
            self._add_rule(
                name=name, category="os", vendor=vendor, product=product,
                match_body=[name, product], confidence=60, cpe=cpe,
                description=f"{name} 操作系统"
            )

        # ===== 中间件/代理 (15个) =====
        middleware = [
            ("HAProxy", "haproxy", "haproxy", r"HAProxy ([\d.]+)", {"Server": "HAProxy"}, ["HAProxy", "haproxy"], "cpe:/a:haproxy:haproxy"),
            ("Envoy", "envoyproxy", "envoy", r"envoy/([\d.]+)", {"Server": "envoy"}, ["envoy", "Envoy"], "cpe:/a:envoyproxy:envoy"),
            ("Traefik", "traefik", "traefik", r"traefik/([\d.]+)", {"Server": "traefik"}, ["Traefik", "traefik"], "cpe:/a:traefik:traefik"),
            ("Kong", "kong", "kong", r"kong/([\d.]+)", {"Server": "kong"}, ["Kong", "kong"], "cpe:/a:kong:kong"),
            ("Nginx Ingress", "kubernetes", "nginx_ingress", {"Server": "nginx"}, ["nginx ingress", "ingress"], ""),
            ("Varnish", "varnish", "varnish", r"varnish/([\d.]+)", {"Server": "varnish"}, ["Varnish", "varnish"], "cpe:/a:varnish:varnish_cache"),
            ("Squid", "squid", "squid", r"squid/([\d.]+)", {"Server": "squid"}, ["Squid", "squid"], "cpe:/a:squid-cache:squid"),
            ("Apache Traffic Server", "apache", "traffic_server", {"Server": "ATS"}, ["ATS", "Apache Traffic Server"], "cpe:/a:apache:traffic_server"),
            ("F5 BIG-IP LTM", "f5", "bigip_ltm", {}, ["BIG-IP", "bigip", "F5"], "cpe:/a:f5:big-ip_local_traffic_manager"),
            ("Citrix ADC", "citrix", "citrix_adc", {"Server": "Citrix"}, ["Citrix", "citrix", "NetScaler"], "cpe:/a:citrix:netscaler"),
            ("A10 Thunder", "a10", "thunder", {}, ["A10", "Thunder", "a10"], ""),
            ("Barracuda", "barracuda", "barracuda", {"Server": "Barracuda"}, ["Barracuda", "barracuda"], "cpe:/a:barracuda:barracuda_load_balancer"),
            ("Cloudflare Tunnel", "cloudflare", "cloudflared", {}, ["cloudflared", "Cloudflare Tunnel"], ""),
            ("Tailscale", "tailscale", "tailscale", {}, ["Tailscale", "tailscale"], ""),
            ("WireGuard", "wireguard", "wireguard", {}, ["WireGuard", "wireguard"], "cpe:/a:wireguard:wireguard"),
        ]

        for item in middleware:
            if len(item) == 6:
                name, vendor, product, headers, body_patterns, cpe = item
                ver_pat = ""
            else:
                name, vendor, product, ver_pat, headers, body_patterns, cpe = item
            self._add_rule(
                name=name, category="middleware", vendor=vendor, product=product,
                version_pattern=ver_pat, match_headers=headers, match_body=body_patterns,
                confidence=75, cpe=cpe, description=f"{name} 中间件/代理"
            )

        self._save_rules()
        log.info(f"初始化完成，共 {len(self.rules)} 个指纹规则")

    # ===== 识别方法 =====
    def identify(self, headers: Dict[str, str] = None, body: str = "",
                 cookies: Dict[str, str] = None, title: str = "") -> List[Dict[str, Any]]:
        """识别服务指纹"""
        results = []
        headers = headers or {}
        cookies = cookies or {}

        for rule in self.rules.values():
            confidence = 0
            matched = False
            version = ""

            # Header匹配
            for hkey, hval_pattern in rule.match_headers.items():
                for header_key, header_val in headers.items():
                    if header_key.lower() == hkey.lower() and hval_pattern.lower() in header_val.lower():
                        confidence += 40
                        matched = True
                        # 尝试提取版本
                        if rule.version_pattern:
                            m = re.search(rule.version_pattern, header_val)
                            if m:
                                version = m.group(1)

            # Body匹配
            for pattern in rule.match_body:
                if re.search(pattern, body, re.IGNORECASE):
                    confidence += 25
                    matched = True
                    # 尝试从body提取版本
                    if rule.version_pattern and not version:
                        m = re.search(rule.version_pattern, body)
                        if m:
                            version = m.group(1)

            # Cookie匹配
            for cookie_pattern in rule.match_cookies:
                if cookie_pattern and cookie_pattern in str(cookies):
                    confidence += 20
                    matched = True

            # Title匹配
            if rule.match_title and title:
                if re.search(rule.match_title, title, re.IGNORECASE):
                    confidence += 30
                    matched = True

            if matched and confidence >= 30:
                final_confidence = min(confidence, rule.confidence)
                results.append({
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "category": rule.category,
                    "vendor": rule.vendor,
                    "product": rule.product,
                    "version": version,
                    "confidence": final_confidence,
                    "cpe": rule.cpe,
                    "related_vulns": rule.related_vulns,
                    "description": rule.description
                })

        results.sort(key=lambda x: x["confidence"], reverse=True)
        return results

    def search_rules(self, category: str = None, keyword: str = None,
                     vendor: str = None) -> List[Dict[str, Any]]:
        """搜索指纹规则"""
        results = []
        for rule in self.rules.values():
            if category and rule.category != category:
                continue
            if vendor and rule.vendor != vendor:
                continue
            if keyword and keyword.lower() not in (rule.name + rule.description + rule.product).lower():
                continue
            results.append(rule.to_dict())
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        by_category = Counter(r.category for r in self.rules.values())
        by_vendor = Counter(r.vendor for r in self.rules.values() if r.vendor)
        return {
            "total_rules": len(self.rules),
            "by_category": dict(by_category),
            "categories_count": len(by_category),
            "top_vendors": by_vendor.most_common(10),
            "with_cpe": sum(1 for r in self.rules.values() if r.cpe),
            "with_version": sum(1 for r in self.rules.values() if r.version_pattern)
        }


# 全局实例
fingerprint_library = FingerprintLibrary()
