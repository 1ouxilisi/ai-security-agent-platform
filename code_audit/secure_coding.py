# -*- coding: utf-8 -*-
"""
code_audit/secure_coding.py — 安全编码规范检查器（第11轮升级）

能力：
- 6 类规范：
  1) OWASP Secure Coding Practices
  2) CERT C / C++ / Java
  3) MITRE CWE Top 25
  4) SANS Top 25
  5) 语言特定规范
  6) 企业内部基线
- 150+ 条检查规则（按语言 / 规范分类，含
  名称 / 描述 / 严重程度 / 规范来源 / 检查方法 / 修复建议 / 示例代码）
- 合规评分（0-100）、差距分析、培训建议、检查报告

说明：规则内嵌，以正则启发式匹配源码；所有功能均为防御 / 评估视角。
"""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from code_audit.sast_engine import EXT_MAP, SKIP_DIRS

SPECS = [
    "owasp-scp", "cert-c", "cert-cpp", "cert-java",
    "cwe-top25", "sans-top25", "language-specific", "enterprise-baseline",
]

SEVERITY_SCORE = {"Critical": 9.5, "High": 7.5, "Medium": 5.0,
                  "Low": 2.5, "Info": 1.0}


@dataclass
class SecureRule:
    id: str
    name: str
    description: str
    severity: str
    spec: str            # 规范来源
    language: str
    method: str          # 检查方法描述
    pattern: str         # 正则
    fix: str
    bad_example: str
    good_example: str


def _mk(rid, name, desc, sev, spec, lang, method, pat, fix, bad, good):
    return SecureRule(rid, name, desc, sev, spec, lang, method, pat,
                      fix, bad, good)


def _build_rules() -> List[SecureRule]:
    rules: List[SecureRule] = []

    # ---- OWASP Secure Coding Practices（跨语言通用 ~25）----
    OWASP = [
        ("scp-input", "输入验证", "所有外部输入必须校验", "High",
         "owasp-scp", "generic", "检测直接使用请求参数",
         r"(request|req)\.(GET|POST|param|body|query)",
         "使用白名单校验输入类型/长度/范围",
         "name = request.GET['name']", "name = sanitize(request.GET['name'])"),
        ("scp-encoding", "输出编码", "输出到浏览器前编码", "High",
         "owasp-scp", "generic", "检测未转义输出",
         r"(echo|print|innerHTML|document\.write)",
         "按输出上下文编码（HTML/JS/URL）",
         'echo $_GET["q"]', 'echo htmlspecialchars($_GET["q"])'),
        ("scp-query", "参数化查询", "禁止拼接 SQL", "Critical",
         "owasp-scp", "generic", "检测 SQL 字符串拼接",
         r"(SELECT|INSERT|UPDATE|DELETE).*\+",
         "使用预编译/参数化查询",
         'db.query("WHERE id=" + id)', "db.query('WHERE id=?', id)"),
        ("scp-authz", "服务端鉴权", "每个受保护资源都要鉴权", "High",
         "owasp-scp", "generic", "检测路由缺少鉴权注解",
         r"@(Get|Post|Request)Mapping(?!.*auth)",
         "强制鉴权中间件/注解",
         "@GetMapping('/admin')", "@RequiresAuth @GetMapping('/admin')"),
        ("scp-session", "会话管理", "会话固定/过期/重新生成", "Medium",
         "owasp-scp", "generic", "检测固定会话 ID",
         r"(session|cookie).*fixed",
         "登录后再生 session id",
         "session.id = uid", "session.rotate(uid)"),
        ("scp-error", "错误处理", "不向用户泄露堆栈", "Medium",
         "owasp-scp", "generic", "检测调试输出",
         r"(traceback|stack|exception).*(print|response)",
         "统一错误页，日志记录细节",
         "echo e.trace", "logger.error(e); return generic_error()"),
        ("scp-crypto", "强密码学", "使用 Approved 算法", "High",
         "owasp-scp", "generic", "检测弱算法",
         r"(MD5|SHA-?1|DES\b|RC4\b)",
         "使用 SHA-256 / AES-256 / bcrypt",
         "md5(pw)", "bcrypt.hash(pw)"),
        ("scp-config", "安全配置", "生产关闭调试/默认口令", "High",
         "owasp-scp", "generic", "检测调试开关",
         r"(debug\s*=\s*true|DEBUG\s*=\s*True)",
         "通过环境区分配置",
         "DEBUG = True", "DEBUG = os.getenv('DEBUG') == '1'"),
        ("scp-comm", "安全传输", "全程 TLS", "Medium",
         "owasp-scp", "generic", "检测 http://",
         r"http://",
         "使用 https:// 并 HSTS",
         "http://api.example.com", "https://api.example.com"),
        ("scp-privacy", "隐私保护", "敏感数据最小化", "Medium",
         "owasp-scp", "generic", "检测日志含敏感字段",
         r"log\w*\([^)]*(ssn|password|credit)",
         "脱敏后记录",
         "logger.info('pw=' + pw)", "logger.info('pw=***')"),
        ("scp-mem", "内存安全", "使用安全函数", "High",
         "owasp-scp", "c", "检测危险函数",
         r"\b(strcpy|gets|sprintf)\s*\(",
         "使用带长度的安全函数",
         "strcpy(dst, src)", "strncpy(dst, src, sizeof(dst))"),
        ("scp-xml", "安全 XML", "禁用外部实体", "High",
         "owasp-scp", "generic", "检测 XML 解析",
         r"(DocumentBuilder|SAXReader|lxml|xmltodict)",
         "禁用 DTD / 外部实体",
         "parser = make_parser()", "parser.set_feature(DISALLOW_DOCTYPE)"),
    ]
    for it in OWASP:
        rules.append(_mk(*it))

    # ---- CERT C / C++ / Java（~30）----
    CERT_C = [
        ("cert-c-exp39", "EXP39-C 范围检查", "数组索引必须在范围内", "High",
         "cert-c", "c", "检测数组索引",
         r"\[\s*(i|len|n)\s*\]", "校验 index < size",
         "buf[i]", "if (i < size) buf[i]"),
        ("cert-c-exp34", "EXP34-C 整数溢出", "无符号回绕", "Medium",
         "cert-c", "c", "检测乘法分配",
         r"malloc\s*\(\s*\w+\s*\*\s*\w+",
         "检查溢出", "malloc(n * size)", "if (n > SIZE_MAX/size) die();"),
        ("cert-c-str31", "STR31-C 字符串终止", "字符串必须 NUL 终止", "High",
         "cert-c", "c", "strncpy 使用",
         r"\bstrncpy\s*\(", "显式补 NUL",
         "strncpy(d,s,n)", "strncpy(d,s,n-1); d[n-1]=0"),
        ("cert-c-err34", "ERR34-C 检测转换错误", "strtol 错误检查", "Medium",
         "cert-c", "c", "atoi 使用",
         r"\batoi\s*\(", "使用 strtol",
         "x = atoi(s)", "x = strtol(s, &end, 10)"),
        ("cert-c-mem00", "MEM00-C 释放置空", "释放后指针置空", "Medium",
         "cert-c", "c", "free 后未置空",
         r"\bfree\s*\([^)]+\);", "free 后 = NULL",
         "free(p)", "free(p); p = NULL;"),
        ("cert-c-con30", "CON30-C 线程同步", "共享数据需同步", "Medium",
         "cert-c", "c", "全局变量并发写",
         r"pthread_mutex", "始终持锁",
         "x++", "pthread_mutex_lock(&m); x++; pthread_mutex_unlock(&m);"),
    ]
    for it in CERT_C:
        rules.append(_mk(*it))
        itx = list(it)
        itx[0] += "-cpp"
        itx[4] = "cert-cpp"
        itx[5] = "cpp"
        rules.append(_mk(*itx))

    CERT_JAVA = [
        ("cert-java-ser01", "SER01-J 反序列化白名单", "反序列化需白名单", "Critical",
         "cert-java", "java", "ObjectInputStream",
         r"ObjectInputStream", "白名单类",
         "new ObjectInputStream(in)", "LookAheadObjectInputStream(in, ALLOW)"),
        ("cert-java-err01", "ERR01-J 不应吞异常", "不要空 catch", "Low",
         "cert-java", "java", "空 catch",
         r"catch\s*\([^)]*\)\s*\{\s*\}", "记录并重抛",
         "catch(e){}", "catch(e){ log.error(e); throw e; }"),
        ("cert-java-sec01", "SEC01-J 安全管理器", "不要禁用安全管理器", "Medium",
         "cert-java", "java", "setSecurityManager",
         r"setSecurityManager\s*\(\s*null\s*\)", "保持开启",
         "System.setSecurityManager(null)", "System.setSecurityManager(new SM())"),
        ("cert-java-dcl00", "DCL00-J 类不可变", "工具类不可实例化", "Low",
         "cert-java", "java", "public 构造",
         r"public\s+class\s+\w+.*public\s+\w+\(\)", "私有构造",
         "public Util(){}", "private Util(){}"),
    ]
    for it in CERT_JAVA:
        rules.append(_mk(*it))

    # ---- CWE Top 25（~25，跨语言）----
    CWE_TOP = [
        (f"cwe-{n:03d}-{key}", title, desc, sev, "cwe-top25", "generic",
         "模式匹配", pat, fix, bad, good)
        for n, key, title, desc, sev, pat, fix, bad, good in [
            (79, "xss", "XSS", "未转义输出", "High",
             r"innerHTML|document\.write", "输出编码",
             'el.innerHTML = u', 'el.textContent = u'),
            (89, "sqli", "SQL 注入", "拼接 SQL", "Critical",
             r"execute\s*\([^)]*\+", "参数化",
             "db.q('..' + id)", "db.q('..?', id)"),
            (78, "cmdi", "命令注入", "拼接 shell", "Critical",
             r"system\s*\(|exec\s*\(", "参数化",
             "os.system('ping ' + ip)", "subprocess.run(['ping', ip])"),
            (22, "path", "路径遍历", "用户输入拼路径", "High",
             r"open\s*\(\s*[^)]*request", "规范化白名单",
             "open(req.path)", "safe_open(req.path)"),
            (502, "deser", "反序列化", "不可信数据反序列化", "Critical",
             r"(pickle|unserialize|readObject)", "白名单/JSON",
             "pickle.loads(x)", "json.loads(x)"),
            (798, "hardcoded", "硬编码凭据", "源码含口令", "High",
             r"(password|secret)\s*=\s*['\"][^'\"]+['\"]", "KMS/环境变量",
             'pw = "hunter2"', 'pw = os.getenv("PW")'),
            (416, "uaf", "释放后使用", "free 后解引用", "Critical",
             r"free\s*\([^)]+\)[\s\S]{0,30}\w+->", "置空",
             "free(p); p->x", "free(p); p=NULL;"),
            (787, "oobwrite", "越界写", "缓冲区溢出", "Critical",
             r"strcpy\s*\(", "安全函数",
             "strcpy(d,s)", "strncpy(d,s,sizeof(d))"),
            (352, "csrf", "CSRF", "缺少 Token", "Medium",
             r"@PostMapping(?!.*csrf)", "CSRF Token",
             "@PostMapping('/transfer')", "@PostMapping + CSRF token"),
            (918, "ssrf", "SSRF", "请求外部 URL", "High",
             r"requests\.(get|post)\([^)]*req", "白名单",
             "requests.get(req.url)", "fetch_safe(req.url)"),
            (862, "authz", "缺失鉴权", "未授权访问", "High",
             r"@GetMapping(?!.*auth)", "鉴权注解",
             "@GetMapping('/admin')", "@PreAuthorize @GetMapping"),
            (287, "authn", "身份认证", "弱认证", "High",
             r"login\s*\([^)]*password\s*=\s*get", "MFA/慢哈希",
             "if pw == input", "verify(pw_hash, input)"),
            (20, "inputval", "输入验证", "未校验输入", "Medium",
             r"request\.(GET|POST|param)\[[^\]]+\]\s*;", "校验类型",
             "name = req['name']", "name = validate(req['name'])"),
            (306, "noauth", "关键功能无认证", "无认证接口", "High",
             r"@(Get|Post)Mapping.*(admin|delete)", "加认证",
             "@DeleteMapping('/user')", "@PreAuth @DeleteMapping"),
            (732, "perms", "不安全权限", "文件 777", "Medium",
             r"chmod\s*\([^)]*0o?777", "最小权限",
             "chmod(f, 0777)", "chmod(f, 0600)"),
        ]
    ]
    for it in CWE_TOP:
        rules.append(_mk(*it))

    # ---- SANS Top 25（与 CWE 重叠，但来源标注不同，~10）----
    SANS_TOP = [
        ("sans-1", "SANS: 注入", "注入类弱点", "Critical",
         "sans-top25", "generic", "模式匹配",
         r"(SELECT .* \+|exec\s*\()", "参数化/白名单",
         "q('..' + x)", "q('..?', x)"),
        ("sans-2", "SANS: 失效访问控制", "访问控制缺失", "High",
         "sans-top25", "generic", "模式匹配",
         r"@(Get|Post)Mapping(?!.*auth)", "默认拒绝",
         "@GetMapping", "@DenyAll @GetMapping"),
        ("sans-3", "SANS: 敏感数据暴露", "明文存储敏感", "High",
         "sans-top25", "generic", "模式匹配",
         r"(credit|ssn)\s*=\s*['\"][0-9]", "加密/令牌化",
         "save(ssn)", "save(encrypt(ssn))"),
        ("sans-4", "SANS: XML 外部实体", "XXE", "High",
         "sans-top25", "generic", "模式匹配",
         r"DocumentBuilder", "禁用 DTD",
         "dbf.newDocumentBuilder()", "dbf.setFeature(XXE, false)"),
        ("sans-5", "SANS: 越权", "水平/垂直越权", "High",
         "sans-top25", "generic", "模式匹配",
         r"user\s*=\s*getById\s*\(\s*req", "校验归属",
         "u = get(req.uid)", "u = get_owned(req.uid, req.user)"),
        ("sans-6", "SANS: 不安全反序列化", "Deser", "Critical",
         "sans-top25", "generic", "模式匹配",
         r"(pickle|yaml\.load|unserialize)", "JSON/白名单",
         "pickle.loads(x)", "json.loads(x)"),
        ("sans-7", "SANS: 使用含已知漏洞组件", "依赖漏洞", "High",
         "sans-top25", "generic", "依赖扫描",
         r"lodash|<4.17.21", "升级组件",
         "lodash@4.17.10", "lodash@4.17.21"),
        ("sans-8", "SANS: 不安全随机数", "弱随机", "Medium",
         "sans-top25", "generic", "模式匹配",
         r"\b(rand|Random)\s*\(", "CSPRNG",
         "rand()", "secrets.randbits()"),
        ("sans-9", "SANS: 权限校验错误", "鉴权绕过", "High",
         "sans-top25", "generic", "模式匹配",
         r"if\s*\(\s*false\s*\)", "条件鉴权",
         "if (false)", "if (user.isAdmin())"),
        ("sans-10", "SANS: 缺少加密", "传输未加密", "Medium",
         "sans-top25", "generic", "模式匹配",
         r"http://", "TLS",
         "http://", "https://"),
    ]
    for it in SANS_TOP:
        rules.append(_mk(*it))

    # ---- 语言特定（Python/JS/Java 各 ~10）----
    LANG_PY = [
        ("ls-py-eval", "Python: eval", "禁止 eval", "Critical",
         "language-specific", "python", "模式匹配",
         r"\beval\s*\(", "ast.literal_eval",
         "eval(x)", "ast.literal_eval(x)"),
        ("ls-py-pickle", "Python: pickle", "禁止 pickle", "Critical",
         "language-specific", "python", "模式匹配",
         r"pickle\.loads?", "JSON",
         "pickle.loads(x)", "json.loads(x)"),
        ("ls-py-shell", "Python: shell=True", "关闭 shell", "High",
         "language-specific", "python", "模式匹配",
         r"shell\s*=\s*True", "shell=False",
         "run(cmd, shell=True)", "run(args_list)"),
        ("ls-py-requests", "Python: verify", "校验证书", "High",
         "language-specific", "python", "模式匹配",
         r"verify\s*=\s*False", "verify=True",
         "requests.get(u, verify=False)", "requests.get(u)"),
        ("ls-py-yaml", "Python: safe_load", "安全 YAML", "High",
         "language-specific", "python", "模式匹配",
         r"yaml\.load\s*\((?![^)]*Safe)", "safe_load",
         "yaml.load(x)", "yaml.safe_load(x)"),
        ("ls-py-md5", "Python: 哈希", "强哈希", "Medium",
         "language-specific", "python", "模式匹配",
         r"hashlib\.(md5|sha1)", "sha256",
         "hashlib.md5(d)", "hashlib.sha256(d)"),
    ]
    for it in LANG_PY:
        rules.append(_mk(*it))

    LANG_JS = [
        ("ls-js-eval", "JS: eval", "禁止 eval", "Critical",
         "language-specific", "javascript", "模式匹配",
         r"\beval\s*\(", "JSON.parse",
         "eval(x)", "JSON.parse(x)"),
        ("ls-js-innerhtml", "JS: innerHTML", "避免 innerHTML", "High",
         "language-specific", "javascript", "模式匹配",
         r"\.innerHTML\s*=", "textContent",
         "el.innerHTML = u", "el.textContent = u"),
        ("ls-js-localstorage", "JS: localStorage", "不要存敏感", "Medium",
         "language-specific", "javascript", "模式匹配",
         r"localStorage\.setItem\s*\([^)]*(token|pwd)", "HttpOnly",
         "localStorage.t = t", "setCookie(t, {httpOnly:true})"),
        ("ls-js-child", "JS: exec", "参数化", "High",
         "language-specific", "javascript", "模式匹配",
         r"child_process\.exec\s*\(", "spawn",
         "exec('ls ' + d)", "spawn('ls', [d])"),
        ("ls-js-postmsg", "JS: postMessage", "校验 origin", "High",
         "language-specific", "javascript", "模式匹配",
         r"postMessage\s*\([^,]+,\s*['\"]\*['\"]", "指定 origin",
         "w.postMessage(x, '*')", "w.postMessage(x, ORIGIN)"),
    ]
    for it in LANG_JS:
        rules.append(_mk(*it))
        itx = list(it)
        itx[0] += "-ts"
        itx[5] = "typescript"
        rules.append(_mk(*itx))

    LANG_JV = [
        ("ls-jv-prepstmt", "Java: PreparedStatement", "预编译", "Critical",
         "language-specific", "java", "模式匹配",
         r"Statement.*execute\s*\([^)]*\+", "PreparedStatement",
         "st.execute(q + id)", "ps = conn.prepareStatement(q); ps.setString(1, id)"),
        ("ls-jv-xxe", "Java: XXE", "禁 DTD", "High",
         "language-specific", "java", "模式匹配",
         r"DocumentBuilderFactory", "setFeature",
         "dbf.newDocumentBuilder()", "dbf.setFeature(DISALLOW_DOCTYPE, true)"),
        ("ls-jv-random", "Java: SecureRandom", "安全随机", "Medium",
         "language-specific", "java", "模式匹配",
         r"\bnew\s+Random\s*\(", "SecureRandom",
         "new Random()", "new SecureRandom()"),
        ("ls-jv-log", "Java: 不要打印密码", "日志脱敏", "Medium",
         "language-specific", "java", "模式匹配",
         r"logger\.\w+\([^)]*password", "脱敏",
         "log.info(pw)", "log.info(mask(pw))"),
    ]
    for it in LANG_JV:
        rules.append(_mk(*it))

    # ---- 企业基线（~20 通用）----
    ENTERPRISE = [
        ("ent-01", "禁止内网 IP 硬编码", "配置化", "Low",
         "enterprise-baseline", "generic", "正则",
         r"\b(\d{1,3}\.){3}\d{1,3}\b", "配置中心",
         "host='10.0.0.5'", "host = cfg.host"),
        ("ent-02", "禁止 TODO 遗留", "清理待办", "Info",
         "enterprise-baseline", "generic", "正则",
         r"(TODO|FIXME)", "本周修复",
         "# TODO: fix", "issue#123"),
        ("ent-03", "异常必须记录", "不要吞异常", "Low",
         "enterprise-baseline", "generic", "正则",
         r"catch\s*\([^)]*\)\s*\{\s*\}", "log.error",
         "catch(e){}", "catch(e){log.error(e);}"),
        ("ent-04", "禁止 commit .env", "敏感文件", "Medium",
         "enterprise-baseline", "generic", "正则",
         r"\.env\b", ".gitignore",
         "git add .env", "git rm --cached .env"),
        ("ent-05", "JWT 必须强密钥", "密钥长度 >= 32", "High",
         "enterprise-baseline", "generic", "正则",
         r"jwt\.encode\s*\([^,]+,\s*['\"][^'\"]{8,20}['\"]", "随机长密钥",
         "jwt.encode(p, 'secret')", "jwt.encode(p, env.JWT_KEY)"),
        ("ent-06", "Cookie 必须 HttpOnly", "会话保护", "Medium",
         "enterprise-baseline", "generic", "正则",
         r"Set-Cookie:(?!.*HttpOnly)", "加 HttpOnly",
         "Set-Cookie: sid=x", "Set-Cookie: sid=x; HttpOnly; Secure"),
        ("ent-07", "禁用 TLS 1.0", "过时协议", "Medium",
         "enterprise-baseline", "generic", "正则",
         r"TLSv1\.0", "TLS1.2+",
         "ssl.min=TLSv1", "ssl.min=TLSv1.2"),
        ("ent-08", "禁止默认口令", "首次改密", "High",
         "enterprise-baseline", "generic", "正则",
         r"(admin|root)[:/](admin|123456)", "强制改密",
         "admin/admin", "第一次登录强制改密"),
        ("ent-09", "日志不含手机号", "PII", "Medium",
         "enterprise-baseline", "generic", "正则",
         r"log\w*\([^)]*1[3-9]\d{9}", "脱敏",
         "log.info(phone)", "log.info(mask(phone))"),
        ("ent-10", "分页必须上限", "防止全表拖取", "Low",
         "enterprise-baseline", "generic", "正则",
         r"limit\s*=\s*\d{4,}", "最大 500",
         "limit = 10000", "limit = min(req, 500)"),
    ]
    for it in ENTERPRISE:
        rules.append(_mk(*it))

    # ---- 第二批：扩充到 150+ ----
    OWASP2 = [
        ("scp-totp", "多因素认证", "敏感操作 MFA", "Medium",
         "owasp-scp", "generic", "检测登录分支",
         r"(login|signin).*\(.*password", "MFA",
         "if pw == x", "if pw_ok(x) and totp_ok(code)"),
        ("scp-rate", "限流", "防暴力破解", "Medium",
         "owasp-scp", "generic", "检测登录无限流",
         r"(login|signin)\s*\([^)]*\)\s*{", "限流中间件",
         "app.post('/login', login)", "app.post('/login', limit(5), login)"),
        ("scp-hash", "口令慢哈希", "不要用 MD5/SHA1 存口令", "High",
         "owasp-scp", "generic", "检测口令哈希",
         r"(hashlib\.(md5|sha1)|md5\s*\()", "bcrypt/argon2",
         "hashlib.md5(pw)", "bcrypt.hash(pw)"),
        ("scp-sql-order", "ORDER BY 注入", "排序列白名单", "Medium",
         "owasp-scp", "generic", "检测 order by 拼接",
         r"ORDER\s+BY\s*['\"]?\s*\+", "白名单列",
         "ORDER BY <user_input>", "ORDER BY <whitelisted_column>"),
        ("scp-redis", "Redis 未授权", "Redis 需密码", "Medium",
         "owasp-scp", "generic", "检测无密码连接",
         r"redis\.(Redis|new\s+Client)\s*\([^)]*\)", "requirepass",
         "redis.Redis()", "redis.Redis(password=cfg.pw)"),
        ("scp-cors", "CORS 最小化", "不要 *", "Medium",
         "owasp-scp", "generic", "检测通配",
         r"Access-Control-Allow-Origin.*\*", "明确来源",
         "ACAO: *", "ACAO: https://app.example.com"),
        ("scp-clickjack", "防点击劫持", "X-Frame-Options", "Medium",
         "owasp-scp", "generic", "检测缺响应头",
         r"(response|headers)\s*\[[^\]]*\]\s*=\s*['\"]\*", "DENY/SAMEORIGIN",
         "no frame header", "X-Frame-Options: DENY"),
        ("scp-csp", "内容安全策略", "CSP 头", "Medium",
         "owasp-scp", "generic", "检测缺 CSP",
         r"(?<!Content-Security-Policy)", "设置 CSP",
         "no CSP", "Content-Security-Policy: default-src 'self'"),
        ("scp-upload", "文件上传校验", "类型/大小白名单", "High",
         "owasp-scp", "generic", "检测上传处理",
         r"(upload|move_uploaded_file)", "校验 MIME/扩展名",
         "save(req.file)", "validate(req.file); save(req.file)"),
        ("scp-downgrade", "禁止降级", "强制 https 重定向", "Medium",
         "owasp-scp", "generic", "检测 http 监听",
         r"(listen|bind)\s*\(\s*80\b", "80 跳 443",
         "listen(80)", "listen(80, redirect->443)"),
        ("scp-audit", "审计日志", "安全事件留痕", "Low",
         "owasp-scp", "generic", "检测关键操作无日志",
         r"(delete|admin)\s*\(", "审计日志",
         "db.delete(user)", "audit.log('delete', user); db.delete(user)"),
        ("scp-minpriv", "最小权限", "服务用低权账户", "Medium",
         "owasp-scp", "generic", "检测 root 运行",
         r"(useradd root|run as root|sudo)", "非 root",
         "run as root", "run as appuser"),
        ("scp-secretscan", "密钥扫描", "提交前扫描", "Medium",
         "owasp-scp", "generic", "检测密钥模式",
         r"-----BEGIN.*PRIVATE KEY", "gitleaks",
         "commit key.pem", "gitleaks pre-commit"),
    ]
    for it in OWASP2:
        rules.append(_mk(*it))

    CERT_J2 = [
        ("cert-java-err08", "ERR08-J 不要断言做安全", "断言不可用于鉴权", "Medium",
         "cert-java", "java", "assert",
         r"\bassert\s+\w+\.(isAdmin|authenticated)", "显式校验",
         "assert user.admin", "if (!user.admin) throw new AuthzException();"),
        ("cert-java-thd00", "THD00-J 线程安全", "可变共享需同步", "Medium",
         "cert-java", "java", "static 可变",
         r"static\s+\w+\s+\w+\s*=", "不可变或同步",
         "static List x", "static final ImmutableList x"),
        ("cert-java-env00", "ENV00-J 环境变量", "不要 trust 环境", "Medium",
         "cert-java", "java", "getenv",
         r"System\.getenv\s*\(\s*['\"]PATH", "校验",
         "System.getenv(\"PATH\")", "validate(System.getenv(\"PATH\"))"),
        ("cert-java-fio00", "FIO00-J 文件权限", "创建文件 600", "Medium",
         "cert-java", "java", "setReadable",
         r"setReadable\s*\([^,]+,\s*true\s*,\s*true", "最小权限",
         "f.setReadable(true,true)", "f.setReadable(false,false)"),
        ("cert-java-num00", "NUM00-J 整数溢出", "检查溢出", "Medium",
         "cert-java", "java", "乘法",
         r"int\s+\w+\s*=\s*\w+\s*\*\s*\w+", "Math.multiplyExact",
         "int c = a * b", "int c = Math.multiplyExact(a,b)"),
        ("cert-java-sec09", "SEC09-J 安全随机", "SecureRandom", "Medium",
         "cert-java", "java", "new Random",
         r"\bnew\s+Random\s*\(", "SecureRandom",
         "new Random()", "new SecureRandom()"),
    ]
    for it in CERT_J2:
        rules.append(_mk(*it))

    CERT_C2 = [
        ("cert-c-exp33", "EXP33-C 有符号比较", "无符号比较", "Medium",
         "cert-c", "c", "sizeof 比较",
         r"(int)\s*sizeof\s*\(", "size_t",
         "if ((int)sizeof(x) > n)", "if (sizeof(x) > (size_t)n)"),
        ("cert-c-arr30", "ARR30-C 数组范围", "数组下标", "High",
         "cert-c", "c", "下标计算",
         r"\[\s*\w+\s*\+\s*\w+\s*\]", "边界检查",
         "a[i+j]", "if (i+j < N) a[i+j]"),
        ("cert-c-flp30", "FLP30-FP 浮点比较", "不要 == 比较", "Low",
         "cert-c", "c", "浮点等号",
         r"==\s*0\.0", "容差",
         "if (x == 0.0)", "if (fabs(x) < EPS)"),
        ("cert-c-str32", "STR32-C 终止 null", "字符串长度", "High",
         "cert-c", "c", "strlen 计算",
         r"strlen\s*\([^)]+\)\s*[<>=!]=?\s*\d+", "留终止位",
         "dst[strlen(src)]", "dst[sizeof(dst)-1] = 0"),
    ]
    for it in CERT_C2:
        rules.append(_mk(*it))
        itx = list(it)
        itx[0] += "-cpp"
        itx[4] = "cert-cpp"
        itx[5] = "cpp"
        rules.append(_mk(*itx))

    CWE2 = [
        (f"cwe-{n:03d}-{key}", title, desc, sev, "cwe-top25", "generic",
         "模式匹配", pat, fix, bad, good)
        for n, key, title, desc, sev, pat, fix, bad, good in [
            (119, "oob", "越界读", "缓冲区溢出读", "Critical",
             r"\[index\]", "边界检查",
             "a[i]", "if (i < n) a[i]"),
            (125, "oobread", "越界读", "读越界", "High",
             r"memcpy\s*\([^,]+,[^,]+,\s*len", "校验 len",
             "memcpy(d,s,l)", "if (l <= cap) memcpy(d,s,l)"),
            (200, "leak", "信息泄露", "错误信息泄露", "Medium",
             r"printStackTrace", "统一错误",
             "e.printStackTrace()", "logger.error(e)"),
            (269, "priv", "权限管理不当", "提权", "High",
             r"chmod\s*\([^)]*777", "最小权限",
             "chmod(f,777)", "chmod(f,600)"),
            (312, "plaintext", "明文存储", "明文敏感", "High",
             r"(password|secret)\s*=\s*[\"']", "加密",
             "pw = 'x'", "pw = enc('x')"),
            (326, "weakcrypto", "弱加密", "密钥过短", "Medium",
             r"RSA\s*\(\s*1024", ">= 2048",
             "RSA(1024)", "RSA(2048)"),
            (327, "broken", "弱算法", "MD5/SHA1", "Medium",
             r"(MD5|SHA1)\b", "SHA256",
             "MD5(d)", "SHA256(d)"),
            (338, "weakrand", "弱随机", "rand", "Medium",
             r"\brand\s*\(", "CSPRNG",
             "rand()", "arc4random()"),
            (347, "jwtalg", "JWT 校验", "未校验签名", "High",
             r"jwt\.decode\s*\([^)]*options", "校验 alg",
             "jwt.decode(t, {verify:false})", "jwt.decode(t, key)"),
            (384, "sessionfix", "会话固定", "登录后不换 id", "Medium",
             r"login\s*\([^)]*\)\s*{", "regenerate",
             "login(u)", "login(u); session.regenerate()"),
            (400, "dos", "资源耗尽", "无限制循环", "Medium",
             r"while\s*\(\s*true\s*\)", "退出条件",
             "while(1){}", "while(running){}"),
            (401, "unauth", "未授权", "访问控制", "High",
             r"@GetMapping.*(admin|report)", "鉴权",
             "@GetMapping('/admin')", "@PreAuth @GetMapping"),
            (476, "nullderef", "空指针", "未判空", "Medium",
             r"\w+\.toString\s*\(\s*\)", "判空",
             "u.toString()", "u?.toString()"),
            (522, "creds", "凭据保护不当", "传输明文", "High",
             r"http://[^/]*:8080", "TLS",
             "http://x:8080", "https://x"),
            (732, "perms2", "不安全权限", "umask 0", "Medium",
             r"umask\s*\(\s*0\s*\)", "077",
             "umask(0)", "umask(077)"),
        ]
    ]
    for it in CWE2:
        rules.append(_mk(*it))

    SANS2 = [
        ("sans-11", "SANS: 认证缺失", "未认证", "High",
         "sans-top25", "generic", "模式匹配",
         r"@(Get|Post)Mapping(?!.*auth)", "认证",
         "@PostMapping", "@Auth @PostMapping"),
        ("sans-12", "SANS: 敏感信息明文", "明文", "High",
         "sans-top25", "generic", "模式匹配",
         r"(http://|ftp://)", "TLS",
         "ftp://x", "sftp://x"),
        ("sans-13", "SANS: 缓冲区错误", "溢出", "Critical",
         "sans-top25", "c", "模式匹配",
         r"strcpy\s*\(", "strncpy",
         "strcpy(d,s)", "strncpy(d,s,sizeof(d))"),
        ("sans-14", "SANS: 跨站脚本", "XSS", "High",
         "sans-top25", "generic", "模式匹配",
         r"innerHTML", "textContent",
         "el.innerHTML=u", "el.textContent=u"),
        ("sans-15", "SANS: 权限提升", "提权", "High",
         "sans-top25", "generic", "模式匹配",
         r"setuid\s*\(\s*0\s*\)", "最小权限",
         "setuid(0)", "setuid(app)"),
    ]
    for it in SANS2:
        rules.append(_mk(*it))

    LANG2 = [
        ("ls-py-temp", "Python: mktemp", "竞态", "Medium",
         "language-specific", "python", "模式匹配",
         r"mktemp\s*\(", "mkstemp",
         "mktemp()", "mkstemp()"),
        ("ls-py-ssl", "Python: unverified", "证书校验", "High",
         "language-specific", "python", "模式匹配",
         r"_create_unverified_context", "默认",
         "_create_unverified_context()", "create_default_context()"),
        ("ls-py-assert", "Python: assert 鉴权", "assert", "Low",
         "language-specific", "python", "模式匹配",
         r"^\s*assert\s+\w+\.is_", "显式异常",
         "assert u.admin", "if not u.admin: raise"),
        ("ls-go-tls", "Go: InsecureSkipVerify", "TLS", "High",
         "language-specific", "go", "模式匹配",
         r"InsecureSkipVerify:\s*true", "false",
         "InsecureSkipVerify: true", "InsecureSkipVerify: false"),
        ("ls-go-rand", "Go: math/rand", "CSPRNG", "Medium",
         "language-specific", "go", "模式匹配",
         r"math/rand", "crypto/rand",
         "rand.Int()", "rand.Read(b)"),
        ("ls-go-sqli", "Go: Sprintf SQL", "SQLi", "Critical",
         "language-specific", "go", "模式匹配",
         "fmt.Sprintf\\s*\\(.*SELECT", "占位符",
         "fmt.Sprintf(\"WHERE id=%s\", id)", "db.Query(\"WHERE id=?\", id)"),
        ("ls-cpp-smt", "C++: std::system", "命令注入", "High",
         "language-specific", "cpp", "模式匹配",
         r"std::system\s*\(", "execvp",
         "std::system(cmd)", "execvp(args[0], args)"),
        ("ls-cpp-cin", "C++: gets", "gets", "Critical",
         "language-specific", "cpp", "模式匹配",
         r"\bgets\s*\(", "fgets",
         "gets(buf)", "fgets(buf, n, stdin)"),
        ("ls-rb-sql", "Ruby: 字符串 SQL", "SQLi", "Critical",
         "language-specific", "ruby", "模式匹配",
         r"where\s*\(\s*['\"][^'\"]*#\{", "?",
         "where(\"n=#{x}\")", "where('n=?', x)"),
        ("ls-rb-yaml", "Ruby: YAML.load", "反序列化", "High",
         "language-specific", "ruby", "模式匹配",
         r"YAML\.load\s*\(", "safe_load",
         "YAML.load(x)", "YAML.safe_load(x)"),
    ]
    for it in LANG2:
        rules.append(_mk(*it))

    ENT2 = [
        ("ent-11", "禁止 SELECT *", "性能/泄露", "Low",
         "enterprise-baseline", "generic", "正则",
         r"SELECT\s+\*", "列名",
         "SELECT * FROM t", "SELECT id,name FROM t"),
        ("ent-12", "分页参数上限", "拖库", "Low",
         "enterprise-baseline", "generic", "正则",
         r"page_size\s*=\s*\d{4,}", "上限",
         "page_size=10000", "page_size=min(req,200)"),
        ("ent-13", "密码强度策略", "弱密码", "Medium",
         "enterprise-baseline", "generic", "正则",
         r"len\s*\(\s*\w+\s*\)\s*<\s*4", ">=8",
         "if len(pw)<4", "if len(pw)<8"),
        ("ent-14", "登录失败锁定", "暴力破解", "Medium",
         "enterprise-baseline", "generic", "正则",
         r"login_attempts", "锁定",
         "no lockout", "after 5 fail, lock 15min"),
        ("ent-15", "日志脱敏手机号", "PII", "Medium",
         "enterprise-baseline", "generic", "正则",
         r"log\w*\([^)]*1[3-9]\d{9}", "mask",
         "log(phone)", "log(mask(phone))"),
        ("ent-16", "日志脱敏身份证", "PII", "Medium",
         "enterprise-baseline", "generic", "正则",
         r"log\w*\([^)]*\d{17}[\dXx]", "mask",
         "log(idno)", "log(mask(idno))"),
        ("ent-17", "禁止 print 调试", "调试残留", "Low",
         "enterprise-baseline", "generic", "正则",
         r"\bprint\s*\(", "logging",
         "print(x)", "logger.debug(x)"),
        ("ent-18", "异常不吞", "空 catch", "Low",
         "enterprise-baseline", "generic", "正则",
         r"catch\s*\([^)]*\)\s*\{\s*\}", "log",
         "catch(e){}", "catch(e){log.error(e)}"),
        ("ent-19", "依赖锁定", "无 lockfile", "Low",
         "enterprise-baseline", "generic", "正则",
         r"requirements\.txt(?!.*lock)", "lock",
         "pip install pkg", "pip install pkg && pip freeze"),
        ("ent-20", "CI 必须跑扫描", "门禁", "Medium",
         "enterprise-baseline", "generic", "正则",
         r"(.github/workflows|Jenkinsfile)", "加入 SAST",
         "no security job", "add semgrep job"),
    ]
    for it in ENT2:
        rules.append(_mk(*it))

    return rules


# ---------------------------------------------------------------------------
# 检查器
# ---------------------------------------------------------------------------
class SecureCodingChecker:
    def __init__(self) -> None:
        self.rules: List[SecureRule] = _build_rules()

    def list_rules(self, spec: Optional[str] = None,
                   language: Optional[str] = None) -> List[Dict[str, Any]]:
        out = []
        for r in self.rules:
            if spec and r.spec != spec:
                continue
            if language and r.language not in (language, "generic"):
                continue
            out.append(asdict(r))
        return out

    def stats(self) -> Dict[str, Any]:
        by_spec: Dict[str, int] = {}
        by_lang: Dict[str, int] = {}
        for r in self.rules:
            by_spec[r.spec] = by_spec.get(r.spec, 0) + 1
            by_lang[r.language] = by_lang.get(r.language, 0) + 1
        return {"total": len(self.rules), "by_spec": by_spec,
                "by_language": by_lang}

    def check_file(self, path: str) -> List[Dict[str, Any]]:
        lang = EXT_MAP.get(os.path.splitext(path)[1].lower())
        if not lang:
            return []
        hits = []
        try:
            lines = open(path, encoding="utf-8", errors="ignore").readlines()
        except OSError:
            return hits
        applicable = [r for r in self.rules
                      if r.language in (lang, "generic")]
        for i, line in enumerate(lines, 1):
            for r in applicable:
                try:
                    if re.search(r.pattern, line, re.IGNORECASE):
                        hits.append({
                            "rule_id": r.id, "name": r.name,
                            "spec": r.spec, "severity": r.severity,
                            "file": path, "line": i,
                            "snippet": line.strip()[:200],
                            "fix": r.fix,
                            "bad_example": r.bad_example,
                            "good_example": r.good_example,
                        })
                except re.error:
                    continue
        return hits

    def check_directory(self, directory: str) -> Dict[str, Any]:
        started = time.time()
        hits: List[Dict[str, Any]] = []
        files = 0
        for root, dirs, fns in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fn in fns:
                if EXT_MAP.get(os.path.splitext(fn)[1].lower()):
                    files += 1
                    hits.extend(self.check_file(os.path.join(root, fn)))
        by_sev: Dict[str, int] = {}
        by_spec: Dict[str, int] = {}
        for h in hits:
            by_sev[h["severity"]] = by_sev.get(h["severity"], 0) + 1
            by_spec[h["spec"]] = by_spec.get(h["spec"], 0) + 1
        total_rules = len(self.rules)
        score = max(0, 100 - len(hits) * 2)
        return {
            "engine": "SecureCoding",
            "files": files,
            "hits": hits,
            "hits_count": len(hits),
            "by_severity": by_sev,
            "by_spec": by_spec,
            "rules_total": total_rules,
            "compliance_score": score,
            "elapsed_seconds": round(time.time() - started, 3),
            "timestamp": datetime.now().isoformat(),
        }

    def gap_analysis(self, result: Dict[str, Any]) -> List[str]:
        gaps = []
        for spec, cnt in result.get("by_spec", {}).items():
            gaps.append(f"规范 {spec} 检出 {cnt} 个不合规项")
        if result.get("compliance_score", 100) < 70:
            gaps.append("合规率低于 70%，建议开展专项培训")
        return gaps

    def training_suggestions(self, result: Dict[str, Any]) -> List[str]:
        suggestions = []
        by_spec = result.get("by_spec", {})
        if by_spec.get("owasp-scp"):
            suggestions.append("OWASP Secure Coding Practices 专项培训")
        if by_spec.get("cert-c") or by_spec.get("cert-cpp"):
            suggestions.append("C/C++ 内存安全与 CERT 培训")
        if by_spec.get("cwe-top25"):
            suggestions.append("CWE Top 25 弱点攻防演练")
        if not suggestions:
            suggestions.append("保持每季度一次安全编码复训")
        return suggestions

    def generate_report(self, result: Optional[Dict[str, Any]] = None
                        ) -> Dict[str, Any]:
        result = result or {}
        return {
            "report_type": "安全编码合规报告",
            "generated_at": datetime.now().isoformat(),
            "compliance_score": result.get("compliance_score", 100),
            "hits_count": result.get("hits_count", 0),
            "by_spec": result.get("by_spec", {}),
            "by_severity": result.get("by_severity", {}),
            "gap_analysis": self.gap_analysis(result),
            "training": self.training_suggestions(result),
            "rule_stats": self.stats(),
        }


_sc = SecureCodingChecker()


def get_secure_coding_checker() -> SecureCodingChecker:
    return _sc
