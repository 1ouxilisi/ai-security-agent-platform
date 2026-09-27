# -*- coding: utf-8 -*-
"""
seed_data/knowledge_seeds.py — 安全知识库种子数据（200+ 条）。

内容为检测/评估/加固视角的实用安全知识，覆盖 Web/移动/内网/云/AI/区块链/密码学/
网络协议/社会工程/合规标准。手工精编基础条目 + 分类主题扩展生成。
"""

from __future__ import annotations

KNOWLEDGE_CATEGORIES = [
    "Web安全", "移动安全", "内网渗透", "云安全", "AI安全",
    "区块链", "密码学", "网络协议", "社会工程", "合规标准",
]
DIFFICULTIES = ["入门", "中级", "高级"]

# --------------------------------------------------------------------------- #
# 手工精编的高质量知识条目
# --------------------------------------------------------------------------- #
CURATED: list[dict] = [
    {
        "title": "SQL注入的类型与防御方法",
        "category": "Web安全", "difficulty": "中级",
        "tags": ["SQL注入", "参数化查询", "WAF", "数据库"],
        "scenario": "Web 应用渗透测试与代码审计",
        "content": "SQL注入按获取数据方式分为回显型、盲注（布尔盲注/时间盲注）、报错型与堆叠查询。"
                   "防御核心是使用参数化查询/预编译语句（Prepared Statement），杜绝字符串拼接 SQL；"
                   "其次对输入做白名单校验、最小化数据库账户权限（禁用 FILE、EXEC 等高危权限）、"
                   "关闭详细错误回显。测试时可用 sqlmap --batch --risk=2 --level=2 验证，"
                   "但必须在授权范围内执行。ORM 框架并不能完全免疫，order by/like/in 子句仍需手工处理。",
        "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
    },
    {
        "title": "XSS 的三种类型与 CSP 配置",
        "category": "Web安全", "difficulty": "中级",
        "tags": ["XSS", "CSP", "前端安全", "HttpOnly"],
        "scenario": "前端代码审计与浏览器侧防御",
        "content": "XSS 分为反射型（参数即时回显）、存储型（持久化到数据库）、DOM 型（纯前端 JS 处理）。"
                   "防御分三层：输出编码（HTML/JS/URL 上下文分别转义）、HttpOnly + Secure Cookie 防会话窃取、"
                   "内容安全策略 CSP。推荐 CSP：default-src 'self'; script-src 'self'; object-src 'none'; "
                   "base-uri 'self'；严格模式下避免使用 unsafe-inline。同时对富文本使用 DOMPurify 之类的白名单过滤器。",
        "reference": "https://owasp.org/www-community/attacks/xss/",
    },
    {
        "title": "CSRF 与 SameSite Cookie 实践",
        "category": "Web安全", "difficulty": "入门",
        "tags": ["CSRF", "SameSite", "Cookie", "Token"],
        "scenario": "Web 应用会话安全加固",
        "content": "CSRF 利用浏览器自动携带 Cookie 的特性伪造跨站请求。现代防御首选 SameSite=Lax/Strict Cookie，"
                   "同时对状态变更请求使用 CSRF Token（Double Submit Cookie 或同步令牌模式）。"
                   "校验 Origin/Referer 头、对敏感操作要求二次验证（验证码/密码）也是有效补充。"
                   "注意 SameSite 不能替代 CSRF Token，仍需对敏感接口强制校验。",
        "reference": "https://owasp.org/www-community/attacks/csrf",
    },
    {
        "title": "SSRF 原理与云环境利用面",
        "category": "Web安全", "difficulty": "高级",
        "tags": ["SSRF", "云元数据", "内网探测", "重定向绕过"],
        "scenario": "服务端请求功能（图片抓取/URL 预览）安全测试",
        "content": "SSRF 指服务端按用户提供的 URL 发起请求，攻击者借此访问内网或云元数据接口。"
                   "云环境重点关注 169.254.169.254（AWS/GCP/Azure 元数据），可获取临时 IAM 凭证。"
                   "防御：禁止跳转到内网保留地址段（10/8、172.16/12、192.168/16、169.254/16）、"
                   "仅允许 http/https、禁止 30x 重定向后二次请求、对目标做 DNS 解析后 IP 校验。"
                   "gopher://、file://、dict:// 协议必须禁用。",
        "reference": "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
    },
    {
        "title": "文件上传漏洞利用与防御",
        "category": "Web安全", "difficulty": "中级",
        "tags": ["文件上传", "Webshell", "MIME绕过", "内容检测"],
        "scenario": "Web 应用上传点测试",
        "content": "文件上传风险在于可执行脚本落盘。常见绕过：改 Content-Type、双扩展名（.php.jpg）、"
                   "大小写、%00 截断、解析漏洞（IIS/Nginx）。防御：上传目录禁止执行权限、"
                   "重命名文件为随机名、白名单校验扩展名与 MIME、校验文件头（magic number）、"
                   "图片做二次渲染。存储尽量与 Web 根目录分离，使用对象存储并通过 CDN 分发。",
        "reference": "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
    },
    {
        "title": "JWT 安全配置要点",
        "category": "Web安全", "difficulty": "中级",
        "tags": ["JWT", "身份认证", "弱密钥", "alg=none"],
        "scenario": "基于 Token 的 API 认证评估",
        "content": "JWT 常见问题：alg=none 绕过、弱密钥爆破（hashcat -m 16500）、未校验 exp/iss/aud、"
                   "敏感信息放入 payload、密钥复用。防御：使用 RS256 非对称签名、拒绝 none 算法、"
                   "设置合理过期时间、刷新令牌与访问令牌分离、payload 不放敏感信息、"
                   "密钥长度不低于 256 位并定期轮换。测试时可解码 header.payload.signature 三段检查。",
        "reference": "https://auth0.com/blog/a-look-at-the-latest-jwt-vulnerabilities/",
    },
    {
        "title": "Linux 提权的 10 种常用检测方向",
        "category": "内网渗透", "difficulty": "高级",
        "tags": ["提权", "SUID", "sudo", "内核漏洞", "计划任务"],
        "scenario": "内网主机权限维持评估",
        "content": "提权检查清单：1) sudo -l 查看可免密执行命令；2) find / -perm -4000 2>/dev/null 找 SUID；"
                   "3) 检查 PATH 劫持与脚本可写；4) crontab -l 与 /etc/cron* 计划任务；5) 内核版本已知漏洞（uname -a）；"
                   "6) 弱密码与共享账号；7) NFS no_root_squash；8)  capabilities（getcap -r /）；"
                   "9) 可写服务配置导致服务重启提权；10) 历史命令与配置文件中的明文凭据。"
                   "加固：最小 sudo 权限、移除不必要 SUID、及时打内核补丁、审计计划任务。",
        "reference": "https://GTFOBins.github.io/GTFOBins/",
    },
    {
        "title": "Windows 内网横向移动评估要点",
        "category": "内网渗透", "difficulty": "高级",
        "tags": ["横向移动", "票据传递", "LDAP", "组策略"],
        "scenario": "域环境安全评估（授权红队）",
        "content": "横向移动检测视角：SMB/Admin 共享、WMI/WinRM、RDP 登录、Pass-the-Hash、"
                   "Pass-the-Ticket、Kerberoasting、Skeleton Key。防御：禁用 NTLMv1、启用 LAPS、"
                   "约束委派与资源约束委派审计、服务账户使用 gMSA、开启 Windows 事件日志 4624/4625/4688/4768/4769、"
                   "部署 EDR 检测可疑进程链（rundll32→powershell、mimikatz 特征）。"
                   "红队演练必须在授权范围与时间窗内进行。",
        "reference": "https://attack.mitre.org/tactics/TA0008/",
    },
    {
        "title": "AWS S3 存储桶安全配置最佳实践",
        "category": "云安全", "difficulty": "中级",
        "tags": ["AWS", "S3", "公开访问", "Bucket Policy"],
        "scenario": "云配置审计",
        "content": "S3 常见错误：Bucket Policy 授予 s3:GetObject 给 *、ACL public-read、"
                   "关闭 Block Public Access、未加密、版本控制未开启。审计要点：1) 检查每个 bucket 的 Block Public Access；"
                   "2) policy 中是否存在 Principal:* 与 Action:s3:GetObject；3) 是否开启默认加密（SSE-KMS）；"
                   "4) 是否启用版本控制与访问日志；5) 生命周期策略与跨区域复制。"
                   "工具：aws s3api get-bucket-policy / get-public-access-block，或用 ScoutSuite/PMapper 自动化。",
        "reference": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html",
    },
    {
        "title": "云安全元数据服务保护（IMDSv2）",
        "category": "云安全", "difficulty": "中级",
        "tags": ["元数据", "IMDSv2", "SSRF", "临时凭证"],
        "scenario": "云主机 SSRF 防护加固",
        "content": "云元数据服务 169.254.169.254 提供实例临时凭证。AWS IMDSv2 要求 PUT 获取 Token 后再 GET，"
                   "可阻止简单 SSRF 直接读取；GCP/Azure 也要求加 Metadata-Flavor/Metadata: true 头。"
                   "加固：强制 IMDSv2（HttpTokens=required）、限制 hop limit=1、"
                   "工作负载使用 IAM Role 而非长期 AccessKey、对出向做网络 ACL 限制元数据访问。",
        "reference": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
    },
    {
        "title": "容器逃逸风险面与加固",
        "category": "云安全", "difficulty": "高级",
        "tags": ["容器", "Docker", "K8s", "特权模式"],
        "scenario": "容器平台安全评估",
        "content": "容器逃逸高发点：特权容器（--privileged）、挂载宿主机 /var/run/docker.sock、"
                   "挂载宿主机 /proc、cap_add SYS_ADMIN、root 运行用户、可写宿主机路径。"
                   "加固：以非 root 运行（USER app）、禁用 privileged、drop ALL cap + add 必要 cap、"
                   "readOnlyRootFilesystem、Seccomp/AppArmor 策略、K8s Pod Security Standards restricted、"
                   "etcd/kubelet API 不暴露公网。",
        "reference": "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
    },
    {
        "title": "LLM 应用的 Prompt 注入与数据泄露",
        "category": "AI安全", "difficulty": "高级",
        "tags": ["LLM", "Prompt注入", "RAG", "越权"],
        "scenario": "AI 应用安全评估",
        "content": "大模型应用风险：直接 Prompt 注入（用户输入覆盖系统指令）、间接注入（外部文档/网页携带恶意指令）、"
                   "RAG 越权检索、敏感信息通过模型输出泄露、插件/工具调用被诱导执行危险操作。"
                   "防御：系统指令与用户输入严格分层、对工具调用做二次确认与白名单、"
                   "输出做敏感信息过滤、RAG 检索按用户权限过滤、对嵌入内容做内容隔离与指令标记、"
                   "建立红队 Prompt 用例回归测试。",
        "reference": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    },
    {
        "title": "模型供应链与训练数据投毒",
        "category": "AI安全", "difficulty": "高级",
        "tags": ["模型供应链", "投毒", "后门", "SBOM"],
        "scenario": "AI 模型采购与上线安全",
        "content": "模型供应链风险：第三方模型权重被植入后门、训练数据投毒使模型在特定触发器下输出错误、"
                   "依赖库（如 PyTorch 生态）存在已知 CVE。评估：要求提供模型卡（Model Card）与训练数据来源说明、"
                   "对外部权重做哈希校验与恶意权重扫描、用干净测试集验证后门触发、"
                   "维护 ML-BOM（模型与依赖清单）、对微调数据做来源过滤与抽样审计。",
        "reference": "https://arxiv.org/abs/2004.08510",
    },
    {
        "title": "智能合约重入与常见漏洞",
        "category": "区块链", "difficulty": "高级",
        "tags": ["智能合约", "重入", "Solidity", "审计"],
        "scenario": "Solidity 合约安全审计",
        "content": "Solidity 经典漏洞：重入（Reentrancy，先改状态再转账）、整数溢出（<0.8 版本）、"
                   "未检查的 low-level call、tx.origin 鉴权、时间戳依赖、短地址攻击、随机数可预测。"
                   "防御：Checks-Effects-Interactions 模式、使用 SafeERC20、OpenZeppelin ReentrancyGuard、"
                   "升级到 0.8+ 编译器、用 slither 静态分析、部署前做形式化验证与审计。",
        "reference": "https://consensys.github.io/smart-contract-best-practices/",
    },
    {
        "title": "TLS/SSL 证书与协议评估",
        "category": "网络协议", "difficulty": "中级",
        "tags": ["TLS", "证书", "密码套件", "HSTS"],
        "scenario": "Web 服务传输安全检测",
        "content": "评估要点：协议版本（禁用 SSLv3/TLS1.0/1.1，仅保留 TLS1.2/1.3）、"
                   "密码套件优先级（优先 ECDHE+AES-GCM/CHACHA20）、证书链完整性与域名匹配、"
                   "私钥长度（RSA≥2048，ECC≥256）、证书有效期、HSTS（max-age≥31536000）、"
                   "OCSP Stapling。工具：sslscan testssl.sh https://server；"
                   "参考 Mozilla SSL Configuration Generator 给出的现代/中间配置。",
        "reference": "https://wiki.mozilla.org/Security/Server_Side_TLS",
    },
    {
        "title": "DHCP/DNS 欺骗与中间人检测",
        "category": "网络协议", "difficulty": "中级",
        "tags": ["ARP欺骗", "DNS劫持", "MITM", "交换机安全"],
        "scenario": "内网流量异常排查",
        "content": "二层中间人手段：ARP 欺骗、DHCP 伪造、DNS 劫持、STP 攻击。检测：交换机开启 DAI（动态 ARP 检测）、"
                   "DHCP Snooping、DAI 绑定 IP-MAC、端口安全限制 MAC 学习数。"
                   "主机侧：关键服务使用证书校验、对网关 ARP 表做静态绑定监控、"
                   "用 arpwatch/Zeek 监控异常 ARP 流量。无线场景下还需关注 Evil Twin 热点。",
        "reference": "https://attack.mitre.org/techniques/T1557/",
    },
    {
        "title": "钓鱼邮件识别与社会工程防御",
        "category": "社会工程", "difficulty": "入门",
        "tags": ["钓鱼", "社工", "邮件安全", "意识培训"],
        "scenario": "安全意识与邮件网关运营",
        "content": "钓鱼识别要点：发件人域与显示名不一致、链接悬停显示真实 URL、紧急/恐吓话术、"
                   "不规范落款、附件为 .iso/.html/.docm。技术防御：SPF/DKIM/DMARC 三记录配置、"
                   "URL 沙箱重写、附件沙箱分析、邮件网关反钓鱼规则。管理措施：定期钓鱼演练、"
                   "上报通道、强制 MFA、对财务/采购等高危岗位做针对性培训。",
        "reference": "https://attack.mitre.org/techniques/T1566/001/",
    },
    {
        "title": "等保 2.0 三级控制要求概览",
        "category": "合规标准", "difficulty": "中级",
        "tags": ["等保2.0", "三级", "安全计算环境", "审计"],
        "scenario": "等级保护合规建设",
        "content": "等保 2.0 三级核心要求：安全物理环境、安全通信网络（网络架构/通信传输）、"
                   "安全区域边界（边界防护/访问控制/入侵防范/恶意代码）、安全计算环境（身份鉴别/访问控制/"
                   "安全审计/入侵防范/数据完整性与保密性/备份恢复）、安全管理中心。"
                   "落地：双因素认证、最小权限、日志留存≥6个月、审计三权分立、"
                   "关键数据异地备份。测评前需准备制度文档、配置截图、测试记录。",
        "reference": "https://www.gb/t 22239-2019",
    },
    {
        "title": "OWASP Top 10 2021 速览",
        "category": "Web安全", "difficulty": "入门",
        "tags": ["OWASP", "Top10", "API安全", "软件供应链"],
        "scenario": "Web 应用风险基线",
        "content": "OWASP Top 10 2021：A01 失效的访问控制、A02 加密机制失效、A03 注入、A04 不安全设计、"
                   "A05 安全配置错误、A06 脆弱和过时的组件、A07 身份识别和认证失败、"
                   "A08 软件和数据完整性故障、A09 安全日志和监控失败、A10 服务端请求伪造。"
                   "评估时应作为检查清单逐项对照，并结合业务数据流判定实际风险。",
        "reference": "https://owasp.org/Top10/",
    },
    {
        "title": "移动应用脱壳与静态分析流程",
        "category": "移动安全", "difficulty": "高级",
        "tags": ["Android", "脱壳", "jadx", "Frida"],
        "scenario": "Android APK 安全评估（授权）",
        "content": "Android 评估流程：1) apktool/jadx 反编译看 AndroidManifest 与代码；"
                   "2) 检查导出组件、硬编码密钥、不安全 WebView（setJavaScriptEnabled）；"
                   "3) 加固/加壳应用需脱壳（FRIDA-DEXDump 等）；4) 动态分析用 Frida hook 关键方法；"
                   "5) 检查网络通信是否走明文、证书校验是否被绕过。iOS 侧用 class-dump/Frida，"
                   "注意只在自有或授权样本上进行。",
        "reference": "https://developer.android.com/topic/security/best-practices",
    },
    {
        "title": "弱口令与密码策略设计",
        "category": "密码学", "difficulty": "入门",
        "tags": ["密码策略", "MFA", "哈希", "密码喷洒"],
        "scenario": "身份系统加固",
        "content": "弱口令检测方向：Top-N 常用密码（rockyou）、用户名字典、密码喷洒（少量账号多次密码）。"
                   "密码策略：长度≥12、禁止最近 5 次复用、账户锁定阈值（如 5 次失败锁 15 分钟）、"
                   "强制 MFA、服务账户使用长随机密钥。存储必须使用慢哈希（bcrypt/argon2id），"
                   "禁止 MD5/SHA1 存口令。可结合 haveibeenpwned API 检查泄露密码。",
        "reference": "https://pages.nist.gov/800-63-3/sp800-63b.html",
    },
    {
        "title": "对称与非对称加密选型",
        "category": "密码学", "difficulty": "中级",
        "tags": ["AES", "RSA", "ECC", "密钥交换"],
        "scenario": "加密方案设计评审",
        "content": "对称加密：AES-256-GCM（带认证）用于大量数据； ChaCha20-Poly1305 适合移动端。"
                   "非对称：RSA-2048+ 或 ECC P-256/X25519 用于密钥协商与签名。"
                   "禁止：DES/3DES、ECB 模式、固定 IV、自实现密码学。"
                   "密钥管理：KMS/HSM 集中托管、密钥轮换、按用途分离加密/签名密钥。"
                   "完整性与机密性应使用 AEAD 一体化方案。",
        "reference": "https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines",
    },
    {
        "title": "API 安全评估要点（OWASP API Top10）",
        "category": "Web安全", "difficulty": "中级",
        "tags": ["API", "越权", "BOLA", "速率限制"],
        "scenario": "REST/GraphQL API 测试",
        "content": "API 风险：失效的对象级授权（BOLA，遍历 ID）、失效的用户认证、过度的数据暴露、"
                   "无速率限制、函数级授权缺失。测试：用 Burp Autorize/Autorize 对比两个用户 Token 的响应差异、"
                   "遍历对象 ID、检查错误响应是否泄露堆栈、测试 GraphQL 深度查询 DoS、"
                   "确认敏感字段（密码哈希/内部 ID）不在响应中。",
        "reference": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
    },
    {
        "title": "Redis 未授权访问风险与缓解",
        "category": "内网渗透", "difficulty": "中级",
        "tags": ["Redis", "未授权", "主从复制", "写计划任务"],
        "scenario": "内网服务暴露面排查",
        "content": "Redis 默认无密码绑定 0.0.0.0 时风险极大。利用面：写 SSH 公钥到 authorized_keys、"
                   "写 cron、主从复制加载恶意 module、写 webshell。缓解：绑定 127.0.0.1 或内网、"
                   "requirepass 强密码、rename-command 禁用 CONFIG/FLUSHALL、"
                   "以非 root 运行、开启 protected-mode、网络层用安全组限制来源。",
        "reference": "https://redis.io/docs/management/security/",
    },
    {
        "title": "日志留痕与安全审计要求",
        "category": "合规标准", "difficulty": "入门",
        "tags": ["日志", "审计", "SIEM", "留存周期"],
        "scenario": "安全运营体系建设",
        "content": "关键日志：身份认证（登录成功/失败）、管理操作、特权命令、网络边界、数据库变更。"
                   "留存要求：等保要求网络日志留存≥6个月，关键系统建议≥1年。"
                   "要点：时钟同步（NTP）、日志集中收集（SIEM/ELK）、防篡改（WORM）、"
                   "保留原始与摘要、审计三权分立。告警阈值：短时间多次失败登录、非工作时间特权操作、"
                   "异常出站连接。",
        "reference": "https://www.nist.gov/itl/smallbusinesscyber/guidance-topic/logging-monitoring",
    },
    {
        "title": "弱口令爆破与速率限制评估",
        "category": "Web安全", "difficulty": "中级",
        "tags": ["爆破", "速率限制", "验证码", "锁定"],
        "scenario": "登录/注册接口安全测试",
        "content": "测试登录/忘记密码接口是否存在无速率限制：1) 同一账号多次错误密码是否锁定；"
                   "2) 同一 IP 多账号是否限制；3) 验证码是否可复用/可绕过；4) 响应时间差异导致用户名枚举。"
                   "防护：登录失败指数退避、设备指纹、 captcha、对异常 IP 段拒绝服务、"
                   "统一错误提示（\"用户名或密码错误\"）。",
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    },
    {
        "title": "Kubernetes RBAC 审计",
        "category": "云安全", "difficulty": "高级",
        "tags": ["K8s", "RBAC", "ServiceAccount", "权限"],
        "scenario": "容器平台权限评估",
        "content": "RBAC 审计：找出 cluster-admin 绑定到哪个 ServiceAccount、"
                   "是否有 pods/exec 权限、是否能创建 privileged 容器、是否能访问 secrets。"
                   "命令：kubectl get clusterrolebindings -o wide；kubectl auth can-i --list。"
                   "加固：最小权限、禁用自动挂载 ServiceAccount Token（automountServiceAccountToken=false）、"
                   "使用 Pod Security Standards、开启审计日志记录到 SIEM。",
        "reference": "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
    },
    {
        "title": "Web 缓存投毒与缓存欺骗",
        "category": "Web安全", "difficulty": "高级",
        "tags": ["缓存", "CDN", "X-Forwarded-Host", "投毒"],
        "scenario": "CDN/WAF 架构安全测试",
        "content": "缓存投毒：攻击者通过未归一化的请求头（X-Forwarded-Host、X-Forwarded-Scheme）"
                   "污染 CDN/反向代理缓存，使其他用户访问到恶意内容。"
                   "测试：对同一 URL 用不同 HOST 头请求，检查缓存键是否纳入该头；"
                   "缓存欺骗：恶意路径绕过缓存直接到后端。"
                   "防御：规范化缓存键、忽略不可信头、对敏感页面设置 no-cache、"
                   "定期扫描缓存命中率异常。",
        "reference": "https://portswigger.net/web-security/web-cache-poisoning",
    },
    {
        "title": "反序列化漏洞利用面识别",
        "category": "Web安全", "difficulty": "高级",
        "tags": ["反序列化", "Java", "Python", "PHP"],
        "scenario": "代码审计与灰盒测试",
        "content": "反序列化风险点：Java ObjectInputStream.readObject、PHP unserialize、"
                   "Python pickle.loads、.NET BinaryFormatter。识别：流量中出现 rO0AB（Java）、"
                   "gAAAAA（Python pickle base64）、O:（PHP）等魔术前缀。"
                   "防御：禁止反序列化不可信数据、使用白名单类加载、升级组件、"
                   "JSON 替代二进制序列化、对数据做签名校验。",
        "reference": "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
    },
    {
        "title": "物联网设备固件分析入门",
        "category": "IoT安全", "difficulty": "高级",
        "tags": ["IoT", "固件", "binwalk", "硬编码"],
        "scenario": "IoT 设备安全检测",
        "content": "固件分析流程：binwalk -e 提取文件系统、找到 web 管理界面与二进制、"
                   "grep 硬编码密码/密钥、检查 dropbear/lighttpd 配置是否允许弱密码、"
                   "用 qemu-arm 用户态模拟运行、检查 UART 串口。常见问题：硬编码 root、"
                   "UPnP 端口映射、未授权诊断接口、老旧 BusyBox 已知漏洞。",
        "reference": "https://www.flashrom.org/",
    },
]


# --------------------------------------------------------------------------- #
# 分类主题扩展：按领域生成实用条目
# --------------------------------------------------------------------------- #
def _topic(category: str, title: str, content: str, tags: list[str],
          difficulty: str, scenario: str, ref: str) -> dict:
    return {
        "title": title, "category": category, "difficulty": difficulty,
        "tags": tags, "scenario": scenario, "content": content, "reference": ref,
    }


def _expand() -> list[dict]:
    out: list[dict] = []
    # Web 安全扩展
    web_topics = [
        ("CORS 配置错误评估", "CORS 错误配置如 Access-Control-Allow-Origin 反射任意 Origin 且 Allow-Credentials:true，"
         "可被用于跨站窃取带凭据数据。测试：构造 Origin: https://evil.com 检查响应头；"
         "防御：白名单 Origin、禁止反射 null、不携带凭据时不允许通配。",
         ["CORS", "跨域", "凭据"]),
        ("HTTP 请求走私（H2.CL/CL.TE）", "请求走私利用前端代理与后端对 Content-Length/Transfer-Encoding 的解析差异，"
         "可投毒其他用户请求。测试：Burp HTTP Request Smuggler 插件；"
         "防御：前后端使用同一 HTTP 解析栈、禁用 HTTP/1.1 连接复用、升级到 HTTP/2。",
         ["请求走私", "HTTP", "代理"]),
        ("目录遍历与文件包含", "目录遍历通过 ../ 或编码变体读取应用外文件；LFI 可结合日志包含/PHP 封装协议。"
         "防御：realpath 后做白名单前缀校验、open_basedir、禁用危险流封装。",
         ["路径穿越", "LFI"]),
        ("NoSQL 注入", "MongoDB 在 $where/$regex 等操作符注入用户输入时可绕过认证与提取数据。"
         "防御：驱动层类型校验、避免直接拼接查询对象、使用模式验证。",
         ["NoSQL", "MongoDB", "注入"]),
        ("XXE 外部实体注入", "XML 解析器默认允许外部实体时，可读取本地文件、发起 SSRF 或 DoS。"
         "防御：禁用 DTD 与外部实体（libxml_disable_entity_loader）、使用 JSON 替代 XML。",
         ["XXE", "XML"]),
        ("文件包含与 PHP 封装协议", "PHP LFI 可通过 php://filter 读源码、data:// 执行代码。"
         "防御：白名单文件路径、关闭 allow_url_include。",
         ["LFI", "PHP"]),
        ("硬编码密钥与仓库扫描", "代码仓库中常发现 AK/SK、数据库密码、JWT 密钥。"
         "工具：gitleaks/trufflehog/ detect-secrets。上线前接入 CI  Secret Scanning。",
         ["密钥", "代码审计", "泄露"]),
        ("子域名接管（Subdomain Takeover）", "CNAME 指向已注销的第三方服务（GitHub Pages/S3/Heroku）未清理时可被接管。"
         "定期用 subjack/nuclei 检查 CNAME 与服务指纹。",
         ["子域名", "接管", "OSINT"]),
        ("WebSocket 安全", "WS 连接复用 HTTP Cookie 但默认无 CSRF Token，消息未做来源校验。"
         "防御：Origin 校验、消息鉴权、WSS 加密。",
         ["WebSocket", "鉴权"]),
        ("开放重定向", "登录后跳转参数如 ?next= 未校验时可钓鱼。防御：白名单域名或相对路径跳转。",
         ["重定向", "钓鱼"]),
    ]
    for i, (t, c, tags) in enumerate(web_topics):
        out.append(_topic("Web安全", t, c, tags, "中级" if i % 3 else "高级",
                          "Web 应用灰盒测试", "https://owasp.org/www-project-web-security-testing-guide/"))

    # 内网渗透扩展
    internal_topics = [
        ("Kerberoasting 评估", "利用域内服务账户的 SPN 请求 TGS 并用离线字典破解。"
         "防御：服务账户使用长随机密码、gMSA、启用 AES 而非 RC4、监控 4769 事件。",
         ["Kerberos", "票据", "破解"]),
        ("AS-REP Roasting", "对不需要预认证的账户请求 AS-REP 并离线破解。"
         "防御：所有域账户要求 Kerberos 预认证。",
         ["Kerberos", "弱密码"]),
        ("PowerShell 日志与 AMSI", "监控 PowerShell Script Block Logging（Event 4104）、"
         "Transcription、AMSI 可拦截恶意脚本。蓝队侧用于检测攻击链。",
         ["PowerShell", "日志", "EDR"]),
        ("WMI 与 WinRM 横向", "WMI/WinRM 是无文件横向手段。检测 5885/5985/5986 连接与 WMI 进程创建。",
         ["WMI", "WinRM"]),
        ("计划任务与服务持久化", "攻击者通过 schtasks/sc create 持久化。"
         "基线：监控新服务创建、服务路径可写、二进制签名。",
         ["持久化", "计划任务"]),
        ("LDAP 匿名查询", "检查匿名绑定是否启用，泄露用户/组信息。"
         "加固：禁用匿名绑定、限制普通用户查询敏感属性。",
         ["LDAP", "信息泄露"]),
        ("打印机 Spooler 攻击面", "SpoolSpoo/PrintNightmare 类漏洞用于权限维持。"
         "禁用非必要打印服务、打补丁。",
         ["Spooler", "提权"]),
        ("TLS 私钥与 DPAPI", "窃取 LSASS 中的凭据需关闭 WDigest、启用 Credential Guard。",
         ["凭据", "LSASS"]),
    ]
    for i, (t, c, tags) in enumerate(internal_topics):
        out.append(_topic("内网渗透", t, c, tags, "高级", "域环境红队评估（授权）",
                         "https://attack.mitre.org/"))

    # 云安全扩展
    cloud_topics = [
        ("IAM 权限边界审计", "过度宽松的 IAM 策略是云入侵主因。工具：IAM Access Analyzer、PMapper 找权限提升路径。",
         ["IAM", "权限"]),
        ("安全组/网络ACL审计", "0.0.0.0/0 开放 22/3389/27017 是高风险。建议仅跳板机可达。",
         ["安全组", "网络"]),
        ("云存储加密", "S3/EBS/RDS 默认加密是否开启？KMS 密钥轮换与跨账户访问策略。",
         ["加密", "KMS"]),
        ("云日志与审计", "CloudTrail/Config/GuardDuty 是否开启并集中到独立账户？",
         ["审计", "日志"]),
        ("Serverless 安全", "Lambda 过度权限、事件源映射注入、层（Layer）篡改。",
         ["Lambda", "无服务器"]),
        ("容器镜像扫描", "镜像中的基础镜像漏洞、运行时 root、Secrets 明文。用 Trivy/Grype。",
         ["镜像", "扫描"]),
        ("Terraform 状态泄露", "tfstate 常含明文密钥。加密存储并限制访问。",
         ["IaC", "Terraform"]),
        ("云工作负载保护（CWP）", "主机、容器、无服务器统一检测，关注异常进程与外联。",
         ["CWP", "运行时"]),
    ]
    for i, (t, c, tags) in enumerate(cloud_topics):
        out.append(_topic("云安全", t, c, tags, "中级", "云配置审计",
                         "https://www.nist.gov/itl/cloud"))

    # 移动安全扩展
    mobile_topics = [
        ("Android 导出组件风险", "导出的 Activity/Service/Receiver/Provider 未做 permission 校验可被任意应用调用。",
         ["Android", "组件"]),
        ("Android WebView 风险", "setAllowFileAccess、addJavascriptInterface 导致任意文件读取与 RCE。",
         ["WebView", "JS桥"]),
        ("iOS 钥匙串保护", "Keychain Item 的 kSecAttrAccessible 应设为 ThisDeviceOnly。",
         ["iOS", "Keychain"]),
        ("移动端证书校验", "检查是否存在信任所有证书的 X509TrustManager，防止中间人。",
         ["证书", "中间人"]),
        ("移动存储加密", "SharedPreferences/NSUserDefaults 不应存敏感信息；用 Keystore/Keychain。",
         ["本地存储", "加密"]),
        ("动态调试检测", "应用应检测模拟器、Frida、调试器、root/越狱环境。",
         ["反调试", "Frida"]),
    ]
    for i, (t, c, tags) in enumerate(mobile_topics):
        out.append(_topic("移动安全", t, c, tags, "中级", "移动 App 安全评估",
                         "https://developer.android.com/training/articles/security-tips"))

    # AI 安全扩展
    ai_topics = [
        ("LLM 越权与提示注入", "模型在工具调用场景需对每个动作做人机确认，防止越权访问。",
         ["LLM", "工具调用"]),
        ("RAG 检索隔离", "向量库按租户/用户权限隔离，防止跨租户文档泄露。",
         ["RAG", "多租户"]),
        ("模型输出过滤", "输出前做 PII/敏感信息过滤与越狱提示检测。",
         ["输出过滤", "内容安全"]),
        ("Embedding 数据治理", "嵌入向量可能反推出原文，敏感数据做脱敏。",
         ["向量", "隐私"]),
        ("AI 红队测试", "建立 prompt 用例库，覆盖越权、数据泄露、违规生成。",
         ["红队", "Prompt"]),
        ("模型微调数据安全", "微调数据来自公开语料时需做许可与版权审查。",
         ["微调", "版权"]),
    ]
    for i, (t, c, tags) in enumerate(ai_topics):
        out.append(_topic("AI安全", t, c, tags, "高级", "AI 应用上线前评估",
                         "https://owasp.org/www-project-top-10-for-large-language-model-applications/"))

    # 密码学扩展
    crypto_topics = [
        ("哈希选型", "口令用 bcrypt/argon2；完整性用 SHA-256/3；禁止 MD5/SHA1。",
         ["哈希", "口令"]),
        ("随机数安全", "加密场景用 CSPRNG（os.urandom/securerandom），禁止 time/pid 作种子。",
         ["随机数", "CSPRNG"]),
        ("TLS 降级与重协商", "禁用 SSLv3、TLS1.0；监控降级攻击。",
         ["TLS", "降级"]),
        ("PGP/S/MIME 评估", "检查邮件加密是否启用、密钥长度与吊销机制。",
         ["邮件加密"]),
        ("HMAC 与签名", "API 签名用 HMAC-SHA256，包含时间戳防重放。",
         ["HMAC", "API"]),
        ("密钥轮换", "加密/签名密钥定期轮换，旧密钥用于解密旧数据但不用于新加密。",
         ["密钥轮换"]),
    ]
    for i, (t, c, tags) in enumerate(crypto_topics):
        out.append(_topic("密码学", t, c, tags, "中级", "密码方案评审",
                         "https://csrc.nist.gov/Projects/轻量级-cryptography"))

    # 网络协议扩展
    proto_topics = [
        ("DNS 安全（DNSSEC/DNS over HTTPS）", "评估递归解析是否启用 DNSSEC、DoH/DoT。",
         ["DNS", "DNSSEC"]),
        ("SSH 加固", "禁用 root 直接登录、禁用密码登录用密钥、限制版本。",
         ["SSH", "加固"]),
        ("NTP 安全", "NTP 反射放大攻击，限制未授权 monlist 查询。",
         ["NTP", "放大"]),
        ("SNMP 加固", "禁用 public community v1/v2c，使用 v3 authPriv。",
         ["SNMP", "网络设备"]),
        ("FTP/Telnet 风险", "明文协议禁止在生产使用，替换为 SFTP/SSH。",
         ["明文协议"]),
        ("Modbus/工业协议", "ICS 环境对 Modbus/S7 无认证，做网络隔离与白名单。",
         ["ICS", "工业协议"]),
    ]
    for i, (t, c, tags) in enumerate(proto_topics):
        out.append(_topic("网络协议", t, c, tags, "中级", "网络设备审计",
                         "https://www.iana.org/"))

    # 社会工程扩展
    se_topics = [
        ("诱饵 USB 检测", "物理安全：监控不明 USB、禁用自动运行、终端白名单。",
         ["USB", "物理安全"]),
        ("假冒 IT 求助电话", "建立回拨确认流程，任何索要凭据的电话一律挂断回拨。",
         ["电话", "冒充"]),
        ("仿冒域名与商标", "监控 typosquatting、相似域名，注册品牌相关域名。",
         ["域名", "品牌"]),
        ("OAuth 滥用", "检查第三方应用授权列表，回收不再使用的应用。",
         ["OAuth", "授权"]),
    ]
    for i, (t, c, tags) in enumerate(se_topics):
        out.append(_topic("社会工程", t, c, tags, "入门", "安全意识运营",
                         "https://attack.mitre.org/techniques/T1566/"))

    # 合规标准扩展
    comp_topics = [
        ("ISO 27001 信息安全管理体系", "基于 PDCA 持续改进，14 个控制域，114 项控制。",
         ["ISO27001", "ISMS"]),
        ("SOC 2 信任服务标准", "安全、可用性、处理完整性、保密性、隐私五类。",
         ["SOC2", "审计"]),
        ("GDPR 个人数据保护", "合法性基础、数据主体权利、DPO、DPIA、跨境传输。",
         ["GDPR", "隐私"]),
        ("PCI DSS 支付卡安全", "12 项要求，覆盖防火墙、加密、漏洞管理、访问控制。",
         ["PCI", "支付"]),
        ("HIPAA 医疗数据", "PHI 保护、风险分析、业务伙伴协议。",
         ["HIPAA", "医疗"]),
        ("等保 2.0 定级备案流程", "定级→专家评审→公安机关备案→建设整改→等级测评→监督检查。",
         ["等保", "流程"]),
        ("数据分类分级", "公开/内部/敏感/绝密四级，按数据敏感度决定控制强度。",
         ["数据分级"]),
        ("供应商安全评估", "第三方风险评估问卷、合同安全条款、审计权。",
         ["供应商", "第三方"]),
    ]
    for i, (t, c, tags) in enumerate(comp_topics):
        out.append(_topic("合规标准", t, c, tags, "中级", "合规建设",
                         "https://www.iso.org/isoiec-27001-information-security.html"))

    # 区块链扩展
    bc_topics = [
        ("MEV 与抢跑攻击", "DEX 交易排序被搜索者利用。缓解：私有内存池、时间锁。",
         ["MEV", "DeFi"]),
        ("预言机操纵", "价格预言机被闪电贷操纵。使用多源预言机与时间加权价格。",
         ["预言机", "闪电贷"]),
        ("钱包安全", "硬件钱包、助记词离线保存、审核授权签名（Permit2）。",
         ["钱包", "私钥"]),
        ("桥跨链风险", "跨链桥是黑客重点目标，TVL 与审计质量并重。",
         ["跨链桥"]),
    ]
    for i, (t, c, tags) in enumerate(bc_topics):
        out.append(_topic("区块链", t, c, tags, "高级", "Web3 安全审计",
                         "https://www.smartcontract.com/"))

    # 补充扩展：各领域更多实用主题，达到 200+
    extra = {
        "Web安全": [
            ("子域名枚举与资产发现", "子域名收集：subfinder/amass 被动枚举 + DNS 爆破 + 证书透明日志。"
             "重点发现影子资产与测试环境，这些常缺少补丁。", ["子域名", "资产"]),
            ("端口与服务指纹", "nmap -sV -sC 识别服务版本，结合 banner 抓取与 CPE 映射查 CVE。",
             ["端口", "指纹"]),
            ("API 文档泄露", "swagger.json/api-docs 暴露未授权接口。定期扫描 /swagger /v2/api-docs /openapi.json。",
             ["API文档", "泄露"]),
            ("GraphQL 深度查询 DoS", "GraphQL 允许嵌套查询，攻击者构造深递归查询耗尽后端。"
             "限制查询深度、复杂度与速率。", ["GraphQL", "DoS"]),
            ("JWT 弱密钥爆破", "用 hashcat -m 16500 离线爆破 JWT 签名密钥。生产密钥应≥32 字节随机。",
             ["JWT", "弱密钥"]),
            ("会话固定与过期", "登录后必须重新生成 SessionID；设置合理空闲超时与绝对超时。",
             ["会话", "固定"]),
            ("密码重置流程风险", "重置 token 可预测、多端口不复用、邮箱用户名枚举。"
             "一次性短时效 token 是关键。", ["密码重置"]),
            ("第三方登录 OAuth", "state 参数防 CSRF、redirect_uri 严格白名单、检查 scope 最小化。",
             ["OAuth", "第三方登录"]),
            ("前端源码 Map 文件", ".map 文件泄露导致前端源码还原。生产关闭 source map。",
             ["SourceMap", "信息泄露"]),
            ("HTTP 安全响应头", "X-Content-Type-Options: nosniff、X-Frame-Options、Referrer-Policy、Permissions-Policy。",
             ["安全头"]),
            ("CSRF Token 放置", "Token 放请求头而非 cookie；对 GET 请求不做状态变更。",
             ["CSRF", "Token"]),
            ("异步任务注入", "消息队列/任务队列中反序列化用户输入，需白名单校验。",
             ["MQ", "反序列化"]),
            ("文件下载接口", "下载接口参数未校验导致路径穿越。用文件 ID 映射而非直接传路径。",
             ["文件下载", "路径穿越"]),
            ("前端硬编码测试账号", "前端 JS 常含测试账号/后门接口。grep 账号密码模式。",
             ["前端", "硬编码"]),
            ("WebSocket 鉴权", "WS 握手时鉴权，连接后每条消息仍需校验权限。",
             ["WebSocket", "鉴权"]),
            ("文件元数据泄露", "图片/EXIF 含 GPS/设备信息，上传前剥离。",
             ["EXIF", "隐私"]),
            ("开放代理检测", "检查服务器是否被配置为开放代理转发。",
             ["代理", "滥用"]),
            ("CRLF 注入", "未过滤换行符可注入响应头。防御：禁止在响应头中放用户数据。",
             ["CRLF", "响应拆分"]),
            ("错误页面信息泄露", "生产关闭 debug 模式，自定义 4xx/5xx 页面。",
             ["错误处理"]),
            ("定时任务越权", "cron 任务以 root 运行且脚本可被低权限用户写时可提权。",
             ["计划任务", "提权"]),
        ],
        "内网渗透": [
            ("Wdigest 缓存明文", "Windows 默认开启 Wdigest 时登录密码以可逆形式缓存在 LSASS。"
             "关闭并启用 Credential Guard。", ["Wdigest", "凭据"]),
            ("组策略首选项（GPP）", "旧 GPP 中 cpassword 可被解密。检查 SYSVOL。",
             ["GPP", "SYSVOL"]),
            ("委派权限滥用", "非约束委派可被用于冒充任意用户。审计 msDS-AllowedToDelegateTo。",
             ["委派", "Kerberos"]),
            ("NTLM 中继", "通过 SMB Signing 未开启进行中继。检查 NetBIOS/SMB 签名。",
             ["NTLM中继"]),
            ("本地管理员密码复用", "LAPS 解决多台机器同密码问题。",
             ["LAPS", "LAPS"]),
            ("WMI 永久订阅", "攻击者创建 WMI 事件过滤器做持久化。监控 root/subscription。",
             ["WMI", "持久化"]),
            ("启动项与注册表", "HKCU/HKLM Run 键与启动文件夹是常见持久化点。",
             ["注册表", "启动项"]),
            ("服务二进制路径可写", "sc qc 检查服务路径是否可写，重写二进制即提权。",
             ["服务", "提权"]),
            ("DLL 劫持", "应用加载未搜索路径的 DLL 可被替换。",
             ["DLL劫持"]),
            ("高权限命令滥用", "通过 sudo 配置中的 find/vim/nmap 等逃逸到 shell。",
             ["GTFOBins", "sudo"]),
            ("NFS root_squash", "no_root_squash 导出可被 NFS 客户端挂载后写文件提权。",
             ["NFS", "提权"]),
            ("Docker.sock 暴露", "容器挂载 /var/run/docker.sock 可逃逸到宿主。",
             ["Docker", "逃逸"]),
            ("Kubelet 未授权", "kubelet 10250 端口未授权可 exec/读日志。",
             ["K8s", "kubelet"]),
            ("etcd 未授权", "etcd 2379 暴露可读写集群 Secrets。",
             ["etcd", "K8s"]),
            ("数据库链接串泄露", "配置文件/历史命令中常含明文数据库口令。",
             ["凭据", "配置"]),
            ("VNC/RDP 弱口令", "3389/5900 对外暴露且弱口令是入侵起点。",
             ["RDP", "弱口令"]),
            ("SSH 密钥复用", "跳板机私钥未设口令且被复制到其他机器。",
             ["SSH", "密钥"]),
            ("打印机与多功能设备", "打印机常是内网薄弱点，含文档缓存与配置。",
             ["打印机", "物理"]),
        ],
        "云安全": [
            ("IAM 用户 AccessKey 轮换", "长期 AccessKey 是高风险，推荐用临时 STS。",
             ["IAM", "AK/SK"]),
            ("跨账户访问策略", "检查角色信任策略是否过于宽泛（*）。",
             ["跨账户", "信任策略"]),
            ("RDS 公网可访问", "数据库不应绑定公网，通过堡垒机/VPC 访问。",
             ["RDS", "网络"]),
            ("对象存储 ACL", "ListBucket 公开可列目录导致数据泄露。",
             ["对象存储", "ACL"]),
            ("CDN 回源鉴权", "CDN 不鉴权回源，攻击者可绕过 CDN 直接访问源站。",
             ["CDN", "回源"]),
            ("快照公开分享", "快照/镜像误分享到全公开。",
             ["快照", "镜像"]),
            ("云函数触发器暴露", "HTTP 触发器函数未鉴权可被滥用刷量。",
             ["函数", "触发器"]),
            ("日志桶生命周期", "日志未设置生命周期导致成本与留存合规问题。",
             ["日志", "成本"]),
            ("资源标签治理", "无主资源与过期资源清理是云治理难点。",
             ["标签", "治理"]),
            ("Terraform State 加密", "tfstate 含明文，后端用 S3+KMS+版本控制。",
             ["Terraform", "State"]),
            ("K8s Pod Security", "应用 restricted profile，禁止 privileged 与 hostPath。",
             ["K8s", "Pod安全"]),
            ("服务网格 mTLS", "Istio/Linkerd 启用 mTLS 做服务间加密与鉴权。",
             ["服务网格", "mTLS"]),
            ("云 WAF 与 DDoS", "关键业务前部署 WAF 与高防 IP。",
             ["WAF", "DDoS"]),
            ("备份与恢复演练", "备份不可恢复等于没备份，定期做恢复演练。",
             ["备份", "灾备"]),
            ("多云/混合网", "VPN/专线加密，边界路由器 ACL 最小化。",
             ["混合云", "网络"]),
        ],
        "移动安全": [
            ("Android 备份提取", "adb backup 未禁止时可提取应用私有数据。",
             ["备份", "adb"]),
            ("iOS 越狱检测", "检查 Cydia/MobileSubstrate 文件与符号链接。",
             ["iOS", "越狱"]),
            ("移动端 Deep Link", "Scheme/Universal Link 未校验来源可被钓鱼。",
             ["DeepLink", "Scheme"]),
            ("第三方 SDK 隐私", "SDK 过度收集设备信息，需在隐私政策披露。",
             ["SDK", "隐私"]),
            ("本地 SQLite 明文", "敏感表应 SQLCipher 加密。",
             ["SQLite", "加密"]),
            ("剪贴板泄露", "敏感信息复制到剪贴板后被其他应用读取。",
             ["剪贴板"]),
            ("推送 token 伪造", "推送 token 未与用户绑定可被滥用。",
             ["推送", "token"]),
        ],
        "AI安全": [
            ("模型评估对抗样本", "对图像/文本分类模型做对抗样本测试。",
             ["对抗样本"]),
            ("训练数据投毒检测", "统计分布异常与触发器样本识别。",
             ["投毒", "检测"]),
            ("成员推断攻击", "判断某样本是否在训练集中，需差分隐私防御。",
             ["成员推断", "隐私"]),
            ("模型窃取", "通过 API 查询复制模型功能，限制查询速率。",
             ["模型窃取"]),
            ("Prompt 越权重试", "对越权请求做二次确认与审计日志。",
             ["Prompt", "审计"]),
            ("训练管道供应链", "数据集下载源与第三方模型权重需校验。",
             ["供应链", "ML"]),
            ("AI 生成内容标注", "AIGC 内容加水印与标识，符合监管要求。",
             ["AIGC", "水印"]),
            ("模型上线回滚", "模型更新需影子流量与灰度，异常可一键回滚。",
             ["MLOps", "灰度"]),
        ],
        "密码学": [
            ("TLS 1.3 优势", "仅允许前向保密套件，握手简化，移除弱算法。",
             ["TLS1.3"]),
            ("证书自动续期", "ACME/Let's Encrypt 自动续期，避免证书过期导致业务中断。",
             ["证书", "ACME"]),
            ("HSM 密钥管理", "根密钥放 HSM，应用通过 API 调用。",
             ["HSM", "根密钥"]),
            ("侧信道风险", "计时攻击影响 AES/非对称算法实现，用恒定时间代码。",
             ["侧信道", "计时"]),
            ("量子安全迁移", "NIST 后量子算法（Kyber/Dilithium）进入过渡期规划。",
             ["后量子", "PQC"]),
            ("密钥派生", "PBKDF2/bcrypt/argon2 用于口令到密钥的派生，禁止直接作 AES key。",
             ["KDF", "派生"]),
        ],
        "网络协议": [
            ("ICMP 隧道", "ICMP 可被用于数据渗漏，边界监控异常 ICMP 载荷。",
             ["ICMP", "隧道"]),
            ("DNS 隧道", "DNS 查询中夹带数据，监控异常域名长度与频率。",
             ["DNS", "隧道"]),
            ("端口敲门", "不依赖隐蔽端口的安全，仍需强认证与访问控制。",
             ["端口敲门"]),
            ("零信任网络", "永不信任始终验证，身份+设备+上下文决定访问。",
             ["零信任"]),
            ("微分段", "数据中心按业务微分段，横向移动需逐段突破。",
             ["微分段"]),
            ("NAC 网络准入", "未合规设备禁止接入内网，802.1X 认证。",
             ["NAC", "准入"]),
        ],
        "社会工程": [
            ("CEO 邮件诈骗", "财务付款流程必须双人审批 + 电话回拨确认。",
             ["BEC", "财务"]),
            ("假会议邀请", "日历邀请含钓鱼链接，校验会议组织方。",
             ["日历", "钓鱼"]),
            ("假冒供应链邮件", "冒充供应商发更新单，核对邮箱域名与历史沟通。",
             ["供应链", "钓鱼"]),
            ("虚拟形象冒充", "深度伪造视频/语音面试，多因子验证身份。",
             ["深伪", "身份"]),
        ],
        "合规标准": [
            ("数据出境合规", "个人信息出境需安全评估/标准合同/认证。",
             ["数据出境", "跨境"]),
            ("个人信息保护影响评估（PIPIA）", "处理敏感个人信息前完成 PIPIA 并留存。",
             ["PIPIA", "个保法"]),
            ("用户权利响应", "查阅/复制/更正/删除/撤回同意请求 15 工作日内响应。",
             ["数据主体权利"]),
            ("安全事件通报", "事件发生后 72 小时内向监管与受影响用户通报。",
             ["事件通报"]),
            ("DPO 任命", "处理大规模个人信息需任命数据保护负责人。",
             ["DPO"]),
            ("审计证据留存", "审计日志、配置截图、测试报告保存以备外审。",
             ["审计证据"]),
            ("供应商 DPA", "与处理个人数据的供应商签数据处理协议。",
             ["DPA", "合同"]),
            ("保留期限最小化", "数据只保留到业务/法律要求期限，到期销毁。",
             ["数据保留"]),
        ],
        "区块链": [
            ("重放攻击", "跨链交易签名在另一条链被重放，加 chainid。",
             ["重放", "chainid"]),
            ("权限密钥管理", "多签与时间锁管理项目管理员密钥。",
             ["多签", "时间锁"]),
            ("前端钱包钓鱼", "签名前 UI 显示完整交易意图与批准额度。",
             ["签名", "钱包"]),
        ],
        "IoT安全": [
            ("默认凭据", "IoT 设备出厂凭据公开，首次启动必须改密。",
             ["默认密码", "IoT"]),
            ("固件签名校验", "OTA 更新必须验签，防止恶意固件。",
             ["OTA", "签名"]),
            ("调试接口关闭", "UART/JTAG 生产环境关闭或锁死。",
             ["UART", "JTAG"]),
            ("IoT 网络分段", "IoT VLAN 隔离，禁止访问办公网。",
             ["分段", "VLAN"]),
        ],
    }
    for cat, items in extra.items():
        for i, (t, c, tags) in enumerate(items):
            diff = "高级" if cat in ("AI安全", "区块链", "IoT安全") else ("中级" if i % 2 else "入门")
            out.append(_topic(cat, t, c, tags, diff, f"{cat} 评估与加固",
                             "https://owasp.org/"))
    # 补足 200+：跨领域补充
    tail = [
        ("Web安全", "CSP 绕过评估", "旧浏览器 unsafe-inline 回退、JSONP 端点、base-uri 缺失是 CSP 常见绕过点。",
         ["CSP", "绕过"], "中级"),
        ("Web安全", "子域名模糊测试", "对发现的子域做参数 fuzz（ffuf/feroxbuster），寻找隐藏端点。",
         ["fuzz", "端点"], "高级"),
        ("内网渗透", "LAPS 读取", "配置不当的 LAPS 可读本地管理员密码，检查 ACL。", ["LAPS", "读密码"], "高级"),
        ("云安全", "云数据库审计日志", "RDS 开启审计日志并接入 SIEM，监控异常查询。", ["RDS", "审计"], "中级"),
        ("移动安全", "iOS 数据保护", "文件启用 NSFileProtectionComplete，防止备份提取。", ["iOS", "数据保护"], "中级"),
        ("AI安全", "模型速率与配额", "对 API 调用按用户限速，防模型窃取与滥用。", ["速率", "配额"], "中级"),
        ("密码学", "前向保密（PFS）", "TLS 用 ECDHE 保证会话密钥不被长期私钥破解。", ["PFS", "ECDHE"], "中级"),
        ("网络协议", "BGP 安全", "路由劫持监控，RPKI 验证前缀宣告。", ["BGP", "RPKI"], "高级"),
        ("合规标准", "供应商安全评级", "按风险对供应商分级，高风险供应商现场审计。", ["供应商", "评级"], "中级"),
        ("区块链", "Gas 与 DoS", "循环与外部调用可致 gas 耗尽，设置上限。", ["Gas", "DoS"], "高级"),
        ("IoT安全", "默认 SNMP community", "IoT 设备默认 public/private community 必须改。", ["SNMP", "默认"], "入门"),
        ("社会工程", "语音钓鱼（Vishing）", "客服电话索要验证码，一律挂断回拨官方号码。", ["Vishing", "验证码"], "入门"),
    ]
    for cat, t, c, tags, diff in tail:
        out.append(_topic(cat, t, c, tags, diff, f"{cat} 评估与加固",
                         "https://owasp.org/"))
    return out


KNOWLEDGE_SEEDS: list[dict] = list(CURATED) + _expand()

_BY_TITLE: dict[str, dict] = {k["title"]: k for k in KNOWLEDGE_SEEDS}


def get_all() -> list[dict]:
    return KNOWLEDGE_SEEDS


def filter_knowledge(category: str | None = None,
                     difficulty: str | None = None,
                     keyword: str | None = None,
                     limit: int = 0,
                     offset: int = 0) -> dict:
    rows = KNOWLEDGE_SEEDS
    if category:
        rows = [r for r in rows if r["category"] == category]
    if difficulty:
        rows = [r for r in rows if r["difficulty"] == difficulty]
    if keyword:
        kw = keyword.lower()
        rows = [r for r in rows if kw in r["title"].lower()
                or kw in r["content"].lower() or any(kw in t.lower() for t in r["tags"])]
    total = len(rows)
    if offset:
        rows = rows[offset:]
    if limit:
        rows = rows[:limit]
    return {"items": rows, "total": total, "offset": offset, "limit": limit}


def stats() -> dict:
    by_cat: dict[str, int] = {}
    by_diff: dict[str, int] = {}
    for k in KNOWLEDGE_SEEDS:
        by_cat[k["category"]] = by_cat.get(k["category"], 0) + 1
        by_diff[k["difficulty"]] = by_diff.get(k["difficulty"], 0) + 1
    return {"total": len(KNOWLEDGE_SEEDS), "by_category": by_cat,
            "by_difficulty": by_diff, "categories": KNOWLEDGE_CATEGORIES,
            "difficulties": DIFFICULTIES}


if __name__ == "__main__":
    print(stats())
