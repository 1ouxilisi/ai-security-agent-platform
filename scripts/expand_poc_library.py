#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC漏洞验证脚本库模块，支持PoC分类管理、搜索、执行和结果验证。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import sys
import json
from pathlib import Path
from datetime import datetime

# 添加项目根目录
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from exploit.poc_library import POC, get_poc_library


def generate_more_pocs():
    """生成更多POC"""
    more_pocs = [
        # ===== 更多Web漏洞 =====
        POC(
            poc_id="POC-WEB-011",
            name="HTTP请求走私检测",
            category="info",
            severity="high",
            target_service="http",
            target_port=80,
            description="检测目标是否存在HTTP请求走私漏洞（CL.TE/TE.CL/TE.TE）",
            payload="发送包含矛盾Content-Length和Transfer-Encoding头的请求",
            verification="检查后端服务器是否解析了走私的请求",
        ),
        POC(
            poc_id="POC-WEB-012",
            name="Web缓存投毒检测",
            category="info",
            severity="medium",
            target_service="http",
            target_port=80,
            description="检测目标是否存在Web缓存投毒漏洞",
            payload="发送包含特殊X-Forwarded-Host头的请求，检查缓存是否被污染",
            verification="检查后续请求是否返回了污染的缓存内容",
        ),
        POC(
            poc_id="POC-WEB-013",
            name="CRLF注入检测",
            category="info",
            severity="medium",
            target_service="http",
            target_port=80,
            description="检测目标是否存在CRLF注入漏洞（HTTP响应拆分）",
            payload="在参数中注入%0d%0aSet-Cookie: crlf_injected=1",
            verification="检查响应头是否包含注入的Set-Cookie",
        ),
        POC(
            poc_id="POC-WEB-014",
            name="HTTP参数污染检测",
            category="info",
            severity="low",
            target_service="http",
            target_port=80,
            description="检测目标是否存在HTTP参数污染漏洞",
            payload="发送包含重复参数的请求（?id=1&id=2）",
            verification="检查应用使用了哪个参数值",
        ),
        POC(
            poc_id="POC-WEB-015",
            name="服务端模板注入检测",
            category="rce",
            severity="critical",
            target_service="http",
            target_port=80,
            description="检测目标是否存在服务端模板注入（SSTI）漏洞",
            payload="在参数中注入{{7*7}}或${7*7}，检查是否返回49",
            verification="检查响应是否包含模板执行结果",
        ),
        POC(
            poc_id="POC-WEB-016",
            name="不安全的反序列化检测",
            category="rce",
            severity="critical",
            target_service="http",
            target_port=80,
            description="检测目标是否存在不安全的反序列化漏洞",
            payload="发送包含恶意序列化对象的Cookie或参数",
            verification="检查应用是否反序列化了恶意对象",
        ),
        POC(
            poc_id="POC-WEB-017",
            name="XML外部实体注入检测",
            category="xxe",
            severity="high",
            cve_id="",
            target_service="http",
            target_port=80,
            description="检测目标是否存在XML外部实体注入（XXE）漏洞",
            payload="发送包含<!ENTITY xxe SYSTEM 'file:///etc/passwd'>的XML",
            verification="检查响应是否包含/etc/passwd内容",
        ),
        POC(
            poc_id="POC-WEB-018",
            name="GraphQL内省查询检测",
            category="info",
            severity="medium",
            target_service="http",
            target_port=80,
            description="检测GraphQL端点是否启用了内省查询，可能泄露敏感信息",
            payload="POST /graphql {\"query\":\"{__schema{types{name}}}\"}",
            verification="检查响应是否包含GraphQL schema信息",
        ),
        POC(
            poc_id="POC-WEB-019",
            name="GraphQL批量请求攻击检测",
            category="dos",
            severity="medium",
            target_service="http",
            target_port=80,
            description="检测GraphQL端点是否允许批量请求，可能导致拒绝服务",
            payload="发送包含大量查询的批量请求",
            verification="检查应用是否处理了所有批量请求",
        ),
        POC(
            poc_id="POC-WEB-020",
            name="JWT弱密钥检测",
            category="info",
            severity="high",
            target_service="http",
            target_port=80,
            description="检测JWT令牌是否使用弱密钥签名，可能被伪造",
            payload="使用常见弱密钥（secret、123456、password）尝试验证JWT",
            verification="检查是否能用弱密钥验证JWT",
        ),

        # ===== 更多中间件漏洞 =====
        POC(
            poc_id="POC-MID-011",
            name="Nginx alias路径穿越检测",
            category="lfi",
            severity="high",
            target_service="http",
            target_port=80,
            description="检测Nginx alias配置是否存在路径穿越漏洞",
            payload="访问/img../etc/passwd或类似路径",
            verification="检查是否返回了/etc/passwd内容",
        ),
        POC(
            poc_id="POC-MID-012",
            name="Apache mod_jk访问控制绕过检测",
            category="info",
            severity="medium",
            target_service="http",
            target_port=80,
            description="检测Apache mod_jk是否存在访问控制绕过漏洞",
            payload="访问受保护路径时添加特殊字符（/.;/、/%2e/）",
            verification="检查是否绕过了访问控制",
        ),
        POC(
            poc_id="POC-MID-013",
            name="IIS短文件名枚举检测",
            category="info",
            severity="low",
            target_service="http",
            target_port=80,
            description="检测IIS是否存在短文件名枚举漏洞（~1）",
            payload="访问/*~1*/.aspx或类似路径",
            verification="检查响应是否泄露了短文件名",
        ),
        POC(
            poc_id="POC-MID-014",
            name="IIS HTTP.sys远程代码执行检测",
            category="rce",
            severity="critical",
            cve_id="CVE-2015-1635",
            target_service="http",
            target_port=80,
            description="检测IIS HTTP.sys是否存在远程代码执行漏洞（MS15-034）",
            payload="发送包含Range: bytes=0-18446744073709551615的请求",
            verification="检查响应是否包含Requested Range Not Satisfiable",
        ),
        POC(
            poc_id="POC-MID-015",
            name="Tomcat AJP文件包含检测",
            category="lfi",
            severity="high",
            cve_id="CVE-2020-1938",
            target_service="tcp",
            target_port=8009,
            description="检测Tomcat AJP连接器是否存在文件包含漏洞（Ghostcat）",
            payload="通过AJP协议发送包含特殊属性的请求",
            verification="检查是否能读取WEB-INF/web.xml等敏感文件",
        ),
        POC(
            poc_id="POC-MID-016",
            name="JBoss未授权访问检测",
            category="rce",
            severity="critical",
            target_service="http",
            target_port=8080,
            description="检测JBoss是否存在未授权访问，可能导致远程代码执行",
            payload="访问/jmx-console/、/web-console/、/invoker/JMXInvokerServlet",
            verification="检查是否能未授权访问JBoss管理控制台",
        ),
        POC(
            poc_id="POC-MID-017",
            name="WebLogic未授权访问检测",
            category="rce",
            severity="critical",
            target_service="http",
            target_port=7001,
            description="检测WebLogic是否存在未授权访问，可能导致远程代码执行",
            payload="访问/console/、/wls-wsat/、/_async/、/uddiexplorer/",
            verification="检查是否能未授权访问WebLogic管理控制台",
        ),
        POC(
            poc_id="POC-MID-018",
            name="GlassFish未授权访问检测",
            category="info",
            severity="high",
            target_service="http",
            target_port=4848,
            description="检测GlassFish是否存在未授权访问管理控制台",
            payload="访问/、/common/index.jsf",
            verification="检查是否能未授权访问GlassFish管理控制台",
        ),

        # ===== 更多数据库/缓存漏洞 =====
        POC(
            poc_id="POC-DB-011",
            name="Redis未授权访问检测",
            category="info",
            severity="critical",
            target_service="tcp",
            target_port=6379,
            description="检测Redis是否存在未授权访问，可能导致数据泄露或远程代码执行",
            payload="发送INFO、CONFIG GET dir、KEYS *等命令",
            verification="检查是否能未授权执行Redis命令",
        ),
        POC(
            poc_id="POC-DB-012",
            name="Memcached未授权访问检测",
            category="info",
            severity="medium",
            target_service="tcp",
            target_port=11211,
            description="检测Memcached是否存在未授权访问，可能导致数据泄露",
            payload="发送stats、version、stats slabs等命令",
            verification="检查是否能未授权执行Memcached命令",
        ),
        POC(
            poc_id="POC-DB-013",
            name="MongoDB未授权访问检测",
            category="info",
            severity="high",
            target_service="tcp",
            target_port=27017,
            description="检测MongoDB是否存在未授权访问，可能导致数据泄露",
            payload="发送listDatabases、listCollections等命令",
            verification="检查是否能未授权执行MongoDB命令",
        ),
        POC(
            poc_id="POC-DB-014",
            name="Elasticsearch未授权访问检测",
            category="info",
            severity="high",
            target_service="http",
            target_port=9200,
            description="检测Elasticsearch是否存在未授权访问，可能导致数据泄露",
            payload="访问/_cat/indices、/_cluster/health、/_nodes",
            verification="检查是否能未授权访问Elasticsearch",
        ),
        POC(
            poc_id="POC-DB-015",
            name="CouchDB未授权访问检测",
            category="info",
            severity="high",
            target_service="http",
            target_port=5984,
            description="检测CouchDB是否存在未授权访问，可能导致数据泄露",
            payload="访问/_all_dbs、/_utils/",
            verification="检查是否能未授权访问CouchDB",
        ),
        POC(
            poc_id="POC-DB-016",
            name="ZooKeeper未授权访问检测",
            category="info",
            severity="medium",
            target_service="tcp",
            target_port=2181,
            description="检测ZooKeeper是否存在未授权访问，可能导致数据泄露",
            payload="发送ls /、get /、stat等命令",
            verification="检查是否能未授权访问ZooKeeper",
        ),
        POC(
            poc_id="POC-DB-017",
            name="Consul未授权访问检测",
            category="info",
            severity="high",
            target_service="http",
            target_port=8500,
            description="检测Consul是否存在未授权访问，可能导致远程代码执行",
            payload="访问/v1/agent/services、/v1/kv/?keys",
            verification="检查是否能未授权访问Consul",
        ),
        POC(
            poc_id="POC-DB-018",
            name="etcd未授权访问检测",
            category="info",
            severity="high",
            target_service="http",
            target_port=2379,
            description="检测etcd是否存在未授权访问，可能导致敏感数据泄露",
            payload="访问/v2/keys、/version",
            verification="检查是否能未授权访问etcd",
        ),
    ]

    return more_pocs


def main():
    """在...中。

        Returns:
            操作结果。
    """
    print("=" * 60)
    print("  POC库扩充脚本")
    print("=" * 60)
    print()

    library = get_poc_library()
    initial_count = len(library.list_all())
    print(f"现有POC数量: {initial_count}")

    # 生成新POC
    more_pocs = generate_more_pocs()
    print(f"待添加POC数量: {len(more_pocs)}")

    # 添加POC
    added = 0
    skipped = 0
    for poc in more_pocs:
        if library.add_poc(poc):
            added += 1
            print(f"  ✅ 添加: {poc.poc_id} - {poc.name}")
        else:
            skipped += 1
            print(f"  ⏭️  已存在: {poc.poc_id}")

    # 保存
    library.save_to_file()

    # 统计
    stats = library.get_statistics()
    print()
    print("=" * 60)
    print("  扩充完成")
    print("=" * 60)
    print(f"原有POC: {initial_count}")
    print(f"新增POC: {added}")
    print(f"跳过（已存在）: {skipped}")
    print(f"当前总数: {stats['total']}")
    print(f"按类别: {stats['by_category']}")
    print(f"按严重程度: {stats['by_severity']}")
    print(f"有CVE编号: {stats['has_cve']}")


if __name__ == "__main__":
    main()
