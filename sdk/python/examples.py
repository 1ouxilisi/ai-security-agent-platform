"""
AI Hacking Agent SDK 示例集合
==============================

包含12个完整可运行的示例，覆盖SDK主要功能场景。
运行方式：
    from sdk.python.examples import example_quickstart
    example_quickstart()

或直接运行本文件选择示例。

免责声明：所有示例仅用于演示SDK用法，实际使用时请确保已获得目标系统的授权。
"""

import json
import time
from typing import Any, Dict

from .ai_hacking_sdk import (
    AIAgentClient,
    APIError,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
)


# ============================================================
# 配置：根据实际环境修改
# ============================================================
API_BASE_URL = "http://localhost:8000"
API_KEY = ""  # 如果开启了认证，填入API密钥
TEST_TARGET = "https://demo.testfire.net"  # 测试用目标（授权测试环境）


def _get_client() -> AIAgentClient:
    """创建预配置的客户端实例。"""
    return AIAgentClient(
        base_url=API_BASE_URL,
        api_key=API_KEY,
        timeout=30,
        max_retries=2,
        debug=False,
    )


# ============================================================
# 示例1：快速开始
# ============================================================

def example_quickstart():
    """快速开始示例：初始化客户端 + 健康检查 + 基础调用。

    预期输出：
        连接成功，服务版本: 1.0.0
        服务状态: healthy
    """
    print("=" * 60)
    print("示例1：快速开始")
    print("=" * 60)

    # 初始化客户端
    client = _get_client()

    try:
        # 健康检查
        health = client.health()
        print(f"[OK] 连接成功！")
        print(f"  服务状态: {health.get('status', 'unknown')}")
        print(f"  服务版本: {health.get('version', 'unknown')}")

        # 获取评估历史
        assessments = client.list_assessments(limit=5)
        print(f"  历史评估数: {assessments.get('total', 0)}")

    except APIError as e:
        print(f"[失败] API错误: {e}")
    finally:
        client.close()

    print()


# ============================================================
# 示例2：完整渗透测试工作流
# ============================================================

def example_full_pentest_workflow():
    """完整渗透测试工作流：执行模板 -> 轮询状态 -> 获取结果。

    演示如何：
    1. 列出可用工作流模板
    2. 执行指定模板
    3. 轮询等待完成
    4. 获取最终报告
    """
    print("=" * 60)
    print("示例2：完整渗透测试工作流")
    print("=" * 60)

    client = _get_client()

    try:
        # 步骤1：列出可用模板
        print("[步骤1] 获取工作流模板列表...")
        templates = client.list_workflow_templates()
        print(f"  可用模板数: {len(templates.get('templates', []))}")
        for tpl in templates.get("templates", [])[:5]:
            print(f"  - {tpl.get('id')}: {tpl.get('name')}")

        # 步骤2：执行Web安全工作流
        print(f"\n[步骤2] 执行工作流，目标: {TEST_TARGET}")
        result = client.execute_workflow(
            template_id="web_security",
            target=TEST_TARGET,
        )
        instance_id = result.get("instance_id")
        print(f"  工作流ID: {instance_id}")

        # 步骤3：轮询等待完成
        print("\n[步骤3] 等待工作流完成...")
        final = client.poll_until_done(
            check_func=lambda: client.get_workflow_status(instance_id),
            interval=10,
            timeout=300,
        )
        print(f"  最终状态: {final.get('status')}")
        print(f"  完成进度: {final.get('progress', 'N/A')}")

        # 步骤4：获取报告
        print("\n[步骤4] 获取工作流报告...")
        report = client.get_workflow_result(instance_id)
        print(f"  发现漏洞数: {report.get('summary', {}).get('total_vulns', 0)}")

    except TimeoutError:
        print("[超时] 工作流执行超时，可稍后手动查询结果")
    except APIError as e:
        print(f"[失败] API错误: {e}")
    finally:
        client.close()

    print()


# ============================================================
# 示例3：Web应用扫描
# ============================================================

def example_web_scan():
    """Web应用扫描：创建评估 -> 等待完成 -> 获取漏洞列表。

    演示针对Web应用的完整扫描流程。
    """
    print("=" * 60)
    print("示例3：Web应用扫描")
    print("=" * 60)

    client = _get_client()

    try:
        # 创建Web类型评估
        print(f"创建Web安全评估，目标: {TEST_TARGET}")
        result = client.create_assessment(
            target=TEST_TARGET,
            assessment_type="web",
            config={"depth": "standard", "modules": ["xss", "sqli", "dirb"]},
        )
        assessment_id = result.get("assessment_id")
        print(f"评估ID: {assessment_id}")

        # 等待完成
        print("等待扫描完成...")
        final = client.poll_until_done(
            lambda: client.get_assessment(assessment_id),
            interval=15,
            timeout=600,
        )
        print(f"扫描状态: {final.get('status')}")

        # 获取高危漏洞
        print("\n获取高危及以上漏洞...")
        vulns = client.list_vulnerabilities(
            assessment_id=assessment_id,
            severity="high",
            limit=20,
        )
        print(f"发现高危漏洞: {len(vulns.get('items', []))}个")
        for v in vulns.get("items", [])[:5]:
            print(f"  [{v.get('severity', '?').upper()}] {v.get('name', 'unknown')} - {v.get('location', '')}")

    except APIError as e:
        print(f"[失败] {e}")
    finally:
        client.close()

    print()


# ============================================================
# 示例4：移动应用分析
# ============================================================

def example_mobile_analysis():
    """移动应用安全分析：调用移动安全评估API。

    演示对Android APK或iOS IPA进行安全评估。
    """
    print("=" * 60)
    print("示例4：移动应用安全分析")
    print("=" * 60)

    client = _get_client()

    try:
        # 创建移动应用评估
        # 实际使用时替换为你的APK路径或URL
        print("启动移动应用安全评估...")
        result = client.create_assessment(
            target="test_sample.apk",
            assessment_type="mobile",
            config={
                "platform": "android",
                "checks": ["manifest", "crypto", "storage", "network"],
            },
        )
        print(f"评估任务已创建: {result.get('assessment_id')}")
        print("提示：移动分析通常需要几分钟，请稍后查询结果")

    except APIError as e:
        print(f"[失败] {e}")
    finally:
        client.close()

    print()


# ============================================================
# 示例5：AI聊天交互
# ============================================================

def example_ai_chat():
    """AI聊天：与安全AI助手进行多轮对话。

    演示如何使用AI进行安全咨询和问题解答。
    """
    print("=" * 60)
    print("示例5：AI安全助手对话")
    print("=" * 60)

    client = _get_client()

    try:
        # 第一轮对话
        print("[用户] 什么是XSS跨站脚本攻击？")
        resp1 = client.ai_chat("什么是XSS跨站脚本攻击？")
        print(f"[AI] {resp1.get('response', '').strip()[:200]}...")
        conv_id = resp1.get("conversation_id")

        # 第二轮对话（保持上下文）
        if conv_id:
            print(f"\n[用户] 如何防御XSS攻击？")
            resp2 = client.ai_chat("如何防御XSS攻击？", conversation_id=conv_id)
            print(f"[AI] {resp2.get('response', '').strip()[:200]}...")

        # AI助手（带上下文）
        print("\n[用户] 我刚扫描发现了一个SQL注入漏洞，怎么处理？")
        resp3 = client.ai_assistant(
            query="发现SQL注入漏洞后应该如何处理？",
            context={"vuln_type": "sql_injection", "severity": "high"},
        )
        print(f"[AI助手] {resp3.get('response', '').strip()[:200]}...")

    except APIError as e:
        print(f"[失败] {e}")
    finally:
        client.close()

    print()


# ============================================================
# 示例6：漏洞验证
# ============================================================

def example_vuln_verification():
    """漏洞验证：验证SQL注入 -> 轮询获取结果。

    演示如何使用漏洞真实验证功能确认漏洞存在性，避免误报。
    """
    print("=" * 60)
    print("示例6：漏洞真实验证")
    print("=" * 60)

    client = _get_client()

    try:
        # 验证Web漏洞
        print("验证Web SQL注入漏洞...")
        result = client.verify_web_vuln(
            url=f"{TEST_TARGET}/search",
            vuln_type="sql_injection",
            params={"param": "query"},
        )
        task_id = result.get("task_id")
        print(f"验证任务ID: {task_id}")

        # 轮询等待结果
        print("等待验证结果...")
        verify_result = client.poll_until_done(
            lambda: client.get_verify_result(task_id),
            interval=3,
            timeout=60,
            done_statuses=["verified", "not_vulnerable", "error", "timeout"],
        )

        verified = verify_result.get("verified", False)
        print(f"\n验证结论: {'漏洞确认存在' if verified else '未发现漏洞'}")
        print(f"风险等级: {verify_result.get('risk_level', 'unknown')}")
        if verify_result.get("evidence"):
            print(f"验证证据: {verify_result['evidence'][:100]}")

    except APIError as e:
        print(f"[失败] {e}")
    finally:
        client.close()

    print()


# ============================================================
# 示例7：报告生成与下载
# ============================================================

def example_report_generation():
    """报告生成：生成HTML报告 -> 下载保存到本地。

    演示如何根据已有评估任务生成安全报告并下载。
    """
    print("=" * 60)
    print("示例7：安全报告生成与下载")
    print("=" * 60)

    client = _get_client()

    try:
        # 先获取一个评估ID（这里使用示例，实际从你的评估中获取）
        assessments = client.list_assessments(limit=1)
        if not assessments.get("items"):
            print("暂无评估任务，请先执行扫描")
            return

        assessment_id = assessments["items"][0].get("assessment_id")
        print(f"使用评估ID: {assessment_id}")

        # 生成HTML报告
        print("生成HTML格式报告...")
        gen_result = client.generate_report(assessment_id, report_format="html")
        report_id = gen_result.get("report_id")
        print(f"报告ID: {report_id}")

        # 下载报告
        if report_id:
            print("下载报告内容...")
            content = client.download_report(report_id)
            output_path = "security_report.html"
            with open(output_path, "wb") as f:
                f.write(content)
            print(f"报告已保存: {output_path} ({len(content)} 字节)")

    except APIError as e:
        print(f"[失败] {e}")
    except IOError as e:
        print(f"[文件错误] {e}")
    finally:
        client.close()

    print()


# ============================================================
# 示例8：漏洞数据库查询
# ============================================================

def example_vuln_database_query():
    """漏洞库查询：搜索CVE -> 匹配服务版本 -> 获取修复方案。

    演示如何利用内置漏洞数据库进行情报查询。
    """
    print("=" * 60)
    print("示例8：漏洞数据库查询")
    print("=" * 60)

    client = _get_client()

    try:
        # 步骤1：搜索CVE
        print("[步骤1] 搜索Nginx相关高危CVE...")
        results = client.search_cve(product="nginx", severity="high", page_size=5)
        cves = results.get("items", [])
        print(f"找到{len(cves)}条结果")
        for cve in cves[:3]:
            print(f"  {cve.get('cve_id', '?')}: {cve.get('description', '')[:80]}...")

        # 步骤2：按服务版本匹配
        print("\n[步骤2] 匹配OpenSSL 1.0.2g已知漏洞...")
        match = client.match_cve(service="openssl", version="1.0.2g")
        matched = match.get("matched_cves", [])
        print(f"匹配到{len(matched)}个已知漏洞")
        print(f"整体风险: {match.get('risk_level', 'unknown')}")

        # 步骤3：获取修复方案
        if matched:
            cve_id = matched[0].get("cve_id")
            print(f"\n[步骤3] 获取{cve_id}修复方案...")
            remedy = client.get_remediation(cve_id)
            print(f"修复优先级: {remedy.get('priority', 'unknown')}")
            print(f"修复建议: {str(remedy.get('steps', ''))[:100]}...")

    except APIError as e:
        print(f"[失败] {e}")
    finally:
        client.close()

    print()


# ============================================================
# 示例9：可视化数据获取
# ============================================================

def example_visualization():
    """可视化：生成攻击路径图 + 网络拓扑 + 风险热力图数据。

    演示获取各类可视化图表所需的数据格式。
    """
    print("=" * 60)
    print("示例9：可视化数据获取")
    print("=" * 60)

    client = _get_client()

    try:
        # 攻击路径分析
        print("[1] 生成攻击路径分析...")
        attack_path = client.get_attack_path(assessment_id="demo_assessment_id")
        print(f"  风险攻击路径节点: {len(attack_path.get('nodes', []))}")

        # 网络拓扑
        print("\n[2] 获取网络拓扑数据...")
        topology = client.get_network_topology(assessment_id="demo_assessment_id")
        print(f"  发现主机数: {len(topology.get('nodes', []))}")

        # 风险热力图
        print("\n[3] 生成风险热力图...")
        heatmap = client.get_risk_heatmap(
            scan_data={"demo": True},
            dimension="host_port",
        )
        print(f"  热力图数据点: {len(heatmap.get('grid', []))}")

        # 趋势分析
        print("\n[4] 获取漏洞趋势数据...")
        trend = client.get_analytics_trend(metric="vulnerability")
        print(f"  趋势时间点: {len(trend.get('timeline', []))}")
        print(f"  变化率: {trend.get('change_rate', 'N/A')}%")

    except APIError as e:
        print(f"[提示] 可视化API需要先有扫描数据: {e}")
    finally:
        client.close()

    print()


# ============================================================
# 示例10：定时扫描
# ============================================================

def example_scheduled_scan():
    """定时扫描：创建定时工作流 + 查看定时任务列表。

    演示如何配置周期性安全扫描任务。
    """
    print("=" * 60)
    print("示例10：定时扫描配置")
    print("=" * 60)

    client = _get_client()

    try:
        # 查看可用工作流模板
        print("查看预置工作流模板...")
        templates = client.list_workflow_templates()
        tpl_list = templates.get("templates", [])
        scheduled_tpls = [t for t in tpl_list if "daily" in t.get("id", "") or "scheduled" in t.get("id", "")]
        print(f"  定时类模板: {len(scheduled_tpls)}个")

        # 创建自定义定时工作流（演示定义）
        print("\n定义每日定时Web扫描工作流...")
        custom_wf = {
            "name": "每日Web安全巡检",
            "schedule": "0 2 * * *",  # 每天凌晨2点
            "target": TEST_TARGET,
            "type": "web",
            "notify": "email",
        }
        print(f"  工作流定义: {json.dumps(custom_wf, ensure_ascii=False, indent=2)}")
        print("  提示：实际创建请调用create_custom_workflow()")

    except APIError as e:
        print(f"[失败] {e}")
    finally:
        client.close()

    print()


# ============================================================
# 示例11：异常处理
# ============================================================

def example_error_handling():
    """异常处理：演示各种异常的捕获和处理方式。

    展示如何根据不同的API错误类型进行差异化处理。
    """
    print("=" * 60)
    print("示例11：异常处理最佳实践")
    print("=" * 60)

    client = AIAgentClient(
        base_url="http://localhost:9999",  # 故意使用错误端口触发连接错误
        timeout=2,
        max_retries=0,
    )

    # 1. 捕获网络错误
    print("[1] 测试连接失败处理...")
    try:
        client.health()
    except APIError as e:
        print(f"  捕获API错误: status={e.status_code}, msg={e.message}")

    # 2. 认证错误处理
    print("\n[2] 测试认证错误处理...")
    try:
        bad_client = AIAgentClient(base_url=API_BASE_URL, api_key="invalid-key", timeout=5)
        bad_client.list_assessments()
    except AuthenticationError as e:
        print(f"  认证失败: {e.message}")
        print("  -> 请检查API密钥是否正确")
    except APIError as e:
        print(f"  其他API错误: {e.message}")

    # 3. 资源不存在
    print("\n[3] 测试404处理...")
    try:
        good_client = _get_client()
        good_client.get_assessment("nonexistent_id_12345")
    except NotFoundError as e:
        print(f"  资源不存在: {e.message}")
    except APIError as e:
        print(f"  API错误: {e.message}")
    finally:
        if 'good_client' in dir():
            good_client.close()

    # 4. 参数验证错误
    print("\n[4] 测试参数验证错误处理...")
    try:
        c = _get_client()
        c.match_cve(service="", version="")  # 空参数
    except ValidationError as e:
        print(f"  参数验证失败: {e.message}")
    except APIError as e:
        print(f"  API错误: {e.message}")
    finally:
        if 'c' in dir():
            c.close()

    client.close()
    print("\n异常处理示例完成，所有异常均被正确捕获。")
    print()


# ============================================================
# 示例12：批量操作
# ============================================================

def example_batch_operations():
    """批量操作：对多个目标执行扫描并汇总结果。

    演示如何在批量场景下高效使用SDK：
    - 多个目标依次扫描
    - 汇总所有目标的漏洞统计
    - 生成整体风险报告
    """
    print("=" * 60)
    print("示例12：批量多目标扫描")
    print("=" * 60)

    # 目标列表（替换为你授权测试的目标）
    targets = [
        "https://example.com",
        "https://demo.testfire.net",
        # 可添加更多目标
    ]

    client = _get_client()
    batch_results = {}

    try:
        for i, target in enumerate(targets, 1):
            print(f"\n[{i}/{len(targets)}] 扫描目标: {target}")
            try:
                # 创建评估
                result = client.create_assessment(target=target, assessment_type="web")
                assessment_id = result.get("assessment_id")
                print(f"  评估ID: {assessment_id}")

                # 等待完成（批量场景可异步提交后统一轮询）
                final = client.poll_until_done(
                    lambda aid=assessment_id: client.get_assessment(aid),
                    interval=10,
                    timeout=300,
                )

                batch_results[target] = {
                    "status": final.get("status"),
                    "total_vulns": final.get("summary", {}).get("total_vulns", 0),
                    "high_vulns": final.get("summary", {}).get("high_count", 0),
                    "critical_vulns": final.get("summary", {}).get("critical_count", 0),
                }
                print(f"  完成: 总计{batch_results[target]['total_vulns']}个漏洞")

            except APIError as e:
                print(f"  [失败] {e}")
                batch_results[target] = {"error": str(e)}
            except TimeoutError:
                print(f"  [超时] 扫描未在规定时间内完成")
                batch_results[target] = {"status": "timeout"}

        # 汇总报告
        print("\n" + "=" * 40)
        print("批量扫描汇总结果")
        print("=" * 40)
        total_critical = sum(r.get("critical_vulns", 0) for r in batch_results.values())
        total_high = sum(r.get("high_vulns", 0) for r in batch_results.values())
        print(f"总目标数: {len(targets)}")
        print(f"总严重漏洞: {total_critical}")
        print(f"总高危漏洞: {total_high}")
        for target, res in batch_results.items():
            print(f"  {target}: {res}")

    finally:
        client.close()

    print()


# ============================================================
# 示例运行入口
# ============================================================

EXAMPLES = {
    "1": ("快速开始", example_quickstart),
    "2": ("完整渗透工作流", example_full_pentest_workflow),
    "3": ("Web应用扫描", example_web_scan),
    "4": ("移动应用分析", example_mobile_analysis),
    "5": ("AI聊天交互", example_ai_chat),
    "6": ("漏洞验证", example_vuln_verification),
    "7": ("报告生成", example_report_generation),
    "8": ("漏洞库查询", example_vuln_database_query),
    "9": ("可视化", example_visualization),
    "10": ("定时扫描", example_scheduled_scan),
    "11": ("异常处理", example_error_handling),
    "12": ("批量操作", example_batch_operations),
}


if __name__ == "__main__":
    print("AI Hacking Agent SDK 示例运行器")
    print("=" * 40)
    for key, (name, _) in EXAMPLES.items():
        print(f"  {key}. {name}")
    print("  all. 运行全部示例（不推荐，会触发多次API调用）")
    print("  q. 退出")

    choice = input("\n请选择要运行的示例编号: ").strip()
    if choice == "q":
        print("再见！")
    elif choice == "all":
        for key, (name, func) in EXAMPLES.items():
            print(f"\n>>> 运行示例{key}: {name}")
            try:
                func()
            except Exception as e:
                print(f"示例运行异常: {e}")
    elif choice in EXAMPLES:
        EXAMPLES[choice][1]()
    else:
        print("无效选择")
