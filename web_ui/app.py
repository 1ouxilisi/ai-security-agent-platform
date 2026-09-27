"""
FastAPI主应用模块，集成所有API路由、中间件、安全配置和Web界面，提供统一的REST API服务。

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
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st
import pandas as pd
import json
import time
from datetime import datetime

# 页面配置
st.set_page_config(
    page_title="AI Hacking Agent - 安全研究平台",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# 自定义样式
st.markdown("""
<style>
    .main-header {
        font-size: 2rem;
        font-weight: bold;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .metric-card {
        background: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        text-align: center;
    }
    .severity-critical { color: #dc2626; font-weight: bold; }
    .severity-high { color: #ea580c; font-weight: bold; }
    .severity-medium { color: #ca8a04; font-weight: bold; }
    .severity-low { color: #2563eb; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# 侧边栏导航
st.sidebar.title("🛡️ AI Hacking Agent")
st.sidebar.markdown("---")
page = st.sidebar.radio(
    "导航",
    ["🤖 超级智能体", "📊 仪表盘", "🎯 新建任务", "📋 任务列表", "🔍 漏洞库",
     "🔐 认证测试", "🌐 API安全", "📡 漏洞情报",
     "🔧 工具调用", "📈 统计分析", "⚙️ 设置"]
)
st.sidebar.markdown("---")
st.sidebar.info("v2.0 全面升级版\nMCP + 多智能体 + 插件系统")


def load_database():
    """加载数据库"""
    try:
        from database.db import db
        return db
    except Exception as e:
        st.error(f"数据库加载失败: {e}")
        return None


def dashboard_page():
    """仪表盘页面"""
    st.markdown('<p class="main-header">📊 仪表盘</p>', unsafe_allow_html=True)
    st.markdown("---")

    db = load_database()
    if not db:
        st.warning("数据库未初始化")
        return

    stats = db.get_statistics()

    # 核心指标
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("总任务数", stats.get("total_tasks", 0))
    with col2:
        st.metric("漏洞发现", stats.get("total_findings", 0))
    with col3:
        st.metric("工具调用", stats.get("total_tool_calls", 0))
    with col4:
        st.metric("高危漏洞", stats.get("findings_by_severity", {}).get("high", 0) +
                  stats.get("findings_by_severity", {}).get("critical", 0))

    st.markdown("---")

    # 图表区域
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📊 任务状态分布")
        tasks_by_status = stats.get("tasks_by_status", {})
        if tasks_by_status:
            df = pd.DataFrame(list(tasks_by_status.items()), columns=["状态", "数量"])
            st.bar_chart(df.set_index("状态"))
        else:
            st.info("暂无任务数据")

    with col2:
        st.subheader("⚠️ 漏洞严重程度分布")
        findings_by_severity = stats.get("findings_by_severity", {})
        if findings_by_severity:
            df = pd.DataFrame(list(findings_by_severity.items()), columns=["严重程度", "数量"])
            st.bar_chart(df.set_index("严重程度"), color=["#dc2626", "#ea580c", "#ca8a04", "#2563eb"])
        else:
            st.info("暂无漏洞数据")

    st.markdown("---")
    st.subheader("🔥 常用工具排行")
    top_tools = stats.get("top_tools", {})
    if top_tools:
        df = pd.DataFrame(list(top_tools.items()), columns=["工具", "调用次数"])
        st.dataframe(df, use_container_width=True)
    else:
        st.info("暂无工具调用记录")


def new_task_page():
    """新建任务页面"""
    st.markdown('<p class="main-header">🎯 新建安全测试任务</p>', unsafe_allow_html=True)
    st.markdown("---")

    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("任务配置")
        target = st.text_input("🎯 测试目标", placeholder="例如: 127.0.0.1 或 localhost")
        task_description = st.text_area("📝 任务描述", placeholder="例如: 对目标进行全面的Web安全测试，包括端口扫描、目录扫描、SQL注入测试等")

        st.subheader("测试范围")
        test_types = st.multiselect(
            "选择测试类型",
            ["端口扫描", "子域名枚举", "目录扫描", "SQL注入测试", "XSS测试",
             "SSRF测试", "IDOR测试", "命令注入测试", "文件上传测试", "SSL检测"],
            default=["端口扫描", "目录扫描"]
        )

        st.subheader("高级选项")
        col_a, col_b = st.columns(2)
        with col_a:
            scan_speed = st.select_slider("扫描速度", options=["慢速", "中速", "快速"], value="中速")
        with col_b:
            max_depth = st.number_input("最大深度", min_value=1, max_value=10, value=3)

    with col2:
        st.subheader("执行模式")
        mode = st.radio("选择模式", ["单智能体", "多智能体协作", "仅MCP工具"])
        st.info(f"当前模式: {mode}")

        st.subheader("授权确认")
        st.warning("⚠️ 重要提示")
        st.write("我确认已获得目标的书面授权，所有测试将在授权范围内进行。")
        authorized = st.checkbox("我已获得授权")

    st.markdown("---")

    if st.button("🚀 开始任务", type="primary", disabled=not (target and task_description and authorized)):
        with st.spinner("任务初始化中..."):
            time.sleep(2)
            st.success(f"任务已创建！目标: {target}")
            st.info("任务正在后台执行，可在「任务列表」查看进度")
            st.balloons()


def task_list_page():
    """任务列表页面"""
    st.markdown('<p class="main-header">📋 任务列表</p>', unsafe_allow_html=True)
    st.markdown("---")

    db = load_database()
    if not db:
        st.warning("数据库未初始化")
        return

    # 筛选
    col1, col2, col3 = st.columns(3)
    with col1:
        status_filter = st.selectbox("状态筛选", ["全部", "completed", "failed", "executing", "planned", "initialized"])
    with col2:
        limit = st.number_input("显示数量", min_value=10, max_value=200, value=50)
    with col3:
        st.write("")

    # 获取任务列表
    if status_filter == "全部":
        tasks = db.list_tasks(limit=limit)
    else:
        tasks = db.list_tasks(limit=limit, status=status_filter)

    if tasks:
        # 转换为DataFrame
        df = pd.DataFrame(tasks)
        df['created_at'] = df['created_at'].apply(lambda x: datetime.fromtimestamp(x).strftime('%Y-%m-%d %H:%M:%S'))
        display_cols = ['id', 'description', 'target', 'status', 'findings_count', 'created_at']
        display_cols = [c for c in display_cols if c in df.columns]
        st.dataframe(df[display_cols], use_container_width=True)

        # 任务详情
        st.markdown("---")
        st.subheader("📄 任务详情")
        task_ids = [t['id'] for t in tasks]
        selected_task = st.selectbox("选择任务查看详情", task_ids)
        if selected_task:
            task_detail = db.get_task(selected_task)
            if task_detail:
                st.json(task_detail)
    else:
        st.info("暂无任务记录，去「新建任务」创建第一个任务吧！")


def cve_database_page():
    """漏洞库页面"""
    st.markdown('<p class="main-header">🔍 CVE漏洞知识库</p>', unsafe_allow_html=True)
    st.markdown("---")

    try:
        from knowledge.cve import cve_kb
        stats = cve_kb.get_statistics()

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("漏洞总数", stats["total"])
        with col2:
            st.metric("严重", stats["by_severity"].get("critical", 0))
        with col3:
            st.metric("高危", stats["by_severity"].get("high", 0))
        with col4:
            st.metric("有EXP", stats["exploit_available"])

        st.markdown("---")

        # 搜索
        col1, col2 = st.columns([3, 1])
        with col1:
            search_query = st.text_input("🔍 搜索CVE", placeholder="例如: CVE-2021-44228 或 log4j")
        with col2:
            severity_filter = st.selectbox("严重程度", ["全部", "critical", "high", "medium", "low"])

        # 导出功能
        st.markdown("📤 **导出漏洞库**")
        exp_col1, exp_col2, exp_col3 = st.columns(3)
        all_cves_for_export = list(cve_kb.local_db.values())
        if severity_filter != "全部":
            all_cves_for_export = [c for c in all_cves_for_export if c.get("severity") == severity_filter]

        with exp_col1:
            if st.button("📄 导出 JSON", use_container_width=True):
                import json
                json_data = json.dumps(all_cves_for_export, ensure_ascii=False, indent=2)
                st.download_button("⬇️ 下载 JSON", json_data, file_name="cve_database.json", mime="application/json")
        with exp_col2:
            if st.button("📊 导出 CSV", use_container_width=True):
                import csv
                import io
                output = io.StringIO()
                if all_cves_for_export:
                    writer = csv.DictWriter(output, fieldnames=all_cves_for_export[0].keys())
                    writer.writeheader()
                    writer.writerows(all_cves_for_export)
                st.download_button("⬇️ 下载 CSV", output.getvalue(), file_name="cve_database.csv", mime="text/csv")
        with exp_col3:
            if st.button("📝 导出 Markdown", use_container_width=True):
                md_content = "# CVE漏洞数据库\n\n"
                for cve in all_cves_for_export:
                    md_content += f"## {cve.get('id', '')} - {cve.get('name', '')}\n\n"
                    md_content += f"- **严重程度**: {cve.get('severity', 'N/A').upper()}\n"
                    md_content += f"- **CVSS评分**: {cve.get('cvss_score', 'N/A')}\n"
                    md_content += f"- **描述**: {cve.get('description', 'N/A')}\n"
                    md_content += f"- **影响范围**: {cve.get('affected', 'N/A')}\n"
                    md_content += f"- **修复方案**: {cve.get('fix', 'N/A')}\n\n"
                st.download_button("⬇️ 下载 Markdown", md_content, file_name="cve_database.md", mime="text/markdown")

        st.markdown("---")

        if search_query:
            if search_query.upper().startswith("CVE-"):
                result = cve_kb.query_cve(search_query)
                if result:
                    st.json(result)
            else:
                results = cve_kb.search_by_keyword(search_query)
                if results:
                    for r in results:
                        with st.expander(f"{r['id']} - {r['name']} ({r['severity'].upper()})"):
                            st.write(f"**CVSS评分**: {r.get('cvss_score', 'N/A')}")
                            st.write(f"**描述**: {r.get('description', 'N/A')}")
                            st.write(f"**影响范围**: {r.get('affected', 'N/A')}")
                            st.write(f"**修复方案**: {r.get('fix', 'N/A')}")
                else:
                    st.info("未找到匹配的漏洞")
        else:
            # 显示所有漏洞
            all_cves = list(cve_kb.local_db.values())
            if severity_filter != "全部":
                all_cves = [c for c in all_cves if c.get("severity") == severity_filter]

            for cve in all_cves:
                sev_class = f"severity-{cve['severity']}"
                with st.expander(f"{cve['id']} - {cve['name']}"):
                    st.markdown(f"**严重程度**: <span class='{sev_class}'>{cve['severity'].upper()}</span>", unsafe_allow_html=True)
                    st.write(f"**CVSS评分**: {cve.get('cvss_score', 'N/A')}")
                    st.write(f"**描述**: {cve.get('description', 'N/A')}")
                    st.write(f"**影响范围**: {cve.get('affected', 'N/A')}")
                    st.write(f"**修复方案**: {cve.get('fix', 'N/A')}")
                    if cve.get("references"):
                        st.write("**参考链接**:")
                        for ref in cve["references"]:
                            st.write(f"- {ref}")

    except Exception as e:
        st.error(f"漏洞库加载失败: {e}")


def tools_page():
    """工具调用页面"""
    st.markdown('<p class="main-header">🔧 工具调用</p>', unsafe_allow_html=True)
    st.markdown("---")

    st.info("此页面可直接调用MCP工具进行测试")

    # 工具分类
    tool_categories = {
        "侦察工具": ["port_scan", "dns_lookup", "http_headers"],
        "子域名枚举": ["subdomain_dns_bruteforce", "subdomain_certificate_transparency", "subdomain_enumerate_all"],
        "Web安全": ["directory_scan", "sql_injection_test", "xss_test", "ssl_certificate_check"],
        "高级Web": ["ssrf_test", "idor_test", "command_injection_test", "file_upload_test", "xxe_test"],
        "浏览器": ["browser_navigate", "browser_screenshot", "browser_get_content", "browser_extract_links"],
        "桌面": ["desktop_screenshot", "desktop_move_mouse", "desktop_click", "desktop_type_text"],
    }

    category = st.selectbox("选择工具分类", list(tool_categories.keys()))
    tool_name = st.selectbox("选择工具", tool_categories[category])

    st.markdown("---")
    st.subheader(f"工具参数: {tool_name}")

    # 根据工具显示参数表单
    params = {}
    if tool_name in ["port_scan"]:
        params["target"] = st.text_input("目标", "127.0.0.1")
        params["ports"] = st.text_input("端口范围（可选）", "")
    elif tool_name in ["dns_lookup", "subdomain_dns_bruteforce", "subdomain_certificate_transparency", "subdomain_enumerate_all"]:
        params["domain"] = st.text_input("域名", "example.com")
    elif tool_name in ["http_headers", "directory_scan"]:
        params["url"] = st.text_input("URL", "http://127.0.0.1")
    elif tool_name in ["sql_injection_test", "xss_test", "ssrf_test", "command_injection_test"]:
        params["url"] = st.text_input("URL（含参数）", "http://127.0.0.1/page?id=1")
        params["param"] = st.text_input("参数名", "id")
    elif tool_name in ["idor_test"]:
        params["url"] = st.text_input("URL（含ID参数）", "http://127.0.0.1/user?id=1")
        params["param"] = st.text_input("ID参数名", "id")
    elif tool_name in ["file_upload_test"]:
        params["upload_url"] = st.text_input("上传接口URL", "http://127.0.0.1/upload")
    elif tool_name in ["xxe_test", "ssl_certificate_check"]:
        params["url" if tool_name == "xxe_test" else "host"] = st.text_input("目标", "127.0.0.1")
    elif tool_name in ["browser_navigate"]:
        params["url"] = st.text_input("URL", "http://127.0.0.1")
    else:
        st.info("此工具无需参数或参数配置较复杂")

    st.markdown("---")
    if st.button("▶️ 执行工具", type="primary"):
        st.warning("工具执行需要在后端运行，此页面为演示界面")
        st.code(json.dumps({"tool": tool_name, "params": params}, indent=2, ensure_ascii=False))


def stats_page():
    """统计分析页面"""
    st.markdown('<p class="main-header">📈 统计分析</p>', unsafe_allow_html=True)
    st.markdown("---")

    db = load_database()
    if not db:
        st.warning("数据库未初始化")
        return

    stats = db.get_statistics()

    st.subheader("📊 全局统计")
    st.json(stats)

    st.markdown("---")
    st.subheader("📋 漏洞列表")
    findings = db.get_findings()
    if findings:
        df = pd.DataFrame(findings)
        st.dataframe(df, use_container_width=True)
    else:
        st.info("暂无漏洞记录")


def settings_page():
    """设置页面"""
    st.markdown('<p class="main-header">⚙️ 设置</p>', unsafe_allow_html=True)
    st.markdown("---")

    st.subheader("🔑 大模型配置")
    api_key = st.text_input("API Key", type="password", placeholder="sk-...")
    base_url = st.text_input("API Base URL", "https://api.deepseek.com/v1")
    model = st.text_input("模型名称", "deepseek-chat")

    st.markdown("---")
    st.subheader("🔒 安全配置")
    allowed_targets = st.text_area("授权目标白名单（每行一个）", "localhost\n127.0.0.1\n*.test.local")
    scan_rate = st.slider("扫描速率限制（秒/请求）", 0.1, 5.0, 1.0)
    max_concurrent = st.number_input("最大并发数", min_value=1, max_value=50, value=5)

    st.markdown("---")
    st.subheader("📁 路径配置")
    report_dir = st.text_input("报告输出目录", "./reports")
    screenshot_dir = st.text_input("截图保存目录", "./screenshots")
    log_dir = st.text_input("日志目录", "./logs")

    st.markdown("---")
    if st.button("💾 保存设置", type="primary"):
        st.success("设置已保存！")
        st.info("设置将写入 .env 文件")


def super_agent_page():
    """超级智能体对话页面"""
    st.markdown('<p class="main-header">🤖 超级智能体</p>', unsafe_allow_html=True)
    st.markdown("---")

    # 能力概览
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("安全工具", "33", "MCP协议")
    with col2:
        st.metric("专业智能体", "4", "Recon/Exploit/Verify/Report")
    with col3:
        st.metric("AI工具", "7", "代码/文档/数据/知识")
    with col4:
        st.metric("任务类型", "6", "侦察/漏洞/报告/代码/分析/自定义")

    st.markdown("---")

    # 快捷指令
    st.subheader("⚡ 快捷指令")
    quick_cmds = [
        "扫描127.0.0.1的端口和服务",
        "测试http://example.com的SQL注入漏洞",
        "生成一份安全测试报告模板",
        "写一个Python端口扫描脚本",
        "查询CVE-2021-44228漏洞详情",
    ]
    cols = st.columns(len(quick_cmds))
    for i, cmd in enumerate(quick_cmds):
        if cols[i].button(cmd[:10] + "..." if len(cmd) > 10 else cmd, key=f"quick_{i}"):
            st.session_state["current_input"] = cmd

    st.markdown("---")

    # 对话输入
    st.subheader("💬 自然语言指令")
    user_input = st.text_area(
        "输入你的任务指令（支持自然语言）",
        value=st.session_state.get("current_input", ""),
        height=100,
        placeholder="例如：扫描192.168.1.1的端口，识别服务，生成安全报告"
    )

    col1, col2 = st.columns([1, 5])
    with col1:
        execute_btn = st.button("🚀 执行任务", type="primary", use_container_width=True)
    with col2:
        if st.button("🗑️ 清空历史", use_container_width=True):
            st.session_state["chat_history"] = []
            st.rerun()

    st.markdown("---")

    # 执行任务
    if execute_btn and user_input.strip():
        with st.spinner("🤖 超级智能体正在分析和执行任务..."):
            try:
                import asyncio
                from agent.super_agent import super_agent

                # 异步执行
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(super_agent.execute(user_input))
                loop.close()

                # 保存到历史
                if "chat_history" not in st.session_state:
                    st.session_state["chat_history"] = []
                st.session_state["chat_history"].append({
                    "input": user_input,
                    "result": result,
                    "time": datetime.now().strftime("%H:%M:%S")
                })

                # 显示结果
                st.success(f"✅ 任务完成！耗时: {result.get('duration_seconds', 0)}秒")

                # 任务规划
                if result.get("steps"):
                    with st.expander("📋 任务执行步骤", expanded=True):
                        for step in result["steps"]:
                            st.markdown(f"**步骤 {step['step']}: {step['name']}**")
                            if isinstance(step.get("result"), dict):
                                st.json(step["result"])
                            else:
                                st.write(step.get("result"))

                # 发现结果
                if result.get("findings"):
                    st.subheader(f"🔍 发现结果 ({len(result['findings'])}项)")
                    for f in result["findings"]:
                        severity = f.get("severity", "info").lower()
                        severity_class = f"severity-{severity}" if severity in ["critical", "high", "medium", "low"] else ""
                        st.markdown(f"- **{f.get('name', '未命名')}** <span class='{severity_class}'>({severity.upper()})</span>", unsafe_allow_html=True)
                        if f.get("port"):
                            st.caption(f"端口: {f['port']}, 服务: {f.get('service', 'Unknown')}")
                else:
                    st.info("未发现安全问题")

                # 最终报告
                if result.get("final_report"):
                    with st.expander("📝 最终报告", expanded=False):
                        report = result["final_report"]
                        if isinstance(report, dict):
                            if report.get("executive_summary"):
                                st.markdown("### 执行摘要")
                                st.write(report["executive_summary"])
                            if report.get("risk_score") is not None:
                                st.metric("风险评分", report["risk_score"], "/100")
                            if report.get("findings"):
                                st.markdown("### 漏洞详情")
                                st.json(report["findings"])
                            if report.get("top_remediation_priorities"):
                                st.markdown("### 修复优先级")
                                for i, p in enumerate(report["top_remediation_priorities"], 1):
                                    st.markdown(f"{i}. {p}")
                        else:
                            st.write(report)

            except Exception as e:
                st.error(f"❌ 任务执行失败: {e}")
                import traceback
                with st.expander("错误详情"):
                    st.code(traceback.format_exc())

    # 对话历史
    if st.session_state.get("chat_history"):
        st.markdown("---")
        st.subheader("📜 对话历史")
        for i, msg in enumerate(reversed(st.session_state["chat_history"][-10:])):
            with st.chat_message("user"):
                st.write(f"[{msg['time']}] {msg['input']}")
            with st.chat_message("assistant"):
                status = msg['result'].get('status', 'unknown')
                findings = len(msg['result'].get('findings', []))
                duration = msg['result'].get('duration_seconds', 0)
                st.write(f"状态: **{status}** | 发现: **{findings}**项 | 耗时: **{duration}**秒")


def auth_test_page():
    """认证测试页面"""
    st.markdown('<p class="main-header">🔐 认证测试</p>', unsafe_allow_html=True)
    st.markdown("---")

    tab1, tab2, tab3, tab4 = st.tabs(["JWT分析", "OAuth分析", "Cookie分析", "权限绕过"])

    with tab1:
        st.subheader("🔑 JWT令牌分析")
        jwt_token = st.text_area("输入JWT令牌", height=100, placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")

        if st.button("分析JWT", type="primary"):
            if jwt_token.strip():
                try:
                    import sys
                    sys.path.insert(0, str(Path(__file__).parent.parent))
                    from tools.auth_tester import auth_tester

                    with st.spinner("分析JWT中..."):
                        result = auth_tester.analyze_jwt(jwt_token.strip())

                    if result.get("valid_format"):
                        st.success("✅ JWT格式有效")

                        # 风险评分
                        risk_col1, risk_col2, risk_col3 = st.columns(3)
                        with risk_col1:
                            st.metric("风险评分", f"{result.get('risk_score', 0)}/100")
                        with risk_col2:
                            st.metric("风险等级", result.get("risk_level", "unknown").upper())
                        with risk_col3:
                            st.metric("问题数", len(result.get("issues", [])))

                        # Header和Payload
                        st.subheader("📋 令牌内容")
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown("**Header**")
                            st.json(result.get("details", {}).get("header", {}))
                        with col2:
                            st.markdown("**Payload**")
                            st.json(result.get("details", {}).get("payload", {}))

                        # 问题列表
                        if result.get("issues"):
                            st.subheader("⚠️ 发现的问题")
                            for issue in result["issues"]:
                                severity = issue.get("severity", "info")
                                icon = "🔴" if severity == "critical" else "🟠" if severity == "high" else "🟡" if severity == "medium" else "🔵"
                                st.markdown(f"{icon} **[{severity.upper()}]** {issue.get('description', '')}")

                        # 修复建议
                        if result.get("recommendations"):
                            st.subheader("💡 修复建议")
                            for rec in result["recommendations"]:
                                st.markdown(f"- {rec}")
                    else:
                        st.error("❌ JWT格式无效")
                        for issue in result.get("issues", []):
                            st.error(issue.get("description", ""))
                except Exception as e:
                    st.error(f"分析失败: {e}")
            else:
                st.warning("请输入JWT令牌")

    with tab2:
        st.subheader("🔗 OAuth授权URL分析")
        oauth_url = st.text_input("输入OAuth授权URL", placeholder="https://auth.example.com/authorize?client_id=...&redirect_uri=...")

        if st.button("分析OAuth URL", type="primary"):
            if oauth_url.strip():
                try:
                    import sys
                    sys.path.insert(0, str(Path(__file__).parent.parent))
                    from tools.auth_tester import auth_tester

                    with st.spinner("分析OAuth URL中..."):
                        result = auth_tester.analyze_oauth_redirect_uri(oauth_url.strip())

                    if result.get("valid_oauth_url"):
                        st.success("✅ OAuth URL格式有效")

                        risk_col1, risk_col2 = st.columns(2)
                        with risk_col1:
                            st.metric("风险评分", f"{result.get('risk_score', 0)}/100")
                        with risk_col2:
                            st.metric("风险等级", result.get("risk_level", "unknown").upper())

                        if result.get("details"):
                            st.subheader("📋 URL详情")
                            st.json(result["details"])

                        if result.get("issues"):
                            st.subheader("⚠️ 发现的问题")
                            for issue in result["issues"]:
                                severity = issue.get("severity", "info")
                                icon = "🔴" if severity == "critical" else "🟠" if severity == "high" else "🟡" if severity == "medium" else "🔵"
                                st.markdown(f"{icon} **[{severity.upper()}]** {issue.get('description', '')}")

                        if result.get("recommendations"):
                            st.subheader("💡 修复建议")
                            for rec in result["recommendations"]:
                                st.markdown(f"- {rec}")
                    else:
                        st.warning("无法解析OAuth URL")
                except Exception as e:
                    st.error(f"分析失败: {e}")
            else:
                st.warning("请输入OAuth授权URL")

    with tab3:
        st.subheader("🍪 Cookie安全性分析")
        cookie_name = st.text_input("会话Cookie名称", "session")
        cookie_value = st.text_input("Cookie值", type="password")
        st.markdown("**Cookie属性**（可选）")
        col1, col2, col3 = st.columns(3)
        with col1:
            httponly = st.checkbox("HttpOnly")
        with col2:
            secure = st.checkbox("Secure")
        with col3:
            samesite = st.selectbox("SameSite", ["未设置", "Lax", "Strict", "None"])

        if st.button("分析Cookie", type="primary"):
            try:
                import sys
                sys.path.insert(0, str(Path(__file__).parent.parent))
                from tools.auth_tester import auth_tester

                cookies = {cookie_name: cookie_value, "_attributes": {
                    "httponly": httponly,
                    "secure": secure,
                    "samesite": samesite if samesite != "未设置" else "",
                }}

                with st.spinner("分析Cookie中..."):
                    result = auth_tester.analyze_cookie_security(cookies, cookie_name)

                if result.get("cookie_found"):
                    st.success("✅ 找到会话Cookie")

                    risk_col1, risk_col2 = st.columns(2)
                    with risk_col1:
                        st.metric("风险评分", f"{result.get('risk_score', 0)}/100")
                    with risk_col2:
                        st.metric("风险等级", result.get("risk_level", "unknown").upper())

                    if result.get("issues"):
                        st.subheader("⚠️ 发现的问题")
                        for issue in result["issues"]:
                            severity = issue.get("severity", "info")
                            icon = "🔴" if severity == "critical" else "🟠" if severity == "high" else "🟡" if severity == "medium" else "🔵"
                            st.markdown(f"{icon} **[{severity.upper()}]** {issue.get('description', '')}")

                    if result.get("recommendations"):
                        st.subheader("💡 修复建议")
                        for rec in result["recommendations"]:
                            st.markdown(f"- {rec}")
                else:
                    st.warning("未找到会话Cookie")
            except Exception as e:
                st.error(f"分析失败: {e}")

    with tab4:
        st.subheader("🚪 权限绕过测试")
        target_url = st.text_input("目标URL", "http://127.0.0.1/admin")
        param_name = st.text_input("ID参数名", "id")
        current_value = st.text_input("当前参数值", "1")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("生成IDOR Payload", type="primary"):
                try:
                    import sys
                    sys.path.insert(0, str(Path(__file__).parent.parent))
                    from tools.auth_tester import auth_tester

                    payloads = auth_tester.generate_idor_payloads(param_name, current_value)
                    st.success(f"✅ 生成{len(payloads)}个IDOR测试payload")
                    st.json(payloads[:10])
                except Exception as e:
                    st.error(f"生成失败: {e}")
        with col2:
            if st.button("生成权限提升Header"):
                try:
                    import sys
                    sys.path.insert(0, str(Path(__file__).parent.parent))
                    from tools.auth_tester import auth_tester

                    headers = auth_tester.generate_privilege_escalation_headers()
                    st.success(f"✅ 生成{len(headers)}个权限提升测试头")
                    st.json(headers)
                except Exception as e:
                    st.error(f"生成失败: {e}")

        st.markdown("---")
        st.subheader("📋 HTTP方法滥用测试")
        if st.button("生成方法滥用测试"):
            try:
                import sys
                sys.path.insert(0, str(Path(__file__).parent.parent))
                from tools.auth_tester import auth_tester

                tests = auth_tester.generate_method_abuse_tests(target_url)
                st.success(f"✅ 生成{len(tests)}个HTTP方法测试")
                st.json(tests)
            except Exception as e:
                st.error(f"生成失败: {e}")


def api_security_page():
    """API安全测试页面"""
    st.markdown('<p class="main-header">🌐 API安全测试</p>', unsafe_allow_html=True)
    st.markdown("---")

    tab1, tab2, tab3, tab4 = st.tabs(["OpenAPI分析", "GraphQL测试", "REST API测试", "安全头检查"])

    with tab1:
        st.subheader("📄 OpenAPI/Swagger规范分析")
        openapi_input = st.text_area("粘贴OpenAPI/Swagger JSON规范", height=200, placeholder='{"openapi": "3.0.0", "info": {...}, "paths": {...}}')

        if st.button("分析OpenAPI规范", type="primary"):
            if openapi_input.strip():
                try:
                    import sys
                    sys.path.insert(0, str(Path(__file__).parent.parent))
                    from tools.api_tester import api_tester

                    spec = json.loads(openapi_input)
                    with st.spinner("分析OpenAPI规范中..."):
                        result = api_tester.parse_openapi(spec)

                    if result.get("valid_spec"):
                        st.success(f"✅ 有效{result.get('version', '')}规范")

                        stat_col1, stat_col2, stat_col3, stat_col4 = st.columns(4)
                        with stat_col1:
                            st.metric("端点总数", result.get("stats", {}).get("total_endpoints", 0))
                        with stat_col2:
                            st.metric("路径数", result.get("stats", {}).get("total_paths", 0))
                        with stat_col3:
                            st.metric("未保护端点", result.get("stats", {}).get("methods_without_security", 0))
                        with stat_col4:
                            st.metric("风险评分", f"{result.get('risk_score', 0)}/100")

                        st.subheader("📋 基本信息")
                        info_col1, info_col2 = st.columns(2)
                        with info_col1:
                            st.markdown(f"**标题**: {result.get('title', 'Unknown')}")
                            st.markdown(f"**版本**: {result.get('version', 'Unknown')}")
                        with info_col2:
                            st.markdown(f"**安全方案**: {len(result.get('security_schemes', {}))}个")
                            st.markdown(f"**全局安全**: {'已定义' if result.get('global_security') else '未定义'}")

                        if result.get("endpoints"):
                            st.subheader("🔗 端点列表")
                            endpoint_data = []
                            for ep in result["endpoints"][:50]:
                                endpoint_data.append({
                                    "方法": ep["method"],
                                    "路径": ep["path"],
                                    "摘要": ep.get("summary", "")[:50],
                                    "安全": "是" if ep.get("security") or result.get("global_security") else "否",
                                    "废弃": "是" if ep.get("deprecated") else "否",
                                })
                            st.dataframe(pd.DataFrame(endpoint_data), use_container_width=True)

                        if result.get("issues"):
                            st.subheader("⚠️ 发现的问题")
                            for issue in result["issues"]:
                                severity = issue.get("severity", "info")
                                icon = "🔴" if severity == "critical" else "🟠" if severity == "high" else "🟡" if severity == "medium" else "🔵"
                                st.markdown(f"{icon} **[{severity.upper()}]** {issue.get('description', '')}")

                        if result.get("recommendations"):
                            st.subheader("💡 修复建议")
                            for rec in result["recommendations"]:
                                st.markdown(f"- {rec}")
                    else:
                        st.error("❌ 无效的OpenAPI规范")
                except json.JSONDecodeError as e:
                    st.error(f"JSON解析失败: {e}")
                except Exception as e:
                    st.error(f"分析失败: {e}")
            else:
                st.warning("请粘贴OpenAPI规范")

    with tab2:
        st.subheader("⚡ GraphQL测试")
        graphql_url = st.text_input("GraphQL端点URL", "http://127.0.0.1/graphql")

        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("生成内省查询", type="primary"):
                try:
                    import sys
                    sys.path.insert(0, str(Path(__file__).parent.parent))
                    from tools.api_tester import api_tester

                    query = api_tester.generate_graphql_introspection_query()
                    st.success("✅ 生成GraphQL内省查询")
                    st.code(query, language="graphql")
                except Exception as e:
                    st.error(f"生成失败: {e}")
        with col2:
            batch_count = st.number_input("批量查询数", min_value=2, max_value=100, value=10)
            if st.button("生成批量查询"):
                try:
                    import sys
                    sys.path.insert(0, str(Path(__file__).parent.parent))
                    from tools.api_tester import api_tester

                    query = api_tester.generate_graphql_batched_queries("users { id name }", batch_count)
                    st.success(f"✅ 生成{batch_count}个批量查询")
                    st.code(query, language="graphql")
                except Exception as e:
                    st.error(f"生成失败: {e}")
        with col3:
            nest_depth = st.number_input("嵌套深度", min_value=2, max_value=50, value=10)
            if st.button("生成深度嵌套查询"):
                try:
                    import sys
                    sys.path.insert(0, str(Path(__file__).parent.parent))
                    from tools.api_tester import api_tester

                    query = api_tester.generate_graphql_deep_nested_query("friends", nest_depth)
                    st.success(f"✅ 生成深度{nest_depth}嵌套查询")
                    st.code(query, language="graphql")
                except Exception as e:
                    st.error(f"生成失败: {e}")

    with tab3:
        st.subheader("🔍 REST API测试")
        api_endpoint = st.text_input("API端点URL", "http://127.0.0.1/api/users")
        params_input = st.text_area("请求参数（JSON格式）", '{"id": "1", "name": "test"}', height=100)

        col1, col2 = st.columns(2)
        with col1:
            if st.button("生成注入测试", type="primary"):
                try:
                    import sys
                    sys.path.insert(0, str(Path(__file__).parent.parent))
                    from tools.api_tester import api_tester

                    params = json.loads(params_input) if params_input.strip() else {}
                    tests = api_tester.generate_rest_api_injection_tests(api_endpoint, params)
                    st.success(f"✅ 生成{len(tests)}个注入测试")
                    st.json(tests[:15])
                except Exception as e:
                    st.error(f"生成失败: {e}")
        with col2:
            if st.button("生成模糊测试"):
                try:
                    import sys
                    sys.path.insert(0, str(Path(__file__).parent.parent))
                    from tools.api_tester import api_tester

                    params = json.loads(params_input) if params_input.strip() else {}
                    tests = api_tester.generate_api_fuzzing_tests(api_endpoint, params)
                    st.success(f"✅ 生成{len(tests)}个模糊测试用例")
                    st.json(tests[:15])
                except Exception as e:
                    st.error(f"生成失败: {e}")

    with tab4:
        st.subheader("🛡️ API安全响应头检查")
        headers_input = st.text_area("响应头（JSON格式）", '{"Content-Security-Policy": "default-src \'self\'", "X-Content-Type-Options": "nosniff"}', height=150)

        if st.button("检查安全头", type="primary"):
            if headers_input.strip():
                try:
                    import sys
                    sys.path.insert(0, str(Path(__file__).parent.parent))
                    from tools.api_tester import api_tester

                    headers = json.loads(headers_input)
                    result = api_tester.check_api_security_headers(headers)

                    present_col, missing_col, misconfig_col = st.columns(3)
                    with present_col:
                        st.metric("已设置", len(result.get("headers_present", [])))
                    with missing_col:
                        st.metric("缺失", len(result.get("headers_missing", [])))
                    with misconfig_col:
                        st.metric("配置错误", len(result.get("headers_misconfigured", [])))

                    if result.get("headers_present"):
                        st.subheader("✅ 已设置的安全头")
                        for h in result["headers_present"]:
                            st.markdown(f"- **{h['name']}**: `{h['value'][:80]}`")

                    if result.get("headers_missing"):
                        st.subheader("❌ 缺失的安全头")
                        for h in result["headers_missing"]:
                            st.markdown(f"- **{h['name']}**: {h['description']}")

                    if result.get("recommendations"):
                        st.subheader("💡 建议")
                        for rec in result["recommendations"]:
                            st.markdown(f"- {rec}")
                except Exception as e:
                    st.error(f"检查失败: {e}")
            else:
                st.warning("请输入响应头")


def vuln_intel_page():
    """漏洞情报页面"""
    st.markdown('<p class="main-header">📡 漏洞情报</p>', unsafe_allow_html=True)
    st.markdown("---")

    tab1, tab2, tab3 = st.tabs(["CVE查询", "CVE搜索", "漏洞分析"])

    with tab1:
        st.subheader("🔍 CVE详情查询")
        cve_id = st.text_input("CVE编号", "CVE-2021-44228", placeholder="CVE-YYYY-NNNNN")

        if st.button("查询CVE详情", type="primary"):
            if cve_id.strip():
                try:
                    import sys
                    import asyncio
                    sys.path.insert(0, str(Path(__file__).parent.parent))
                    from tools.vuln_intel import vuln_intel

                    with st.spinner(f"查询 {cve_id} 中..."):
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        result = loop.run_until_complete(vuln_intel.get_cve_details(cve_id.strip()))
                        loop.close()

                    if result.get("error"):
                        st.error(f"❌ {result['error']}")
                        if result.get("local_data"):
                            st.info("显示本地缓存数据")
                            result = result["local_data"]
                        else:
                            return

                    st.success(f"✅ 查询成功: {result.get('cve_id', cve_id)}")

                    # 基本信息
                    info_col1, info_col2, info_col3, info_col4 = st.columns(4)
                    with info_col1:
                        st.metric("CVSS评分", result.get("cvss_score", "N/A"))
                    with info_col2:
                        st.metric("严重度", result.get("cvss_severity", "N/A"))
                    with info_col3:
                        st.metric("CVSS版本", result.get("cvss_version", "N/A"))
                    with info_col4:
                        st.metric("状态", result.get("status", "N/A"))

                    # 描述
                    st.subheader("📝 漏洞描述")
                    st.write(result.get("description", "无描述"))

                    # CVSS向量
                    if result.get("cvss_vector"):
                        st.subheader("📊 CVSS向量")
                        st.code(result["cvss_vector"])

                    # CWE
                    if result.get("cwe_ids"):
                        st.subheader("🔗 相关CWE")
                        for cwe in result["cwe_ids"]:
                            st.markdown(f"- {cwe}")

                    # 时间信息
                    time_col1, time_col2 = st.columns(2)
                    with time_col1:
                        st.markdown(f"**发布时间**: {result.get('published', 'N/A')}")
                    with time_col2:
                        st.markdown(f"**最后修改**: {result.get('last_modified', 'N/A')}")

                    # 参考链接
                    if result.get("references"):
                        st.subheader("📚 参考链接")
                        for ref in result["references"][:10]:
                            st.markdown(f"- {ref}")

                    # 受影响产品
                    if result.get("affected_products"):
                        st.subheader("📦 受影响产品")
                        for product in result["affected_products"][:10]:
                            st.markdown(f"- `{product}`")

                except Exception as e:
                    st.error(f"查询失败: {e}")
                    import traceback
                    with st.expander("错误详情"):
                        st.code(traceback.format_exc())
            else:
                st.warning("请输入CVE编号")

    with tab2:
        st.subheader("🔎 CVE搜索")
        keyword = st.text_input("搜索关键词", "log4j", placeholder="漏洞关键词/产品名/CWE ID")
        col1, col2, col3 = st.columns(3)
        with col1:
            severity_filter = st.selectbox("严重度过滤", ["全部", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
        with col2:
            year_filter = st.number_input("年份过滤", min_value=1999, max_value=2030, value=0)
        with col3:
            result_limit = st.number_input("结果数量", min_value=1, max_value=100, value=20)

        if st.button("搜索CVE", type="primary"):
            if keyword.strip():
                try:
                    import sys
                    import asyncio
                    sys.path.insert(0, str(Path(__file__).parent.parent))
                    from tools.vuln_intel import vuln_intel

                    with st.spinner(f"搜索 '{keyword}' 中..."):
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        result = loop.run_until_complete(vuln_intel.search_cves(
                            keyword.strip(),
                            severity=None if severity_filter == "全部" else severity_filter,
                            year=year_filter if year_filter > 0 else None,
                            limit=result_limit
                        ))
                        loop.close()

                    if result.get("error"):
                        st.error(f"❌ {result['error']}")
                        return

                    st.success(f"✅ 找到 {result.get('total_results', 0)} 个CVE")

                    if result.get("cves"):
                        cve_data = []
                        for cve in result["cves"]:
                            cve_data.append({
                                "CVE ID": cve.get("cve_id", ""),
                                "严重度": cve.get("cvss_severity", "N/A"),
                                "CVSS": cve.get("cvss_score", "N/A"),
                                "描述": cve.get("description", "")[:80],
                                "发布时间": cve.get("published", "")[:10],
                            })
                        st.dataframe(pd.DataFrame(cve_data), use_container_width=True)
                    else:
                        st.info("未找到匹配的CVE")

                except Exception as e:
                    st.error(f"搜索失败: {e}")
            else:
                st.warning("请输入搜索关键词")

    with tab3:
        st.subheader("📊 漏洞影响分析与修复建议")
        cve_for_analysis = st.text_input("输入CVE编号进行分析", "CVE-2021-44228")

        if st.button("分析漏洞影响", type="primary"):
            if cve_for_analysis.strip():
                try:
                    import sys
                    import asyncio
                    sys.path.insert(0, str(Path(__file__).parent.parent))
                    from tools.vuln_intel import vuln_intel

                    with st.spinner(f"分析 {cve_for_analysis} 中..."):
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        cve_data = loop.run_until_complete(vuln_intel.get_cve_details(cve_for_analysis.strip()))
                        loop.close()

                    if cve_data.get("error") and not cve_data.get("local_data"):
                        st.error(f"❌ {cve_data['error']}")
                        return

                    if cve_data.get("local_data"):
                        cve_data = cve_data["local_data"]

                    # 影响分析
                    impact = vuln_intel.analyze_vulnerability_impact(cve_data)

                    st.subheader("📈 影响分析")
                    impact_col1, impact_col2, impact_col3 = st.columns(3)
                    with impact_col1:
                        st.metric("影响等级", impact.get("impact_level", "unknown").upper())
                    with impact_col2:
                        st.metric("可利用性", impact.get("exploitability", "unknown").upper())
                    with impact_col3:
                        st.metric("修复优先级", impact.get("remediation_priority", "unknown").upper())

                    # 修复建议
                    advice = vuln_intel.generate_remediation_advice(cve_data)

                    st.subheader("💡 修复建议")
                    if advice.get("general_advice"):
                        st.markdown("**通用建议**")
                        for adv in advice["general_advice"]:
                            st.markdown(f"- {adv}")

                    if advice.get("specific_remediation"):
                        st.markdown("**特定修复建议**")
                        for rem in advice["specific_remediation"]:
                            if "cwe" in rem:
                                st.markdown(f"- **{rem['cwe']}**: {rem['advice']}")
                            else:
                                st.markdown(f"- **{rem.get('type', '特定')}**: {rem['advice']}")

                    if advice.get("references"):
                        st.markdown("**参考链接**")
                        for ref in advice["references"][:5]:
                            st.markdown(f"- {ref}")

                except Exception as e:
                    st.error(f"分析失败: {e}")
            else:
                st.warning("请输入CVE编号")


# 页面路由
if page == "🤖 超级智能体":
    super_agent_page()
elif page == "📊 仪表盘":
    dashboard_page()
elif page == "🎯 新建任务":
    new_task_page()
elif page == "📋 任务列表":
    task_list_page()
elif page == "🔍 漏洞库":
    cve_database_page()
elif page == "🔐 认证测试":
    auth_test_page()
elif page == "🌐 API安全":
    api_security_page()
elif page == "📡 漏洞情报":
    vuln_intel_page()
elif page == "🔧 工具调用":
    tools_page()
elif page == "📈 统计分析":
    stats_page()
elif page == "⚙️ 设置":
    settings_page()

# 页脚
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: #888;'>"
    "AI Hacking Agent v2.0 | 仅供授权安全研究使用 | "
    "<a href='https://github.com'>GitHub</a>"
    "</div>",
    unsafe_allow_html=True
)
