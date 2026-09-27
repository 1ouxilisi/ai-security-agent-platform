#!/usr/bin/env python3
"""
AI Hacking Agent v6.0 - 主入口（全面升级版）
整合 MCP服务端 + 多智能体协作 + 浏览器自动化 + 桌面自动化 + 插件系统 + CVE知识库 + Web UI

使用方式:
  python main.py mcp                  # 启动MCP服务端
  python main.py scan --target 127.0.0.1  # 单智能体扫描
  python main.py multi-agent --target 127.0.0.1  # 多智能体协作扫描
  python main.py webui                # 启动Web UI界面
  python main.py list-tools           # 列出所有工具
  python main.py plugins              # 插件管理
  python main.py cve CVE-2021-44228  # CVE漏洞查询
  python main.py stats                # 统计信息
  python main.py report               # 查看报告
"""
import asyncio
import sys
import json
import argparse
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent))

from utils.logger import log
from config.settings import settings


def print_banner():
    """打印启动横幅"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║           AI Hacking Agent - v6.0 (全面升级版)               ║
║   MCP + 多智能体 + 插件系统 + CVE知识库 + Web UI             ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def cmd_mcp(args):
    """启动MCP服务端"""
    from mcp_server.server import main as mcp_main
    mode = "http" if args.http else "stdio"
    log.info(f"启动MCP服务端，模式: {mode}")
    sys.argv = ["mcp_server.py", mode]
    mcp_main()


def cmd_scan(args):
    """执行单智能体安全扫描任务"""
    from agent.planner import TaskPlanner
    from agent.executor import TaskExecutor
    from agent.reporter import ReportGenerator

    if not settings.llm.api_key or settings.llm.api_key == "sk-your-api-key-here":
        print("❌ 错误: 未配置大模型API密钥")
        print("   请复制 .env.example 为 .env，填入 LLM_API_KEY")
        return

    target = args.target
    task = args.task or f"对目标 {target} 进行全面安全测试"

    print_banner()
    print(f"🎯 目标: {target}")
    print(f"📋 任务: {task}")
    print(f"🤖 模式: 单智能体")
    print()

    async def run():
        print("📝 阶段1: 任务规划中...")
        planner = TaskPlanner()
        memory = planner.create_plan(task_description=task, target=target)

        if memory.status == "failed":
            print(f"❌ 任务规划失败: {memory.error}")
            return

        print(f"✅ 规划完成，共 {len(memory.plan)} 个步骤")
        for i, step in enumerate(memory.plan, 1):
            tool_info = f" [{step.tool_name}]" if step.tool_name else ""
            print(f"   {i}. {step.description}{tool_info}")
        print()

        print("⚙️  阶段2: 执行任务中...")
        executor = TaskExecutor()
        memory = await executor.execute_all(memory, delay=args.delay)

        print()
        print("📊 阶段3: 生成报告...")
        reporter = ReportGenerator()
        report_path = reporter.generate(memory, format=args.format)

        print()
        print(reporter.generate_summary(memory))
        print()
        print(f"📄 完整报告已保存: {report_path}")

        # 保存到数据库
        try:
            from database.db import db
            db.save_task(memory.to_dict())
            print(f"💾 任务已保存到数据库")
        except Exception as e:
            log.debug(f"数据库保存失败: {e}")

    asyncio.run(run())


def cmd_multi_agent(args):
    """多智能体协作扫描"""
    if not settings.llm.api_key or settings.llm.api_key == "sk-your-api-key-here":
        print("❌ 错误: 未配置大模型API密钥")
        return

    target = args.target
    task = args.task or f"对目标 {target} 进行多智能体协作安全评估"

    print_banner()
    print(f"🎯 目标: {target}")
    print(f"📋 任务: {task}")
    print(f"🤖 模式: 多智能体协作 (侦察Agent + 利用Agent + 验证Agent + 报告Agent)")
    print()

    async def run():
        from agent.multi_agent import MultiAgentOrchestrator

        print("🚀 初始化多智能体协调器...")
        orchestrator = MultiAgentOrchestrator()

        print("📊 智能体状态:")
        status = orchestrator.get_agent_status()
        for agent_name, agent_info in status.items():
            if isinstance(agent_info, dict):
                print(f"   • {agent_info['name']} - {agent_info['role']}")

        print()
        print("⚡ 开始多智能体协作安全评估...")
        print()

        results = await orchestrator.execute_full_assessment(target, task)

        print()
        print("=" * 60)
        print("✅ 多智能体协作评估完成")
        print("=" * 60)
        print(f"⏱️  耗时: {results['statistics']['duration_seconds']}秒")
        print(f"💬 消息交换: {results['statistics']['messages_exchanged']}条")
        print()

        # 保存报告
        if results.get("final_report"):
            report_dir = Path(settings.report.output_dir)
            report_dir.mkdir(parents=True, exist_ok=True)
            report_path = report_dir / f"multi_agent_report_{int(asyncio.get_event_loop().time())}.md"
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(results["final_report"])
            print(f"📄 报告已保存: {report_path}")

        # 输出报告摘要
        if results.get("final_report"):
            print()
            print("📄 报告摘要:")
            print("-" * 60)
            print(results["final_report"][:1000])
            if len(results["final_report"]) > 1000:
                print("... (更多内容请查看完整报告)")

    asyncio.run(run())


def cmd_webui(args):
    """启动Web UI"""
    print_banner()
    print("🌐 启动 Streamlit Web UI...")
    print(f"📂 界面地址: http://localhost:{args.port}")
    print()

    import subprocess
    app_path = Path(__file__).parent / "web_ui" / "app.py"
    cmd = [sys.executable, "-m", "streamlit", "run", str(app_path), "--server.port", str(args.port)]
    if args.headless:
        cmd.append("--server.headless=true")

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n👋 Web UI 已停止")


def cmd_list_tools(args):
    """列出所有可用工具"""
    from mcp_server.server import TOOL_DEFINITIONS

    print_banner()
    print(f"🔧 可用工具列表 (共 {len(TOOL_DEFINITIONS)} 个)")
    print("=" * 70)

    categories = {
        "侦察工具": [],
        "子域名枚举": [],
        "Web安全工具": [],
        "高级Web安全": [],
        "浏览器自动化": [],
        "桌面自动化": [],
    }

    for tool in TOOL_DEFINITIONS:
        name = tool["name"]
        if name.startswith(("port_scan", "dns_lookup", "http_headers")):
            categories["侦察工具"].append(tool)
        elif name.startswith("subdomain_"):
            categories["子域名枚举"].append(tool)
        elif name.startswith(("directory_scan", "sql_injection", "xss_test", "ssl_certificate")):
            categories["Web安全工具"].append(tool)
        elif name in ["ssrf_test", "idor_test", "command_injection_test", "file_upload_test", "xxe_test"]:
            categories["高级Web安全"].append(tool)
        elif name.startswith("browser_"):
            categories["浏览器自动化"].append(tool)
        elif name.startswith("desktop_"):
            categories["桌面自动化"].append(tool)

    for category, tools in categories.items():
        if tools:
            print(f"\n📂 {category} ({len(tools)}个)")
            print("-" * 70)
            for tool in tools:
                print(f"  • {tool['name']}")
                print(f"    {tool['description'][:80]}...")

    print()
    print("=" * 70)


def cmd_plugins(args):
    """插件管理"""
    from plugins.manager import plugin_manager

    print_banner()
    print("🔌 插件管理")
    print("=" * 60)

    if args.action == "list":
        plugins = plugin_manager.list_plugins()
        print(f"\n已安装插件 ({len(plugins)}个):")
        for p in plugins:
            status = "✅ 启用" if p["enabled"] else "❌ 禁用"
            print(f"  • {p['name']} v{p['version']} - {status} ({p['tool_count']}个工具)")
            print(f"    {p['description']}")

    elif args.action == "enable":
        if plugin_manager.enable_plugin(args.name):
            print(f"✅ 插件已启用: {args.name}")
        else:
            print(f"❌ 插件不存在: {args.name}")

    elif args.action == "disable":
        if plugin_manager.disable_plugin(args.name):
            print(f"✅ 插件已禁用: {args.name}")
        else:
            print(f"❌ 插件不存在: {args.name}")

    elif args.action == "load":
        if plugin_manager.load_external_plugin(args.path):
            print(f"✅ 外部插件加载成功: {args.path}")
        else:
            print(f"❌ 外部插件加载失败: {args.path}")

    print()


def cmd_cve(args):
    """CVE漏洞查询"""
    from knowledge.cve import cve_kb

    print_banner()
    print("🔍 CVE漏洞知识库")
    print("=" * 60)

    if args.query:
        if args.query.upper().startswith("CVE-"):
            result = cve_kb.query_cve(args.query)
            if result:
                print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            results = cve_kb.search_by_keyword(args.query)
            print(f"\n找到 {len(results)} 条匹配:")
            for r in results:
                print(f"  • {r['id']} - {r['name']} [{r['severity'].upper()}]")

    elif args.stats:
        stats = cve_kb.get_statistics()
        print(f"\n漏洞库统计:")
        print(f"  总数: {stats['total']}")
        print(f"  严重: {stats['by_severity'].get('critical', 0)}")
        print(f"  高危: {stats['by_severity'].get('high', 0)}")
        print(f"  中危: {stats['by_severity'].get('medium', 0)}")
        print(f"  低危: {stats['by_severity'].get('low', 0)}")
        print(f"  有EXP: {stats['exploit_available']}")

    else:
        # 显示所有漏洞
        all_cves = list(cve_kb.local_db.values())
        print(f"\n漏洞库 ({len(all_cves)}条):")
        for cve in all_cves:
            print(f"  • {cve['id']} - {cve['name']} [{cve['severity'].upper()}] CVSS:{cve.get('cvss_score', 'N/A')}")

    print()


def cmd_stats(args):
    """统计信息"""
    print_banner()
    print("📊 系统统计")
    print("=" * 60)

    try:
        from database.db import db
        stats = db.get_statistics()
        print(json.dumps(stats, ensure_ascii=False, indent=2))
    except Exception as e:
        print(f"数据库统计失败: {e}")
        print("提示: 执行扫描任务后会生成统计数据")

    print()


def cmd_report(args):
    """查看已保存的任务报告"""
    report_dir = Path(settings.report.output_dir)

    if not report_dir.exists():
        print(f"报告目录不存在: {report_dir}")
        return

    if args.task_id:
        state_file = report_dir / f"task_{args.task_id}.json"
        if state_file.exists():
            with open(state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            print(json.dumps(data.get("statistics", {}), ensure_ascii=False, indent=2))
        else:
            print(f"未找到任务: {args.task_id}")
    else:
        print(f"📄 报告目录: {report_dir}")
        print()
        reports = list(report_dir.glob("report_*"))
        tasks = list(report_dir.glob("task_*"))
        print(f"安全报告: {len(reports)} 个")
        for r in sorted(reports)[-10:]:
            print(f"  • {r.name}")
        print(f"\n任务状态: {len(tasks)} 个")
        for t in sorted(tasks)[-10:]:
            print(f"  • {t.name}")


def cmd_react(args):
    """🆕 v6.0: ReAct推理模式"""
    if not settings.llm.api_key or settings.llm.api_key == "sk-your-api-key-here":
        print("❌ 错误: 未配置大模型API密钥")
        return

    print_banner()
    print("🧠 ReAct推理模式（思考-行动-观察循环）")
    print(f"📋 任务: {args.task}")
    print(f"🔄 最大迭代: {args.max_iterations}")
    print()

    async def run():
        from agent.react_engine import ReActEngine
        from mcp_server.server import TOOL_DEFINITIONS

        # 构建工具注册表
        tool_registry = {}
        for tool_def in TOOL_DEFINITIONS:
            tool_registry[tool_def["name"]] = tool_def["handler"]

        engine = ReActEngine(tool_registry, max_iterations=args.max_iterations)
        result = await engine.run(args.task)

        print()
        print("=" * 60)
        print("✅ ReAct执行完成")
        print("=" * 60)
        print(f"状态: {result.status}")
        print(f"迭代次数: {result.total_iterations}")
        print(f"工具调用: {result.tool_calls}")
        print(f"耗时: {result.to_dict().get('duration_seconds', 0)}秒")
        if result.errors:
            print(f"错误: {len(result.errors)}个")
        print()
        print("📝 最终答案:")
        print("-" * 60)
        print(result.final_answer[:2000])
        if len(result.final_answer) > 2000:
            print("... (更多内容请查看完整执行记录)")

    asyncio.run(run())


def cmd_rag(args):
    """🆕 v6.0: RAG知识库查询"""
    from agent.rag_engine import rag_engine

    print_banner()
    print("📚 RAG知识库查询")
    print()

    if args.stats:
        stats = rag_engine.get_statistics()
        print(json.dumps(stats, ensure_ascii=False, indent=2))
        return

    if args.query:
        result = rag_engine.retrieve(args.query, top_k=args.top_k)
        print(f"查询: {args.query}")
        print(f"找到 {result.total_found} 条相关知识，返回前 {len(result.results)} 条")
        print(f"检索耗时: {result.retrieval_time_ms}ms")
        print()
        for i, (entry, score) in enumerate(result.results, 1):
            print(f"{i}. [{entry.category.upper()}] {entry.title} (相似度: {score:.2f})")
            print(f"   {entry.content[:200]}...")
            print()
    else:
        print("使用方法:")
        print("  python main.py rag \"查询文本\"")
        print("  python main.py rag --stats")
        print()
        stats = rag_engine.get_statistics()
        print(f"知识库当前状态: {stats['total_entries']} 条记录")
        print(f"分类: {stats['by_category']}")


def cmd_analyze(args):
    """🆕 v6.0: 智能结果分析"""
    from agent.result_analyzer import result_analyzer

    print_banner()
    print("🔍 智能结果分析器")
    print()

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                result_data = json.load(f)
            findings = result_analyzer.analyze_result(
                tool_name=args.tool or "unknown",
                target=args.target or "unknown",
                result=result_data,
            )
            print(f"分析完成，发现 {len(findings)} 个潜在漏洞")
            print()
            for finding in findings:
                print(f"  [{finding.severity.upper()}] {finding.title}")
                print(f"    置信度: {finding.confidence:.2f}, 误报风险: {finding.false_positive_risk:.2f}")
                print(f"    修复建议: {finding.recommendations[0] if finding.recommendations else 'N/A'}")
                print()
        except Exception as e:
            print(f"❌ 分析失败: {e}")
    else:
        print("使用方法:")
        print("  python main.py analyze --file result.json --tool port_scan --target 127.0.0.1")
        print()
        print("当前分析器统计:")
        print(json.dumps(result_analyzer.get_statistics(), ensure_ascii=False, indent=2))


def cmd_agents(args):
    """🆕 v6.0: 查看多智能体状态"""
    print_banner()
    print("🤖 多智能体状态")
    print()

    agents_info = [
        {"name": "ReconAgent", "role": "侦察专家", "description": "信息收集、端口扫描、子域名枚举、技术栈识别"},
        {"name": "ExploitAgent", "role": "漏洞测试专家", "description": "SQL注入/XSS/SSRF/IDOR等各类漏洞测试和验证"},
        {"name": "VerificationAgent", "role": "漏洞验证专家", "description": "深度验证、排除误报、生成PoC、评估实际风险"},
        {"name": "ReportAgent", "role": "安全报告专家", "description": "整合结果、生成专业报告、风险评级、修复建议"},
    ]

    for agent in agents_info:
        print(f"  📌 {agent['name']} - {agent['role']}")
        print(f"     {agent['description']}")
        print()

    print("=" * 60)
    print("v6.0 核心引擎:")
    print("  • ReAct推理引擎 - 思考-行动-观察动态循环")
    print("  • RAG知识库引擎 - 漏洞知识检索增强")
    print("  • 智能结果分析器 - 漏洞提取/置信度评估/误报过滤")
    print("  • 通用Agent框架 - 可迁移到任意业务领域")
    print("  • Agent编排器 - 多Agent协作流水线")


def cmd_api_server(args):
    """🆕 v6.0: 启动FastAPI REST API服务"""
    print_banner()
    print("🌐 FastAPI REST API 服务")
    print(f"📍 监听地址: http://{args.host}:{args.port}")
    print(f"📚 API文档: http://{args.host}:{args.port}/docs")
    print(f"🔴 ReDoc文档: http://{args.host}:{args.port}/redoc")
    print()
    print("API端点:")
    print("  GET  /health                    - 健康检查")
    print("  GET  /api/v1/tools              - 列出工具")
    print("  POST /api/v1/tools/call         - 调用工具")
    print("  POST /api/v1/tasks              - 创建任务")
    print("  GET  /api/v1/tasks              - 列出任务")
    print("  GET  /api/v1/tasks/{id}         - 任务详情")
    print("  POST /api/v1/agents/react       - ReAct推理")
    print("  POST /api/v1/knowledge/rag      - RAG检索")
    print("  GET  /api/v1/system/stats       - 系统统计")
    print("  WS   /ws/tasks/{id}             - 实时进度")
    print()
    print("按 Ctrl+C 停止服务")
    print("-" * 60)

    try:
        from api_server.app import run_api_server
        run_api_server(host=args.host, port=args.port)
    except ImportError as e:
        print(f"❌ 错误: 缺少依赖 - {e}")
        print("请运行: pip install fastapi uvicorn")
    except KeyboardInterrupt:
        print("\n服务已停止")


def cmd_health(args):
    """🆕 v6.0: 系统健康检查"""
    print_banner()
    print("🩺 系统健康检查")
    print()

    checks = []

    # 检查Python
    import sys
    checks.append(("Python版本", f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}", True))

    # 检查项目目录
    from pathlib import Path
    project_root = Path(__file__).parent
    checks.append(("项目目录", str(project_root), project_root.exists()))

    # 检查关键模块
    modules_to_check = [
        ("config.settings", "配置模块"),
        ("utils.logger", "日志模块"),
        ("mcp_server.server", "MCP服务端"),
        ("agent.react_engine", "ReAct引擎"),
        ("agent.rag_engine", "RAG引擎"),
        ("agent.result_analyzer", "结果分析器"),
        ("api_server.app", "API服务"),
        ("scheduler.task_scheduler", "任务调度器"),
        ("reporting.report_exporter", "报告导出器"),
    ]

    for module_name, desc in modules_to_check:
        try:
            __import__(module_name)
            checks.append((desc, "OK", True))
        except ImportError as e:
            checks.append((desc, f"缺失: {e}", False))
        except Exception as e:
            checks.append((desc, f"错误: {e}", False))

    # 检查数据目录
    for dir_name in ["data", "reports", "logs"]:
        dir_path = project_root / dir_name
        checks.append((f"{dir_name}目录", "存在" if dir_path.exists() else "不存在", dir_path.exists()))

    # 检查.env
    env_path = project_root / ".env"
    checks.append((".env配置", "存在" if env_path.exists() else "不存在(复制.env.example)", env_path.exists()))

    # 输出结果
    all_passed = True
    for name, status, ok in checks:
        icon = "✅" if ok else "❌"
        if not ok:
            all_passed = False
        print(f"  {icon} {name}: {status}")

    print()
    print("=" * 60)
    if all_passed:
        print("🎉 系统健康检查全部通过！")
    else:
        print("⚠️  部分检查未通过，请根据上述提示修复")
    print()


def cmd_nuclei(args):
    """🆕 v6.0: Nuclei POC模板漏洞扫描"""
    print_banner()
    print("🔬 Nuclei POC模板漏洞扫描引擎")
    print()

    try:
        from nuclei_engine.engine import nuclei_engine

        # 列出模板
        if args.list:
            templates = nuclei_engine.list_templates(severity=args.severity, tags=args.tags)
            stats = nuclei_engine.get_stats()
            print(f"📊 模板统计: {stats['total_templates']} 个模板")
            print(f"   按严重程度: {stats['by_severity']}")
            print()
            print(f"{'ID':<25} {'严重程度':<10} {'名称'}")
            print("-" * 70)
            for t in templates:
                print(f"{t['id']:<25} {t['severity']:<10} {t['name']}")
            print()
            return

        # 扫描目标
        print(f"🎯 目标: {args.target}")
        if args.severity:
            print(f"📊 严重程度过滤: {args.severity}")
        if args.tags:
            print(f"🏷️  标签过滤: {args.tags}")
        print()

        async def run_scan():
            severity_filter = args.severity.split(",") if args.severity else None
            tags_filter = args.tags.split(",") if args.tags else None
            results = await nuclei_engine.scan_target(
                target=args.target,
                severity_filter=severity_filter,
                tags_filter=tags_filter,
            )

            matched = [r for r in results if r.matched]
            print(f"✅ 扫描完成: 总模板 {len(results)}, 匹配 {len(matched)}")
            print()

            if matched:
                print("🔴 发现的漏洞:")
                print("-" * 70)
                for r in matched:
                    severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(r.severity, "⚪")
                    print(f"{severity_icon} [{r.severity.upper()}] {r.template_name}")
                    print(f"   URL: {r.url}")
                    print(f"   匹配: {r.matched_at}")
                    if r.description:
                        print(f"   描述: {r.description[:80]}")
                    print()
            else:
                print("✅ 未发现匹配的漏洞")

            await nuclei_engine.close()

        asyncio.run(run_scan())

    except ImportError as e:
        print(f"❌ 错误: 缺少依赖 - {e}")
        print("请运行: pip install pyyaml aiohttp")
    except Exception as e:
        print(f"❌ 扫描失败: {e}")


def cmd_test(args):
    """🆕 v6.0: 运行集成测试套件"""
    print_banner()
    print("🧪 集成测试套件")
    print()

    try:
        from tests.test_suite import run_all_tests
        success = run_all_tests()
        if not success:
            print("\n❌ 部分测试失败，请检查上述错误")
    except Exception as e:
        print(f"❌ 测试运行失败: {e}")


def cmd_cache(args):
    """🆕 v6.0: 缓存管理"""
    print_banner()
    print("💾 缓存管理")
    print()

    try:
        from cache.cache_manager import cache_manager

        if args.clear:
            cache_manager.clear()
            print("✅ 所有缓存已清空")
            return

        if args.stats:
            stats = cache_manager.get_stats()
            print(json.dumps(stats, ensure_ascii=False, indent=2))
            return

        # 默认显示统计
        stats = cache_manager.get_stats()
        print("📊 缓存统计:")
        print(f"  内存缓存: {stats['memory']['size']}/{stats['memory']['max_size']} 条")
        print(f"  命中率: {stats['memory']['hit_rate']}%")
        print(f"  命中: {stats['memory']['hits']}, 未命中: {stats['memory']['misses']}")
        print(f"  磁盘缓存: {stats['disk']['files']} 个文件")
        print()
        print("使用方法:")
        print("  python main.py cache --stats   # 查看详细统计")
        print("  python main.py cache --clear   # 清空所有缓存")

    except Exception as e:
        print(f"❌ 缓存管理失败: {e}")


def cmd_worker(args):
    """🆕 v6.0: 分布式Worker节点管理"""
    print_banner()
    print("🔗 分布式Worker节点")
    print()

    try:
        from distributed.scheduler import distributed_scheduler

        if args.status:
            stats = distributed_scheduler.get_worker_stats()
            print(f"📊 Worker统计:")
            print(f"   总Worker: {stats['total_workers']}")
            print(f"   在线: {stats['online_workers']}")
            print(f"   离线: {stats['offline_workers']}")
            print(f"   待处理任务: {stats['pending_tasks']}")
            print(f"   已完成任务: {stats['total_tasks_completed']}")
            print(f"   失败任务: {stats['total_tasks_failed']}")
            print()
            if stats['workers']:
                print(f"{'ID':<15} {'主机':<15} {'状态':<10} {'当前任务':<10} {'CPU':<8} {'内存':<8}")
                print("-" * 70)
                for w in stats['workers']:
                    print(f"{w['id']:<15} {w['hostname']:<15} {w['status']:<10} {w['current_tasks']}/{w['max_tasks']:<6} {w['cpu']:<7.1f} {w['memory']:<7.1f}")
            return

        if args.start:
            worker_id = distributed_scheduler.register_worker(
                hostname=args.hostname, ip="127.0.0.1", port=args.port,
                capabilities=["*"], max_tasks=10,
            )
            print(f"✅ Worker已注册: {worker_id}")
            print(f"   地址: {args.hostname}:{args.port}")
            print(f"   能力: 全部任务类型")
            print(f"   最大并发: 10")
            print()
            print("按 Ctrl+C 停止Worker")
            try:
                asyncio.run(distributed_scheduler.start())
            except KeyboardInterrupt:
                asyncio.run(distributed_scheduler.stop())
                print("\nWorker已停止")
            return

        # 默认显示帮助
        print("使用方法:")
        print("  python main.py worker --start    # 启动Worker节点")
        print("  python main.py worker --status   # 查看Worker状态")

    except Exception as e:
        print(f"❌ Worker管理失败: {e}")


def cmd_monitor(args):
    """🆕 v6.0: 系统监控和告警"""
    print_banner()
    print("📊 系统监控和告警")
    print()

    try:
        from monitoring.system import monitoring_system

        if args.health:
            print("🔍 运行健康检查...")
            results = monitoring_system.run_health_checks()
            print(f"总体状态: {results['overall_status'].upper()}")
            print(f"活动告警: {results['active_alerts']}")
            print()
            for name, result in results['checks'].items():
                status_icon = "✅" if result.get('status') == 'healthy' else "⚠️" if result.get('status') == 'degraded' else "❌"
                print(f"  {status_icon} {name}: {result.get('status', 'unknown')}")
                if 'cpu_usage' in result:
                    print(f"     CPU: {result['cpu_usage']:.1f}%, 内存: {result['memory_usage']:.1f}%, 磁盘: {result['disk_usage']:.1f}%")
            return

        if args.metrics:
            print("📈 Prometheus格式指标:")
            print("-" * 50)
            print(monitoring_system.export_prometheus())
            return

        if args.alerts:
            alerts = monitoring_system.get_alerts()
            print(f"🚨 告警列表 ({len(alerts)}条):")
            print()
            if alerts:
                for a in alerts[:20]:
                    icon = "🔴" if a['severity'] == 'critical' else "🟡"
                    ack = "✅" if a['acknowledged'] else "⏳"
                    print(f"  {icon} [{a['severity'].upper()}] {ack} {a['rule_name']}")
                    print(f"     {a['message']}")
                    print(f"     当前值: {a['metric_value']}, 阈值: {a['threshold']}")
                    print()
            else:
                print("  暂无告警")
            return

        # 默认显示统计
        stats = monitoring_system.get_stats()
        print(json.dumps(stats, ensure_ascii=False, indent=2))
        print()
        print("使用方法:")
        print("  python main.py monitor --health    # 运行健康检查")
        print("  python main.py monitor --metrics   # 导出Prometheus指标")
        print("  python main.py monitor --alerts    # 查看告警列表")

    except Exception as e:
        print(f"❌ 监控失败: {e}")


def cmd_export(args):
    """🆕 v6.0: 高级报告导出"""
    print_banner()
    print("📤 高级报告导出")
    print()

    try:
        from reporting.report_exporter import report_exporter, ReportConfig
        from pathlib import Path

        config = ReportConfig(
            title=f"安全测试报告 - {args.task_id}",
            target=args.task_id,
            task_type="full_scan",
        )

        # 模拟报告数据
        data = {
            "task_id": args.task_id,
            "target": args.task_id,
            "findings": [],
            "summary": {"total_findings": 0},
        }

        results = report_exporter.generate_report(data, config)

        print(f"✅ 报告已生成:")
        for fmt, path in results.items():
            print(f"  {fmt.upper()}: {path}")

        if args.output:
            import shutil
            src = results.get(args.format, list(results.values())[0])
            shutil.copy(src, args.output)
            print(f"\n📋 已复制到: {args.output}")

    except Exception as e:
        print(f"❌ 报告导出失败: {e}")


def cmd_ml(args):
    """🆕 v6.0: 机器学习增强引擎"""
    print_banner()
    print("🧠 机器学习增强引擎")
    print()

    try:
        from ml_engine.engine import ml_engine

        if args.stats:
            stats = ml_engine.get_stats()
            print(json.dumps(stats, ensure_ascii=False, indent=2))
            return

        if args.payload:
            payloads = ml_engine.generate_smart_payload(args.payload, count=5)
            print(f"🔓 智能Payload生成 ({args.payload}):")
            print()
            for i, p in enumerate(payloads, 1):
                print(f"  {i}. {p}")
            return

        if args.predict:
            try:
                target_features = json.loads(args.predict)
            except json.JSONDecodeError:
                target_features = {"target": args.predict, "tech_stack": [], "server": "", "open_ports": []}
            predictions = ml_engine.predict_vulnerabilities(target_features)
            print(f"🔮 漏洞预测:")
            print()
            for p in predictions[:10]:
                print(f"  [{p['confidence']:.0%}] {p['vulnerability']}")
                print(f"     {p['reason']}")
            return

        if args.strategy:
            try:
                target_info = json.loads(args.strategy)
            except json.JSONDecodeError:
                target_info = {"target": args.strategy, "tech_stack": [], "server": "", "open_ports": []}
            strategy = ml_engine.generate_scan_strategy(target_info)
            print(f"📋 智能扫描策略:")
            print(f"   风险等级: {strategy['risk_level'].upper()}")
            print(f"   预计时间: {strategy['estimated_time']}秒")
            print(f"   推荐工具: {', '.join(strategy['recommended_tools'])}")
            print()
            print("预测漏洞:")
            for p in strategy['predicted_vulnerabilities'][:5]:
                print(f"  [{p['confidence']:.0%}] {p['vulnerability']}")
            return

        # 默认显示帮助
        print("使用方法:")
        print("  python main.py ml --payload sqli              # 生成智能Payload")
        print("  python main.py ml --predict '{\"tech_stack\":[\"php\"]}'  # 漏洞预测")
        print("  python main.py ml --strategy '{\"target\":\"127.0.0.1\"}'  # 扫描策略")
        print("  python main.py ml --stats                       # ML引擎统计")

    except Exception as e:
        print(f"❌ ML引擎失败: {e}")


def main():
    """主入口"""
    parser = argparse.ArgumentParser(
        description="AI Hacking Agent v6.0 - AI驱动的安全研究智能体平台（全面升级版）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py mcp                              # 启动MCP服务端
  python main.py scan --target 127.0.0.1         # 单智能体扫描
  python main.py multi-agent --target 127.0.0.1  # 多智能体协作扫描
  python main.py webui                             # 启动Web UI
  python main.py list-tools                        # 列出所有工具
  python main.py plugins list                      # 列出插件
  python main.py cve CVE-2021-44228               # 查询CVE漏洞
  python main.py stats                             # 查看统计
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    # MCP服务端
    mcp_parser = subparsers.add_parser("mcp", help="启动MCP服务端")
    mcp_parser.add_argument("--http", action="store_true", help="使用HTTP模式")
    mcp_parser.set_defaults(func=cmd_mcp)

    # 单智能体扫描
    scan_parser = subparsers.add_parser("scan", help="单智能体安全扫描")
    scan_parser.add_argument("--target", "-t", required=True, help="目标地址")
    scan_parser.add_argument("--task", "-T", help="任务描述")
    scan_parser.add_argument("--delay", "-d", type=float, default=1.0, help="步骤间延迟")
    scan_parser.add_argument("--format", "-f", choices=["markdown", "html", "json"], default="markdown")
    scan_parser.set_defaults(func=cmd_scan)

    # 多智能体协作
    ma_parser = subparsers.add_parser("multi-agent", help="多智能体协作安全评估")
    ma_parser.add_argument("--target", "-t", required=True, help="目标地址")
    ma_parser.add_argument("--task", "-T", help="任务描述")
    ma_parser.set_defaults(func=cmd_multi_agent)

    # Web UI
    webui_parser = subparsers.add_parser("webui", help="启动Streamlit Web UI")
    webui_parser.add_argument("--port", "-p", type=int, default=8501, help="端口号")
    webui_parser.add_argument("--headless", action="store_true", help="无头模式")
    webui_parser.set_defaults(func=cmd_webui)

    # 工具列表
    tools_parser = subparsers.add_parser("list-tools", help="列出所有可用工具")
    tools_parser.set_defaults(func=cmd_list_tools)

    # 插件管理
    plugin_parser = subparsers.add_parser("plugins", help="插件管理")
    plugin_parser.add_argument("action", choices=["list", "enable", "disable", "load"], help="操作")
    plugin_parser.add_argument("--name", help="插件名称")
    plugin_parser.add_argument("--path", help="插件路径")
    plugin_parser.set_defaults(func=cmd_plugins)

    # CVE查询
    cve_parser = subparsers.add_parser("cve", help="CVE漏洞查询")
    cve_parser.add_argument("query", nargs="?", help="CVE ID或关键词")
    cve_parser.add_argument("--stats", action="store_true", help="显示统计")
    cve_parser.set_defaults(func=cmd_cve)

    # 统计
    stats_parser = subparsers.add_parser("stats", help="系统统计")
    stats_parser.set_defaults(func=cmd_stats)

    # 报告
    report_parser = subparsers.add_parser("report", help="查看任务报告")
    report_parser.add_argument("--task-id", help="任务ID")
    report_parser.set_defaults(func=cmd_report)

    # 🆕 v6.0: ReAct推理模式
    react_parser = subparsers.add_parser("react", help="ReAct推理模式（思考-行动-观察循环）")
    react_parser.add_argument("--task", "-T", required=True, help="任务描述")
    react_parser.add_argument("--max-iterations", type=int, default=15, help="最大迭代次数")
    react_parser.set_defaults(func=cmd_react)

    # 🆕 v6.0: RAG知识库查询
    rag_parser = subparsers.add_parser("rag", help="RAG知识库查询")
    rag_parser.add_argument("query", nargs="?", help="查询文本")
    rag_parser.add_argument("--stats", action="store_true", help="显示知识库统计")
    rag_parser.add_argument("--top-k", type=int, default=5, help="返回结果数")
    rag_parser.set_defaults(func=cmd_rag)

    # 🆕 v6.0: 结果分析
    analyze_parser = subparsers.add_parser("analyze", help="智能结果分析（漏洞提取/置信度评估/误报过滤）")
    analyze_parser.add_argument("--file", help="要分析的结果JSON文件")
    analyze_parser.add_argument("--tool", help="工具名称")
    analyze_parser.add_argument("--target", help="目标地址")
    analyze_parser.set_defaults(func=cmd_analyze)

    # 🆕 v6.0: Agent状态
    agents_parser = subparsers.add_parser("agents", help="查看多智能体状态")
    agents_parser.set_defaults(func=cmd_agents)

    # 🆕 v6.0: API服务
    api_parser = subparsers.add_parser("api-server", help="启动FastAPI REST API服务")
    api_parser.add_argument("--host", default="0.0.0.0", help="监听地址")
    api_parser.add_argument("--port", type=int, default=8000, help="监听端口")
    api_parser.set_defaults(func=cmd_api_server)

    # 🆕 v6.0: 健康检查
    health_parser = subparsers.add_parser("health", help="系统健康检查")
    health_parser.set_defaults(func=cmd_health)

    # 🆕 v6.0: Nuclei POC扫描
    nuclei_parser = subparsers.add_parser("nuclei", help="Nuclei POC模板漏洞扫描")
    nuclei_parser.add_argument("--target", "-t", required=True, help="目标URL")
    nuclei_parser.add_argument("--severity", help="按严重程度过滤 (critical/high/medium/low/info)")
    nuclei_parser.add_argument("--tags", help="按标签过滤")
    nuclei_parser.add_argument("--list", action="store_true", help="列出所有POC模板")
    nuclei_parser.set_defaults(func=cmd_nuclei)

    # 🆕 v6.0: 运行测试
    test_parser = subparsers.add_parser("test", help="运行集成测试套件")
    test_parser.set_defaults(func=cmd_test)

    # 🆕 v6.0: 缓存管理
    cache_parser = subparsers.add_parser("cache", help="缓存管理")
    cache_parser.add_argument("--stats", action="store_true", help="查看缓存统计")
    cache_parser.add_argument("--clear", action="store_true", help="清空缓存")
    cache_parser.set_defaults(func=cmd_cache)

    # 🆕 v6.0: Worker节点
    worker_parser = subparsers.add_parser("worker", help="分布式Worker节点管理")
    worker_parser.add_argument("--start", action="store_true", help="启动Worker节点")
    worker_parser.add_argument("--status", action="store_true", help="查看Worker状态")
    worker_parser.add_argument("--hostname", default="localhost", help="Worker主机名")
    worker_parser.add_argument("--port", type=int, default=9000, help="Worker端口")
    worker_parser.set_defaults(func=cmd_worker)

    # 🆕 v6.0: 监控系统
    monitor_parser = subparsers.add_parser("monitor", help="系统监控和告警")
    monitor_parser.add_argument("--health", action="store_true", help="运行健康检查")
    monitor_parser.add_argument("--metrics", action="store_true", help="导出Prometheus指标")
    monitor_parser.add_argument("--alerts", action="store_true", help="查看告警列表")
    monitor_parser.set_defaults(func=cmd_monitor)

    # 🆕 v6.0: 报告导出
    export_parser = subparsers.add_parser("export", help="高级报告导出")
    export_parser.add_argument("--task-id", required=True, help="任务ID")
    export_parser.add_argument("--format", default="markdown", choices=["markdown", "html", "json", "pdf"], help="导出格式")
    export_parser.add_argument("--output", help="输出文件路径")
    export_parser.set_defaults(func=cmd_export)

    # 🆕 v6.0: ML引擎
    ml_parser = subparsers.add_parser("ml", help="机器学习增强引擎")
    ml_parser.add_argument("--predict", help="预测目标漏洞（目标特征JSON）")
    ml_parser.add_argument("--payload", help="生成智能Payload（漏洞类型）")
    ml_parser.add_argument("--strategy", help="生成扫描策略（目标信息JSON）")
    ml_parser.add_argument("--stats", action="store_true", help="查看ML引擎统计")
    ml_parser.set_defaults(func=cmd_ml)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    args.func(args)


if __name__ == "__main__":
    main()
