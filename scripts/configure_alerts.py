#!/usr/bin/env python3
"""
configure_alerts脚本工具模块，提供相关的命令行工具和自动化脚本。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.alert_manager import alert_manager


def print_banner():
    """在...中。

        Returns:
            操作结果。
    """
    print("=" * 60)
    print("  AI Hacking Agent - 告警通知配置工具")
    print("=" * 60)
    print()


def print_channels():
    """在...中。

        Returns:
            操作结果。
    """
    channels = alert_manager.list_channels()
    if not channels:
        print("  暂无配置的通知渠道")
    else:
        print(f"  已配置 {len(channels)} 个通知渠道:")
        for i, ch in enumerate(channels, 1):
            status = "启用" if ch["enabled"] else "禁用"
            print(f"    {i}. [{ch['type']}] {ch['name']} - {status}")
    print()


def add_dingtalk():
    """添加钉钉机器人"""
    print("\n--- 配置钉钉机器人 ---")
    print("获取方式: 钉钉群设置 -> 智能群助手 -> 添加机器人 -> 自定义")
    print()
    name = input("  渠道名称 (如: 安全告警钉钉群): ").strip()
    webhook_url = input("  Webhook地址: ").strip()
    secret = input("  加签密钥 (可选，没有直接回车): ").strip()

    if not name or not webhook_url:
        print("  [错误] 名称和Webhook地址不能为空")
        return

    config = {"webhook_url": webhook_url}
    if secret:
        config["secret"] = secret

    result = alert_manager.add_channel(name=name, channel_type="dingtalk", config=config)
    if result.get("success"):
        print(f"  [成功] 钉钉渠道已添加: {name}")
        # 发送测试消息
        send_test(result["channel_id"])
    else:
        print(f"  [失败] {result.get('error')}")


def add_feishu():
    """添加飞书机器人"""
    print("\n--- 配置飞书机器人 ---")
    print("获取方式: 飞书群设置 -> 群机器人 -> 添加机器人 -> 自定义机器人")
    print()
    name = input("  渠道名称 (如: 安全告警飞书群): ").strip()
    webhook_url = input("  Webhook地址: ").strip()

    if not name or not webhook_url:
        print("  [错误] 名称和Webhook地址不能为空")
        return

    config = {"webhook_url": webhook_url}
    result = alert_manager.add_channel(name=name, channel_type="feishu", config=config)
    if result.get("success"):
        print(f"  [成功] 飞书渠道已添加: {name}")
        send_test(result["channel_id"])
    else:
        print(f"  [失败] {result.get('error')}")


def add_wecom():
    """添加企业微信机器人"""
    print("\n--- 配置企业微信机器人 ---")
    print("获取方式: 企业微信群 -> 右键 -> 添加群机器人 -> 新创建一个机器人")
    print()
    name = input("  渠道名称 (如: 安全告警企业微信群): ").strip()
    webhook_url = input("  Webhook地址: ").strip()

    if not name or not webhook_url:
        print("  [错误] 名称和Webhook地址不能为空")
        return

    config = {"webhook_url": webhook_url}
    result = alert_manager.add_channel(name=name, channel_type="wecom", config=config)
    if result.get("success"):
        print(f"  [成功] 企业微信渠道已添加: {name}")
        send_test(result["channel_id"])
    else:
        print(f"  [失败] {result.get('error')}")


def add_email():
    """添加邮件通知"""
    print("\n--- 配置邮件通知 ---")
    print("支持: QQ邮箱/163邮箱/Gmail/企业邮箱等")
    print()
    name = input("  渠道名称 (如: 管理员邮件): ").strip()
    smtp_server = input("  SMTP服务器 (如: smtp.qq.com): ").strip() or "smtp.qq.com"
    smtp_port = input("  SMTP端口 (默认587): ").strip() or "587"
    username = input("  邮箱账号: ").strip()
    password = input("  邮箱授权码 (不是登录密码): ").strip()
    to_addrs = input("  接收邮箱 (多个用逗号分隔): ").strip()

    if not name or not username or not password or not to_addrs:
        print("  [错误] 请填写完整信息")
        return

    config = {
        "smtp_server": smtp_server,
        "smtp_port": int(smtp_port),
        "username": username,
        "password": password,
        "from_addr": username,
        "to_addrs": [e.strip() for e in to_addrs.split(",")],
    }
    result = alert_manager.add_channel(name=name, channel_type="email", config=config)
    if result.get("success"):
        print(f"  [成功] 邮件渠道已添加: {name}")
        send_test(result["channel_id"])
    else:
        print(f"  [失败] {result.get('error')}")


def add_webhook():
    """添加通用Webhook"""
    print("\n--- 配置通用Webhook ---")
    print("适用于自定义系统、Slack、Discord等支持Webhook的平台")
    print()
    name = input("  渠道名称: ").strip()
    webhook_url = input("  Webhook地址: ").strip()

    if not name or not webhook_url:
        print("  [错误] 名称和Webhook地址不能为空")
        return

    config = {"webhook_url": webhook_url}
    result = alert_manager.add_channel(name=name, channel_type="webhook", config=config)
    if result.get("success"):
        print(f"  [成功] Webhook渠道已添加: {name}")
        send_test(result["channel_id"])
    else:
        print(f"  [失败] {result.get('error')}")


def send_test(channel_id: str = None):
    """发送测试消息"""
    choice = input("  是否发送测试消息? (y/n): ").strip().lower()
    if choice != "y":
        return

    from tools.alert_manager import Alert
    test_alert = Alert(
        alert_id="test_" + os.urandom(4).hex(),
        title="测试告警 - AI Hacking Agent",
        message="这是一条测试消息，用于验证通知渠道是否正常工作。\n\n如果你收到这条消息，说明配置成功！",
        severity="info",
        category="test",
    )

    print("  正在发送测试消息...")
    result = alert_manager.notify_alert(test_alert)
    print(f"  通知结果: 成功 {result['success_count']} 个, 失败 {result['failed_count']} 个")
    for r in result["results"]:
        status = "成功" if r.get("success") else "失败"
        print(f"    - [{r.get('channel')}] {status}: {r.get('error') or r.get('message', '')}")


def show_stats():
    """显示统计信息"""
    stats = alert_manager.get_statistics()
    print("\n--- 告警系统统计 ---")
    print(f"  总告警数: {stats.get('total_alerts', 0)}")
    print(f"  启用渠道数: {stats.get('enabled_channels', 0)}")
    print(f"  成功通知数: {stats.get('successful_notifications', 0)}")
    print(f"  按严重级别: {stats.get('by_severity', {})}")
    print(f"  按状态: {stats.get('by_status', {})}")
    print()


def main():
    """在...中。

        Returns:
            操作结果。
    """
    print_banner()

    while True:
        print("--- 主菜单 ---")
        print("  1. 查看已配置渠道")
        print("  2. 添加钉钉机器人")
        print("  3. 添加飞书机器人")
        print("  4. 添加企业微信机器人")
        print("  5. 添加邮件通知")
        print("  6. 添加通用Webhook")
        print("  7. 发送测试消息")
        print("  8. 查看统计信息")
        print("  0. 退出")
        print()

        choice = input("请选择操作 (0-8): ").strip()

        if choice == "0":
            print("\n再见！")
            break
        elif choice == "1":
            print_channels()
        elif choice == "2":
            add_dingtalk()
        elif choice == "3":
            add_feishu()
        elif choice == "4":
            add_wecom()
        elif choice == "5":
            add_email()
        elif choice == "6":
            add_webhook()
        elif choice == "7":
            send_test()
        elif choice == "8":
            show_stats()
        else:
            print("  [错误] 无效选择，请重新输入")
            print()


if __name__ == "__main__":
    main()
