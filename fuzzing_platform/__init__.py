#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fuzzing_platform — 第27轮升级方向2：安全 Fuzzing 与模糊测试平台。

包含 7 大核心模块：
    - protocol_fuzzer    协议 Fuzzing（HTTP/HTTPS/FTP/SMTP/POP3/IMAP/DNS/Telnet/SSH/
                          SMB/RDP/MySQL/PostgreSQL/Redis/MongoDB/MQTT/CoAP/Modbus/S7）
    - file_fuzzer        文件格式 Fuzzing（PDF/Office/图片/视频/音频/压缩/可执行/字体等）
    - api_fuzzer         API Fuzzing（端点发现/参数变异/漏洞检测）
    - browser_fuzzer     浏览器 Fuzzing（HTML/CSS/JS/DOM/WebGL/WASM）
    - kernel_fuzzer      内核 Fuzzing（系统调用序列/状态变异/崩溃检测）
    - fuzzing_manager    Fuzzing 管理平台（项目/任务/结果/覆盖率/性能/报告）
    - fuzzing_dashboard  Fuzzing 控制台数据聚合层

设计定位：全部内存字典模拟，不建数据库表；协议/文件/API/浏览器/内核用例可真实生成，
变异算法（位翻转/字节翻转/算术/块变异/模板/语法/状态/覆盖率引导/遗传/模拟退火）真实执行。
"""

from __future__ import annotations

__version__ = "27.2.0"
__all__ = [
    "protocol_fuzzer",
    "file_fuzzer",
    "api_fuzzer",
    "browser_fuzzer",
    "kernel_fuzzer",
    "fuzzing_manager",
    "fuzzing_dashboard",
]
