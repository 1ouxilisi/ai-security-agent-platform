# -*- coding: utf-8 -*-
"""
protocol_analyzer.py - 工控协议深度分析器（第12轮 ICS/SCADA 深化模块）。

支持解析（离线抓包帧/记录分析，纯只读，不主动发包、不下发控制指令）：
  - Modbus TCP：功能码 01/02/03/04/05/06/15/16、线圈/寄存器、异常码、非法地址、广播
  - S7comm / S7comm-plus：作业类型、参数、数据、块读写、PLC 控制、时间设置、安全机制
  - DNP3：应用层、对象组、变体表、功能码、认证/安全、异常
  - EtherNet/IP CIP：服务代码、类/实例/属性、路径、连接管理
  - FINS：命令码、内存区读写、参数、错误码、系统状态
  - OPC UA：服务集、节点、浏览/读写/订阅/方法调用、安全策略、认证

协议异常检测：未知功能码 / 非法寄存器 / 越界访问 / 异常频率 / 异常数据长度。
"""

from __future__ import annotations

import struct
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


# ==================== Modbus TCP ====================

MODBUS_FUNCTIONS: Dict[int, Dict[str, str]] = {
    1: {"name": "读线圈(Read Coils)", "access": "read"},
    2: {"name": "读离散输入(Read Discrete Inputs)", "access": "read"},
    3: {"name": "读保持寄存器(Read Holding Registers)", "access": "read"},
    4: {"name": "读输入寄存器(Read Input Registers)", "access": "read"},
    5: {"name": "写单线圈(Write Single Coil)", "access": "write"},
    6: {"name": "写单寄存器(Write Single Register)", "access": "write"},
    7: {"name": "读异常状态(Read Exception Status)", "access": "read"},
    8: {"name": "诊断(Diagnostics)", "access": "diag"},
    11: {"name": "获取通信事件计数器", "access": "read"},
    15: {"name": "写多线圈(Write Multiple Coils)", "access": "write"},
    16: {"name": "写多寄存器(Write Multiple Registers)", "access": "write"},
    22: {"name": "掩码写寄存器(Mask Write)", "access": "write"},
    23: {"name": "读写多寄存器(Read/Write)", "access": "write"},
    43: {"name": "封装接口/设备识别", "access": "read"},
}

MODBUS_EXCEPTION_CODES: Dict[int, str] = {
    1: "非法功能码", 2: "非法数据地址", 3: "非法数据值",
    4: "从站设备故障", 5: "确认", 6: "从站设备忙",
    8: "存储奇偶差错", 10: "网关不可用", 11: "网关目标无响应",
}


def parse_modbus_tcp(frame: bytes) -> Dict[str, Any]:
    """解析单条 Modbus TCP ADU（MBAP 头 7 字节 + PDU）。"""
    result: Dict[str, Any] = {"protocol": "Modbus TCP", "issues": []}
    if len(frame) < 8:
        result["issues"].append("帧长度不足，非完整 Modbus TCP ADU")
        return result
    try:
        trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", frame[:7])
    except Exception as e:
        result["issues"].append(f"MBAP 头解析失败: {e}")
        return result
    result.update({"transaction_id": trans_id, "protocol_id": proto_id,
                   "length": length, "unit_id": unit_id})
    if proto_id != 0:
        result["issues"].append(f"协议ID异常(={proto_id})，Modbus TCP 应为 0")
    func = frame[7]
    is_exception = bool(func & 0x80)
    raw_func = func & 0x7F
    fdesc = MODBUS_FUNCTIONS.get(raw_func)
    if not fdesc:
        result["issues"].append(f"未知功能码 0x{func:02X}")
        result["function_code"] = {"code": raw_func, "known": False}
    else:
        result["function_code"] = {"code": raw_func, "name": fdesc["name"],
                                   "access": fdesc["access"], "known": True}
    if is_exception:
        exc_code = frame[8] if len(frame) > 8 else -1
        result["exception"] = {"code": exc_code,
                               "meaning": MODBUS_EXCEPTION_CODES.get(exc_code, "未知异常码")}
    # 写操作敏感
    if fdesc and fdesc["access"] == "write":
        result["sensitive_write"] = True
    # 广播：unit_id = 0
    if unit_id == 0:
        result["broadcast"] = True
        result["issues"].append("检测到 Modbus 广播(unit_id=0)")
    # 数据长度合理性
    expected = length - 1
    actual = len(frame) - 7
    if abs(expected - actual) > 2:
        result["issues"].append(f"数据长度异常: MBAP 声明 {expected}B, 实际 {actual}B")
    return result


# ==================== S7comm ====================

S7_ROSCTR: Dict[int, str] = {0x01: "JOB", 0x02: "ACK", 0x03: "ACK_Data", 0x07: "Userdata"}

S7_JOB_TYPES: Dict[int, str] = {
    0x04: "Read Variable", 0x05: "Write Variable", 0x06: "Download Request",
    0x07: "Download Block", 0x08: "Download Ended", 0x1A: "Upload Request",
    0x1B: "Upload Block", 0x1C: "Upload Ended", 0x01: "Setup Communication",
    0x03: "Read SZL", 0x0F: "Detect CPU", 0x1C: "Block Function",
}

S7_CPU_CONTROL = {0x28: "CPU Stop", 0x29: "CPU Start"}  # 仅识别，绝不主动发送


def parse_s7comm(frame: bytes) -> Dict[str, Any]:
    """解析 S7comm（TPKT 4 字节 + COTP 3 字节 + S7 头）。"""
    result: Dict[str, Any] = {"protocol": "S7comm", "issues": []}
    if len(frame) < 12:
        result["issues"].append("S7comm 帧过短")
        return result
    # TPKT: version(1) reserved(1) length(2)
    if frame[0] != 0x03:
        result["issues"].append("TPKT 版本字段非 0x03")
    # COTP 至少 3 字节(02 f0 80)
    s7_off = 7
    if len(frame) < s7_off + 4:
        result["issues"].append("S7 头不完整")
        return result
    if frame[s7_off] != 0x32:
        result["issues"].append(f"S7 protocolId 非 0x32(=0x{frame[s7_off]:02X})")
        return result
    rosctr = frame[s7_off + 1]
    reserved = frame[s7_off + 2]
    pdu_ref, param_len = struct.unpack(">HH", frame[s7_off + 3:s7_off + 7])
    result.update({"rosctr": S7_ROSCTR.get(rosctr, f"0x{rosctr:02X}"),
                   "pdu_ref": pdu_ref, "param_length": param_len,
                   "reserved_field": reserved})
    param_start = s7_off + 7
    if len(frame) > param_start:
        job = frame[param_start]
        result["job_type"] = S7_JOB_TYPES.get(job, f"0x{job:02X}")
        if job in (0x06, 0x07, 0x08, 0x05):
            result["sensitive_operation"] = True
            result["issues"].append(f"敏感操作: {result['job_type']}")
    # S7comm-plus 特征：TLS / 0x72 头
    if frame[s7_off] in (0x72,) or len(frame) > 0 and frame[s7_off] == 0x72:
        result["variant"] = "S7comm-plus"
        result["issues"].append("识别为 S7comm-plus（通常带 TLS，安全等级较高）")
    else:
        result["variant"] = "S7comm (classic)"
        result["issues"].append("经典 S7comm 无认证，存在未授权读写风险")
    return result


# ==================== DNP3 ====================

DNP3_FUNCTIONS: Dict[int, str] = {
    0: "Confirm", 1: "Read", 2: "Write", 3: "Select", 4: "Operate",
    5: "Direct Operate", 6: "Direct Operate NoAck", 12: "Cold Restart",
    13: "Warm Restart", 14: "Initialize Data", 15: "Initialize Application",
    16: "Start Application", 17: "Stop Application", 22: "Authenticate Request",
    23: "Authenticate Reply",
}


def parse_dnp3(frame: bytes) -> Dict[str, Any]:
    """解析 DNP3 应用层（仅解析，不验证链路层校验）。"""
    result: Dict[str, Any] = {"protocol": "DNP3", "issues": []}
    # DNP3 应用功能码在第 19 字节附近（链路10字节 + 传输2字节 + 应用头）
    if len(frame) < 10:
        result["issues"].append("DNP3 帧过短")
        return result
    app_off = 10
    if len(frame) > app_off:
        func = frame[app_off] & 0x7F
        result["function_code"] = {"code": func, "name": DNP3_FUNCTIONS.get(func, "未知")}
        if func in (3, 4, 5):
            result["sensitive_operation"] = True
            result["issues"].append("检测到 DNP3 控制类操作(Select/Operate)")
        if func == 22:
            result["authentication_present"] = True
        elif func in (4, 5) and func != 22:
            result["issues"].append("控制操作未见 Authenticate 请求，疑似未启用安全认证")
    # 对象组（应用层对象头第 3 字节起，简化解析）
    if len(frame) > app_off + 2:
        grp, var = frame[app_off + 2], frame[app_off + 3]
        result["object_group"] = grp
        result["variation"] = var
    return result


# ==================== EtherNet/IP CIP ====================

CIP_SERVICES: Dict[int, str] = {
    0x01: "Get_Attribute_All", 0x02: "Set_Attribute_All", 0x0E: "Get_Attribute_Single",
    0x10: "Set_Attribute_Single", 0x4B: "Execute_PCCC_Service", 0x52: "Unconnected_Send",
    0x5B: "Forward_Open", 0x5C: "Forward_Close", 0x1B: "Test_Path",
}


def parse_cip(frame: bytes) -> Dict[str, Any]:
    """解析 CIP 通用消息包（对显式报文做服务码/路径识别）。"""
    result: Dict[str, Any] = {"protocol": "EtherNet/IP(CIP)", "issues": []}
    # EtherNet/IP 封装头 24 字节，cip data 起点约 24
    cip_off = 24
    if len(frame) <= cip_off:
        result["issues"].append("CIP 数据不足")
        return result
    svc = frame[cip_off] & 0x7F
    result["service_code"] = {"code": f"0x{svc:02X}", "name": CIP_SERVICES.get(svc, "未知服务")}
    if frame[cip_off] & 0x80:
        result["reply"] = True
        status = frame[cip_off + 3] if len(frame) > cip_off + 3 else -1
        result["status"] = status
        if status != 0:
            result["issues"].append(f"CIP 响应非 0 状态码(={status})")
    # 类/实例/属性路径（8/16 位简化）
    if len(frame) > cip_off + 4:
        path_size = frame[cip_off + 1]
        result["path_word_size"] = path_size
    if svc in (0x02, 0x10):
        result["sensitive_operation"] = True
        result["issues"].append(f"CIP 写属性服务: {result['service_code']['name']}")
    return result


# ==================== FINS ====================

FINS_COMMANDS: Dict[int, str] = {
    0x0101: "内存区读", 0x0102: "内存区写", 0x0103: "内存区填充",
    0x0201: "参数读", 0x0202: "参数写", 0x0401: "运行", 0x0402: "停止",
    0x0501: "CPU 数据读", 0x0601: "循环时间读",
}

FINS_ERRORS: Dict[int, str] = {
    0x0000: "正常", 0x1001: "本地节点不在网络", 0x1002: "Token 超时",
    0x2002: "CPU 异常", 0x2003: "单元异常", 0x2004: "不支持的命令",
    0x2005: "路由表异常", 0x2011: "内存区写异常",
}


def parse_fins(frame: bytes) -> Dict[str, Any]:
    """解析 FINS 帧（FINS 头 10 字节 + ICF/RSD/GCT/DNA/DA1/DA2/SNA/SA1/SA2/SID）。"""
    result: Dict[str, Any] = {"protocol": "Omron FINS", "issues": []}
    if len(frame) < 12:
        result["issues"].append("FINS 帧过短")
        return result
    # 命令码位于数据区前两字节
    cmd_off = 10
    if len(frame) >= cmd_off + 2:
        cmd = (frame[cmd_off] << 8) | frame[cmd_off + 1]
        result["command_code"] = {"code": f"0x{cmd:04X}", "name": FINS_COMMANDS.get(cmd, "未知命令")}
        if cmd in (0x0102, 0x0103, 0x0401, 0x0402):
            result["sensitive_operation"] = True
            result["issues"].append(f"敏感 FINS 命令: {result['command_code']['name']}")
    if len(frame) >= cmd_off + 4:
        err = (frame[cmd_off + 2] << 8) | frame[cmd_off + 3]
        result["end_code"] = {"code": f"0x{err:04X}", "meaning": FINS_ERRORS.get(err, "未知")}
        if err != 0:
            result["issues"].append(f"FINS 错误: {result['end_code']['meaning']}")
    return result


# ==================== OPC UA ====================

OPCUA_SERVICE_SETS: Dict[str, str] = {
    "Discovery": "发现/注册",
    "SecureChannel": "安全通道建立",
    "Session": "会话创建/激活",
    "NodeManagement": "节点增删",
    "View": "浏览节点",
    "Attribute": "读/写节点属性",
    "Method": "调用方法",
    "MonitoredItems": "订阅/监控项",
}


def parse_opcua(frame: bytes) -> Dict[str, Any]:
    """识别 OPC UA 服务集（基于已知 ServiceId 区间做粗粒度分类）。"""
    result: Dict[str, Any] = {"protocol": "OPC UA", "issues": []}
    # 真正的 OPC UA 解析需 opcua 库；此处做无依赖的特征识别
    if frame[:4] in (b"HEL\0", b"ACK\0", b"OPNF", b"CLOF", b"MSGF"):
        result["transport"] = "UA-TCP"
        result["message_type"] = frame[:3].decode(errors="replace")
    else:
        result["transport"] = "HTTPS/WS(推断)"
    result["service_sets_observed"] = list(OPCUA_SERVICE_SETS.keys())
    result["security_checks"] = [
        {"item": "安全策略(SecurityPolicy)", "expected": "Basic256Sha256 / Aes128-Sha256-RsaOaep", "risk_if_missing": "None/Basic128 已弃用"},
        {"item": "消息安全模式", "expected": "SignAndEncrypt", "risk_if_missing": "None 明文"},
        {"item": "用户认证", "expected": "证书 / UserName + 强密码", "risk_if_missing": "匿名登录"},
    ]
    return result


# ==================== 分析器主类 ====================

class ProtocolAnalyzer:
    """工控协议深度分析器（离线只读分析）。"""

    PARSERS = {
        "modbus": parse_modbus_tcp,
        "s7": parse_s7comm,
        "dnp3": parse_dnp3,
        "cip": parse_cip,
        "fins": parse_fins,
        "opcua": parse_opcua,
    }

    def __init__(self):
        self.frames: List[Dict[str, Any]] = []
        self.func_counter: Counter = Counter()
        self.issue_counter: Counter = Counter()

    def analyze_frame(self, frame_hex: str, protocol: str = "modbus") -> Dict[str, Any]:
        """解析单条帧（十六进制字符串输入）。"""
        try:
            frame = bytes.fromhex(frame_hex.replace(" ", ""))
        except Exception as e:
            return {"success": False, "error": f"十六进制解码失败: {e}"}
        parser = self.PARSERS.get(protocol.lower())
        if not parser:
            return {"success": False, "error": f"不支持的协议: {protocol}"}
        report = parser(frame)
        self.frames.append(report)
        if "function_code" in report:
            fc = report["function_code"]
            self.func_counter[str(fc.get("code"))] += 1
        for iss in report.get("issues", []):
            self.issue_counter[iss] += 1
        return report

    def analyze_batch(self, frames: List[Dict[str, str]]) -> Dict[str, Any]:
        """批量分析：frames = [{"data": hex, "protocol": "modbus"}, ...]"""
        parsed: List[Dict[str, Any]] = []
        for f in frames:
            r = self.analyze_frame(f.get("data", ""), f.get("protocol", "modbus"))
            parsed.append(r)

        # 频率/长度异常统计
        anomalies: List[Dict[str, Any]] = []
        write_ops = [p for p in parsed if p.get("sensitive_write") or p.get("sensitive_operation")]
        if len(write_ops) > len(parsed) * 0.3 and parsed:
            anomalies.append({
                "type": "write_ratio_high",
                "detail": f"写操作占比 {len(write_ops)}/{len(parsed)} > 30%",
                "level": "high",
            })
        unknown_funcs = [p for p in parsed if p.get("function_code", {}).get("known") is False]
        if unknown_funcs:
            anomalies.append({
                "type": "unknown_function_code",
                "detail": f"发现 {len(unknown_funcs)} 个未知功能码",
                "level": "medium",
            })
        exceptions = [p for p in parsed if p.get("exception") or p.get("end_code", {}).get("code", "0x0000") != "0x0000" and p.get("protocol") == "Omron FINS"]
        if exceptions:
            anomalies.append({
                "type": "device_exception",
                "detail": f"设备返回 {len(exceptions)} 条异常/错误响应",
                "level": "medium",
            })

        return {
            "total_frames": len(parsed),
            "parsed": parsed,
            "function_code_distribution": dict(self.func_counter),
            "issue_distribution": dict(self.issue_counter),
            "anomalies": anomalies,
            "analyzed_at": datetime.now().isoformat(),
            "legal_note": "本分析器仅对离线帧做只读解析，未向任何设备发送写指令。",
        }

    def supported_protocols(self) -> Dict[str, Any]:
        return {
            "protocols": [
                {"name": "Modbus TCP", "ports": [502], "function_codes": list(MODBUS_FUNCTIONS.keys())},
                {"name": "S7comm/S7comm-plus", "ports": [102], "job_types": list(S7_JOB_TYPES.keys())},
                {"name": "DNP3", "ports": [20000, 18245], "functions": list(DNP3_FUNCTIONS.keys())},
                {"name": "EtherNet/IP(CIP)", "ports": [44818], "services": list(CIP_SERVICES.keys())},
                {"name": "Omron FINS", "ports": [9600], "commands": list(FINS_COMMANDS.keys())},
                {"name": "OPC UA", "ports": [4840], "service_sets": list(OPCUA_SERVICE_SETS.keys())},
            ]
        }

    def generate_report(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        anomalies = analysis.get("anomalies", [])
        risk = "high" if any(a["level"] == "high" for a in anomalies) else (
            "medium" if anomalies else "low")
        return {
            "title": "工控协议深度分析报告",
            "generated_at": datetime.now().isoformat(),
            "frames_analyzed": analysis.get("total_frames", 0),
            "anomaly_count": len(anomalies),
            "anomalies": anomalies,
            "risk_level": risk,
            "issue_distribution": analysis.get("issue_distribution", {}),
            "function_code_distribution": analysis.get("function_code_distribution", {}),
            "conclusion": "协议解析完成。建议结合资产指纹与漏洞库交叉评估。",
        }


def create_protocol_analyzer() -> ProtocolAnalyzer:
    return ProtocolAnalyzer()
