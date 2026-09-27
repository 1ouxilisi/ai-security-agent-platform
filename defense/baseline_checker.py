# -*- coding: utf-8 -*-
"""
安全配置基线检查器（Baseline Checker）—— 模拟配置合规检查

覆盖四大类别，每类 >= 5 个检查项：
    - web       Web 服务器（HTTPS / 安全响应头 / 目录列表 / 默认页 / Server 头 / HTTP 方法）
    - os        操作系统（密码策略 / 账户锁定 / 防火墙 / 不必要服务 / SSH / 文件权限）
    - database  数据库（默认密码 / 远程访问 / 审计 / 权限最小化 / 默认库 / 版本补丁）
    - container 容器（特权容器 / 镜像漏洞 / 资源限制 / 网络隔离 / 只读根FS / 敏感挂载）

每个检查项含：check_id, category, name, check_method, risk_level, remediation,
compliance_refs（CIS Benchmark / 等保2.0）。

检查结果：passed / failed / warning。纯配置字典比对，不真实改动系统。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

try:
    from utils.logger import log  # type: ignore
except Exception:  # pragma: no cover
    import logging

    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("baseline_checker")


class BaselineChecker:
    """安全配置基线检查。所有检查基于传入的 config_dict 做模拟判定。"""

    def __init__(self):
        self.results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # 结果辅助
    # ------------------------------------------------------------------ #
    @staticmethod
    def _rec(check_id, category, name, risk_level, passed, detail, remediation, refs,
             status="passed"):
        return {
            "check_id": check_id,
            "category": category,
            "name": name,
            "risk_level": risk_level,
            "status": status,            # passed / failed / warning
            "passed": bool(passed),
            "detail": detail,
            "remediation": remediation,
            "compliance_refs": refs,
        }

    # ------------------------------------------------------------------ #
    # Web 服务器检查
    # ------------------------------------------------------------------ #
    def check_web_server(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        c = config or {}
        out = []

        https_redirect = c.get("https_redirect", False)
        out.append(self._rec(
            "WEB-001", "web", "强制 HTTPS / HTTP 跳转 HTTPS", "high",
            https_redirect,
            f"HTTP 是否自动跳转 HTTPS: {https_redirect}",
            "配置 HTTP 80 端口 301/308 跳转到 HTTPS，启用 TLS1.2+。",
            ["CIS 3.1", "等保2.0 8.1.4.1"]))

        hsts = c.get("hsts_enabled", False)
        out.append(self._rec(
            "WEB-002", "web", "启用 HSTS 响应头", "high",
            hsts, f"Strict-Transport-Security: {hsts}",
            "添加响应头 Strict-Transport-Security: max-age=31536000; includeSubDomains。",
            ["CIS 3.3", "等保2.0 8.1.4.2"]))

        security_headers = c.get("security_headers", {}) or {}
        need_headers = {
            "X-Frame-Options": security_headers.get("X-Frame-Options", "DENY"),
            "X-Content-Type-Options": security_headers.get("X-Content-Type-Options", "nosniff"),
            "Content-Security-Policy": security_headers.get("Content-Security-Policy", ""),
        }
        missing = [k for k, v in need_headers.items() if not v]
        out.append(self._rec(
            "WEB-003", "web", "关键安全响应头完整性", "medium",
            len(missing) == 0,
            f"缺失响应头: {missing if missing else '无'}",
            "补齐 X-Frame-Options=DENY、X-Content-Type-Options=nosniff、配置合理的 CSP。",
            ["CIS 3.4", "等保2.0 8.1.4.3"]))

        autoindex = c.get("directory_listing", True)
        out.append(self._rec(
            "WEB-004", "web", "禁用目录列表", "medium",
            not autoindex,
            f"目录列表(AutoIndex)当前为: {autoindex}",
            "关闭 Options Indexes / autoindex off，避免敏感目录被枚举。",
            ["CIS 3.5", "等保2.0 8.1.4.4"]))

        default_pages = c.get("default_pages_removed", False)
        out.append(self._rec(
            "WEB-005", "web", "移除默认欢迎/测试页面", "low",
            default_pages, f"默认页面已移除: {default_pages}",
            "删除 index.html(apache默认)、iisstart.htm 等默认欢迎页。",
            ["CIS 3.6", "等保2.0 8.1.4.5"]))

        server_hidden = c.get("server_tokens_hidden", False)
        out.append(self._rec(
            "WEB-006", "web", "隐藏 Server 版本头", "low",
            server_hidden, f"Server 头是否隐藏版本: {server_hidden}",
            "设置 server_tokens off / Header unset Server，避免版本泄露。",
            ["CIS 3.7", "等保2.0 8.1.4.6"]))

        unsafe_methods = c.get("allowed_methods", ["GET", "POST"])
        bad = set(unsafe_methods) & {"PUT", "DELETE", "TRACE", "CONNECT"}
        out.append(self._rec(
            "WEB-007", "web", "限制危险 HTTP 方法", "medium",
            len(bad) == 0,
            f"启用的危险方法: {sorted(bad) if bad else '无'}",
            "仅开放 GET/POST，禁用 TRACE/PUT/DELETE/CONNECT 等不需要的方法。",
            ["CIS 3.8", "等保2.0 8.1.4.7"]))

        self.results.extend(out)
        return out

    # ------------------------------------------------------------------ #
    # 操作系统检查
    # ------------------------------------------------------------------ #
    def check_os(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        c = config or {}
        out = []

        min_len = c.get("password_min_length", 0)
        out.append(self._rec(
            "OS-001", "os", "密码最小长度 >= 14", "high",
            min_len >= 14, f"当前最小密码长度: {min_len}",
            "设置 minlen=14（PASS_MIN_LEN / 组策略）。",
            ["CIS 5.2.1", "等保2.0 7.1.1.1"]))

        complexity = c.get("password_complexity", False)
        out.append(self._rec(
            "OS-002", "os", "密码复杂度（多类字符）", "high",
            complexity, f"复杂度要求: {complexity}",
            "启用至少三类字符（大小写/数字/符号）组合要求。",
            ["CIS 5.2.2", "等保2.0 7.1.1.2"]))

        max_age = c.get("password_max_age", 999)
        out.append(self._rec(
            "OS-003", "os", "密码最长有效期 <= 90 天", "medium",
            0 < max_age <= 90, f"当前有效期: {max_age} 天",
            "设置 PASS_MAX_DAYS=90。",
            ["CIS 5.2.3", "等保2.0 7.1.1.3"]))

        lock = c.get("account_lock_threshold", 0)
        out.append(self._rec(
            "OS-004", "os", "账户锁定阈值 <= 5 次失败", "high",
            0 < lock <= 5, f"当前锁定阈值: {lock}",
            "配置失败 N 次后锁定账户（faillock / 组策略）。",
            ["CIS 5.3.2", "等保2.0 7.1.2.1"]))

        firewall = c.get("firewall_enabled", False)
        out.append(self._rec(
            "OS-005", "os", "防火墙已启用", "high",
            firewall, f"防火墙状态: {'启用' if firewall else '未启用'}",
            "启用 firewalld/ufw/Windows 防火墙，默认拒绝入站。",
            ["CIS 3.5.1", "等保2.0 8.1.3.1"]))

        ssh_cfg = c.get("ssh_config", {}) or {}
        no_root = ssh_cfg.get("permit_root_login", "yes") in ("no", False)
        no_pw = ssh_cfg.get("password_auth", "yes") in ("no", False)
        ssh_ok = no_root and no_pw
        out.append(self._rec(
            "OS-006", "os", "SSH 安全配置（禁root/禁密码）", "high",
            ssh_ok,
            f"PermitRootLogin={ssh_cfg.get('permit_root_login')}, "
            f"PasswordAuthentication={ssh_cfg.get('password_auth')}",
            "设置 PermitRootLogin no、PasswordAuthentication no，改用密钥登录并改默认端口。",
            ["CIS 5.2.10", "等保2.0 7.1.4.1"]))

        unused_svc = c.get("unused_services_disabled", False)
        out.append(self._rec(
            "OS-007", "os", "不必要服务已禁用", "medium",
            unused_svc, f"不必要服务禁用: {unused_svc}",
            "禁用 telnet/rsh/ftp 等不必要服务，减少攻击面。",
            ["CIS 2.2", "等保2.0 7.1.3.1"]))

        self.results.extend(out)
        return out

    # ------------------------------------------------------------------ #
    # 数据库检查
    # ------------------------------------------------------------------ #
    def check_database(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        c = config or {}
        out = []

        default_pw = c.get("default_password_changed", False)
        out.append(self._rec(
            "DB-001", "database", "默认/弱口令已修改", "high",
            default_pw, f"默认密码是否已改: {default_pw}",
            "修改 root/sa/admin 等默认账号口令，禁用空密码。",
            ["CIS 1.1", "等保2.0 7.1.4.2"]))

        remote = c.get("remote_access", True)
        out.append(self._rec(
            "DB-002", "database", "限制数据库远程访问", "high",
            not remote, f"允许远程访问: {remote}",
            "绑定监听 127.0.0.1 或白名单 IP，禁止 0.0.0.0 对外开放。",
            ["CIS 1.2", "等保2.0 8.1.3.2"]))

        audit = c.get("audit_log_enabled", False)
        out.append(self._rec(
            "DB-003", "database", "开启审计日志", "medium",
            audit, f"审计日志: {audit}",
            "开启数据库审计（general log / audit plugin），记录关键操作。",
            ["CIS 2.8", "等保2.0 7.1.5.1"]))

        least_priv = c.get("least_privilege", False)
        out.append(self._rec(
            "DB-004", "database", "应用账号权限最小化", "high",
            least_priv, f"权限最小化: {least_priv}",
            "应用账号仅授予所需库表权限，禁用 SUPER/FILE 等高危权限。",
            ["CIS 2.1", "等保2.0 7.1.4.3"]))

        default_db = c.get("default_db_removed", False)
        out.append(self._rec(
            "DB-005", "database", "移除默认测试数据库", "low",
            default_db, f"默认库(test)已移除: {default_db}",
            "删除 test 库及匿名账号。",
            ["CIS 1.3", "等保2.0 7.1.4.4"]))

        patched = c.get("patch_up_to_date", False)
        out.append(self._rec(
            "DB-006", "database", "数据库版本补丁最新", "medium",
            patched, f"补丁是否最新: {patched}",
            "升级到受支持的最新小版本，修复已知 CVE。",
            ["CIS 1.4", "等保2.0 7.1.5.2"]))

        self.results.extend(out)
        return out

    # ------------------------------------------------------------------ #
    # 容器检查
    # ------------------------------------------------------------------ #
    def check_container(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        c = config or {}
        out = []

        privileged = c.get("privileged", False)
        out.append(self._rec(
            "CT-001", "container", "禁止特权容器", "high",
            not privileged, f"特权模式(privileged): {privileged}",
            "移除 --privileged，按需用 cap-add 授予最小 capability。",
            ["CIS 5.1", "等保2.0 8.1.4.8"]))

        vuln_free = c.get("image_vulnerability_free", False)
        out.append(self._rec(
            "CT-002", "container", "镜像基础漏洞扫描通过", "high",
            vuln_free, f"镜像高危漏洞清零: {vuln_free}",
            "用 trivy/grype 扫描基础镜像，修复高危 CVE 后再上线。",
            ["CIS 4.1", "等保2.0 8.1.4.9"]))

        limits = c.get("resource_limits", {}) or {}
        has_cpu = "cpu" in limits or "cpus" in limits
        has_mem = "memory" in limits
        out.append(self._rec(
            "CT-003", "container", "配置 CPU/内存资源限制", "medium",
            has_cpu and has_mem,
            f"cpu限制={has_cpu}, 内存限制={has_mem}",
            "设置 --cpus 与 --memory，防止单容器耗尽节点资源。",
            ["CIS 5.2", "等保2.0 8.1.4.10"]))

        net_iso = c.get("network_isolated", False)
        out.append(self._rec(
            "CT-004", "container", "容器网络隔离", "medium",
            net_iso, f"网络隔离: {net_iso}",
            "使用自定义 bridge/overlay 网络，避免默认 bridge 互通。",
            ["CIS 6.1", "等保2.0 8.1.4.11"]))

        ro_root = c.get("readonly_rootfs", False)
        out.append(self._rec(
            "CT-005", "container", "只读根文件系统", "medium",
            ro_root, f"只读根FS: {ro_root}",
            "配置 --read-only，挂载临时可写目录，防运行时篡改。",
            ["CIS 5.3", "等保2.0 8.1.4.12"]))

        secret_mount = c.get("mounts_separated", False)
        out.append(self._rec(
            "CT-006", "container", "避免挂载宿主机敏感目录", "high",
            secret_mount,
            f"敏感信息(/)挂载宿主: {not secret_mount}",
            "禁止挂载 /var/run/docker.sock、/etc、宿主机密钥目录。",
            ["CIS 7.1", "等保2.0 8.1.4.13"]))

        self.results.extend(out)
        return out

    # ------------------------------------------------------------------ #
    # 调度
    # ------------------------------------------------------------------ #
    def run_check(self, category: Optional[str] = None,
                  configs: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        执行基线检查。configs: {web:{...}, os:{...}, database:{...}, container:{...}}
        未提供的类别使用空配置（会全部判为不通过，用于演示）。
        """
        configs = configs or {}
        dispatch = {
            "web": self.check_web_server,
            "os": self.check_os,
            "database": self.check_database,
            "container": self.check_container,
        }
        self.results = []
        cats = [category] if category else list(dispatch.keys())
        for cat in cats:
            fn = dispatch.get(cat)
            if fn:
                fn(configs.get(cat, {}))
        return self.generate_report()

    def generate_report(self) -> Dict[str, Any]:
        total = len(self.results)
        passed = sum(1 for r in self.results if r["passed"])
        failed = total - passed
        by_cat: Dict[str, Dict[str, int]] = {}
        for r in self.results:
            bc = by_cat.setdefault(r["category"], {"total": 0, "passed": 0, "failed": 0})
            bc["total"] += 1
            if r["passed"]:
                bc["passed"] += 1
            else:
                bc["failed"] += 1
        return {
            "generated_at": datetime.now().isoformat(),
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": round(passed / total, 4) if total else 0,
            "by_category": by_cat,
            "checks": self.results,
        }


if __name__ == "__main__":
    bc = BaselineChecker()
    rep = bc.run_check(configs={
        "web": {"https_redirect": True, "hsts_enabled": True,
                "security_headers": {"X-Frame-Options": "DENY"}},
        "os": {"password_min_length": 16, "firewall_enabled": True},
    })
    print(f"通过 {rep['passed']}/{rep['total_checks']}")
