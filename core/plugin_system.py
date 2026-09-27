#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
插件系统
Plugin System

功能：插件管理、自定义扫描器、工具集成、插件市场、热加载
"""

import os
import sys
import json
import time
import uuid
import importlib
import importlib.util
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List, Callable, Type
from enum import Enum
from abc import ABC, abstractmethod
from loguru import logger


class PluginType(str, Enum):
    """插件类型"""
    SCANNER = "scanner"              # 扫描器插件
    EXPLOIT = "exploit"              # 利用插件
    PAYLOAD = "payload"              # 载荷插件
    REPORTER = "reporter"            # 报告插件
    ANALYZER = "analyzer"            # 分析器插件
    INTEGRATION = "integration"      # 工具集成插件
    CUSTOM = "custom"                # 自定义插件


class PluginStatus(str, Enum):
    """插件状态"""
    ENABLED = "enabled"
    DISABLED = "disabled"
    ERROR = "error"
    LOADING = "loading"


@dataclass
class PluginInfo:
    """插件信息"""
    plugin_id: str
    name: str
    description: str
    version: str
    author: str
    plugin_type: PluginType
    status: PluginStatus = PluginStatus.DISABLED
    entry_point: str = ""           # 入口模块或文件
    dependencies: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    config_schema: Dict[str, Any] = field(default_factory=dict)
    default_config: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    is_builtin: bool = False
    load_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'plugin_id': self.plugin_id,
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'author': self.author,
            'plugin_type': self.plugin_type.value,
            'status': self.status.value,
            'entry_point': self.entry_point,
            'dependencies': self.dependencies,
            'tags': self.tags,
            'config_schema': self.config_schema,
            'default_config': self.default_config,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'is_builtin': self.is_builtin,
            'load_error': self.load_error,
        }


class BasePlugin(ABC):
    """插件基类"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logger.bind(plugin=self.__class__.__name__)

    @abstractmethod
    def run(self, target: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """执行插件"""
        pass

    def validate_config(self) -> bool:
        """验证配置"""
        return True

    def get_info(self) -> Dict[str, Any]:
        """获取插件信息"""
        return {
            'name': self.__class__.__name__,
            'version': getattr(self, 'version', '1.0.0'),
            'description': getattr(self, 'description', ''),
        }

    def cleanup(self):
        """清理资源"""
        pass


class ScannerPlugin(BasePlugin):
    """扫描器插件基类"""

    @abstractmethod
    def scan(self, target: str, ports: List[int] = None,
             params: Dict[str, Any] = None) -> Dict[str, Any]:
        """执行扫描"""
        pass

    def run(self, target: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        params = params or {}
        return self.scan(target, params.get('ports'), params)


class ExploitPlugin(BasePlugin):
    """利用插件基类"""

    @abstractmethod
    def exploit(self, target: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """执行利用"""
        pass

    def run(self, target: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        return self.exploit(target, params)


class AnalyzerPlugin(BasePlugin):
    """分析器插件基类"""

    @abstractmethod
    def analyze(self, data: Any, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """执行分析"""
        pass

    def run(self, target: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        return self.analyze(target, params)


# ============== 内置插件实现 ==============

class PortScannerPlugin(ScannerPlugin):
    """端口扫描器插件"""
    version = "1.0.0"
    description = "基础TCP端口扫描器"

    def scan(self, target: str, ports: List[int] = None,
             params: Dict[str, Any] = None) -> Dict[str, Any]:
        import socket
        params = params or {}
        timeout = params.get('timeout', 1.0)
        ports = ports or [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]

        open_ports = []
        start_time = time.time()

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append({
                        'port': port,
                        'state': 'open',
                        'service': self._get_service_name(port),
                    })
                sock.close()
            except Exception:
                pass

        return {
            'target': target,
            'open_ports': open_ports,
            'total_scanned': len(ports),
            'open_count': len(open_ports),
            'duration': round(time.time() - start_time, 2),
        }

    def _get_service_name(self, port: int) -> str:
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
            8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
        }
        return services.get(port, 'Unknown')


class DirectoryScannerPlugin(ScannerPlugin):
    """目录扫描器插件"""
    version = "1.0.0"
    description = "Web目录/文件扫描器"

    def scan(self, target: str, ports: List[int] = None,
             params: Dict[str, Any] = None) -> Dict[str, Any]:
        import requests
        params = params or {}
        wordlist = params.get('wordlist', ['admin', 'login', 'wp-admin', 'phpmyadmin',
                                            'backup', 'config', 'test', 'api', 'upload',
                                            'images', 'css', 'js', 'robots.txt', 'sitemap.xml'])
        extensions = params.get('extensions', ['', '.php', '.html', '.txt', '.bak', '.zip'])
        timeout = params.get('timeout', 5.0)

        found = []
        start_time = time.time()
        base_url = target if target.startswith('http') else f'http://{target}'

        for path in wordlist:
            for ext in extensions:
                url = f"{base_url}/{path}{ext}"
                try:
                    response = requests.get(url, timeout=timeout, allow_redirects=False)
                    if response.status_code in [200, 301, 302, 403]:
                        found.append({
                            'url': url,
                            'status_code': response.status_code,
                            'size': len(response.content),
                        })
                except Exception:
                    pass

        return {
            'target': base_url,
            'found': found,
            'total_tested': len(wordlist) * len(extensions),
            'found_count': len(found),
            'duration': round(time.time() - start_time, 2),
        }


class SubdomainScannerPlugin(ScannerPlugin):
    """子域名扫描器插件"""
    version = "1.0.0"
    description = "子域名枚举扫描器"

    def scan(self, target: str, ports: List[int] = None,
             params: Dict[str, Any] = None) -> Dict[str, Any]:
        import socket
        params = params or {}
        wordlist = params.get('wordlist', ['www', 'mail', 'ftp', 'localhost', 'webmail',
                                            'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
                                            'cpanel', 'whm', 'autodiscover', 'autoconfig',
                                            'm', 'imap', 'test', 'ns', 'blog', 'pop3',
                                            'dev', 'www2', 'admin', 'forum', 'new', 'mysql',
                                            'remote', 'db', 'vpn', 'ns3', 'mail2', 'secure',
                                            'bbs', 'www1', 'data', 'web', 'dns1', 'dns2'])

        found = []
        start_time = time.time()
        domain = target.replace('http://', '').replace('https://', '').split('/')[0]

        for sub in wordlist:
            subdomain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                found.append({
                    'subdomain': subdomain,
                    'ip': ip,
                })
            except socket.gaierror:
                pass

        return {
            'target': domain,
            'found': found,
            'total_tested': len(wordlist),
            'found_count': len(found),
            'duration': round(time.time() - start_time, 2),
        }


class VulnerabilityAnalyzerPlugin(AnalyzerPlugin):
    """漏洞分析器插件"""
    version = "1.0.0"
    description = "基于服务/版本的漏洞分析器"

    def analyze(self, data: Any, params: Dict[str, Any] = None) -> Dict[str, Any]:
        params = params or {}
        vulnerabilities = []

        # 简单的基于规则的漏洞分析
        if isinstance(data, dict):
            services = data.get('services', [])
            for service in services:
                port = service.get('port')
                name = service.get('service', '').lower()
                version = service.get('version', '')

                # 检查已知漏洞
                if 'ssh' in name:
                    if version and any(v in version for v in ['1.', '2.0', '2.1', '2.2']):
                        vulnerabilities.append({
                            'name': 'SSH弱加密算法',
                            'severity': 'medium',
                            'port': port,
                            'description': f'SSH版本 {version} 可能存在弱加密算法',
                            'remediation': '升级到最新版本，禁用弱算法',
                        })

                if 'ftp' in name:
                    vulnerabilities.append({
                        'name': 'FTP明文传输',
                        'severity': 'low',
                        'port': port,
                        'description': 'FTP使用明文传输凭证',
                        'remediation': '使用SFTP或FTPS',
                    })

                if 'telnet' in name:
                    vulnerabilities.append({
                        'name': 'Telnet明文传输',
                        'severity': 'high',
                        'port': port,
                        'description': 'Telnet使用明文传输，易被窃听',
                        'remediation': '使用SSH替代',
                    })

                if 'smb' in name or port == 445:
                    vulnerabilities.append({
                        'name': 'SMB服务暴露',
                        'severity': 'medium',
                        'port': port,
                        'description': 'SMB服务可能存在远程代码执行风险',
                        'remediation': '限制访问，安装最新补丁',
                    })

        return {
            'vulnerabilities': vulnerabilities,
            'total_found': len(vulnerabilities),
            'risk_level': 'high' if any(v['severity'] == 'high' for v in vulnerabilities) else 'medium',
        }


class JSONReporterPlugin(BasePlugin):
    """JSON报告插件"""
    version = "1.0.0"
    description = "生成JSON格式扫描报告"

    def run(self, target: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        params = params or {}
        report = {
            'report_type': 'json',
            'target': target,
            'generated_at': time.time(),
            'summary': params.get('summary', {}),
            'vulnerabilities': params.get('vulnerabilities', []),
            'findings': params.get('findings', []),
        }
        return report


# ============== 插件管理器 ==============

class PluginManager:
    """插件管理器"""

    def __init__(self, plugins_dir: str = "plugins"):
        self.plugins_dir = plugins_dir
        self._plugins: Dict[str, PluginInfo] = {}
        self._instances: Dict[str, BasePlugin] = {}
        self._plugin_classes: Dict[str, Type[BasePlugin]] = {}

        os.makedirs(plugins_dir, exist_ok=True)

        self._register_builtin_plugins()
        self._load_custom_plugins()

        logger.info(f"插件管理器初始化完成: {len(self._plugins)}个插件")

    def _register_builtin_plugins(self):
        """注册内置插件"""
        builtin_plugins = [
            (PluginInfo(
                plugin_id="builtin_port_scanner",
                name="端口扫描器",
                description="基础TCP端口扫描器，支持自定义端口列表",
                version="1.0.0",
                author="AI Hacking Agent",
                plugin_type=PluginType.SCANNER,
                status=PluginStatus.ENABLED,
                entry_point="PortScannerPlugin",
                tags=["port", "scan", "tcp", "network"],
                is_builtin=True,
            ), PortScannerPlugin),
            (PluginInfo(
                plugin_id="builtin_directory_scanner",
                name="目录扫描器",
                description="Web目录/文件扫描器，支持自定义字典和扩展名",
                version="1.0.0",
                author="AI Hacking Agent",
                plugin_type=PluginType.SCANNER,
                status=PluginStatus.ENABLED,
                entry_point="DirectoryScannerPlugin",
                tags=["directory", "scan", "web", "brute-force"],
                is_builtin=True,
            ), DirectoryScannerPlugin),
            (PluginInfo(
                plugin_id="builtin_subdomain_scanner",
                name="子域名扫描器",
                description="子域名枚举扫描器，基于字典的DNS枚举",
                version="1.0.0",
                author="AI Hacking Agent",
                plugin_type=PluginType.SCANNER,
                status=PluginStatus.ENABLED,
                entry_point="SubdomainScannerPlugin",
                tags=["subdomain", "dns", "scan", "recon"],
                is_builtin=True,
            ), SubdomainScannerPlugin),
            (PluginInfo(
                plugin_id="builtin_vulnerability_analyzer",
                name="漏洞分析器",
                description="基于服务/版本的漏洞分析器，规则匹配",
                version="1.0.0",
                author="AI Hacking Agent",
                plugin_type=PluginType.ANALYZER,
                status=PluginStatus.ENABLED,
                entry_point="VulnerabilityAnalyzerPlugin",
                tags=["vulnerability", "analyze", "rule", "service"],
                is_builtin=True,
            ), VulnerabilityAnalyzerPlugin),
            (PluginInfo(
                plugin_id="builtin_json_reporter",
                name="JSON报告生成器",
                description="生成JSON格式的扫描/测试报告",
                version="1.0.0",
                author="AI Hacking Agent",
                plugin_type=PluginType.REPORTER,
                status=PluginStatus.ENABLED,
                entry_point="JSONReporterPlugin",
                tags=["report", "json", "export"],
                is_builtin=True,
            ), JSONReporterPlugin),
        ]

        for info, plugin_class in builtin_plugins:
            self._plugins[info.plugin_id] = info
            self._plugin_classes[info.plugin_id] = plugin_class

    def _load_custom_plugins(self):
        """加载自定义插件"""
        try:
            for filename in os.listdir(self.plugins_dir):
                if filename.endswith('.py') and not filename.startswith('_'):
                    plugin_file = os.path.join(self.plugins_dir, filename)
                    try:
                        self._load_plugin_from_file(plugin_file)
                    except Exception as e:
                        logger.warning(f"加载插件失败 {filename}: {e}")
        except Exception as e:
            logger.warning(f"扫描插件目录失败: {e}")

    def _load_plugin_from_file(self, filepath: str):
        """从文件加载插件"""
        module_name = os.path.splitext(os.path.basename(filepath))[0]
        spec = importlib.util.spec_from_file_location(module_name, filepath)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            # 查找插件类
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and
                    issubclass(attr, BasePlugin) and
                    attr != BasePlugin and
                    attr not in [ScannerPlugin, ExploitPlugin, AnalyzerPlugin]):

                    plugin_id = f"custom_{module_name}_{attr_name.lower()}"
                    info = PluginInfo(
                        plugin_id=plugin_id,
                        name=getattr(attr, 'name', attr_name),
                        description=getattr(attr, 'description', ''),
                        version=getattr(attr, 'version', '1.0.0'),
                        author=getattr(attr, 'author', 'Custom'),
                        plugin_type=PluginType.CUSTOM,
                        status=PluginStatus.DISABLED,
                        entry_point=filepath,
                        is_builtin=False,
                    )
                    self._plugins[plugin_id] = info
                    self._plugin_classes[plugin_id] = attr
                    logger.info(f"加载自定义插件: {info.name} ({plugin_id})")

    def list_plugins(self, plugin_type: PluginType = None,
                     status: PluginStatus = None) -> List[PluginInfo]:
        """列出插件"""
        plugins = list(self._plugins.values())
        if plugin_type:
            plugins = [p for p in plugins if p.plugin_type == plugin_type]
        if status:
            plugins = [p for p in plugins if p.status == status]
        return sorted(plugins, key=lambda p: p.name)

    def get_plugin(self, plugin_id: str) -> Optional[PluginInfo]:
        """获取插件信息"""
        return self._plugins.get(plugin_id)

    def enable_plugin(self, plugin_id: str) -> bool:
        """启用插件"""
        if plugin_id in self._plugins:
            self._plugins[plugin_id].status = PluginStatus.ENABLED
            logger.info(f"启用插件: {plugin_id}")
            return True
        return False

    def disable_plugin(self, plugin_id: str) -> bool:
        """禁用插件"""
        if plugin_id in self._plugins:
            self._plugins[plugin_id].status = PluginStatus.DISABLED
            # 卸载实例
            if plugin_id in self._instances:
                self._instances[plugin_id].cleanup()
                del self._instances[plugin_id]
            logger.info(f"禁用插件: {plugin_id}")
            return True
        return False

    def get_instance(self, plugin_id: str, config: Dict[str, Any] = None) -> Optional[BasePlugin]:
        """获取插件实例"""
        info = self._plugins.get(plugin_id)
        if not info or info.status != PluginStatus.ENABLED:
            return None

        if plugin_id not in self._instances:
            plugin_class = self._plugin_classes.get(plugin_id)
            if not plugin_class:
                return None
            try:
                instance = plugin_class(config or info.default_config)
                self._instances[plugin_id] = instance
            except Exception as e:
                info.status = PluginStatus.ERROR
                info.load_error = str(e)
                logger.error(f"插件实例化失败 {plugin_id}: {e}")
                return None

        return self._instances[plugin_id]

    def run_plugin(self, plugin_id: str, target: str,
                   params: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """运行插件"""
        instance = self.get_instance(plugin_id)
        if not instance:
            return None

        try:
            start_time = time.time()
            result = instance.run(target, params)
            duration = time.time() - start_time

            if isinstance(result, dict):
                result['_plugin_id'] = plugin_id
                result['_duration'] = round(duration, 3)
                result['_success'] = True

            return result
        except Exception as e:
            logger.error(f"插件运行失败 {plugin_id}: {e}")
            return {
                '_plugin_id': plugin_id,
                '_success': False,
                '_error': str(e),
            }

    def install_plugin(self, name: str, description: str, code: str,
                       plugin_type: PluginType = PluginType.CUSTOM) -> Optional[PluginInfo]:
        """安装自定义插件"""
        plugin_id = f"custom_{name.lower().replace(' ', '_')}_{uuid.uuid4().hex[:8]}"
        filename = f"{plugin_id}.py"
        filepath = os.path.join(self.plugins_dir, filename)

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(code)

            # 尝试加载
            self._load_plugin_from_file(filepath)

            # 查找刚安装的插件
            for pid, info in self._plugins.items():
                if info.entry_point == filepath:
                    logger.info(f"安装插件成功: {name} ({pid})")
                    return info

            return None
        except Exception as e:
            logger.error(f"安装插件失败: {e}")
            if os.path.exists(filepath):
                os.remove(filepath)
            return None

    def uninstall_plugin(self, plugin_id: str) -> bool:
        """卸载插件"""
        info = self._plugins.get(plugin_id)
        if not info or info.is_builtin:
            return False

        # 清理实例
        if plugin_id in self._instances:
            self._instances[plugin_id].cleanup()
            del self._instances[plugin_id]

        # 删除文件
        if info.entry_point and os.path.exists(info.entry_point):
            try:
                os.remove(info.entry_point)
            except Exception:
                pass

        del self._plugins[plugin_id]
        if plugin_id in self._plugin_classes:
            del self._plugin_classes[plugin_id]

        logger.info(f"卸载插件: {plugin_id}")
        return True

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        type_stats = {}
        for pt in PluginType:
            count = len([p for p in self._plugins.values() if p.plugin_type == pt])
            if count > 0:
                type_stats[pt.value] = count

        status_stats = {}
        for st in PluginStatus:
            count = len([p for p in self._plugins.values() if p.status == st])
            if count > 0:
                status_stats[st.value] = count

        return {
            'total_plugins': len(self._plugins),
            'enabled': len([p for p in self._plugins.values() if p.status == PluginStatus.ENABLED]),
            'disabled': len([p for p in self._plugins.values() if p.status == PluginStatus.DISABLED]),
            'builtin': len([p for p in self._plugins.values() if p.is_builtin]),
            'custom': len([p for p in self._plugins.values() if not p.is_builtin]),
            'type_stats': type_stats,
            'status_stats': status_stats,
            'loaded_instances': len(self._instances),
        }


# 全局插件管理器实例
_global_plugin_manager: Optional[PluginManager] = None


def get_plugin_manager() -> PluginManager:
    """获取全局插件管理器实例"""
    global _global_plugin_manager
    if _global_plugin_manager is None:
        _global_plugin_manager = PluginManager()
    return _global_plugin_manager
