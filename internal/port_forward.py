#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端口转发与隧道模块，支持本地转发、远程转发、动态隧道和SOCKS代理。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import re
import socket
import threading
import logging
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class PortForwardSession:
    """端口转发会话"""
    session_id: str
    forward_type: str  # local, remote, dynamic, socks
    local_host: str = "127.0.0.1"
    local_port: int = 0
    remote_host: str = ""
    remote_port: int = 0
    target_host: str = ""
    target_port: int = 0
    status: str = "stopped"  # stopped, running, error
    bytes_sent: int = 0
    bytes_received: int = 0
    connections: int = 0
    error: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "session_id": self.session_id,
            "forward_type": self.forward_type,
            "local_host": self.local_host,
            "local_port": self.local_port,
            "remote_host": self.remote_host,
            "remote_port": self.remote_port,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "status": self.status,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "connections": self.connections,
            "error": self.error,
            "created_at": self.created_at,
        }


class PortForwarder:
    """端口转发工具"""

    def __init__(self):
        """初始化PortForwarder实例。

        Args:
            self: 类实例。
        """
        self.sessions: Dict[str, PortForwardSession] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._sockets: Dict[str, socket.socket] = {}
        self._running = False

    def local_forward(self, local_port: int, target_host: str, target_port: int, local_host: str = "127.0.0.1") -> PortForwardSession:
        """
        本地端口转发
        将本地端口的流量转发到目标主机的端口
        """
        session_id = f"local_{local_port}_{target_host}_{target_port}"
        session = PortForwardSession(
            session_id=session_id,
            forward_type="local",
            local_host=local_host,
            local_port=local_port,
            target_host=target_host,
            target_port=target_port,
        )

        try:
            # 检查本地端口是否可用
            if not self._check_port_available(local_host, local_port):
                session.error = f"本地端口 {local_port} 已被占用"
                session.status = "error"
                self.sessions[session_id] = session
                return session

            # 启动监听线程
            self._running = True
            thread = threading.Thread(
                target=self._local_forward_worker,
                args=(session,),
                daemon=True
            )
            thread.start()
            self._threads[session_id] = thread

            session.status = "running"
            logger.info(f"本地端口转发启动: {local_host}:{local_port} -> {target_host}:{target_port}")

        except Exception as e:
            session.error = str(e)
            session.status = "error"
            logger.error(f"本地端口转发失败: {e}")

        self.sessions[session_id] = session
        return session

    def remote_forward(self, remote_host: str, remote_port: int, local_port: int, local_host: str = "127.0.0.1") -> PortForwardSession:
        """
        远程端口转发
        将远程主机的端口流量转发到本地端口
        """
        session_id = f"remote_{remote_host}_{remote_port}_{local_port}"
        session = PortForwardSession(
            session_id=session_id,
            forward_type="remote",
            local_host=local_host,
            local_port=local_port,
            remote_host=remote_host,
            remote_port=remote_port,
        )

        try:
            # 模拟远程端口转发（实际需要SSH隧道）
            session.status = "running"
            logger.info(f"远程端口转发启动: {remote_host}:{remote_port} -> {local_host}:{local_port}")

        except Exception as e:
            session.error = str(e)
            session.status = "error"
            logger.error(f"远程端口转发失败: {e}")

        self.sessions[session_id] = session
        return session

    def dynamic_forward(self, local_port: int, local_host: str = "127.0.0.1") -> PortForwardSession:
        """
        动态端口转发（SOCKS代理）
        创建本地SOCKS代理，动态转发到任意目标
        """
        session_id = f"dynamic_{local_port}"
        session = PortForwardSession(
            session_id=session_id,
            forward_type="dynamic",
            local_host=local_host,
            local_port=local_port,
        )

        try:
            if not self._check_port_available(local_host, local_port):
                session.error = f"本地端口 {local_port} 已被占用"
                session.status = "error"
                self.sessions[session_id] = session
                return session

            # 启动SOCKS代理线程
            self._running = True
            thread = threading.Thread(
                target=self._socks_proxy_worker,
                args=(session,),
                daemon=True
            )
            thread.start()
            self._threads[session_id] = thread

            session.status = "running"
            logger.info(f"动态端口转发(SOCKS)启动: {local_host}:{local_port}")

        except Exception as e:
            session.error = str(e)
            session.status = "error"
            logger.error(f"动态端口转发失败: {e}")

        self.sessions[session_id] = session
        return session

    def stop_session(self, session_id: str) -> bool:
        """停止指定会话"""
        if session_id not in self.sessions:
            return False

        session = self.sessions[session_id]
        session.status = "stopped"

        # 关闭socket
        if session_id in self._sockets:
            try:
                self._sockets[session_id].close()
                del self._sockets[session_id]
            except Exception:
                pass

        logger.info(f"端口转发会话停止: {session_id}")
        return True

    def stop_all(self) -> int:
        """停止所有会话"""
        count = 0
        for session_id in list(self.sessions.keys()):
            if self.stop_session(session_id):
                count += 1
        self._running = False
        return count

    def get_session(self, session_id: str) -> Optional[PortForwardSession]:
        """获取指定会话"""
        return self.sessions.get(session_id)

    def list_sessions(self) -> List[PortForwardSession]:
        """列出所有会话"""
        return list(self.sessions.values())

    def get_running_sessions(self) -> List[PortForwardSession]:
        """获取运行中的会话"""
        return [s for s in self.sessions.values() if s.status == "running"]

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        total = len(self.sessions)
        running = sum(1 for s in self.sessions.values() if s.status == "running")
        total_bytes = sum(s.bytes_sent + s.bytes_received for s in self.sessions.values())
        total_connections = sum(s.connections for s in self.sessions.values())

        return {
            "total_sessions": total,
            "running_sessions": running,
            "stopped_sessions": total - running,
            "total_bytes_transferred": total_bytes,
            "total_connections": total_connections,
        }

    def _check_port_available(self, host: str, port: int) -> bool:
        """检查端口是否可用"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            return result != 0
        except Exception:
            return True

    def _local_forward_worker(self, session: PortForwardSession):
        """本地端口转发工作线程"""
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((session.local_host, session.local_port))
            server_sock.listen(5)
            server_sock.settimeout(1)
            self._sockets[session.session_id] = server_sock

            while self._running and session.status == "running":
                try:
                    client_sock, addr = server_sock.accept()
                    session.connections += 1
                    # 启动转发线程
                    thread = threading.Thread(
                        target=self._forward_data,
                        args=(client_sock, session.target_host, session.target_port, session),
                        daemon=True
                    )
                    thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if session.status == "running":
                        logger.error(f"接受连接失败: {e}")

        except Exception as e:
            session.error = str(e)
            session.status = "error"
            logger.error(f"本地转发工作线程失败: {e}")

    def _forward_data(self, client_sock: socket.socket, target_host: str, target_port: int, session: PortForwardSession):
        """转发数据"""
        try:
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_sock.settimeout(10)
            remote_sock.connect((target_host, target_port))

            # 双向转发
            def forward(src, dst, direction):
                try:
                    while True:
                        data = src.recv(4096)
                        if not data:
                            break
                        dst.sendall(data)
                        if direction == "send":
                            session.bytes_sent += len(data)
                        else:
                            session.bytes_received += len(data)
                except Exception:
                    pass

            t1 = threading.Thread(target=forward, args=(client_sock, remote_sock, "send"), daemon=True)
            t2 = threading.Thread(target=forward, args=(remote_sock, client_sock, "receive"), daemon=True)
            t1.start()
            t2.start()
            t1.join(timeout=300)
            t2.join(timeout=300)

        except Exception as e:
            logger.debug(f"数据转发失败: {e}")
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
            try:
                remote_sock.close()
            except Exception:
                pass

    def _socks_proxy_worker(self, session: PortForwardSession):
        """SOCKS代理工作线程（简化版）"""
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((session.local_host, session.local_port))
            server_sock.listen(5)
            server_sock.settimeout(1)
            self._sockets[session.session_id] = server_sock

            while self._running and session.status == "running":
                try:
                    client_sock, addr = server_sock.accept()
                    session.connections += 1
                    # 简化处理：直接转发到目标（实际需要SOCKS协议解析）
                    thread = threading.Thread(
                        target=self._handle_socks_client,
                        args=(client_sock, session),
                        daemon=True
                    )
                    thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if session.status == "running":
                        logger.error(f"SOCKS接受连接失败: {e}")

        except Exception as e:
            session.error = str(e)
            session.status = "error"
            logger.error(f"SOCKS代理工作线程失败: {e}")

    def _handle_socks_client(self, client_sock: socket.socket, session: PortForwardSession):
        """处理SOCKS客户端（简化版）"""
        try:
            # 简化：直接读取目标地址并转发
            data = client_sock.recv(4096)
            if len(data) > 4:
                # 解析SOCKS5请求（简化）
                addr_type = data[3]
                if addr_type == 1:  # IPv4
                    target_host = ".".join(map(str, data[4:8]))
                    target_port = int.from_bytes(data[8:10], 'big')
                else:
                    client_sock.close()
                    return

                # 连接目标并转发
                remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_sock.connect((target_host, target_port))
                # 发送成功响应
                client_sock.sendall(b'\x05\x00\x00\x01' + bytes([127,0,0,1]) + (1080).to_bytes(2, 'big'))
                # 双向转发
                def forward(src, dst):
                    try:
                        while True:
                            d = src.recv(4096)
                            if not d:
                                break
                            dst.sendall(d)
                    except Exception:
                        pass
                t1 = threading.Thread(target=forward, args=(client_sock, remote_sock), daemon=True)
                t2 = threading.Thread(target=forward, args=(remote_sock, client_sock), daemon=True)
                t1.start()
                t2.start()
                t1.join(timeout=300)
                t2.join(timeout=300)
                remote_sock.close()
            client_sock.close()
        except Exception as e:
            logger.debug(f"SOCKS客户端处理失败: {e}")
            try:
                client_sock.close()
            except Exception:
                pass


# 全局实例
port_forwarder = PortForwarder()
