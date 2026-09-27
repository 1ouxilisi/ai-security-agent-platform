"""
auth_integrationAPI服务模块，提供相关REST API接口和Web服务功能。

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
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.auth_manager import auth_manager

# 认证方案
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
jwt_bearer = HTTPBearer(auto_error=False)

# 是否启用认证（默认启用，可通过环境变量关闭）
AUTH_ENABLED = os.getenv("API_AUTH_ENABLED", "true").lower() == "true"

# 管理员白名单API密钥（应急使用，可通过环境变量设置）
EMERGENCY_ADMIN_KEY = os.getenv("EMERGENCY_ADMIN_KEY", "")


async def verify_auth(
    api_key: Optional[str] = Depends(api_key_header),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(jwt_bearer),
) -> dict:
    """
    统一认证依赖
    支持两种方式：
    1. X-API-Key 请求头（用户API密钥）
    2. Authorization: Bearer <JWT Token>（登录后获取）
    返回用户信息字典
    """
    if not AUTH_ENABLED:
        return {"user_id": "anonymous", "username": "anonymous", "role": "admin", "auth_type": "disabled"}

    # 方式1：JWT Bearer Token
    if credentials and credentials.credentials:
        token = credentials.credentials
        result = auth_manager.verify_token(token)
        if result.get("valid"):
            return {
                "user_id": result.get("user_id"),
                "username": result.get("username"),
                "role": result.get("role", "user"),
                "auth_type": "jwt",
                "token": token,
            }
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效或过期的JWT Token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 方式2：X-API-Key
    if api_key:
        # 应急管理员密钥
        if EMERGENCY_ADMIN_KEY and api_key == EMERGENCY_ADMIN_KEY:
            return {
                "user_id": "emergency_admin",
                "username": "emergency_admin",
                "role": "admin",
                "auth_type": "emergency_key",
            }

        # 用户API密钥验证
        result = auth_manager.validate_api_key(api_key)
        if result.get("valid"):
            return {
                "user_id": result.get("user_id"),
                "username": result.get("username"),
                "role": result.get("role", "user"),
                "auth_type": "api_key",
                "api_key": api_key,
            }
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的API密钥，请在请求头中添加 X-API-Key 或使用 Bearer Token",
        )

    # 没有提供任何认证信息
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="未提供认证信息，请使用 X-API-Key 请求头或 Authorization: Bearer <Token>",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_admin(current_user: dict = Depends(verify_auth)) -> dict:
    """管理员权限依赖"""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="需要管理员权限",
        )
    return current_user


async def get_current_user_optional(
    api_key: Optional[str] = Depends(api_key_header),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(jwt_bearer),
) -> Optional[dict]:
    """可选认证（不强制，有则返回用户信息，无则返回None）"""
    if not AUTH_ENABLED:
        return {"user_id": "anonymous", "username": "anonymous", "role": "admin"}

    try:
        return await verify_auth(api_key=api_key, credentials=credentials)
    except HTTPException:
        return None
