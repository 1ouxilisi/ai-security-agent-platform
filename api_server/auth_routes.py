"""
auth_routesAPI服务模块，提供相关REST API接口和Web服务功能。

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
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.auth_manager import auth_manager
from api_server.auth_integration import verify_auth, require_admin

router = APIRouter(prefix="/api/v1/auth", tags=["用户认证"])


# ==================== 请求模型 ====================

class RegisterRequest(BaseModel):
    """RegisterRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    username: str = Field(..., min_length=3, max_length=50, description="用户名")
    password: str = Field(..., min_length=8, max_length=128, description="密码（至少8位）")
    email: Optional[str] = Field(None, description="邮箱")


class LoginRequest(BaseModel):
    """LoginRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    username: str = Field(..., description="用户名")
    password: str = Field(..., description="密码")


class ChangePasswordRequest(BaseModel):
    """ChangePasswordRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    old_password: str = Field(..., description="旧密码")
    new_password: str = Field(..., min_length=8, description="新密码（至少8位）")


class CreateApiKeyRequest(BaseModel):
    """CreateApiKeyRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    name: str = Field(..., description="API密钥名称")
    expires_in_days: Optional[int] = Field(365, description="过期天数（默认365天，0表示永不过期）")


# ==================== 注册 ====================

@router.post("/register", summary="用户注册")
async def register(request: RegisterRequest):
    """注册新用户，默认角色为user"""
    result = auth_manager.register(
        username=request.username,
        password=request.password,
        email=request.email,
    )
    if not result.get("success"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("error", "注册失败"),
        )
    return {
        "success": True,
        "user_id": result.get("user_id"),
        "username": result.get("username"),
        "role": result.get("role"),
        "api_key": result.get("api_key"),
        "message": "注册成功，请保存好你的API密钥",
    }


# ==================== 登录 ====================

@router.post("/login", summary="用户登录")
async def login(request: LoginRequest):
    """用户登录，返回JWT Access Token和Refresh Token"""
    result = auth_manager.login(
        username=request.username,
        password=request.password,
    )
    if not result.get("success"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result.get("error", "登录失败"),
        )
    return {
        "success": True,
        "access_token": result.get("access_token"),
        "refresh_token": result.get("refresh_token"),
        "token_type": "bearer",
        "expires_in": result.get("expires_in"),
        "user": {
            "user_id": result.get("user_id"),
            "username": result.get("username"),
            "role": result.get("role"),
            "email": result.get("email"),
        },
    }


# ==================== 登出 ====================

@router.post("/logout", summary="用户登出")
async def logout(current_user: dict = Depends(verify_auth)):
    """登出当前用户（使Token失效）"""
    token = current_user.get("token")
    if token:
        auth_manager.revoke_token(token)
    return {"success": True, "message": "登出成功"}


# ==================== 当前用户信息 ====================

@router.get("/me", summary="获取当前用户信息")
async def get_me(current_user: dict = Depends(verify_auth)):
    """获取当前登录用户的详细信息"""
    user = auth_manager.get_user(current_user["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    return {
        "success": True,
        "user": {
            "user_id": user.get("user_id"),
            "username": user.get("username"),
            "email": user.get("email"),
            "role": user.get("role"),
            "status": user.get("status"),
            "created_at": user.get("created_at"),
            "last_login_at": user.get("last_login_at"),
        },
    }


# ==================== 修改密码 ====================

@router.post("/change-password", summary="修改密码")
async def change_password(
    request: ChangePasswordRequest,
    current_user: dict = Depends(verify_auth),
):
    """修改当前用户密码"""
    result = auth_manager.change_password(
        user_id=current_user["user_id"],
        old_password=request.old_password,
        new_password=request.new_password,
    )
    if not result.get("success"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("error", "修改密码失败"),
        )
    return {"success": True, "message": "密码修改成功，请重新登录"}


# ==================== API密钥管理 ====================

@router.get("/api-keys", summary="获取用户API密钥列表")
async def list_api_keys(current_user: dict = Depends(verify_auth)):
    """获取当前用户的所有API密钥"""
    keys = auth_manager.list_api_keys(current_user["user_id"])
    return {
        "success": True,
        "total": len(keys),
        "api_keys": keys,
    }


@router.post("/api-keys", summary="创建新的API密钥")
async def create_api_key(
    request: CreateApiKeyRequest,
    current_user: dict = Depends(verify_auth),
):
    """创建新的API密钥（请妥善保存，只显示一次）"""
    result = auth_manager.create_api_key(
        user_id=current_user["user_id"],
        name=request.name,
        expires_in_days=request.expires_in_days,
    )
    if not result.get("success"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("error", "创建API密钥失败"),
        )
    return {
        "success": True,
        "api_key": result.get("api_key"),
        "name": result.get("name"),
        "expires_at": result.get("expires_at"),
        "message": "请妥善保存API密钥，只显示一次",
    }


@router.delete("/api-keys/{key_id}", summary="删除API密钥")
async def delete_api_key(
    key_id: str,
    current_user: dict = Depends(verify_auth),
):
    """删除指定的API密钥"""
    result = auth_manager.revoke_api_key(
        user_id=current_user["user_id"],
        key_id=key_id,
    )
    if not result.get("success"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("error", "删除API密钥失败"),
        )
    return {"success": True, "message": "API密钥已删除"}


# ==================== 管理员：用户列表 ====================

@router.get("/users", summary="获取所有用户（管理员）")
async def list_users(
    limit: int = 50,
    offset: int = 0,
    current_user: dict = Depends(require_admin),
):
    """获取所有用户列表（仅管理员）"""
    users = auth_manager.list_users(limit=limit, offset=offset)
    stats = auth_manager.get_statistics()
    return {
        "success": True,
        "total": stats.get("total_users", 0),
        "limit": limit,
        "offset": offset,
        "users": users,
    }


@router.get("/stats", summary="获取认证系统统计")
async def get_auth_stats(current_user: dict = Depends(require_admin)):
    """获取认证系统统计信息（仅管理员）"""
    return auth_manager.get_statistics()
