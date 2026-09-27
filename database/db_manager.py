"""
db_manager模块 —— SQLite 数据库管理器（SQLAlchemy 2.0）。

模块功能：
    - 维护引擎 / 会话工厂 / 表结构自动创建
    - 提供上下文管理器 get_session()
    - 提供通用 CRUD（create/get/list/update/delete）与批量操作（bulk_insert/update/delete）
    - 以单例 db_manager 全局暴露

注意事项：
    - 数据库文件默认位于 项目根/data/platform.db
    - 所有方法均做异常兜底并记录日志，不向上抛出未处理异常
    - 本模块为授权安全评估 / 防御检测产品的数据层
"""
import logging
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from sqlalchemy import create_engine, delete as sa_delete, update as sa_update
from sqlalchemy.orm import Session, sessionmaker

from database.models import Base

# 日志配置（自包含，避免依赖项目内其它模块造成导入副作用）
logger = logging.getLogger("platform.db_manager")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] db_manager: %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# 项目根目录（本文件位于 <root>/database/db_manager.py）
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = _PROJECT_ROOT / "data" / "platform.db"


class DBManager:
    """SQLite 数据库管理器（SQLAlchemy 2.0）。"""

    def __init__(self, db_path: Optional[str] = None):
        """初始化数据库引擎、会话工厂并自动建表。

        Args:
            db_path: 数据库文件路径，默认 data/platform.db
        """
        self.db_path = str(db_path) if db_path else str(DEFAULT_DB_PATH)
        try:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            # check_same_thread=False：允许 FastAPI 多线程下复用引擎连接
            db_url = f"sqlite:///{self.db_path}".replace(chr(92), "/")
            self.engine = create_engine(
                db_url,
                echo=False,
                connect_args={"check_same_thread": False},
            )
            self.SessionLocal = sessionmaker(
                bind=self.engine, autoflush=False, autocommit=False, expire_on_commit=False
            )
            # 自动建表（幂等）
            Base.metadata.create_all(self.engine)
            logger.info(f"数据库初始化完成: {self.db_path}")
        except Exception as e:  # noqa: BLE001
            # 保证引擎/会话工厂一定存在，避免调用方 AttributeError
            self.engine = None
            self.SessionLocal = None

    # -------------------- 会话管理 --------------------

    @contextmanager
    def get_session(self):
        """会话上下文管理器：自动提交 / 回滚 / 关闭，异常不向外抛出。"""
        session: Optional[Session] = None
        try:
            if self.SessionLocal is None:
                yield None
                return
            session = self.SessionLocal()
            yield session
            session.commit()
        except Exception as e:  # noqa: BLE001
            logger.error(f"会话操作失败: {e}")
            if session is not None:
                try:
                    session.rollback()
                except Exception as re:  # noqa: BLE001
                    logger.error(f"回滚失败: {re}")
            # 不向外抛出
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception as ce:  # noqa: BLE001
                    logger.error(f"关闭会话失败: {ce}")

    # -------------------- 通用 CRUD --------------------

    def create(self, model: Type, **fields) -> Optional[Any]:
        """插入单条记录。

        Args:
            model: ORM 模型类
            **fields: 字段键值

        Returns:
            创建后的实例（含 id），失败返回 None
        """
        try:
            with self.get_session() as session:
                if session is None:
                    return None
                obj = model(**fields)
                session.add(obj)
                session.flush()
                session.refresh(obj)
                session.expunge(obj)
                return obj
        except Exception as e:  # noqa: BLE001
            logger.error(f"create 失败 ({model.__name__}): {e}")
            return None

    def get(self, model: Type, obj_id: str) -> Optional[Any]:
        """按主键获取单条记录。"""
        try:
            with self.get_session() as session:
                if session is None:
                    return None
                obj = session.get(model, obj_id)
                if obj is not None:
                    session.refresh(obj)
                    session.expunge(obj)
                return obj
        except Exception as e:  # noqa: BLE001
            logger.error(f"get 失败 ({model.__name__} id={obj_id}): {e}")
            return None

    def list(
        self,
        model: Type,
        limit: int = 100,
        offset: int = 0,
        order_by: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Any]:
        """条件查询记录列表。

        Args:
            model: ORM 模型类
            limit: 最大条数
            offset: 偏移
            order_by: 排序字段名（字符串），缺省按主键
            filters: 等值过滤条件 {字段: 值}
        """
        try:
            with self.get_session() as session:
                if session is None:
                    return []
                stmt = session.query(model)
                if filters:
                    for k, v in filters.items():
                        if hasattr(model, k):
                            stmt = stmt.filter(getattr(model, k) == v)
                if order_by and hasattr(model, order_by):
                    stmt = stmt.order_by(getattr(model, order_by).desc())
                else:
                    stmt = stmt.order_by(model.id.desc())
                stmt = stmt.limit(limit).offset(offset)
                rows = stmt.all()
                for r in rows:
                    session.expunge(r)
                return rows
        except Exception as e:  # noqa: BLE001
            logger.error(f"list 失败 ({model.__name__}): {e}")
            return []

    def update(self, model: Type, obj_id: str, **fields) -> bool:
        """按主键更新记录。"""
        try:
            with self.get_session() as session:
                if session is None:
                    return False
                obj = session.get(model, obj_id)
                if obj is None:
                    logger.warning(f"update 未找到记录 ({model.__name__} id={obj_id})")
                    return False
                for k, v in fields.items():
                    if hasattr(obj, k):
                        setattr(obj, k, v)
                return True
        except Exception as e:  # noqa: BLE001
            logger.error(f"update 失败 ({model.__name__} id={obj_id}): {e}")
            return False

    def delete(self, model: Type, obj_id: str) -> bool:
        """按主键删除记录。"""
        try:
            with self.get_session() as session:
                if session is None:
                    return False
                obj = session.get(model, obj_id)
                if obj is None:
                    return False
                session.delete(obj)
                return True
        except Exception as e:  # noqa: BLE001
            logger.error(f"delete 失败 ({model.__name__} id={obj_id}): {e}")
            return False

    # -------------------- 批量操作 --------------------

    def bulk_insert(self, model: Type, items: List[Dict[str, Any]]) -> int:
        """批量插入。

        Args:
            model: ORM 模型类
            items: 字段字典列表

        Returns:
            成功插入条数
        """
        if not items:
            return 0
        try:
            with self.get_session() as session:
                if session is None:
                    return 0
                objs = [model(**{k: v for k, v in it.items() if hasattr(model, k)}) for it in items]
                session.add_all(objs)
                session.flush()
                return len(objs)
        except Exception as e:  # noqa: BLE001
            logger.error(f"bulk_insert 失败 ({model.__name__}): {e}")
            return 0

    def bulk_update(self, model: Type, items: List[Dict[str, Any]], key: str = "id") -> int:
        """批量更新。

        Args:
            model: ORM 模型类
            items: 字段字典列表，每项必须包含 key 对应的主键
            key: 主键字段名

        Returns:
            成功更新条数
        """
        if not items:
            return 0
        count = 0
        try:
            with self.get_session() as session:
                if session is None:
                    return 0
                for it in items:
                    pk = it.get(key)
                    if pk is None:
                        continue
                    payload = {k: v for k, v in it.items() if k != key and hasattr(model, k)}
                    if not payload:
                        continue
                    session.execute(sa_update(model).where(getattr(model, key) == pk).values(**payload))
                    count += 1
            return count
        except Exception as e:  # noqa: BLE001
            logger.error(f"bulk_update 失败 ({model.__name__}): {e}")
            return count

    def bulk_delete(self, model: Type, ids: List[str], key: str = "id") -> int:
        """批量删除。

        Args:
            model: ORM 模型类
            ids: 主键列表
            key: 主键字段名

        Returns:
            成功删除条数
        """
        if not ids:
            return 0
        try:
            with self.get_session() as session:
                if session is None:
                    return 0
                result = session.execute(sa_delete(model).where(getattr(model, key).in_(ids)))
                return int(result.rowcount or 0)
        except Exception as e:  # noqa: BLE001
            logger.error(f"bulk_delete 失败 ({model.__name__}): {e}")
            return 0

    def count(self, model: Type, filters: Optional[Dict[str, Any]] = None) -> int:
        """统计记录数（可选等值过滤）。"""
        try:
            from sqlalchemy import func

            with self.get_session() as session:
                if session is None:
                    return 0
                stmt = session.query(func.count(model.id))
                if filters:
                    for k, v in filters.items():
                        if hasattr(model, k):
                            stmt = stmt.filter(getattr(model, k) == v)
                return int(stmt.scalar() or 0)
        except Exception as e:  # noqa: BLE001
            logger.error(f"count 失败 ({model.__name__}): {e}")
            return 0


# ==================== 全局单例 ====================
db_manager = DBManager()
