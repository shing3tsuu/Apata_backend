from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional
from sqlalchemy.pool import NullPool
import sqlalchemy as db
import logging
import os
import logging

from src.Config.config import load_config
from src.core.database import Base

class BaseDatabaseManager:
    def __init__(self, logger: logging.Logger | None = None):
        self.logger = logger or logging.getLogger(__name__)
        self.config = load_config(".env")
        self.engine: AsyncEngine | None = None
        self.session_factory = None

    async def initialize(self):
        raise NotImplementedError()

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        if not self.engine:
            await self.initialize()

        async with self.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception as e:
                self.logger.error("Database error: %s", e, exc_info=True)
                await session.rollback()
                raise
            finally:
                await session.close()

    async def create_tables(self):
        if not self.engine:
            await self.initialize()

        async with self.engine.begin() as conn:
            if isinstance(self.engine.url, str) and "sqlite" in self.engine.url:
                await conn.execute("PRAGMA foreign_keys=ON")
            await conn.run_sync(Base.metadata.create_all)


class DatabaseManager(BaseDatabaseManager):
    async def initialize(self):
        db_path = self.config.db.path or "sqlite.db"

        if db_path != ":memory:":
            db_path = os.path.abspath(db_path)
            dir_path = os.path.dirname(db_path)
            if dir_path and not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
                self.logger.info(f"Created database directory: {dir_path}")

        self.engine = create_async_engine(
            f"sqlite+aiosqlite:///{db_path}",
            echo=True,
            connect_args={"check_same_thread": False},
            poolclass=NullPool
        )
        self.session_factory = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )