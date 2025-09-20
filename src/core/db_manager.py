from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from contextlib import asynccontextmanager
from typing import AsyncGenerator
import logging

from src.config import Config
from .database import Base

class BaseDatabaseManager:
    def __init__(
            self,
            config: Config
    ):
        self.config = config
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
                await session.rollback()
                raise
            finally:
                await session.close()

    async def create_tables(self):
        if not self.engine:
            await self.initialize()

        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)


class DatabaseManager(BaseDatabaseManager):
    async def initialize(self):
        self.engine = create_async_engine(
            url=f"postgresql+asyncpg://{self.config.db.user}:{self.config.db.password}@{self.config.db.host}:{self.config.db.port}/{self.config.db.name}",
            # echo=True,
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=True
        )

        self.session_factory = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )