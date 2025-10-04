from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Dict
import asyncpg
import asyncio
import logging

from src.config import Config
from .database import Base


class BaseDatabaseManager:
    def __init__(self, config: Config):
        self.config = config
        self.engine = None
        self.session_factory = None
        self._listen_connections: Dict[int, asyncpg.Connection] = {}
        self._logger = logging.getLogger(__name__)

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

    async def get_asyncpg_dsn(self) -> str:
        """
        Obtaining a DSN for an asyncpg connection
        :return:
        """
        return f"postgresql://{self.config.db.user}:{self.config.db.password}@{self.config.db.host}:{self.config.db.port}/{self.config.db.name}"

    async def wait_for_user_notification(self, user_id: int, timeout: int = 30) -> bool:
        """
        Waiting for a notification for a specific user
        :param user_id: User ID
        :param timeout: Timeout in seconds
        :return: True if a notification has arrived, False if a timeout
        """
        dsn = await self.get_asyncpg_dsn()
        channel = f"user_{user_id}"

        try:
            # Create a connection and set up a listener
            conn = await asyncpg.connect(dsn)
            await conn.add_listener(channel, self._handle_notification)

            # Create an event to wait for
            notification_event = asyncio.Event()
            self._notification_events[channel] = notification_event

            try:
                # Wait for the event with timeout
                await asyncio.wait_for(notification_event.wait(), timeout=timeout)
                return True
            except asyncio.TimeoutError:
                return False
            finally:
                # Clean up
                await conn.remove_listener(channel, self._handle_notification)
                if channel in self._notification_events:
                    del self._notification_events[channel]
                await conn.close()

        except Exception as e:
            self._logger.error(f"Error waiting for notification for user {user_id}: {e}")
            return False

    def _handle_notification(self, connection, pid, channel, payload):
        """Handle incoming PostgreSQL notifications"""
        self._logger.debug(f"Received notification on channel {channel}")
        if channel in self._notification_events:
            self._notification_events[channel].set()

    async def notify_user(self, user_id: int):
        """
        Sending a notification to the user
        :param user_id: User ID
        """
        dsn = await self.get_asyncpg_dsn()
        channel = f"user_{user_id}"

        try:
            # Create a temporary connection for NOTIFY
            conn = await asyncpg.connect(dsn)
            await conn.execute(f"NOTIFY {channel}")
            await conn.close()
            self._logger.debug(f"Sent NOTIFY on channel {channel}")
        except Exception as e:
            self._logger.error(f"Error notifying user {user_id}: {e}")


class DatabaseManager(BaseDatabaseManager):
    def __init__(self, config: Config):
        super().__init__(config)
        self._notification_events = {}  # Store events for different channels

    async def initialize(self):
        self.engine = create_async_engine(
            url=f"postgresql+asyncpg://{self.config.db.user}:{self.config.db.password}@{self.config.db.host}:{self.config.db.port}/{self.config.db.name}",
            pool_size=30,
            max_overflow=20,
            pool_pre_ping=True,
            pool_timeout=60,
            pool_recycle=-1,
            echo=False,
        )

        self.session_factory = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
