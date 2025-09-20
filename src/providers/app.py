from dishka import Provider, Scope, provide
import asyncio
import redis
import logging

from src.config import Config, load_config
from src.core.db_manager import DatabaseManager
from src.core.gateways import UserGateway, MessageGateway

from src.services.routers import AuthAPI, ContactAPI, MessageAPI

class AdaptersProvider(Provider):
    @provide(scope=Scope.APP)
    def get_config(self) -> Config:
        return load_config(".env")

    @provide(scope=Scope.APP)
    def get_logger(self) -> logging.Logger:
        return logging.getLogger(__name__)

    @provide(scope=Scope.APP)
    def get_redis(self, config: Config) -> redis.Redis:
        return redis.Redis(host=config.redis.host, port=config.redis.port, db=0)

    @provide(scope=Scope.APP)
    async def get_db_manager(self, config: Config) -> DatabaseManager:
        db_manager = DatabaseManager(config)
        await db_manager.initialize()
        await db_manager.create_tables()
        return db_manager

class GatewaysProvider(Provider):
    @provide(scope=Scope.REQUEST)
    def get_user_gateway(
            self,
            db_manager: DatabaseManager,
            logger: logging.Logger
    ) -> UserGateway:
        return UserGateway(db_manager, logger)

    @provide(scope=Scope.REQUEST)
    def get_message_gateway(
            self,
            db_manager: DatabaseManager,
            logger: logging.Logger
    ) -> MessageGateway:
        return MessageGateway(db_manager, logger)

class ServicesProvider(Provider):
    @provide(scope=Scope.APP)
    def get_auth_api(
        self,
        config: Config,
        redis: redis.Redis,
        logger: logging.Logger
    ) -> AuthAPI:
        return AuthAPI(
            secret_key=config.jwt.secret_key,
            redis=redis,
            logger=logger
        )

    @provide(scope=Scope.APP)
    def get_contact_api(
            self,
            redis: redis.Redis,
            logger: logging.Logger
    ) -> ContactAPI:
        return ContactAPI(
            redis=redis,
            logger=logger
        )

    @provide(scope=Scope.APP)
    def get_message_api(
            self,
            logger: logging.Logger,
            auth_api: AuthAPI
    ) -> MessageAPI:
        return MessageAPI(
            logger=logger,
            auth_api=auth_api
        )