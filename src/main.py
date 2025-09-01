import asyncio
import logging
import threading
import uvicorn
from fastapi import FastAPI
from contextlib import asynccontextmanager

from core.db_manager import DatabaseManager
from src.services.auth_api import AuthAPI
from src.config import load_config

from core.redis import RedisManager

async def main():
    redis = RedisManager().get_redis()

    config = load_config(".env")

    db_manager = DatabaseManager()
    await db_manager.create_tables()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    )
    logger = logging.getLogger(__name__)

    auth_api = AuthAPI(
        secret_key=config.jwt.secret_key,
        db_manager=db_manager,
        redis=redis,
        logger=logger
    )

    app = FastAPI()
    app.include_router(auth_api.get_router())

    return app

if __name__ == "__main__":
    try:
        app = asyncio.run(main())
        uvicorn.run(app, log_level="info")
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(e, exc_info=True)
        raise
