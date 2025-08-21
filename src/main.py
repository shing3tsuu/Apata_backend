import asyncio
import logging
import threading
import uvicorn
from fastapi import FastAPI
from contextlib import asynccontextmanager

from core.db_manager import DatabaseManager
from src.services.authapi import AuthAPI
from src.Config.config import load_config


async def main():
    config = load_config(".env")

    db_manager = DatabaseManager()
    await db_manager.create_tables()

    auth_api = AuthAPI(
        secret_key=config.jwt.secret_key,
        db_manager=db_manager
    )

    app = FastAPI()
    app.include_router(auth_api.get_router())

    return app

if __name__ == "__main__":
    app = asyncio.run(main())
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")


