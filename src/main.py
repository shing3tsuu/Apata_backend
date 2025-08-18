import asyncio
import logging
import threading
import uvicorn
from fastapi import FastAPI
from contextlib import asynccontextmanager

from core.db_manager import DatabaseManager
from src.services.authapi import AuthAPI
from src.Config.config import load_config

config = load_config(".env")
auth_api = AuthAPI(secret_key=config.jwt.secret_key)

app = FastAPI()
app.include_router(auth_api.get_router())

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
)
logger = logging.getLogger(__name__)

if __name__ == '__main__':
    print("Starting MAIN...")

    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
