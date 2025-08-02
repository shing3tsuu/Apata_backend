import asyncio
import logging
import threading
import uvicorn
from FastAPI.api import app as fastapi_app

from Database.db_manager import DatabaseManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
)
logger = logging.getLogger(__name__)

if __name__ == '__main__':
    print("Starting MAIN...")
    uvicorn.run(fastapi_app, host="127.0.0.1", port=8000, log_level="info")