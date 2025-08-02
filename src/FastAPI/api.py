from fastapi import FastAPI, status, HTTPException
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
import logging
from fastapi.security import OAuth2PasswordBearer

from src.Database.DAO import BaseUserGateway
from src.Database.DTO import UserDomain, MessageDomain
from src.Database.gateways import UserGateway
from src.Database.db_manager import DatabaseManager
from src.Encryption.password_hash import PasswordHash

from src.FastAPI.api_models import *

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger = logging.getLogger("uvicorn.error")
    logger.info("--- Lifespan: Startup ---")
    try:
        await db_manager.initialize()
        await db_manager.create_tables()
        logger.info("Database operations completed.")
    except Exception as e:
        logger.error(f"Error during database initialization: {e}")

    yield
    logger.info("--- Lifespan: Shutdown ---")
    await db_manager.close()
    logger.info("Database operations cleanup completed.")


password_manager = PasswordHash()
app = FastAPI(lifespan=lifespan)
db_manager = DatabaseManager()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


@app.get("/")
async def read_root():
    return {"message": "Hello, World!"}