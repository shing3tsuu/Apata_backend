import asyncio
import logging
from contextlib import asynccontextmanager

from dishka import make_async_container
from dishka.integrations.fastapi import setup_dishka
from fastapi import FastAPI
import uvicorn

from src.providers.dishka_app import AdaptersProvider, GatewaysProvider, ServicesProvider

from src.services import AuthAPI, ContactAPI, MessageAPI

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await app.state.dishka_container.close()

async def create_app():
    container = make_async_container(
        AdaptersProvider(),
        GatewaysProvider(),
        ServicesProvider(),
    )

    app = FastAPI(lifespan=lifespan)
    setup_dishka(container, app)

    auth_api = await container.get(AuthAPI)
    contact_api = await container.get(ContactAPI)
    message_api = await container.get(MessageAPI)

    app.include_router(auth_api.get_router())
    app.include_router(contact_api.get_router())
    app.include_router(message_api.get_router())

    return app

if __name__ == "__main__":
    app = asyncio.run(create_app())
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")